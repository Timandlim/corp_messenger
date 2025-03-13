import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import struct



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messenger.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)

class GroupMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)  # Групповое сообщение
    content = db.Column(db.Text, nullable=False)  # Зашифрованное сообщение (hex)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- ШИФРОВАНИЕ ПО ГОСТ --------------------
# Реализация ГОСТ 28147-89 в режиме ECB с PKCS7‑отступами
SBOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
]

def gost_substitute(value):
    result = 0
    for i in range(8):
        nibble = (value >> (4 * i)) & 0xF
        substituted = SBOX[i][nibble]
        result |= (substituted << (4 * i))
    return result

def rol32(value, bits):
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))

def gost_encrypt_block(block, key_parts):
    n1, n2 = struct.unpack('<II', block)
    for i in range(24):
        k = key_parts[i % 8]
        temp = (n1 + k) % 0x100000000
        temp = gost_substitute(temp)
        temp = rol32(temp, 11)
        n1, n2 = n2, n1 ^ temp
    for i in range(8):
        k = key_parts[7 - (i % 8)]
        temp = (n1 + k) % 0x100000000
        temp = gost_substitute(temp)
        temp = rol32(temp, 11)
        n1, n2 = n2, n1 ^ temp
    return struct.pack('<II', n2, n1)

def gost_decrypt_block(block, key_parts):
    n1, n2 = struct.unpack('<II', block)
    for i in range(8):
        k = key_parts[i]
        temp = (n1 + k) % 0x100000000
        temp = gost_substitute(temp)
        temp = rol32(temp, 11)
        n1, n2 = n2, n1 ^ temp
    for i in range(24):
        k = key_parts[(7 - (i % 8))]
        temp = (n1 + k) % 0x100000000
        temp = gost_substitute(temp)
        temp = rol32(temp, 11)
        n1, n2 = n2, n1 ^ temp
    return struct.pack('<II', n2, n1)

def pkcs7_pad(data, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

DEFAULT_KEY = b'0123456789abcdef0123456789abcdef'
def get_key_parts(key=DEFAULT_KEY):
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for GOST")
    return list(struct.unpack('<8I', key))

def gost_encrypt(data, key=DEFAULT_KEY):
    key_parts = get_key_parts(key)
    padded = pkcs7_pad(data)
    encrypted = b''
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        encrypted += gost_encrypt_block(block, key_parts)
    return encrypted

def gost_decrypt(data, key=DEFAULT_KEY):
    key_parts = get_key_parts(key)
    decrypted = b''
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        decrypted += gost_decrypt_block(block, key_parts)
    return pkcs7_unpad(decrypted)

# -------------------- РОУТЫ --------------------
# Страница логина (регистрация отключена)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Вы успешно вошли в систему.")
            # После логина перенаправляем на единый dashboard
            return redirect(url_for('dashboard'))
        else:
            flash("Неверные учётные данные.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы.")
    return redirect(url_for('login'))

# Единая страница Dashboard: слева список групп, справа чат выбранной группы.
@app.route('/')
@login_required
def dashboard():
    # Если у пользователя есть группы – выбираем первую, иначе пустая страница чата
    memberships = GroupMembership.query.filter_by(user_id=current_user.id).all()
    groups = [Group.query.get(m.group_id) for m in memberships]
    current_group = groups[0] if groups else None
    # Если группа выбрана, загружаем её историю сообщений (полная)
    messages = []
    if current_group:
        messages = Message.query.filter_by(group_id=current_group.id).order_by(Message.timestamp.asc()).all()
    display_messages = []
    for msg in messages:
        try:
            decrypted = gost_decrypt(bytes.fromhex(msg.content)).decode('utf-8')
        except Exception:
            decrypted = "Ошибка расшифровки"
        sender = User.query.get(msg.sender_id)
        display_messages.append({
            'sender': sender.username if sender else 'Неизвестно',
            'content': decrypted,
            'timestamp': msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return render_template('dashboard.html', groups=groups, current_group=current_group, messages=display_messages)

# Выбор группы через URL
@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    # Проверяем, что пользователь состоит в группе
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash("Вы не состоите в этой группе.")
        return redirect(url_for('dashboard'))
    memberships = GroupMembership.query.filter_by(user_id=current_user.id).all()
    groups = [Group.query.get(m.group_id) for m in memberships]
    messages = Message.query.filter_by(group_id=group_id).order_by(Message.timestamp.asc()).all()
    display_messages = []
    for msg in messages:
        try:
            decrypted = gost_decrypt(bytes.fromhex(msg.content)).decode('utf-8')
        except Exception:
            decrypted = "Ошибка расшифровки"
        sender = User.query.get(msg.sender_id)
        display_messages.append({
            'sender': sender.username if sender else 'Неизвестно',
            'content': decrypted,
            'timestamp': msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return render_template('dashboard.html', groups=groups, current_group=Group.query.get(group_id), messages=display_messages)

# -------------------- SocketIO События --------------------
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        print(f"User {current_user.username} connected.")
    else:
        print("Anonymous user connected.")

@socketio.on('send_message')
def handle_send_message(data):
    # Ожидается: data = { group_id: <ID>, message: <текст> }
    group_id = data.get('group_id')
    message_text = data.get('message')
    if not group_id or not message_text:
        emit('error', {'error': 'Неверные данные.'})
        return
    try:
        group_id = int(group_id)
    except ValueError:
        emit('error', {'error': 'Неверный ID группы.'})
        return
    # Проверяем, что пользователь состоит в группе
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        emit('error', {'error': 'Вы не состоите в этой группе.'})
        return
    encrypted = gost_encrypt(message_text.encode('utf-8')).hex()
    msg = Message(sender_id=current_user.id, group_id=group_id, content=encrypted)
    db.session.add(msg)
    db.session.commit()
    try:
        decrypted = gost_decrypt(bytes.fromhex(msg.content)).decode('utf-8')
    except Exception:
        decrypted = "Ошибка расшифровки"
    message_data = {
        'sender': current_user.username,
        'content': decrypted,
        'timestamp': msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    }
    emit('new_message', message_data, broadcast=True)

# -------------------- ЗАПУСК --------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
