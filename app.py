import os
import struct
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_socketio import SocketIO, emit

app = Flask(__name__)
# Абсолютный путь к файлу базы данных
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'messenger.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# -------------------- МОДЕЛИ --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    # Здесь хранится зашифрованное значение пароля (в виде hex строки)
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

# -------------------- ШИФРОВАНИЕ ПО ГОСТ--------------------
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
        result |= (SBOX[i][nibble] << (4 * i))
    return result

def rol32(value, bits):
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))

def f(x, k):
    return rol32(gost_substitute((x + k) % 0x100000000), 11)

def get_round_keys(key_parts):
    return key_parts * 3 + list(reversed(key_parts))

def gost_encrypt_block(block, key_parts):
    n1, n2 = struct.unpack("<II", block)
    round_keys = get_round_keys(key_parts)
    for k in round_keys:
        temp = f(n1, k)
        temp ^= n2
        n2 = n1
        n1 = temp
    # Дополнительный swap для обратимости
    n1, n2 = n2, n1
    return struct.pack("<II", n1, n2)

def gost_decrypt_block(block, key_parts):
    n1, n2 = struct.unpack("<II", block)
    round_keys = list(reversed(get_round_keys(key_parts)))
    for k in round_keys:
        temp = f(n1, k)
        temp ^= n2
        n2 = n1
        n1 = temp
    n1, n2 = n2, n1
    return struct.pack("<II", n1, n2)

def pkcs7_pad(data, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Неверная длина паддинга.")
    return data[:-pad_len]

DEFAULT_KEY = b'0123456789abcdef0123456789abcdef'

def get_key_parts(key=DEFAULT_KEY):
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for GOST")
    return list(struct.unpack("<8I", key))

def gost_encrypt(data, key=DEFAULT_KEY):
    key_parts = get_key_parts(key)
    padded = pkcs7_pad(data)
    encrypted = b""
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        encrypted += gost_encrypt_block(block, key_parts)
    return encrypted

def gost_decrypt(data, key=DEFAULT_KEY):
    key_parts = get_key_parts(key)
    decrypted = b""
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        decrypted += gost_decrypt_block(block, key_parts)
    return pkcs7_unpad(decrypted)
# -------------------- РОУТЫ --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            try:
                stored_password = gost_decrypt(bytes.fromhex(user.password_hash)).decode('utf-8')
            except Exception:
                stored_password = None
            if stored_password == password:
                login_user(user)
                flash("Вы успешно вошли в систему.")
                return redirect(url_for('dashboard'))
        flash("Неверные учётные данные.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы.")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    memberships = GroupMembership.query.filter_by(user_id=current_user.id).all()
    groups = [Group.query.get(m.group_id) for m in memberships]
    current_group = groups[0] if groups else None
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

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
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

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        print(f"User {current_user.username} connected.")
    else:
        print("Anonymous user connected.")

@socketio.on('send_message')
def handle_send_message(data):
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
    socketio.run(app, debug=True, use_reloader=False)
