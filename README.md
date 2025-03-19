## Особенности

- **Регистрация и аутентификация**: Пользователи могут регистрироваться и входить в систему, используя безопасное хэширование паролей.
- **Реальный чат**: Сообщения передаются в реальном времени через Socket.IO.
- **Шифрование сообщений**: Сообщения шифруются с использованием ГОСТ 28147-89.

## Технологии

- [Flask](https://flask.palletsprojects.com/)
- [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/)
- [Flask-Login](https://flask-login.readthedocs.io/)
- [Flask-SocketIO](https://flask-socketio.readthedocs.io/)
- [eventlet](http://eventlet.net/)
- HTML/CSS/JS для фронтенда

## Установка

1. **Клонируйте репозиторий:**
  ```bash
   git clone https://github.com/Timandlim/flask-messenger.git
   cd flask-messenger
```
2. **Создайте и активируйте виртуальное окружение:**
```bash
  python -m venv venv
  # Для Linux/MacOS:
  source venv/bin/activate
  # Для Windows:
  venv\Scripts\activate
```
3. **Установите зависимости:**
```bash
  pip install -r requirements.txt
```
