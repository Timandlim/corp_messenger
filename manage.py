import argparse
from app import app, db, User, Group, GroupMembership, gost_encrypt

def create_user(username, password):
    if User.query.filter_by(username=username).first():
        print(f"Пользователь '{username}' уже существует.")
    else:
        encrypted_password = gost_encrypt(password.encode('utf-8')).hex()
        user = User(username=username, password_hash=encrypted_password)
        db.session.add(user)
        db.session.commit()
        print(f"Пользователь '{username}' создан.")

def create_group(name):
    if Group.query.filter_by(name=name).first():
        print(f"Группа '{name}' уже существует.")
    else:
        group = Group(name=name)
        db.session.add(group)
        db.session.commit()
        print(f"Группа '{name}' создана.")

def add_user_to_group(username, group_name):
    user = User.query.filter_by(username=username).first()
    group = Group.query.filter_by(name=group_name).first()
    if not user:
        print(f"Пользователь '{username}' не найден.")
        return
    if not group:
        print(f"Группа '{group_name}' не найдена.")
        return
    if GroupMembership.query.filter_by(user_id=user.id, group_id=group.id).first():
        print(f"Пользователь '{username}' уже состоит в группе '{group_name}'.")
    else:
        membership = GroupMembership(user_id=user.id, group_id=group.id)
        db.session.add(membership)
        db.session.commit()
        print(f"Пользователь '{username}' добавлен в группу '{group_name}'.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Управление пользователями и группами мессенджера")
    subparsers = parser.add_subparsers(dest='command')

    parser_create_user = subparsers.add_parser('create_user', help='Создать пользователя')
    parser_create_user.add_argument('username')
    parser_create_user.add_argument('password')

    parser_create_group = subparsers.add_parser('create_group', help='Создать группу')
    parser_create_group.add_argument('name')

    parser_add_user = subparsers.add_parser('add_user_to_group', help='Добавить пользователя в группу')
    parser_add_user.add_argument('username')
    parser_add_user.add_argument('group_name')

    args = parser.parse_args()

    with app.app_context():
        db.create_all()
        if args.command == 'create_user':
            create_user(args.username, args.password)
        elif args.command == 'create_group':
            create_group(args.name)
        elif args.command == 'add_user_to_group':
            add_user_to_group(args.username, args.group_name)
        else:
            parser.print_help()
