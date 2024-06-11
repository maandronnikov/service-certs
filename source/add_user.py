from werkzeug.security import generate_password_hash
from models.db import db, User
from app import app

def add_user(email, password):
    with app.app_context():
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, active=True)
        db.session.add(new_user)
        db.session.commit()
        print(f'User {email} has been created.')

if __name__ == '__main__':
    email = input('Enter email: ')
    password = input('Enter password: ')
    add_user(email, password)
