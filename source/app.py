from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import requests
import pandas as pd
import os
import base64
import requests

from models.db import db, User, Certificate, Role

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certificates.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'

db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('You must be logged in to view this page.', 'error')
    return redirect(url_for('login'))


def add_certificate(hostname, common_name, expiration_date, serial_number):
    certificate = Certificate(hostname=hostname, common_name=common_name, expiration_date=expiration_date,
                              serial_number=serial_number)
    db.session.add(certificate)
    db.session.commit()


def get_all_certificates():
    return Certificate.query.all()


def get_expiring_certificates():
    two_months_later = datetime.now() + timedelta(days=60)
    return Certificate.query.filter(Certificate.expiration_date <= two_months_later).all()


# Используется для работы с чатом
def send_yandex_notification(message):
    token = 'y0_AgAAAAB2zmtUAATIlgAAAAEH9VmaAACr-yuiXKVEnqYiyoiGiI7SZhiamw'  # Токен
    chat_id = '0/0/b06ba50c-e026-43fc-8603-69334b06da5d'  # ID чата

    url = 'https://botapi.messenger.yandex.net/bot/v1/messages/sendText/'

    headers = {
        'Authorization': f'OAuth {token}',
        'Content-Type': 'application/json'
    }

    data = {
        'chat_id': chat_id,
        'text': message
    }

    response = requests.post(url, headers=headers, json=data)
    return response.json()


massage = "Привет!"
response = send_yandex_notification(massage)
print(response)


# Создает чат
def create_yandex_notification(chanel_name):
    token = 'y0_AgAAAAB2zmtUAATIlgAAAAEH9VmaAACr-yuiXKVEnqYiyoiGiI7SZhiamw'  # Токен

    url = 'https://botapi.messenger.yandex.net/bot/v1/chats/create/'

    headers = {
        'Authorization': f'OAuth {token}',
        'Content-Type': 'application/json'
    }

    data = {
        "name": chanel_name,
        "description": "Тест канал",
        "admins": [{"login": "v.onishchuk@centrofinans.ru"}]

    }

    response = requests.post(url, headers=headers, json=data)
    return response.json()


#chanel_name = "Перевыпуски Сертификатов"
#response = create_yandex_notification(chanel_name)
#print(response)


@app.route('/update_certificate/<int:certificate_id>', methods=['POST'])
@login_required
def update_certificate(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    certificate.hostname = request.form['hostname']
    certificate.common_name = request.form['common_name']
    expiration_date_str = request.form['expiration_date']
    certificate.expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
    certificate.serial_number = request.form['serial_number']
    db.session.commit()
    flash('Certificate updated successfully.', 'success')
    return redirect(url_for('view_certificates'))


@app.route('/test_notification', methods=['GET'])
@login_required
def test_notification():
    message = "Это тестовое сообщение от вашего бота."
    response = send_yandex_notification(message)
    return jsonify(response)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/view_certificates', methods=['GET'])
@login_required
def view_certificates():
    certificates = get_all_certificates()
    return render_template('certificates.html', certificates=certificates)


@app.route('/view_expiring_certificates', methods=['GET'])
@login_required
def view_expiring_certificates():
    expiring_certificates = get_expiring_certificates()
    return render_template('certificates.html', certificates=expiring_certificates)


@app.route('/add_certificate', methods=['POST'])
@login_required
def add_cert():
    hostname = request.form['hostname']
    common_name = request.form['common_name']
    expiration_date_str = request.form['expiration_date']
    expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
    serial_number = request.form['serial_number']
    add_certificate(hostname, common_name, expiration_date, serial_number)
    flash('Certificate added successfully.', 'success')
    return redirect(url_for('index'))


@app.route('/edit_certificate/<int:certificate_id>', methods=['GET', 'POST'])
@login_required
def edit_certificate(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    if request.method == 'POST':
        certificate.hostname = request.form['hostname']
        certificate.common_name = request.form['common_name']
        expiration_date_str = request.form['expiration_date']
        certificate.expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
        certificate.serial_number = request.form['serial_number']
        db.session.commit()
        flash('Certificate updated successfully.', 'success')
        return redirect(url_for('view_certificates'))
    return render_template('edit_certificate.html', certificate=certificate)


@app.route('/delete_certificate/<int:certificate_id>', methods=['POST'])
@login_required
def delete_certificate(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    db.session.delete(certificate)
    db.session.commit()
    flash('Certificate deleted successfully.', 'success')
    return redirect(url_for('view_certificates'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('Login successful.', 'success')
            app.logger.info(f"User {email} logged in successfully.")
            return redirect(url_for('index'))
        else:
            flash('Incorrect email or password.', 'error')
            app.logger.warning(f"Failed login attempt for {email}.")
    return render_template('login2.0.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/export_certificates', methods=['GET'])
@login_required
def export_certificates():
    certificates = get_all_certificates()
    data = []
    for cert in certificates:
        data.append({
            "Hostname": cert.hostname,
            "Common Name": cert.common_name,
            "Expiration Date": cert.expiration_date.strftime('%Y-%m-%d'),
            "Serial Number": cert.serial_number
        })

    df = pd.DataFrame(data)
    file_path = 'certificates.xlsx'
    df.to_excel(file_path, index=False)

    return send_file(file_path, as_attachment=True, download_name='certificates.xlsx')


if __name__ == '__main__':
    app.run(debug=True)
