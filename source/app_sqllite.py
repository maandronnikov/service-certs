import os
import logging
import atexit
from datetime import datetime, timedelta

import requests
import pandas as pd
from apscheduler.schedulers.background import BackgroundScheduler
from flask import (
    Flask,
    render_template,
    request, redirect,
    url_for,
    flash,
    jsonify,
    send_file
)

from flask_login import LoginManager, login_user, logout_user, login_required
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

from models.db import db, User, Certificate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certificates.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'

db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]', # noqa
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('You must be logged in to view this page.', 'error')
    return redirect(url_for('login'))


def add_certificate(hostname, common_name, expiration_date, serial_number):
    with app.app_context():
        certificate = Certificate(
            hostname=hostname,
            common_name=common_name,
            expiration_date=expiration_date,
            serial_number=serial_number
        )
        db.session.add(certificate)
        db.session.commit()
        logging.info(f"Added certificate for {hostname} expiring on {expiration_date}") # noqa


def get_all_certificates():
    with app.app_context():
        return Certificate.query.all()


def get_expiring_certificates_within_days(days):
    with app.app_context():
        date_later = datetime.now() + timedelta(days=days)
        return Certificate.query.filter(
            Certificate.expiration_date <= date_later
        ).all()


def send_yandex_request(endpoint, data):
    token = os.getenv('Token_YandexMasage', 'Ключа нет')
    url = f'https://botapi.messenger.yandex.net/bot/v1/{endpoint}'
    headers = {
        'Authorization': f'OAuth {token}',
        'Content-Type': 'application/json; charset=utf-8'
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        logging.info("Запрос успешно выполнен.")
    else:
        logging.error(
            f"Ошибка при выполнении запроса: "
            f"{response.status_code} {response.text}"
        )
    return response.json()


def send_yandex_notification(message):
    chat_id = '0/0/b06ba50c-e026-43fc-8603-69334b06da5d'
    data = {
        'chat_id': chat_id,
        'text': message
    }
    return send_yandex_request('messages/sendText/', data)


# def create_yandex_notification(channel_name):
#     data = {
#         "name": channel_name,
#         "description": "Тест канал",
#         "admins": [{"login": "v.onishchuk@centrofinans.ru"}]
#     }
#     return send_yandex_request('chats/create/', data)


def check_certificates_and_send_notification():
    with app.app_context():
        certificates = get_expiring_certificates_within_days(60)
        if certificates:
            if not notification_already_sent_today():
                messages = [
                    f"{cert.hostname} истекает {cert.expiration_date.strftime('%d.%m.%Y')}"
                    for cert in certificates
                ]
                full_message = "\n".join(messages)
                send_yandex_notification(full_message)
                mark_notification_as_sent_today()
        else:
            send_yandex_notification("Нет сертификатов, истекающих в ближайшие 60 дней.")


def notification_already_sent_today():
    return False


def mark_notification_as_sent_today():
    pass


def add_user(email, password):
    with app.app_context():
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, active=True)
        db.session.add(new_user)
        db.session.commit()
        logging.info(f'User {email} has been created.')


@app.route('/yandex_bot_webhook', methods=['POST'])
def yandex_bot_webhook():
    data = request.json
    logging.info(f"Получено сообщение: {data}")
    if 'message' in data:
        message_text = data['message']['text']
        if message_text.lower() == 'повторить':
            check_certificates_and_send_notification()
    return jsonify({"status": "ok"})


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
    logging.info(f"Updated certificate {certificate_id} for {certificate.hostname}")
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
    with app.app_context():
        certificates = get_all_certificates()
    return render_template('certificates.html', certificates=certificates)


@app.route('/view_expiring_certificates', methods=['GET'])
@login_required
def view_expiring_certificates():
    with app.app_context():
        expiring_certificates = get_expiring_certificates_within_days(60)
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
    logging.info(f"Added certificate for {hostname} expiring on {expiration_date}")
    return redirect(url_for('index'))


@app.route('/edit_certificate/<int:certificate_id>', methods=['GET', 'POST'])
@login_required
def edit_certificate(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    if request.method == 'POST':
        certificate.hostname = request.form['hostname']
        certificate.common_name = request.form['common_name']
        expiration_date_str = request.form['expiration_date']
        certificate.expiration_date = datetime.strptime(
            expiration_date_str, '%Y-%m-%d'
        )
        certificate.serial_number = request.form['serial_number']
        db.session.commit()
        flash('Certificate updated successfully.', 'success')
        logging.info(f"Updated certificate {certificate_id} for {certificate.hostname}")
        return redirect(url_for('view_certificates'))
    return render_template('edit_certificate.html', certificate=certificate)


@app.route('/delete_certificate/<int:certificate_id>', methods=['POST'])
@login_required
def delete_certificate(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    db.session.delete(certificate)
    db.session.commit()
    flash('Certificate deleted successfully.', 'success')
    logging.info(f"Deleted certificate {certificate_id} for {certificate.hostname}")
    return redirect(url_for('view_certificates'))


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.email = request.form['email']
        if request.form['password']:
            user.password = generate_password_hash(
                request.form['password'], method='pbkdf2:sha256'
            )
        db.session.commit()
        flash('User updated successfully.', 'success')
        logging.info(f"User {user.email} updated successfully.")
        return redirect(url_for('user_admin'))
    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    logging.info(f"User {user.email} deleted successfully.")
    return redirect(url_for('user_admin'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('Login successful.', 'success')
            logging.info(f"User {email} logged in successfully.")
            return redirect(url_for('index'))
        else:
            flash('Incorrect email or password.', 'error')
            logging.warning(f"Failed login attempt for {email}.")
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
    with app.app_context():
        certificates = get_all_certificates()
        data = []
        for cert in certificates:
            data.append({
                "Hostname": cert.hostname,
                "Common Name": cert.common_name,
                "Expiration Date": cert.expiration_date.strftime('%d.%m.%Y'),
                "Serial Number": cert.serial_number
            })

        df = pd.DataFrame(data)
        file_path = 'certificates.xlsx'
        df.to_excel(file_path, index=False)

    logging.info("Exported certificates to certificates.xlsx")
    return send_file(file_path, as_attachment=True, download_name='certificates.xlsx')


@app.route('/user', methods=['GET', 'POST'])
@login_required
def user_admin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        add_user(email, password)
        flash('User added successfully.', 'success')
        logging.info(f"User {email} added successfully.")
        return redirect(url_for('user_admin'))

    users = User.query.all()
    return render_template('user_admin.html', users=users)


# Инициализация планировщика
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=check_certificates_and_send_notification,
    trigger="interval",
    days=1
)
scheduler.start()

# Завершение работы планировщика при завершении приложения
atexit.register(lambda: scheduler.shutdown())

# Отправка уведомления сразу при запуске приложения
# check_certificates_and_send_notification()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)