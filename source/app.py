import csv
import io
import os
import logging
import atexit
from datetime import datetime

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
    send_file,
    make_response
)
from flask_login import LoginManager, login_user, logout_user, login_required
from werkzeug.security import check_password_hash

from lib.mongo import MongoDB

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Настройка MongoDB
mongo_url = 'mongodb://localhost:27017/certificates'
mongo = MongoDB(mongo_url)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',  # noqa
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)


@login_manager.user_loader
def load_user(email):
    user = mongo.load_user(email)
    if user:
        return User(user['email'], user['password'], user['active'])
    return None


@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('You must be logged in to view this page.', 'error')
    return redirect(url_for('login'))


class User:
    def __init__(self, email, password, active):
        self.email = email
        self.password = password
        self.active = active

    @staticmethod
    def is_authenticated():
        return True

    def is_active(self):
        return self.active

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.email


def add_certificate(hostname, common_name, expiration_date, serial_number):
    mongo.add_certificate(hostname, common_name, expiration_date, serial_number)


def get_all_certificates():
    return mongo.get_all_certificates()


def get_expiring_certificates_within_days(days):
    return mongo.get_expiring_certificates_within_days(days)


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


def check_certificates_and_send_notification():
    certificates = get_expiring_certificates_within_days(60)
    if certificates:
        if not notification_already_sent_today():
            messages = [
                f"{cert['hostname']} истекает {cert['expiration_date'].strftime('%Y.%m.%d')}"
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
    mongo.add_user(email, password)


@app.route('/export_certificates')
@login_required
def export_certificates():
    certificates = get_all_certificates()  # Используем MongoDB метод для получения сертификатов
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Name', 'Expiry Date'])  # заголовки CSV
    for certificate in certificates:
        writer.writerow([certificate['_id'], certificate['hostname'], certificate['expiration_date']])
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=certificates.csv'
    response.headers['Content-type'] = 'text/csv'
    return response


@app.route('/yandex_bot_webhook', methods=['POST'])
def yandex_bot_webhook():
    data = request.json
    logging.info(f"Получено сообщение: {data}")
    if 'message' in data:
        message_text = data['message']['text']
        if message_text.lower() == 'повторить':
            check_certificates_and_send_notification()
    return jsonify({"status": "ok"})


@app.route('/update_certificate/<string:certificate_id>', methods=['POST'])
@login_required
def update_certificate(certificate_id):
    certificate = mongo.db[mongo.collection].find_one({"_id": certificate_id})
    if not certificate:
        flash('Certificate not found.', 'error')
        return redirect(url_for('view_certificates'))

    hostname = request.form['hostname']
    common_name = request.form['common_name']
    expiration_date_str = request.form['expiration_date']
    expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
    serial_number = request.form['serial_number']

    mongo.update_certificate(certificate_id, hostname, common_name, expiration_date, serial_number)
    flash('Certificate updated successfully.', 'success')
    logging.info(f"Updated certificate {certificate_id} for {hostname}")
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
    all_certs = get_all_certificates()
    return render_template('certificates.html', certificates=all_certs)


@app.route('/view_expiring_certificates', methods=['GET'])
@login_required
def view_expiring_certificates():
    expiring_certificates = get_expiring_certificates_within_days(60)
    return render_template('expiring_certificates.html', certificates=expiring_certificates)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = mongo.load_user(email)
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['email'], user['password'], user['active'])
            login_user(user_obj)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login2.0.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        add_user(email, password)
        flash('User created successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('create_user.html')


@app.route('/edit_certificate/<string:serial_number>', methods=['GET', 'POST'])
@login_required
def edit_certificate(serial_number):
    certificate = mongo.get_certificate(serial_number)
    if request.method == 'POST':
        expiration_date_str = request.form['expiration_date']
        expiration_date_new = datetime.strptime(expiration_date_str, '%Y-%m-%d')

        certificate_id = certificate["_id"]

        mongo.update_certificate(
            certificate_id=certificate_id,
            hostname=request.form['hostname'],
            common_name=request.form['common_name'],
            expiration_date=expiration_date_new,
            serial_number=request.form['serial_number']
        )

        flash('Certificate updated successfully.', 'success')
        logging.info(f"Updated certificate {certificate_id} for {certificate['hostname']}")
        return redirect(url_for('view_certificates'))
    return render_template('edit_certificate.html', certificate=certificate)


@app.route('/delete_certificate/<string:serial_number>', methods=['POST'])
@login_required
def delete_certificate(serial_number):
    certificate = mongo.get_certificate(serial_number)
    if certificate:
        mongo.delete_certificate(certificate['_id'])
        flash('Certificate deleted successfully.', 'success')
    else:
        flash('Certificate not found.', 'error')
    return redirect(url_for('view_certificates'))


@app.route('/delete_user/<string:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    mongo.delete_user(user_id)
    flash('User deleted successfully.', 'success')
    return redirect(url_for('index'))


@app.route('/download_certificates_csv', methods=['GET'])
@login_required
def download_certificates_csv():
    certificates = list(get_all_certificates())
    df = pd.DataFrame(certificates)
    csv_path = '/mnt/data/certificates.csv'
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, as_attachment=True)


@app.route('/add_cert', methods=['POST'])
@login_required
def add_cert():
    hostname = request.form['hostname']
    common_name = request.form['common_name']
    expiration_date_str = request.form['expiration_date']
    expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
    serial_number = request.form['serial_number']

    add_certificate(hostname, common_name, expiration_date, serial_number)

    flash('Сертификат успешно добавлен.', 'success')
    return redirect(url_for('index'))


scheduler = BackgroundScheduler()
scheduler.add_job(check_certificates_and_send_notification, 'interval', days=1)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    app.run(debug=True)
