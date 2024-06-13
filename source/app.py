from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

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
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('You must be logged in to view this page.', 'error')
    return redirect(url_for('login'))

def add_certificate(hostname, common_name, expiration_date, serial_number):
    certificate = Certificate(hostname=hostname, common_name=common_name, expiration_date=expiration_date, serial_number=serial_number)
    db.session.add(certificate)
    db.session.commit()

def get_all_certificates():
    return Certificate.query.all()

def get_expiring_certificates():
    two_months_later = datetime.now() + timedelta(days=60)
    return Certificate.query.filter(Certificate.expiration_date <= two_months_later).all()

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
    return redirect(url_for('index'))

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
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
