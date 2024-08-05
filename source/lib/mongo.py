import logging
from datetime import datetime, timedelta
from pymongo import MongoClient

from werkzeug.security import generate_password_hash, check_password_hash

mongo_url = 'mongodb://localhost:27017/certificates'
client = MongoClient(mongo_url)
db = client.get_database()


class MongoDB:
    def __init__(self, mongo_url: str):
        self.mongo_url = mongo_url

        self.connection = None
        self.db = None

        self.collection = "certs"
        self.logging = logging.getLogger("MongoClient")

    def _connect(self):
        """Открываем соединение"""
        self.connection = MongoClient(self.mongo_url)
        self.db = self.connection.get_database()

    def close_connections(self):
        """Закрываем соединение"""
        if self.connection is not None:
            self.connection.close()

    def load_user(self, user_id):
        """загружкает пользователя из базы"""
        user = self.db[self.collection].find_one({"user_id": user_id})
        if user:
            return user
        self.logging.warning(f"Пользователь с таким {user_id} не существует")
        return None

    def add_certificate(self, hostname, common_name, expiration_date, serial_number):
        """В index добавление пользователя"""
        certificate = {
            "hostname": hostname,
            "common_name": common_name,
            "expiration_date": expiration_date,
            "serial_number": serial_number
        }
        self.db[self.collection].insert_one(certificate)
        self.logging.info(f"Added certificate for {hostname} expiring on {expiration_date}")

    def get_all_certificates(self):
        """Возвращает все сертификаты из бызы данных"""
        return self.db[self.collection].find()

    def get_expiring_certificates_within_days(self, days):
        """Возвращает сертификаты, срок действия которых истекает в течение указанных дней"""
        date_later = datetime.now() + timedelta(days=days)
        return list(self.db[self.collection].find({"expiration_date": {"$lte": date_later}}))

    def add_user(self, email, password):
        """Вставляет в коллекцию users"""
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = {
            "email": email,
            "password": hashed_password,
            "active": True
        }
        self.db[self.collection].insert_one(new_user)
        logging.info(f'User {email} has been created.')

    def update_certificate(self, certificate_id, hostname, common_name, expiration_date, serial_number):
        """Так же получает серты оп id нужен ли обновляет форму?"""
        updated_data = {
            "hostname": hostname,
            "common_name": common_name,
            "expiration_date": expiration_date,
            "serial_number": serial_number
        }
        self.db[self.collection].update_one(
            {"certificate_id": certificate_id},
            {"$set": updated_data}
        )
        self.logging.info(f"Обновление сертификата {certificate_id} для {hostname}")

    def view_certificates(self):
        """Отображает сертификаты"""
        certificates = get_all_certificates()
        self.db[self.collection].find(certificates)

    def view_expiring_certificates(self):
        """Отображает истекающие сертификаты"""
        expiring_certificates = get_expiring_certificates_within_days(60)
        self.db[self.collection].find(expiring_certificates)

    def delete_certificate(self, certificate_id):
        """Удаляет по id серт"""
        self.db[self.collection].delete_certificate(certificate_id)
        logging.info(f"Deleted certificate {certificate_id}")

    def edit_user(self, user_id):
        """Марка спросить, можно ли как то облегчить данный варик с add user"""
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        updated_data = {
            "email": email,
            "password": hashed_password
        }
        self.db[self.collection].update_one({"_id": ObjectId(user_id)}, {"$set": updated_data})

    def delete_user(self, user_id):
        """По id находит по логике облегчить надо сделав один метот по поиску серийного номера"""
        self.db[self.collection].delete_one({"user_id": ObjectId(user_id)})
        logging.info(f"User {user_id} deleted successfully.")

    # def login():
    # """Нужен ли они тут ?"""
    # def logout():
    # """Нужен ли он тут ?"""

# Инициализация подключения к базе данных
mongo = MongoDB(mongo_url)
mongo._connect()

"""Тестовая зона"""
def test_delete_user():
    email = "deleteuser@example.com"
    password = "securepassword"
    mongo.add_user(email, password)
    user = db['users'].find_one({"email": email})
    user_id = user['_id']
    mongo.delete_user(user_id)
    deleted_user = db['users'].find_one({"_id": user_id})
    assert deleted_user is None, "User was not deleted."
    print("test_delete_user passed")

if __name__ == '__main__':

    mongo.close_connections()
    print("All tests passed")
