from extensions import db
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

class BaseModel:
    def create(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def save():
        db.session.commit()

class User(db.Model, BaseModel, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)  # username should be unique and not nullable
    _password = db.Column(db.String, nullable=False)  # password is required
    country = db.Column(db.String)
    gender = db.Column(db.String)
    birthday = db.Column(db.Date)

    @property
    def password(self):
        return self._password
    
    @password.setter
    def password(self, value):
        if not value:
            raise ValueError("Password cannot be empty.")
        self._password = generate_password_hash(value)
    
    def check_password(self, password):
        return check_password_hash(self._password, password)
