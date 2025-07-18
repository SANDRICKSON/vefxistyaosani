from datetime import datetime

from extensions import db, login_manager
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
    username = db.Column(db.String, nullable=False, unique=True)
    email = db.Column(db.String, nullable=False, unique=True)
    _password = db.Column(db.String, nullable=False)
    country = db.Column(db.String)
    gender = db.Column(db.String)
    birthday = db.Column(db.Date)
    is_verified = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(255), nullable=True, default='default.png')
    role = db.Column(db.String(10), default='user')

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

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


class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(300), nullable=True)
    description = db.Column(db.Text, nullable=False)


class ChapterAudio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    youtube_link = db.Column(db.String(255))



class ChatResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
