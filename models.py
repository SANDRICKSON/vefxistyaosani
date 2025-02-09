from extensions import db
from flask_login import UserMixin


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
    username = db.Column(db.String)
    password = db.Column(db.String)
    country = db.Column(db.String)
    gender = db.Column(db.String)
    birthday = db.Column(db.Date)