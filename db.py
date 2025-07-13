from models import User, Character, ChapterAudio
from extensions import app, db
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()
