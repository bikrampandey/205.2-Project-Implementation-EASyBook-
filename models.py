from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    age = db.Column(db.Integer)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, email, password, name, phone=None, age=None, is_admin=False):
        self.email = email
        self.password = password
        self.name = name
        self.phone = phone
        self.age = age
        