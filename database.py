from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    first_login = db.Column(db.Boolean, default=True)
    permissions = db.Column(db.String(10), default='read_write')

    def __init__(self, username, password, first_login=True, permissions='read_write'):
        self.username = username
        self.password = password
        self.first_login = first_login
        self.permissions = permissions

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('api_keys', lazy=True))

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Float, default=0.0)
    unit = db.Column(db.String(10), default='quantity')
    image = db.Column(db.String(200), nullable=True)
    tags = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"Item('{self.name}', '{self.quantity} {self.unit}')"