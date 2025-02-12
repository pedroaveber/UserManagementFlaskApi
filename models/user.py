from database import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
  # id (int), username (str), password (str)
  id = db.Column(db.Integer, primary_key = True)
  password = db.Column(db.String(80), nullable = False)
  username = db.Column(db.String(80), unique = True, nullable = False)
