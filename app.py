from flask import Flask, request, jsonify
from database import db
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from bcrypt import hashpw, gensalt, checkpw

app = Flask(__name__)

# UTF-8
app.config['JSON_AS_ASCII'] = False

# Database configuration
app.config['SECRET_KEY'] = 'super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'

# Flask-Login configuration
login_manager = LoginManager()
login_manager.login_view = '/auth/sign-in'

db.init_app(app)
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(user_id)

@app.route('/auth/sign-in', methods=['POST'])
def sign_in():
  body = request.json

  username = body.get('username')
  password = body.get('password')

  if username and password:
    user = User.query.filter_by(username=username).first()

    does_password_match = checkpw(str.encode(password), str.encode(user.password))

    if user and does_password_match:
      login_user(user)
      print(current_user.is_authenticated)
      return jsonify({ 'message': 'Usuário autenticado' }), 200
      
  return jsonify({ 'message': 'Credenciais inválidas' }), 400

@app.route('/auth/sign-out', methods=['GET'])
@login_required
def sign_out():
  logout_user()
  return jsonify({ 'message': 'Usuário deslogado' })

@app.route('/users', methods=['POST'])
def create_user():
  body = request.json

  username = body.get('username')
  password = body.get('password')

  hashed_password = hashpw(str.encode(password), gensalt())

  if username and password:
    user = User(username = username, password = hashed_password, role = 'user')

    db.session.add(user)
    db.session.commit()

    return jsonify({ 'message': 'Usuário criado' }), 201
  
  return jsonify({ 'message': 'Dados inválidas' }), 401

@app.route('/users/<int:id_user>', methods=['GET'])
@login_required
def get_user(id_user):
  user = User.query.get(id_user)

  if user:
    return jsonify({ 'username': user.username }), 200
  
  return jsonify({ 'message': 'Usuário não encontrado' }), 404

@app.route('/users/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
  body = request.json

  password = body.get('password')
  user = User.query.get(id_user)

  if id_user != current_user.id and current_user.role == 'user':
    return jsonify({ 'message': 'Acesso negado' }), 403

  if user and password:
    hashed_password = hashpw(str.encode(password), gensalt())

    user.password = hashed_password
    db.session.commit()

    return jsonify({ 'message': 'Usuário atualizado' }), 200
  
  return jsonify({ 'message': 'Usuário não encontrado' }), 404

@app.route('/users/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
  user = User.query.get(id_user)

  if current_user.role != 'admin':
    return jsonify({ 'message': 'Acesso negado' }), 403

  if user and id_user != current_user.id:
    db.session.delete(user)
    db.session.commit()

    return jsonify({ 'message': 'Usuário deletado' }), 200
  
  return jsonify({ 'message': 'Usuário não encontrado' }), 404

if __name__ == '__main__':
  app.run(debug=True)