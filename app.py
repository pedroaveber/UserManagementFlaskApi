from flask import Flask, request, jsonify
from database import db
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)

# Database configuration
app.config['SECRET_KEY'] = 'super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

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

    if user and user.password == password:
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

  if username and password:
    user = User(username = username, password = password)

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

  if user and password:
    user.password = password
    db.session.commit()

    return jsonify({ 'message': 'Usuário atualizado' }), 200
  
  return jsonify({ 'message': 'Usuário não encontrado' }), 404

@app.route('/users/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
  user = User.query.get(id_user)

  if user and id_user != current_user.id:
    db.session.delete(user)
    db.session.commit()

    return jsonify({ 'message': 'Usuário deletado' }), 200
  
  return jsonify({ 'message': 'Usuário não encontrado' }), 404

if __name__ == '__main__':
  app.run(debug=True)