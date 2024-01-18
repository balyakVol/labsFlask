from sqlalchemy.exc import IntegrityError
from flask import jsonify, request, current_app
from . import api_blueprint
from app import db, bcrypt, jwt
from app.todo.models import Todo
from app.auth.models import User
from flask_httpauth import HTTPBasicAuth
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required, unset_jwt_cookies
import datetime
basicAuth = HTTPBasicAuth()

@basicAuth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        return True
    return False

@basicAuth.error_handler
def unauthorized():
    return jsonify({"message":"Username or password incorrect!"}), 401

@api_blueprint.route('/login', methods=['POST'])
@basicAuth.login_required
def login():
    username = basicAuth.username()
    user = User.query.filter_by(username=username).first()

    if user:
        token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({'token': token, 'refresh_token': refresh_token}), 200
    
    return jsonify({'message': 'Token is not created!'}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify(
        {"message": "The token has been revoked.",
         "error": "token_revoked"}), 401

@api_blueprint.route('/refresh', methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user, fresh=False)
    return jsonify({'token': new_token})

@api_blueprint.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    response = jsonify({"message": "logout successful"})
    unset_jwt_cookies(response)
    return response

@api_blueprint.route('/todos', methods=['GET'])
def get_all_todos():
    todos = Todo.query.all()
    return_values = [
        {"id": todo.id, 
         "title": todo.title, 
         "description": todo.description,
         "complete": todo.complete} 
         for todo in todos]

    return jsonify({'todos': return_values})

@api_blueprint.route('/todos', methods=['POST'])
@jwt_required()
def post_todo():
    new_data = request.get_json()

    if not new_data:
        return jsonify({"message": "No input data provided"}), 400
    
    if not new_data.get("title") or not new_data.get("description"):
        return jsonify({"message": "There's no keys"}), 422 

    todo = Todo(title=new_data.get('title'), description=new_data.get('description'))
    
    db.session.add(todo)
    db.session.commit()

    new_todo = Todo.query.filter_by(id=todo.id).first()
    return jsonify(
        {"id": new_todo.id, 
         "title": new_todo.title, 
         "description": new_todo.description,
         "complete": new_todo.complete}), 201

@api_blueprint.route('/todos/<int:id>', methods=['PUT'])
@jwt_required()
def update_todo(id):
    todo = Todo.query.filter_by(id=id).first()
    
    if not todo:
        return jsonify({"message": f"todo with id = {id} not found"}), 404
    
    new_data = request.get_json()
    
    if not new_data:
        return jsonify({"message": "no input data provided"}), 400
    
    if new_data.get('title'):
        todo.title = new_data.get('title')
    
    if new_data.get('description'):
        todo.description = new_data.get('description')
    
    try:
        db.session.commit()
        return jsonify({"message": "Todo was updated"}), 204
    except IntegrityError:
        db.session.rollback()

@api_blueprint.route('/todos/<int:id>', methods=['GET'])
def get_todo(id):
    todo = Todo.query.get_or_404(id)
    return jsonify(
        {"id": todo.id, 
         "title": todo.title, 
         "description": todo.description,
         "complete": todo.complete})

@api_blueprint.route('/todos/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_todo(id):
      todo = Todo.query.get(id)

      if not todo:
        return jsonify({"message": f"todo with id = {id} not found"}), 404
      
      db.session.delete(todo)
      db.session.commit()
      return jsonify({"message" : "Resource successfully deleted."}), 200