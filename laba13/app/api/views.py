from sqlalchemy.exc import IntegrityError
from flask import jsonify, request
from . import api_blueprint
from app import db
from app.todo.models import Todo

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
def delete_todo(id):
      todo = Todo.query.get(id)

      if not todo:
        return jsonify({"message": f"todo with id = {id} not found"}), 404
      
      db.session.delete(todo)
      db.session.commit()
      return jsonify({"message" : "Resource successfully deleted."}), 200