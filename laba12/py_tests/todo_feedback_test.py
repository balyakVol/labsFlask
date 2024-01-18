from flask import url_for
from app.todo.models import Todo
from app.feedback.models import Feedback

def test_todo_model():
    todo = Todo(title='Test Todo', description='Test description')
    assert todo.title == 'Test Todo'
    assert todo.description == 'Test description'
    assert not todo.complete

def test_create_todo(client, init_database, log_in_default_user):
    data = {
        'title': 'New Task',
        'description': 'Description of the new task'
    }
    response = client.post(url_for('todo_bp.create_todo'), data=data, follow_redirects=True)
    assert response.status_code == 200

def test_update_todo(client, init_database, log_in_default_user, todo):
    response = client.get(url_for('todo_bp.update_todo', todo_id=1), follow_redirects=True)
    updated_todo = Todo.query.filter_by(id=todo[0].id).first()
    assert response.status_code == 200
    assert updated_todo.complete

def test_delete_todo(client, init_database, log_in_default_user, todo):
    todo_id_to_delete = todo[0].id
    response = client.post(url_for('todo_bp.delete_todo', todo_id=todo_id_to_delete), follow_redirects=True)
    deleted_todo = Todo.query.get(todo_id_to_delete)
    assert response.status_code == 200
    assert deleted_todo is None

def test_feedback_model():
    feedback = Feedback(name='Ben', email='benjamin@gmail.com', description='Test description', rate='9')
    assert feedback.name == 'Ben'
    assert feedback.email == 'benjamin@gmail.com'
    assert feedback.description == 'Test description'
    assert feedback.rate != 9

def test_create_feedback(client, init_database, log_in_default_user):
    data = {
        'name': 'Vlad',
        'email': 'creeper2014614@aminda.com',
        'description': 'Enjoy your lose',
        'rate': '5',
        'useful': False
    }
    response = client.post(url_for('feedback_bp.create_feedback'), data=data, follow_redirects=True)
    assert response.status_code == 200

def test_update_feedback(client, init_database, log_in_default_user, feedback):
    response = client.get(url_for('feedback_bp.update_feedback', feedback_id=1), follow_redirects=True)
    updated_feedback = Feedback.query.filter_by(id=feedback[0].id).first()
    assert response.status_code == 200
    assert updated_feedback.useful

def test_delete_feedback(client, init_database, log_in_default_user, feedback):
    feedback_id_to_delete = feedback[0].id
    response = client.post(url_for('feedback_bp.delete_feedback', feedback_id=feedback_id_to_delete), follow_redirects=True)
    deleted_feedback = Feedback.query.get(feedback_id_to_delete)
    assert response.status_code == 200
    assert deleted_feedback is None