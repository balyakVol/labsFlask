from flask import url_for

def test_all_todo_page_loads(client, init_database, log_in_default_user):
    response = client.get(url_for('todo_bp.todo'))
    assert response.status_code == 200
    assert u"База даних ToDo" in response.data.decode('utf8')

def test_all_feedback_page_loads(client, init_database, log_in_default_user):
    response = client.get(url_for('feedback_bp.feedback'))
    assert response.status_code == 200
    assert u"Відгуки" in response.data.decode('utf8')