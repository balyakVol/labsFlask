from flask import url_for

def test_all_posts_page(client, init_database, log_in_default_user):
    response = client.get(url_for('post_bp.view_post'))
    assert response.status_code == 200
    assert u"Світлина" in response.data.decode('utf8')

def test_all_posts_by_date_page(client, init_database, log_in_default_user):
    response = client.get(url_for('post_bp.view_post_by_date'))
    assert response.status_code == 200
    assert u"Час створення" in response.data.decode('utf8')

def test_post_create_page(client, init_database, log_in_default_user):
    response = client.get(url_for('post_bp.create'))
    assert response.status_code == 200
    assert u"Створити пост" in response.data.decode('utf8')

def test_post_by_id_page(client, init_database):
    response = client.get(url_for('post_bp.view_detail', id=1))
    assert response.status_code == 200
    assert u"Категорія" in response.data.decode('utf8')

def test_post_update_page(client, init_database, log_in_default_user):
    response = client.get(url_for('post_bp.update', id=1))
    assert response.status_code == 200
    assert u"Оновити пост" in response.data.decode('utf8')

def test_post_create_category(client, init_database, log_in_default_user):
    response = client.get(url_for('post_bp.view_category'))
    assert response.status_code == 200
    assert u"Додати категорію" in response.data.decode('utf8')

def test_post_create_tag(client, init_database, log_in_default_user):
    response = client.get(url_for('post_bp.view_tag'))
    assert response.status_code == 200
    assert u"Додати тег" in response.data.decode('utf8')