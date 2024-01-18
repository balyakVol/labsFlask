from flask import url_for

def test_register_page(client):
    response = client.get(url_for('auth_bp.register'))
    assert response.status_code == 200
    assert u"Створити аккаунт" in response.data.decode('utf8')

def test_login_page(client):
    response = client.get(url_for('auth_bp.login'))
    assert response.status_code == 200
    assert u"Увійти" in response.data.decode('utf8')

def test_post_account_page(client, init_database, log_in_default_user):
    response = client.get(url_for('account_bp.account'))
    assert response.status_code == 200
    assert u"Ласкаво просимо" in response.data.decode('utf8')

def test_post_all_users(client, init_database, log_in_default_user):
    response = client.get(url_for('auth_bp.users', id=1))
    assert response.status_code == 200
    assert u"База даних користувачів" in response.data.decode('utf8')

def test_post_change_password_page(client, init_database, log_in_default_user):
    response = client.get(url_for('account_bp.account', id=1))
    assert response.status_code == 200
    assert u"Змінити пароль" in response.data.decode('utf8')