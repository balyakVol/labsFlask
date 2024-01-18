from flask import url_for
from flask_login import current_user
from app.auth.models import User
from app import db

def test_user_model():
    user = User("user", "user@gmail.com", "password", "image.png")
    assert user.username == 'user'
    assert user.email == 'user@gmail.com'
    assert user.password != 'password'
    assert user.image_file == 'image.png'

def test_register_user(client):
    """Ensure a new user can be added to the database."""
    response = client.post(
        url_for('auth_bp.register'),
        data=dict(
            username='michael',
            email='michael@realpython.com',
            password='123456',
            confirm_password='123456'
        ),
        follow_redirects=True
    )
    user = User.query.filter_by(email="michael@realpython.com").first()
    assert response.status_code == 200
    assert u'Аккаунт зареєстровано' in response.data.decode('utf8')
    assert user is not None

def test_login_user(client, init_database):
    response = client.post(
        url_for('auth_bp.login', external=True),
        data=dict(
            email='michael@realpython.com',
            password='123456',
            remember = True
        ),
        follow_redirects=True
    )
    assert response.status_code == 200
    assert current_user.is_authenticated == True
    assert u"Вхід виконано" in response.data.decode('utf8')

def test_login_user_with_fixture(log_in_default_user):
    assert current_user.is_authenticated == True

def test_log_out_user(client, log_in_default_user):
    response = client.get(
        url_for('auth_bp.logout'),
        follow_redirects=True
    )

    assert response.status_code == 200
    assert current_user.is_authenticated == False

def test_get_account_page(user_test):
    db.session.add(user_test)
    db.session.commit()
    user = User.query.filter_by(email='brand_new@example.com').first()
    assert user.username == 'brand_new'

def test_get_account_page(init_database):
    user_new = User.query.filter_by(email='patkennedy24@gmail.com').first()
    assert user_new.username == 'patkennedy'

def test_home_page_post_with_fixture(client):
    response = client.post('/')
    assert response.status_code == 405
    assert b"Flask User Management Example!" not in response.data