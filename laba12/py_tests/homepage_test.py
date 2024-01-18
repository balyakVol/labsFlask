from flask import url_for

def test_main_page_view(client):
    response = client.get(url_for('home_bp.home'))
    assert response.status_code == 200
    assert b'Modal' in response.data

def test_cv_view(client):
    response = client.get(url_for('home_bp.cv'))
    assert response.status_code == 200
    assert b'Java' in response.data

def test_edu_view(client):
    response = client.get(url_for('home_bp.edu'))
    assert response.status_code == 200
    assert b'QT' in response.data

def test_hobbies_view(client):
    response = client.get(url_for('home_bp.hobbies'))
    assert response.status_code == 200
    assert b'Dendy' in response.data

def test_skills_view(client):
    response = client.get(url_for('home_bp.skills'))
    assert response.status_code == 200
    assert b'C++' in response.data