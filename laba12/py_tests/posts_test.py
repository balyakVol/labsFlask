from flask import url_for
from app.post.models import Post, PostType

def test_post_model():
    post = Post(title='Lorem ipsum post', text='lorem ipsum post zxc qwerty')
    assert post.title == 'Lorem ipsum post'
    assert post.text == 'lorem ipsum post zxc qwerty'

def test_get_all_posts(init_database):
    number_of_posts = Post.query.count()
    assert number_of_posts == 2

def test_create_new_post(client, init_database, log_in_default_user, tags, category):
    data = {
        'title': 'Sample post',
        'text': 'Sample text',
        'type': 'News',
        'enabled': False,
        'category': 1,
        'tag': [tags[0].id, tags[1].id],
    }
    response = client.post(url_for('post_bp.create'), data=data, follow_redirects=True)
    post = Post.query.filter_by(title='Sample post').first()
    assert post
    assert post.title == 'Sample post'
    assert response.status_code == 200
    assert u"Створення виконано" in response.data.decode('utf8')

def test_view_post(client, init_database, log_in_default_user, tags):
    data = {
        'title': 'Sample post',
        'text': 'Sample text',
        'type': 'News',
        'enabled': False,
        'category': 1,
        'tag': [tags[0].id, tags[1].id],
    }
    response = client.post(url_for('post_bp.create'), data=data, follow_redirects=True)
    create_post = Post.query.filter_by(title='Sample post').first()
    response = client.post(url_for('post_bp.view_detail', id=create_post.id), follow_redirects=True)
    view_post = Post.query.get(create_post.id)
    assert view_post
    assert view_post.title == 'Sample post'
    assert view_post.text == 'Sample text'
    assert view_post.type == PostType.News
    assert response.status_code == 200
    assert u"funky" in response.data.decode('utf8')


def test_update_post(client, init_database, log_in_default_user, tags):
    data = {
        'title': 'Sample post',
        'text': 'Sample text',
        'type': 'Publication',
        'enabled': False,
        'category': 1,
        'tag': [tags[0].id, tags[1].id],
    }
    response = client.post(url_for('post_bp.create'), data=data, follow_redirects=True)
    create_post = Post.query.filter_by(title='Sample post').first()
    update_data = {
        'title': 'Updated title',
        'text': 'Updated text',
        'type': 'Other',
        'category': 1
    }
    response = client.post(url_for('post_bp.update', id=create_post.id), data=update_data, follow_redirects=True)
    updated_post = Post.query.get(create_post.id)
    assert updated_post
    assert updated_post.title == 'Updated title'
    assert updated_post.text == 'Updated text'
    assert updated_post.type == PostType.Other
    assert response.status_code == 200
    assert u"Пост був оновлений" in response.data.decode('utf8')


def test_delete_post(client, init_database, log_in_default_user):
    response = client.get(
        url_for('post_bp.delete', id=1),
        follow_redirects=True
    )
    post = Post.query.filter_by(id=1).first()
    assert response.status_code == 200
    assert post is None
    assert u"Видалення виконано" in response.data.decode('utf8')