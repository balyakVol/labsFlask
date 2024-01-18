from flask import url_for
import pytest
from app import create_app, db
from app.post.models import Post, Category, Tag
from app.auth.models import User
from app.todo.models import Todo
from app.feedback.models import Feedback

@pytest.fixture(scope='module')
def client():
    app = create_app('test')
    app.config['SERVER_NAME'] = '127.0.0.1:5000'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

@pytest.fixture()
def user_test():
    user = User(username='brand_new', email='brand_new@example.com', password='password')
    return user

@pytest.fixture(scope='module')
def category():
    category = Category(name="Category")
    yield category

@pytest.fixture(scope='module')
def todo():
    todo_1 = Todo(title="doing", description="add your description", complete=False)
    todo_2 = Todo(title="sleeping", description="add your description after sleeping", complete=False)

    todo_list = [todo_1, todo_2]

    yield todo_list

@pytest.fixture(scope='module')
def feedback():
    feedback_1 = Feedback(
        name='Vladix',
        email='creeper2014614@lambda.com',
        description='Enjoy your lose',
        rate='5',
        useful=False
    )
    feedback_2 = Feedback(
        name='Krepnt',
        email='tester@aminda.com',
        description='Say anything',
        rate='9',
        useful=False
    )

    feedback_list = [feedback_1, feedback_2]

    yield feedback_list

@pytest.fixture(scope='module')
def tags():
    tag_1 = Tag(name="funky")
    tag_2 = Tag(name="fancy")

    tags = [tag_1, tag_2]

    yield tags

@pytest.fixture(scope='module')
def posts(category, tags):
    post_1 = Post(title="Um consequatur volupta", text='Qui deleniti voluptas', user_id=1, category=category, tags=tags)
    post_2 = Post(title="Optio eum rerum", text='Cumque qui omnis voluptatem.', user_id=1, category=category, tags=tags)

    posts = [post_1, post_2]
    yield posts

@pytest.fixture(scope='module')
def init_database(client, category, posts, todo, feedback):
    # Insert user data
    default_user = User(username='patkennedy', email='patkennedy24@gmail.com', password='FlaskIsAwesome')
    db.session.add(default_user)
    db.session.add(category)
    db.session.add(posts[0])
    db.session.add(posts[1])
    db.session.add(todo[0])
    db.session.add(todo[1])
    db.session.add(feedback[0])
    db.session.add(feedback[1])

    # Commit the changes for the users
    db.session.commit()

    yield  # this is where the testing happens!

@pytest.fixture(scope='function')
def log_in_default_user(client):
    client.post(url_for('auth_bp.login'),
                     data={
                         'email': 'patkennedy24@gmail.com', 
                         'password': 'FlaskIsAwesome', 
                         'remember': True
                         },
                     follow_redirects=True
                     )

    yield  # this is where the testing happens!

    client.get(url_for('auth_bp.logout'))