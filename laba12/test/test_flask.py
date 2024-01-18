import io
import unicodedata
import unittest
from flask import url_for
from flask_login import current_user
from flask_testing import TestCase

from app import create_app, db
from app.auth.models import User
from app.todo.models import Todo
from app.post.models import Post, Category, PostType

class BaseTestCase(TestCase):
    def create_app(self):
        app = create_app('test')
        return app
    
    def setUp(self):
        db.create_all()
        user = User(
            username="wendy", 
            email="wendy@gmail.com", 
            password="ciborg"
        )
        db.session.add(user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

class SetupTestCase(BaseTestCase):
    def test_setup(self):
        self.assertTrue(self.app is not None)
        self.assertTrue(self.client is not None)
        self.assertTrue(self._ctx is not None)

class UserTestCase(BaseTestCase):
    def test_register_user(self):
        user = User.query.filter_by(email='wendy@gmail.com').first()
        assert user.username == "wendy"
        assert user.email == "wendy@gmail.com"
        assert user.password != "ciborg"

    def test_register_post(self):
        with self.client:
            response = self.client.post(
                url_for('auth_bp.register'),
                data=dict(
                    username="test", 
                    email="test@gmail.com", 
                    password="password",
                    confirm_password="password"
                    ),
                follow_redirects=True
            )
            user = User.query.filter_by(email="test@gmail.com").first()
            self.assertEqual(response.status_code, 200)
            self.assertIsNotNone(user)
            self.assertEqual(user.username, "test")
            self.assertEqual(user.email, "test@gmail.com")
            self.assertNotEqual(user.password, "password")

    def test_login_user(self):
        with self.client:
            response = self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "wendy@gmail.com",
                    password = "ciborg",
                    remember = True
                ),
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(current_user.is_authenticated, True)
            self.assertIn(u"Вхід виконано", response.data.decode('utf8'))

    def test_login_user_remember_me_error(self):
        with self.client:
            response = self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "wendy@gmail.com",
                    password = "ciborg",
                ),
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(current_user.is_authenticated, False)
            self.assertIn(u"Ви не запамʼятали себе, введіть дані ще раз", response.data.decode('utf8'))

    def test_register_incorrect_confirm_input_error(self):
        with self.client:
            response = self.client.post(
                url_for('auth_bp.register'),
                data=dict(
                    username="test", 
                    email="test@gmail.com", 
                    password="password",
                    confirm_password="another_password"
                    ),
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(u"Паролі не збігаються", response.data.decode('utf8'))

    def test_register_invalid_email_error(self):
        with self.client:
            response = self.client.post(
                url_for('auth_bp.register'),
                data=dict(
                    username="test", 
                    email="testgmailcom", 
                    password="password",
                    confirm_password="password"
                    ),
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)

    def test_login_invalid_email_error(self):
        with self.client:
            response = self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "wendy_stewart@gmail.com",
                    password = "ciborg",
                    remember = True
                ),
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(current_user.is_authenticated, False)

    def test_register_page(self):
        with self.client:
            response = self.client.get(url_for('auth_bp.register'))
            self.assertEqual(response.status_code, 200)

    def test_login_page(self):
        with self.client:
            response = self.client.get(url_for('auth_bp.login'))
            self.assertEqual(response.status_code, 200)

    def test_get_account_page(self):
        user = User(username='test_user', email='test@example.com', password='123456')
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "test@example.com",
                    password = "123456",
                    remember = True
                ),
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)
            response = self.client.get('/account/account', follow_redirects=True)
            self.assert200(response)
            self.assertIn(u"Ласкаво просимо, test_user", response.data.decode('utf8'))

    def test_update_account_info(self):
        user = User(username='test_user', email='test@example.com', password='123456')
        db.session.add(user)
        db.session.commit()
        with self.client:
            self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "test@example.com",
                    password = "123456",
                    remember = True
                ),
                follow_redirects=True
            )
            new_username = 'quendor'
            new_email = 'quendor@example.com'
            response = self.client.post(
                url_for('account_bp.account'),
                data=dict(
                    username=new_username, 
                    email=new_email
                ),
                follow_redirects=True
            )
            self.assert200(response)
            self.assertIn(u"Аккаунт оновлено", response.data.decode('utf8'))
            updated_user = User.query.filter_by(email=new_email).first()
            self.assertIsNotNone(updated_user)
            self.assertEqual(updated_user.username, new_username)

class HomePageTestCase(BaseTestCase):
    def test_main_page_view(self):
        response = self.client.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Modal', response.data)

    def test_cv_view(self):
        response = self.client.get('/cv', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Java', response.data)

    def test_edu_view(self):
        response = self.client.get('/edu', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'QT', response.data)

    def test_hobbies_view(self):
        response = self.client.get('/hobbies', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dendy', response.data)

    def test_skills_view(self):
        response = self.client.get('/skills', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'C++', response.data)

class TodoTestCase(BaseTestCase):
    def test_todo_create(self):
        data = {
            'new_task': 'Write flask test',
            'description': 'bruh bruh',
        }
        with self.client:
            response = self.client.post(
                url_for('todo_bp.create_todo'),
                data = data,
                follow_redirects = True
            )
            self.assertEqual(response.status_code, 200)
            todo = Todo.query.get(1)
            assert todo.title == data['new_task']

    def test_get_all_todo(self):
        todo_1 = Todo(title="11", description="11", complete=False)
        todo_2 = Todo(title="22", description="22", complete=False)
        db.session.add_all([todo_1, todo_2])
        all_todo = Todo.query.count()
        assert all_todo == 2

    def test_update_todo_complete(self):
        user = User(
            username="test_alt", 
            email="test_alt@gmail.com", 
            password="123456"
        )
        db.session.add(user)
        todo_1 = Todo(title="11", description="11", complete=False)
        db.session.add(todo_1)
        db.session.commit()
        with self.client:
            response = self.client.get(
                url_for('auth_bp.login'),
                data=dict(
                    email = "test_alt@gmail.com",
                    password = "123456",
                    remember=True
                ),
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)
            response = self.client.get(
                url_for('todo_bp.update_todo', todo_id = 1),
                follow_redirects = True
            )
            todo = Todo.query.get(1)
            assert todo.complete is True

    def test_todo_page_view(self):
        user = User(
            username="test_alt", 
            email="test_alt@gmail.com", 
            password="123456"
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "test_alt@gmail.com",
                    password = "123456",
                    remember=True
                ),
                follow_redirects=True
            )
            response = self.client.get('/todo/', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'todoTable', response.data)
"""
def test_category_create(self):
        user = User(
            username="test_alt", 
            email="test_alt@gmail.com", 
            password="123456"
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "test_alt@gmail.com",
                    password = "123456",
                    remember=True
                ),
                follow_redirects=True
            )
            response = self.client.post(
                url_for('post_bp.create_category'),
                data=dict(
                    name="Fun",
                ),
                follow_redirects = True
            )
            self.assertEqual(response.status_code, 200)
            category = Category.query.filter_by(id=1).first()
            self.assertIsNotNone(category)
"""

class PostTestCase(BaseTestCase):
    def test_get_all_post(self):
        user1 = User(
                username="test_alt", 
                email="test_alt@gmail.com", 
                password="123456"
            )
        user2 = User(
                username="test_alt_2", 
                email="test_alt_2@gmail.com", 
                password="12345678"
            )
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()
        with self.client:
            self.client.post(
                url_for('post_bp.create_category'),
                data=dict(
                    name = "Fun",
                ),
                follow_redirects = True
            )
            category = Category.query.filter_by(name="Fun").first()

            post_1 = Post(title="11", text="11", type=PostType.News, user_id=user1.id, category=category)
            post_2 = Post(title="22", text="22", type=PostType.News, user_id=user2.id, category=category)
            db.session.add_all([post_1, post_2])
            all_post = Post.query.count()
            assert all_post == 2

    def test_post_create(self):
        user = User(
            username="test_alt", 
            email="test_alt@gmail.com", 
            password="123456"
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "test_alt@gmail.com",
                    password = "123456",
                    remember=True
                ),
                follow_redirects=True
            )
            self.client.post(
                url_for('post_bp.create_category'),
                data=dict(
                    name = "Fun",
                ),
                follow_redirects = True
            )
            
            category = Category.query.filter_by(name="Fun").first()

            response = self.client.post(
                url_for('post_bp.create'),
                data=dict(
                    title="11", text="11", type="News", user_id=user.id, category=category.id
                ),
                follow_redirects = True
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(u"Створення виконано", response.data.decode('utf8'))
            post = Post.query.filter_by(title="11").first()
            self.assertIsNotNone(post)

    def test_post_update(self):
        user = User(
            username="test_alt", 
            email="test_alt@gmail.com", 
            password="123456"
        )
        category_1 = Category(
            name = "Fun",
        )
        category_2 = Category(
            name = "Unknown"
        )
        db.session.add(user)
        db.session.add(category_1)
        db.session.add(category_2)
        db.session.commit()

        post_1 = Post(
            title="Minecraft", 
            text="1940", 
            type=PostType.News, 
            user_id=user.id,
            category=category_1
        )
        db.session.add(post_1)
        db.session.commit()
        
        with self.client:
            self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "test_alt@gmail.com",
                    password = "123456",
                    remember=True
                ),
                follow_redirects=True
            )
            
            category_2 = Category.query.filter_by(name="Unknown").first()

            response = self.client.post(
                url_for('post_bp.update', id=post_1.id),
                data=dict(
                    title="Angry Birds", text="11", type="Other", enabled=None, user_id=user.id, category=category_2.id
                ),
                follow_redirects = True
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(u"Пост був оновлений", response.data.decode('utf8'))
            post = Post.query.get(1)
            assert post.title == "Angry Birds"

    def test_post_page_view(self):
        user = User(
            username="test_alt", 
            email="test_alt@gmail.com", 
            password="123456"
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = self.client.post(
                url_for('auth_bp.login'),
                data=dict(
                    email = "test_alt@gmail.com",
                    password = "123456",
                    remember=True
                ),
                follow_redirects=True
            )        
            response = self.client.get('/post/', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'postTable', response.data)

if __name__ == '__main__':
    unittest.main()