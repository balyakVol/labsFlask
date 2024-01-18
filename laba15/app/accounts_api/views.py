from flask_sqlalchemy import IntegrityError
from flask import jsonify, make_response
from app.auth.models import User
from . import accounts_api_blueprint
from app import db
from flask_restful import Api, Resource, reqparse

api = Api(accounts_api_blueprint)

parser_create_user = reqparse.RequestParser()
parser_create_user.add_argument('username', type=str, required=True, help='Username is required')
parser_create_user.add_argument('email', type=str, required=True, help='Email is required')
parser_create_user.add_argument('image_file', type=str, help='Image file is default')
parser_create_user.add_argument('password', type=str,required=True, help='Password is required')

class HelloWorld(Resource):
    def get(self):
        return {"hello": "world"}
    
class UsersApi(Resource):
    def get(self):
        pass

    def post(self):
        data = parser_create_user.parse_args()
        username = data.get('username')
        password = data['password']
        image_file = data.get('image_file', 'default.jpg')
        email = data['email']

        new_user = User(username=username, password=password, image_file=image_file, email=email)

        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            return make_response(jsonify({"message": "User has been created"}), 201)

class UserApi(Resource):
    def get(self, id):
        pass

    def put(self, id):
        pass

    def delete(self, id):
        pass

api.add_resource(HelloWorld, '/')
api.add_resource(UsersApi, '/users')
api.add_resource(UserApi, '/user/<int:id>')