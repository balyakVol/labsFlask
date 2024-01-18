from sqlalchemy.exc import IntegrityError
from flask import jsonify, request, current_app
from . import contacts_blueprint
from app import db, bcrypt, jwt
from .models import Contacts
from app.auth.models import User
from flask_httpauth import HTTPBasicAuth
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required, unset_jwt_cookies
import datetime
basicAuth = HTTPBasicAuth()

@basicAuth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        return True
    return False

@basicAuth.error_handler
def unauthorized():
    return jsonify({"message":"Username or password incorrect!"}), 401

@contacts_blueprint.route('/login', methods=['POST'])
@basicAuth.login_required
def login():
    username = basicAuth.username()
    user = User.query.filter_by(username=username).first()

    if user:
        token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({'token': token, 'refresh_token': refresh_token}), 200
    
    return jsonify({'message': 'Token is not created!'}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify(
        {"message": "The token has been revoked.",
         "error": "token_revoked"}), 401

@contacts_blueprint.route('/refresh', methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user, fresh=False)
    return jsonify({'token': new_token})

@contacts_blueprint.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    response = jsonify({"message": "logout successful"})
    unset_jwt_cookies(response)
    return response

@contacts_blueprint.route('/contacts', methods=['GET'])
def get_all_contacts():
    contacts = contacts.query.all()
    return_values = [
        {"id": Contact.id, 
         "name": Contact.name, 
         "second_name": Contact.second_name,
         "number": Contact.number,}
         for Contact in contacts]

    return jsonify({'contacts': return_values})

@contacts_blueprint.route('/contacts', methods=['POST'])
@jwt_required()
def post_Contact():
    data_list = request.get_json()

    if not data_list:
        return jsonify({"message": "No input data provided"}), 400
    
    contacts = []

    for new_data in data_list:
        if not all(key in new_data for key in ["name", "second_name", "number"]):
            return jsonify({"message": "Missing keys in one or more entries. If data are correct, try to use square brackets"}), 422 

        Contact = Contact(
            name=new_data['name'], 
            second_name=new_data['second_name'],
            number=new_data['number'],
        )

        db.session.add(Contact)
        contacts.append(Contact)

    db.session.commit()

    result = []
    for new_Contact in contacts:
        result.append({
            "id": new_Contact.id, 
            "name": new_Contact.name, 
            "second_name": new_Contact.second_name,
            "number": new_Contact.number,
        })

    return jsonify(result), 201

@contacts_blueprint.route('/contacts/<int:id>', methods=['PUT'])
@jwt_required()
def update_Contact(id):
    Contact = Contact.query.filter_by(id=id).first()
    
    if not Contact:
        return jsonify({"message": f"Contact with id = {id} not found"}), 404
    
    new_data = request.get_json()
    
    if not new_data:
        return jsonify({"message": "no input data provided"}), 400
    
    if new_data.get('name'):
        Contact.name = new_data.get('name')
    
    if new_data.get('second_name'):
        Contact.second_name = new_data.get('second_name')

    if new_data.get('number'):
        Contact.number = new_data.get('number')

    try:
        db.session.commit()
        return jsonify({"message": "Contact was updated"}), 204
    except IntegrityError:
        db.session.rollback()

@contacts_blueprint.route('/contacts/<int:id>', methods=['GET'])
def get_Contact(id):
    Contact = Contact.query.get_or_404(id)
    return jsonify(
        {"id": Contact.id, 
         "name": Contact.name, 
         "second_name": Contact.second_name,
         "number": Contact.number})

@contacts_blueprint.route('/contacts/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_Contact(id):
      Contact = Contact.query.get(id)

      if not Contact:
        return jsonify({"message": f"Contact with id = {id} not found"}), 404
      
      db.session.delete(Contact)
      db.session.commit()
      return jsonify({"message" : "Resource successfully deleted."}), 200