from flask import Flask, flash, render_template, request, redirect, url_for, send_file, make_response, session
from flask_login import login_user, current_user, logout_user, login_required

from app import app, bcrypt
from app.forms import LoginForm, ChangePasswordForm, CreateTodoForm, RegisterForm
from app.database import db, Todo, User

from datetime import datetime
import os
import random
import email_validator

my_skills = ["C++", "HTML & CSS", "MySQL", "JavaScript", "Java", "Python"]

def get_user_info():
    user_os = os.name
    user_agent = request.headers.get('User-Agent')
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return user_os, user_agent, current_time

@app.route('/base')
def index():
    user_os, user_agent, current_time = get_user_info()
    return render_template('base.html', user_os=user_os, user_agent=user_agent, current_time=current_time)

@app.route('/home')
@app.route('/')
def home():
    user_os, user_agent, current_time = get_user_info()
    return render_template('home.html', user_os=user_os, user_agent=user_agent, current_time=current_time)

@app.route('/cv')
def cv():
    return render_template('cv.html')

@app.route('/edu')
def edu():
    return render_template('edu.html')

@app.route('/hobbies')
def hobbies():
    return render_template('hobbies.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('info'))
    
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        image_file = form.image_file.data
        if password == confirm_password:
            new_user = User(username=username, email=email, password=password, image_file=image_file)
            db.session.add(new_user)
            db.session.commit()
        flash("Аккаунт зареєстровано", category=("success"))
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('info'))
    
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        form_email = form.email.data
        form_password = form.password.data
        form_remember = form.remember.data

        if user and user.validate_password(form_password) and user.email == form.email.data:
            if form_remember:
                user_id = random.randint(1, 10000)
                session['userId'] = user_id
                session['email'] = form_email
                session['password'] = form_password
                login_user(user, remember=form.remember.data)
                flash("Вхід виконано", category=("success"))
                return redirect(url_for('account'))
            else:
                flash("Ви не запамʼятали себе, введіть дані ще раз", category=("warning"))
                return redirect(url_for('home'))
        else:
            flash("Вхід не виконано", category=("warning"))
            return redirect(url_for('login'))
    
    return render_template('login.html', form=form)

@app.route('/users')
@login_required
def users():
    all_users = User.query.all()
    return render_template('users.html', all_users=all_users)

@app.route('/info', methods=['GET'])
@login_required
def info():
    cookies = request.cookies
    form = ChangePasswordForm()

    return render_template('info.html', cookies=cookies, form=form)

@app.route('/logout')
def logout():
    session.pop('userId')
    session.pop('password')
    logout_user()
    return redirect(url_for("login"))

@app.route("/account")
@login_required
def account():
    return render_template('account.html')

@app.route('/skills/')
@app.route('/skills/<int:id>')
def skills(id=None):
    if id is not None:
        if 0 <= id < len(my_skills):
            skill = my_skills[id]
            return render_template('skills.html', skill=skill)
        else:
            return render_template('skills.html')
    else:
        return render_template('skills.html', skills=my_skills, total_skills=len(my_skills))

def set_cookie(key, value, max_age):
    response = make_response(redirect('info'))
    response.set_cookie(key, value, max_age=max_age)
    return response

def delete_cookie(key):
    response = make_response(redirect('info'))
    response.delete_cookie(key)
    return response

@app.route('/add_cookie', methods=['POST'])
def add_cookie():
    key = request.form.get('key')
    value = request.form.get('value')
    max_age = int(request.form.get('max_age'))

    flash("Кукі додано", category=("success"))
    return set_cookie(key, value, max_age)

@app.route('/remove_cookie/', methods=['GET'])
@app.route('/remove_cookie/<key>', methods=['GET'])
def remove_cookie():

    key = request.args.get('key')

    if key:
        flash("Кукі видалено", category=("dark"))
        response = make_response(redirect(url_for('info')))
        response.delete_cookie(key)
        return response
    else:
        flash("Виникла помилка. Повідомте про ключ нам", category=("info"))
        response = make_response(redirect(url_for('info')))
        return response

@app.route('/remove_all_cookies', methods=['GET'])
def remove_all_cookies():
    flash("Усі кукі видалено", category=("danger"))
    response = make_response(redirect(url_for('info')))
    cookies = request.cookies

    for key in cookies.keys():
        if key != 'session':
            response.delete_cookie(key)

    return response

@app.route('/change_password', methods=['POST'])
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            new_password = form.password.data
            confirm_new_password = form.confirm_password.data

            if user:
                if new_password == confirm_new_password:
                    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    user.password = hashed_password
                    db.session.commit()

                    flash("Пароль успішно змінено", category=("success"))
                    return redirect(url_for('info'))
                else:
                    flash("Паролі не збігаються", category="danger")
        else:
            flash("Користувача з такою поштою не існує", category="danger")

        flash("Ви не змінили пароль", category=("danger"))
        return redirect(url_for('info'))

    flash("Ви не набрали пароль. Спробуйте ще раз", category=("danger"))
    return redirect(url_for('info'))

@app.route("/todo")
@login_required
def todo():
    todo_form = CreateTodoForm()
    todo_list = db.session.query(Todo).all()

    return render_template('todo.html', todo_form=todo_form, todo_list=todo_list)

@app.route("/create_todo", methods=['POST'])
def create_todo():
    todo_form = CreateTodoForm()

    if todo_form.validate_on_submit():
        new_task = todo_form.new_task.data
        description = todo_form.description.data
        new_todo = Todo(title=new_task, description=description, complete=False)
        db.session.add(new_todo)
        db.session.commit()
        flash("Створення виконано", category=("success"))
        return redirect(url_for("todo"))
    
    flash("Помилка при створенні", category=("danger"))
    return redirect(url_for("todo"))

@app.route("/read_todo/<int:todo_id>")
def read_todo(todo_id=None):
    todo = Todo.query.get_or_404(todo_id)
    return redirect(url_for("todo"))

@app.route("/update_todo/<int:todo_id>")
def update_todo(todo_id=None):
    todo = Todo.query.get_or_404(todo_id)

    todo.complete = not todo.complete
    db.session.commit()
    flash("Оновлення виконано", category=("success"))
    return redirect(url_for("todo"))

@app.route("/delete_todo/<int:todo_id>")
def delete_todo(todo_id=None):
    todo = Todo.query.get_or_404(todo_id)

    db.session.delete(todo)
    db.session.commit()
    flash("Видалення виконано", category=("success"))
    return redirect(url_for("todo"))

@app.route("/main")
def main():
    return redirect(url_for("home"))