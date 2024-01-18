from flask import flash, render_template, redirect, url_for
from flask_login import login_user, current_user, logout_user, login_required

from .forms import LoginForm, RegisterForm
from .models import db, User

from . import auth_blueprint

@auth_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('account_bp.account'))
    
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
            return redirect(url_for("auth_bp.login"))
        flash("Паролі не збігаються", category=("warning"))
        return redirect(url_for("auth_bp.register"))
    
    return render_template("register.html", form=form)

@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account_bp.account'))
    
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.validate_password(form.password.data):
            if form.remember.data:
                login_user(user, remember=form.remember.data)
                flash("Вхід виконано", category=("success"))
                return redirect(url_for('account_bp.account'))
            flash("Ви не запамʼятали себе, введіть дані ще раз", category=("warning"))
            return redirect(url_for('home_bp.home'))
        flash("Вхід не виконано", category=("warning"))
        return redirect(url_for('auth_bp.login'))
    
    return render_template('login.html', form=form)

@auth_blueprint.route('/users')
@login_required
def users():
    all_users = User.query.all()
    return render_template('users.html', all_users=all_users)

@auth_blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("auth_bp.login"))