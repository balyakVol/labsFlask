from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length

class LoginForm(FlaskForm):
    username = StringField("Імʼя", validators=[DataRequired("Це поле обовʼязкове")])
    password = PasswordField("Пароль", validators=[
                            DataRequired("Пароль повинен мати від 4 до 10 символів"),
                            Length(min=4, max=10)
                        ])
    remember = BooleanField("Запамʼятати")
    submit = SubmitField("Увійти")

class ChangePasswordForm(FlaskForm):
    password = PasswordField("Новий пароль", validators=[
                            DataRequired("Пароль повинен мати від 4 до 10 символів"),
                            Length(min=4, max=10)
                        ])
    confirm_password = PasswordField("Підтвердити новий пароль", validators=[
                            DataRequired("Пароль повинен мати від 4 до 10 символів"),
                            Length(min=4, max=10)
                        ])
    submit = SubmitField("Увійти")