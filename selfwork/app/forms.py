from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, EmailField
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

class CreateTodoForm(FlaskForm):
    new_task = StringField("Задача", validators=[DataRequired("Це поле обовʼязкове"), Length(min=1, max=100)])
    description = StringField("Опис", validators=[DataRequired("Це поле обовʼязкове"), Length(min=1, max=200)])
    submit = SubmitField("Створити")

class CreateFeedbackForm(FlaskForm):
    name = StringField("Імʼя", validators=[DataRequired("Це поле обовʼязкове"), Length(min=1, max=100)])
    email = EmailField("Пошта", validators=[DataRequired("Це поле обовʼязкове"), Length(min=1, max=100)])
    description = StringField("Розкажіть, що ви думаєте", validators=[DataRequired("Це поле обовʼязкове"), Length(min=1, max=300)])
    rate = SelectField("Оцінка", choices=[
        (1, 1), (2, 2), (3, 3), (4, 4), (5, 5),
        (6, 6), (7, 7), (8, 8), (9, 9), (10, 10)
    ])
    submit = SubmitField("Надіслати")