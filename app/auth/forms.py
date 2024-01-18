from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, ValidationError
from .models import User
 
class RegisterForm(FlaskForm):
    username = StringField("Імʼя", validators=[DataRequired(message="Імʼя повинен містити від 4 до 20 символів"), Length(min=4, max=20),
    Regexp('^[A-Za-z][A-Za-z0-9_.]*$', message='Імʼя має містити букви, цифри, крапку та нижнє підкреслення')])

    email = StringField("Електронна пошта", validators=[DataRequired(message="Це поле обовʼязкове"), Email()])

    password = PasswordField("Пароль", validators=[DataRequired(message="Це поле обовʼязкове"), Length(min=6)])

    confirm_password = PasswordField("Підтвердити пароль", validators=[DataRequired(message="Це поле обовʼязкове"), Length(min=6),
    EqualTo('password', message='Паролі не збігаються, спробуйте ще раз')])

    image_file = FileField("Виберіть файл для аватару")
    submit = SubmitField("Створити")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Користувач з цією поштою існує.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Це імʼя уже використовується.')
        
class LoginForm(FlaskForm):
    email = StringField("Електронна пошта", validators=[DataRequired("Це поле обовʼязкове"), Email()])
    password = PasswordField("Пароль", validators=[
                            DataRequired("Пароль повинен мати більш ніж 6 символів"),
                            Length(min=6)
                        ])
    remember = BooleanField("Запамʼятати", default='unchecked')
    submit = SubmitField("Увійти")