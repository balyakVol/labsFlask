from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, SelectField, SelectMultipleField, SubmitField, BooleanField
from wtforms.validators import Length, InputRequired

class CreatePostForm(FlaskForm):
    title = StringField('Заголовок', validators=[InputRequired(), Length(min=2, max=100)])
    text = TextAreaField('Текст', validators=[Length(max=500)])
    picture = FileField('Зображення', validators=[FileAllowed(['jpg', 'png'])])
    type = SelectField('Тип', choices=[('News', 'News'), ('Publication', 'Publication'), ('Other', 'Other')])
    enabled = BooleanField('Enabled',)
    category = SelectField(u'Категорія', coerce=int)
    tag = SelectMultipleField(u'Тег', coerce=int)
    submit = SubmitField('Створити')

class CreateCategoryForm(FlaskForm):
    name = StringField('Назва', validators=[InputRequired(), Length(min=2, max=50)])
    submit = SubmitField('Створити')

class CreateTagForm(FlaskForm):
    name = StringField('Назва', validators=[InputRequired(), Length(min=2, max=100)])
    submit = SubmitField('Створити')