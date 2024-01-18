from flask import render_template

from . import home_blueprint

my_skills = ["C++", "HTML & CSS", "MySQL", "JavaScript", "Java", "Python", "OpenGL", "Paint.net"]

@home_blueprint.route('/home')
@home_blueprint.route('/')
def home():
    return render_template('home.html')

@home_blueprint.route('/cv')
def cv():
    return render_template('cv.html')

@home_blueprint.route('/edu')
def edu():
    return render_template('edu.html')

@home_blueprint.route('/hobbies')
def hobbies():
    return render_template('hobbies.html')

@home_blueprint.route('/skills/')
@home_blueprint.route('/skills/<int:id>')
def skills(id=None):
    if id is not None:
        if 0 <= id < len(my_skills):
            skill = my_skills[id]
            return render_template('skills.html', skill=skill)
        else:
            return render_template('skills.html')
    else:
        return render_template('skills.html', skills=my_skills, total_skills=len(my_skills))
