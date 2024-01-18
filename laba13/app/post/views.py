from flask import flash, render_template, redirect, request, url_for, current_app
from flask_login import login_required, current_user
from sqlalchemy import desc

from . import post_blueprint
from .models import db, Post, Category, Tag
from .forms import CreatePostForm, CreateCategoryForm, CreateTagForm

import os
import secrets
from PIL import Image

@post_blueprint.route("/", methods=['GET', 'POST'])
@login_required
def view_post():
    all_posts = Post.query.all()
    image_file = url_for('static', filename='images/')

    return render_template('show_all_posts.html', all_posts=all_posts, image_file=image_file)

@post_blueprint.route("/alt", methods=['GET', 'POST'])
@login_required
def view_post_by_date():
    page_num = request.args.get('page', 1, type=int)
    all_posts = Post.query.order_by(desc(Post.created)).paginate(page=page_num, per_page=3)
    image_file = url_for('static', filename='images/')

    return render_template('show_all_posts_by_date.html', all_posts=all_posts, image_file=image_file)

@post_blueprint.route("/<int:id>", methods=['GET', 'POST'])
def view_detail(id):
    get_post = Post.query.get_or_404(id)
    category = (Category.query.get_or_404(get_post.category_id)).name
    return render_template('detail_post.html', pk=get_post, category=category)

@post_blueprint.route("/create", methods=['GET', 'POST'])
@login_required
def create():
    form = CreatePostForm()
    form.category.choices = [(category.id, category.name) for category in Category.query.all()]
    form.tag.choices = [(tag.id, tag.name) for tag in Tag.query.all()]

    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            image = picture_file
        else:
            image = 'postdefault.png'

        category = Category.query.get_or_404(int(form.category.data))

        new_post = Post(title=form.title.data, text=form.text.data, type=form.type.data, image_file=image, user_id=current_user.id, category=category)
        
        selected_tags = form.tag.data
        for tag_id in selected_tags:
            tag = Tag.query.get(tag_id)
            if tag:
                new_post.tags.append(tag)

        db.session.add(new_post)
        db.session.commit()
        flash("Створення виконано", category=("success"))
        return redirect(url_for("post_bp.view_post"))
    
    return render_template('create_post.html', form=form)

@post_blueprint.route("/update/<int:id>", methods=['GET', 'POST'])
def update(id):
    get_post = Post.query.get_or_404(id)
    if current_user.id != get_post.user_id:
        flash("Це не ваш пост", category=("warning"))
        return redirect(url_for('post_bp.view_detail', id=id))
    
    form = CreatePostForm()
    form.category.choices = [(category.id, category.name) for category in Category.query.all()]
    form.tag.choices = [(tag.id, tag.name) for tag in Tag.query.all()]

    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            get_post.image_file = picture_file

        get_post.title = form.title.data
        get_post.text = form.text.data
        get_post.type = form.type.data
        get_post.category_id = form.category.data

        selected_tags = form.tag.data
        for tag_id in selected_tags:
            tag = Tag.query.get(tag_id)
            if tag:
                get_post.tags.append(tag)

        db.session.commit()
        db.session.add(get_post)

        flash("Пост був оновлений", category=("access"))
        return redirect(url_for('post_bp.view_detail', id=id))

    form.title.data = get_post.title
    form.text.data = get_post.text
    form.type.data = get_post.type
    form.category.data = get_post.category_id

    return render_template('update_post.html', form=form)

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'post/static/post/images', picture_fn)
    form_picture.save(picture_path)
    return picture_fn

@post_blueprint.route("/delete/<int:id>", methods=['GET', 'POST'])
def delete(id):
    get_post = Post.query.get_or_404(id)

    if current_user.id == get_post.user_id:
        db.session.delete(get_post)
        db.session.commit()
        flash("Видалення виконано", category=("success"))
    else:
        flash("Це не ваш пост", category=("warning"))

    return redirect(url_for('post_bp.view_post'))

@post_blueprint.route("/category", methods=['GET', 'POST'])
@login_required
def view_category():
    form = CreateCategoryForm()
    list = Category.query.all()

    return render_template('category.html', form=form, list=list)

@post_blueprint.route("/create_category", methods=['GET', 'POST'])
@login_required
def create_category():
    form = CreateCategoryForm()

    if form.validate_on_submit():
        new_category = Category(name=form.name.data)
        db.session.add(new_category)
        db.session.commit()
        flash("Створення виконано", category=("success"))
        return redirect(url_for("post_bp.view_category"))
    
    flash("Помилка при створенні", category=("danger"))
    return redirect(url_for("post_bp.view_category"))

@post_blueprint.route("/update_category/<int:category_id>", methods=['GET', 'POST'])
def update_category(category_id):
    get_category = Category.query.get_or_404(category_id)
    form = CreateCategoryForm()

    if form.validate_on_submit():
        get_category.name = form.name.data
        db.session.commit()
        db.session.add(get_category)
        flash("Оновлення виконано", category=("success"))
        return redirect(url_for("post_bp.view_category"))
    
    form.name.data = get_category.name
    return render_template('update_category.html', form=form)

@post_blueprint.route("/delete_category/<int:category_id>")
def delete_category(category_id):
    get_category = Category.query.get_or_404(category_id)

    db.session.delete(get_category)
    db.session.commit()
    flash("Видалення виконано", category=("success"))
    return redirect(url_for("post_bp.view_category"))

@post_blueprint.route("/tag", methods=['GET', 'POST'])
@login_required
def view_tag():
    form = CreateTagForm()
    list = Tag.query.all()

    return render_template('tag.html', form=form, list=list)

@post_blueprint.route("/create_tag", methods=['GET', 'POST'])
@login_required
def create_tag():
    form = CreateTagForm()

    if form.validate_on_submit():
        new_tag = Tag(name=form.name.data)
        db.session.add(new_tag)
        db.session.commit()
        flash("Створення виконано", category=("success"))
        return redirect(url_for("post_bp.view_tag"))
    
    flash("Помилка при створенні", category=("danger"))
    return redirect(url_for("post_bp.view_tag"))

@post_blueprint.route("/update_tag/<int:tag_id>", methods=['GET', 'POST'])
def update_tag(tag_id):
    get_tag = Tag.query.get_or_404(tag_id)
    form = CreateTagForm()

    if form.validate_on_submit():
        get_tag.name = form.name.data
        db.session.commit()
        db.session.add(get_tag)
        flash("Оновлення виконано", category=("success"))
        return redirect(url_for("post_bp.view_tag"))
    
    form.name.data = get_tag.name
    return render_template('update_tag.html', form=form)

@post_blueprint.route("/delete_tag/<int:tag_id>")
def delete_tag(tag_id):
    get_tag = Tag.query.get_or_404(tag_id)

    db.session.delete(get_tag)
    db.session.commit()
    flash("Видалення виконано", category=("success"))
    return redirect(url_for("post_bp.view_category"))