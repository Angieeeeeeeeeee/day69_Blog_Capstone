from flask import Flask, render_template, redirect, url_for, flash, request, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
from datetime import date
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateRegisterForm, CreateLogInForm, CreateCommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
Base = declarative_base()

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.callback"

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONFIGURE TABLES


# relationship

# parents -> child
# User.posts -> BlogPost.author
# User.comments -> Comment.author
# Blogpost.comments -> Comment.parent_post


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    text = db.Column(db.Text, nullable=False)
    parent_post = db.relationship("BlogPost", back_populates="comments")
    parent_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))


db.create_all()

# admin example user
# Email example@email.com
# Password 123456
# Name example

def admin_role_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() == "1":
            return func(*args, **kwargs)
        return render_template('404.html'), 404
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(user_id)
    return user


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = CreateRegisterForm()
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user is None:
            password = request.form["password"]
            hash_password = generate_password_hash(password=password, method="pbkdf2:sha256", salt_length=8)
            name = request.form["name"]
            add_register = User(email=email, password=hash_password, name=name)
            db.session.add(add_register)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        else:
            flash("You're already signed up with that email, log in instead")
            return redirect(url_for("login"))
    elif request.method == "GET":
        return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = CreateLogInForm()
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash("That email is not exist please try again")
            return redirect(url_for("login"))
        else:
            password = request.form["password"]
            if check_password_hash(pwhash=user.password, password=password) is True:
                print("LOGIN!!")
                login_user(user=user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password incorrect,Please try again")
                return redirect(url_for("login"))
    elif request.method == "GET":
        return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CreateCommentForm()
    if request.method == "POST":
        if current_user is None:
            flash("Please Login")
            return redirect(url_for("login"))
        new_comment = Comment(
            author=current_user,
            text=form.text.data,
            parent_post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    elif request.method == "GET":
        requested_post = BlogPost.query.get(post_id)
        comments = db.session.query(Comment).all()
        return render_template(
            "post.html", post=requested_post, form=form, comments=comments, post_id=post_id, gravatar=gravatar,)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_role_required
def add_new_post():
    form = CreatePostForm()
    if request.method == "POST":
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.get_id(),
        )
        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_role_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_role_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

