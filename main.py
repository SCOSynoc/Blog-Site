from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateUserForm, CreateLoginForm, CreateCommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
login_manager = LoginManager()

app.config['SECRET_KEY'] = f'{os.environ.get("MY_APP_SECRET_KEY")}'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


# db.create_all()


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


# db.create_all()


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=True)


# db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_login(*args, **kwargs):
        if current_user.is_anonymous:
            return abort(403)
        elif current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_login()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    admin = User.query.filter_by(id='1').first()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, admin=admin,
                           user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        password = form.password.data
        new_user = User(
            email=form.email.data,
            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8),
            name=form.name.data
        )
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('You are already registered login to continue')
            return redirect(url_for('login'))
        else:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = CreateLoginForm()
    if form.validate_on_submit():
        check_email = form.email.data
        check_password = form.password.data
        user = User.query.filter_by(email=check_email).first()
        if not user:
            flash("User does not exists register to continue")
            return redirect(url_for('login'))
        if check_password_hash(user.password, check_password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash("Incorrect password")
            return redirect(url_for('login'))

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return render_template("index.html", logged_in=False)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CreateCommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please login to continue")
            return redirect(url_for('login'))
        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('get_all_posts'))

    return render_template("post.html", form=form, post=requested_post, user=current_user,
                           logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@login_required
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
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='localhost', port=5000)
