from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_uploads import UploadSet, configure_uploads, ALL, DATA, IMAGES
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///filesharing.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOADED_FILES_DEST'] = 'uploads'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

files = UploadSet('files', ALL)
configure_uploads(app, files)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

db.create_all()

@app.route('/')
def home():
    if current_user.is_authenticated:
        files = File.query.filter_by(user_id=current_user.id).all()
        return render_template('index.html', files=files)
    return render_template('index.html', files=[])

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST' and 'file' in request.files:
        filename = files.save(request.files['file'])
        new_file = File(filename=filename, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()
        flash('File uploaded successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('upload.html')

@app.route('/download/<filename>')
@login_required
def download(filename):
    return send_from_directory(app.config['UPLOADED_FILES_DEST'], filename)

@app.route('/delete/<int:file_id>')
@login_required
def delete(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    os.remove(os.path.join(app.config['UPLOADED_FILES_DEST'], file.filename))
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
