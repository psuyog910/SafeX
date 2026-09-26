from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
import base64
import hashlib
import secrets
from sqlalchemy.exc import SQLAlchemyError
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-change-me')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
# Some providers hand out postgres:// URLs; SQLAlchemy 2.x wants postgresql://
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    passwords = db.relationship('Password', backref='user', lazy=True, cascade="all, delete-orphan")

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(500), nullable=False)
    salt = db.Column(db.String(64), nullable=False, default='')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

KDF_ITERATIONS = 200_000

def _derive_key(passphrase, salt):
    raw = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, KDF_ITERATIONS, dklen=32)
    return base64.urlsafe_b64encode(raw)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
            
        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password) or not any(char in '!@#$%^&*()_+' for char in password):
            flash('Password must be at least 8 characters long, contain a number, a letter, and a special character.', 'error')
            return redirect(url_for('signup'))
            
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'error')
            return redirect(url_for('signup'))
            
        new_user = User(username=username, password=generate_password_hash(password))
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)  # Added remember=True
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            if not user:
                flash('Username not found', 'error')
            else:
                flash('Incorrect password', 'error')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        passwords = Password.query.filter_by(user_id=current_user.id).order_by(Password.name).all()
        return render_template('dashboard.html', name=current_user.username, passwords=passwords)
    except Exception as e:
        flash('Error accessing dashboard', 'error')
        return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    password_name = request.form['password_name']
    password = request.form['password']
    passkey = request.form['passkey']
    
    salt = secrets.token_bytes(32)
    fernet = Fernet(_derive_key(passkey, salt))
    encrypted_password = fernet.encrypt(password.encode()).decode()

    new_password = Password(name=password_name, encrypted_password=encrypted_password, salt=salt.hex(), user_id=current_user.id)
    try:
        db.session.add(new_password)
        db.session.commit()
        flash('Password encrypted and saved successfully!', 'success')
        return redirect(url_for('dashboard'))
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('An error occurred while saving the password.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/decrypt_password/<int:id>', methods=['GET', 'POST'])
@login_required
def decrypt_password_by_id(id):
    password = Password.query.get_or_404(id)
    if password.user_id != current_user.id:
        flash('You do not have permission to view this password', 'error')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        try:
            passkey = request.form['passkey']
            fernet = Fernet(_derive_key(passkey, bytes.fromhex(password.salt)))
            decrypted_password = fernet.decrypt(password.encrypted_password.encode()).decode()
            return render_template('decrypt_result.html', password=password, decrypted=decrypted_password)
        except Exception as e:
            flash('Invalid passkey or corrupted data', 'error')
            return redirect(url_for('dashboard'))
    return render_template('decrypt_password.html', password=password)

@app.route('/update_password/<int:id>', methods=['GET', 'POST'])
@login_required
def update_password(id):
    password = Password.query.get_or_404(id)
    if password.user_id != current_user.id:
        flash('You do not have permission to update this password', 'error')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        password.name = request.form['password_name']
        new_password = request.form['password']
        passkey = request.form['passkey']
        
        salt = secrets.token_bytes(32)
        fernet = Fernet(_derive_key(passkey, salt))
        encrypted_password = fernet.encrypt(new_password.encode()).decode()

        password.encrypted_password = encrypted_password
        password.salt = salt.hex()
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('update_password.html', password=password)

@app.route('/delete_password/<int:id>', methods=['POST'])
@login_required
def delete_password_by_id(id):
    password = Password.query.get_or_404(id)
    if password.user_id != current_user.id:
        flash('You do not have permission to delete this password', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(password)
        db.session.commit()
        flash('Password deleted successfully!', 'success')
    except SQLAlchemyError:
        db.session.rollback()
        flash('An error occurred while deleting the password', 'error')
    
    return redirect(url_for('dashboard'))

def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

# Create tables at import time too: production servers (gunicorn) never run __main__
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False)
