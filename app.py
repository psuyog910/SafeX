from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
import base64
from sqlalchemy.exc import SQLAlchemyError
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    passwords = db.relationship('Password', backref='user', lazy=True, cascade="all, delete-orphan")

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_key(passphrase):
    return base64.urlsafe_b64encode(passphrase.ljust(32)[:32].encode())

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))
        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password) or not any(char in '!@#$%^&*()_+' for char in password):
            flash('Password must be at least 8 characters long, contain a number, a letter, and a special character.')
            return redirect(url_for('signup'))
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!')
            return redirect(url_for('signup'))
        new_user = User(username=username, password=generate_password_hash(password, method='sha256'))
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            flash('An error occurred. Please try again.')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    passwords = Password.query.filter_by(user_id=current_user.id).order_by(Password.name).all()
    return render_template('dashboard.html', name=current_user.username, passwords=passwords)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    password = request.form['password']
    passkey = request.form['passkey']
    password_name = request.form['password_name']
    key = generate_key(passkey)
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode()).decode()
    
    new_password = Password(name=password_name, encrypted_password=encrypted_password, user_id=current_user.id)
    try:
        db.session.add(new_password)
        db.session.commit()
        return jsonify({"message": "Password encrypted and saved successfully", "id": new_password.id})
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": "Database error occurred"}), 500

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    password_id = request.form['password_id']
    passkey = request.form['passkey']
    
    password_entry = Password.query.filter_by(id=password_id, user_id=current_user.id).first()
    if not password_entry:
        return jsonify({"error": "Password not found"}), 404
    
    key = generate_key(passkey)
    fernet = Fernet(key)
    try:
        decrypted_password = fernet.decrypt(password_entry.encrypted_password.encode()).decode()
        return jsonify({"decrypted_password": decrypted_password})
    except Exception as e:
        return jsonify({"error": "Invalid passkey or corrupted data"}), 400

@app.route('/get_passwords')
@login_required
def get_passwords():
    passwords = Password.query.filter_by(user_id=current_user.id).order_by(Password.name).all()
    return jsonify([{"id": p.id, "name": p.name} for p in passwords])

@app.route('/delete_password', methods=['POST'])
@login_required
def delete_password():
    password_id = request.form['password_id']
    password = Password.query.filter_by(id=password_id, user_id=current_user.id).first()
    if password:
        try:
            db.session.delete(password)
            db.session.commit()
            return jsonify({"message": "Password deleted successfully"})
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({"error": "Database error occurred"}), 500
    return jsonify({"error": "Password not found"}), 404

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/close_about')
def close_about():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=True)
