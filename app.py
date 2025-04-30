from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route('/')
def home():
    return render_template('mainhome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        
        if existing_user:
            flash("Username already taken.", 'danger')
            return redirect(url_for('register'))
        if existing_email:
            flash("Email already registered.", 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, email=email, password=hashed_pw)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. Please login.", 'success')
            return redirect(url_for('login'))
        except:
            flash("An error occurred. Please try again.", 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['email']
        password = request.form['password']

        user = User.query.filter((User.email == login_input) | (User.username == login_input)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Login successful.", 'success')
            return render_template('home.html')
        else:
            flash("Invalid email/username or password.", 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
