from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost:5432/easybook_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    age = db.Column(db.Integer)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, email, password, name, phone=None, age=None, is_admin=False):
        self.email = email
        self.password = password
        self.full_name = name
        self.phone = phone
        self.age = age
        self.is_admin = is_admin

@app.route('/')
def index():
    return redirect(url_for('login_by_ajax'))

@app.route('/login_by_ajax', methods=['GET', 'POST'])
def login_by_ajax():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user = User.query.filter_by(email=email, is_admin=False).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.user_id
            session['is_admin'] = user.is_admin
            return jsonify({'success': True, 'redirect': url_for('home')})
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    return render_template('login.html')

@app.route('/signup_by_ajax', methods=['GET', 'POST'])
def signup_by_ajax():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        name = data.get('name')
        phone = data.get('phone')
        age = data.get('age')

        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400

        try:
            user = User(
                email=email,
                password=bcrypt.generate_password_hash(password).decode('utf-8'),
                name=name,
                phone=phone,
                age=int(age) if age else None,
                is_admin=False
            )
            db.session.add(user)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Registration successful! Please log in.', 'redirect': url_for('login_by_ajax')})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
    return render_template('signup.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login_by_ajax'))
    categories = [
        {'name': 'Fiction', 'static/img': 'fiction.webp'},
        {'name': 'Non-Fiction', 'img': 'non-fiction.jpg'},
        {'name': 'Science', 'img': 'science.webp'},
        {'name': 'History', 'img': 'history.webp'},
        {'name': 'Fantasy', 'img': 'fantasy.webp'},
        {'name': 'Mystery', 'img': 'mystery.jpg'},
        {'name': 'Biography', 'img': 'biography.jpg'},
        {'name': 'Romance', 'img': 'romance.jpg'},
        {'name': 'Thriller', 'img': 'thriller.jpg'},
        {'name': 'Self-Help', 'img': 'self-help.jpg'},
        {'name': 'Poetry', 'img': 'poetry.jpg'},
        {'name': 'Young Adult', 'img': 'young-adult.jpg'}
    ]
    return render_template('home.html', categories=categories)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('login_by_ajax'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)