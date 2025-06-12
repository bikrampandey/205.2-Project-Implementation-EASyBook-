from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
import time
from datetime import datetime as dt
import logging
from sqlalchemy.exc import OperationalError

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost:5432/easybook_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24).hex()
PROFILE_PIC_UPLOAD_FOLDER = 'static/profile_pic_uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'jfif'}
app.config['PROFILE_PIC_UPLOAD_FOLDER'] = PROFILE_PIC_UPLOAD_FOLDER

# Ensure upload folder exists
if not os.path.exists(PROFILE_PIC_UPLOAD_FOLDER):
    os.makedirs(PROFILE_PIC_UPLOAD_FOLDER)
    try:
        os.chmod(PROFILE_PIC_UPLOAD_FOLDER, 0o755)
    except OSError:
        logging.warning("Unable to set permissions on upload folder (likely running on Windows)")

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_extension(filename):
    return filename.rsplit('.', 1)[1].lower()

# User model
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    age = db.Column(db.Integer)
    profile_picture = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, email, password, full_name, phone=None, age=None, profile_picture=None, is_admin=False):
        self.email = email
        self.password = password
        self.full_name = full_name
        self.phone = phone
        self.age = age
        self.profile_picture = profile_picture
        self.is_admin = is_admin

# Category model
class Category(db.Model):
    __tablename__ = 'categories'
    category_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __init__(self, name):
        self.name = name

# Create admin user and ensure tables
with app.app_context():
    db.create_all()
    existing_admin = User.query.filter_by(email='pandeybikram570@gmail.com').first()
    if not existing_admin:
        hashed_password = bcrypt.generate_password_hash('1234').decode('utf-8')
        admin_user = User(
            email='pandeybikram570@gmail.com',
            password=hashed_password,
            full_name='Bikram Pandey',
            phone='1234567890',
            age=30,
            profile_picture='static/profile_pic_uploads/default_profile.jpg',
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
        logging.info("Admin user created successfully!")
    else:
        logging.info("Admin user already exists!")

@app.route('/')
def index():
    return redirect(url_for('login_by_ajax'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            logging.debug(f"Admin login attempt with email: {email}")
            user = User.query.filter_by(email=email).first()
            if user:
                logging.debug(f"User found: {user.email}, is_admin: {user.is_admin}, password hash: {user.password}")
                if user.is_admin:
                    if bcrypt.check_password_hash(user.password, password):
                        session['user_id'] = user.user_id
                        session['is_admin'] = True
                        logging.info(f"Admin login successful for {email}")
                        return jsonify({'success': True, 'redirect': url_for('admin_dashboard')})
                    else:
                        logging.warning(f"Password check failed for {email}")
                        return jsonify({'success': False, 'message': 'Invalid admin email or password'}), 401
                else:
                    logging.warning(f"User {email} is not an admin")
                    return jsonify({'success': False, 'message': 'Invalid admin email or password'}), 401
            else:
                logging.warning(f"No user found with email {email}")
                return jsonify({'success': False, 'message': 'Invalid admin email or password'}), 401
        except OperationalError as e:
            logging.error(f"Database error during admin login: {str(e)}")
            return jsonify({'success': False, 'message': 'Database error. Please try again later.'}), 500
        except Exception as e:
            logging.error(f"Unexpected error during admin login: {str(e)}")
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500
    return render_template('admin_login.html')

@app.route('/login_by_ajax', methods=['GET', 'POST'])
def login_by_ajax():
    if request.method == 'POST':
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            user = User.query.filter_by(email=email, is_admin=False).first()
            if user and bcrypt.check_password_hash(user.password, password):
                session['user_id'] = user.user_id
                session['is_admin'] = False
                return jsonify({'success': True, 'redirect': url_for('home')})
            return jsonify({'success': False, 'message': 'Invalid user email or password'}), 401
        except OperationalError as e:
            logging.error(f"Database error during login: {str(e)}")
            return jsonify({'success': False, 'message': 'Database error. Please try again later.'}), 500
        except Exception as e:
            logging.error(f"Unexpected error during login: {str(e)}")
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500
    return render_template('login.html')

@app.route('/signup_by_ajax', methods=['GET', 'POST'])
def signup_by_ajax():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            full_name = request.form.get('name')
            phone = request.form.get('phone')
            age = request.form.get('age')

            logging.debug(f"Form data: email={email}, name={full_name}, phone={phone}, age={age}")

            if not all([email, password, confirm_password, full_name]):
                return jsonify({'success': False, 'message': 'All required fields must be filled'}), 400

            if password != confirm_password:
                return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'Email already exists'}), 400

            profile_picture = request.files.get('profile_picture')
            profile_pic_file_path = 'static/profile_pic_uploads/default_profile.jpg'

            if profile_picture and allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                dt_now = dt.now().strftime("%Y%m%d%H%M%S%f")
                file_extension = get_file_extension(profile_picture.filename)
                filename_to_save = f"{full_name}_{dt_now}.{file_extension}"
                file_path = os.path.join(app.config['PROFILE_PIC_UPLOAD_FOLDER'], filename_to_save)
                try:
                    profile_picture.save(file_path)
                    profile_pic_file_path = file_path
                    logging.debug(f"Profile picture saved at: {profile_pic_file_path}")
                except Exception as e:
                    logging.error(f"Error saving profile picture: {str(e)}")
                    return jsonify({'success': False, 'message': f'Failed to save profile picture: {str(e)}'}), 500

            try:
                age = int(age) if age else None
            except ValueError:
                return jsonify({'success': False, 'message': 'Age must be a valid number'}), 400

            user = User(
                email=email,
                password=bcrypt.generate_password_hash(password).decode('utf-8'),
                full_name=full_name,
                phone=phone,
                age=age,
                profile_picture=profile_pic_file_path,
                is_admin=False
            )
            db.session.add(user)
            db.session.commit()
            logging.debug(f"User {email} created successfully")
            return jsonify({'success': True, 'message': 'Registration successful! Please log in.', 'redirect': url_for('login_by_ajax')})
        except OperationalError as e:
            db.session.rollback()
            logging.error(f"Database error during signup: {str(e)}")
            return jsonify({'success': False, 'message': 'Database error. Please try again later.'}), 500
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during signup: {str(e)}")
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500
    return render_template('signup.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login_by_ajax'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('login_by_ajax'))
        profile_pic_path = user.profile_picture if user.profile_picture else 'static/profile_pic_uploads/default_profile.jpg'
        if user.profile_picture:
            absolute_path = os.path.join(app.config['PROFILE_PIC_UPLOAD_FOLDER'], os.path.basename(profile_pic_path))
            logging.debug(f"Checking profile picture at: {absolute_path}, Exists: {os.path.exists(absolute_path)}")
        
        categories = [
            {'name': 'Fiction', 'img': 'fiction.webp'},
            {'name': 'Non-Fiction', 'img': 'non-fiction.jpg'},
            {'name': 'Science', 'img': 'science.webp'},
            {'name': 'History', 'img': 'history.webp'},
            {'name': 'Fantasy', 'img': 'fantasy.webp'},
            {'name': 'Mystery', 'img': 'mystery.jpg'},
            {'name': 'Biography', 'img': 'biography.jpg'},
            {'name': 'Romance', 'img': 'romance.jpg'},
            {'name': 'Thriller', 'img': 'thriller.jpg'},
        ]
        return render_template('home.html', categories=categories, user=user)
    except OperationalError as e:
        logging.error(f"Database error in home route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.'), 500

@app.route('/profile')
def profile():
    return redirect(url_for('my_account'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        if request.method == 'POST':
            name = request.form.get('name')
            logging.debug(f"Add category form data: name={name}")
            if not name:
                flash('Category name is required!', 'error')
                return render_template('admin_dashboard.html', user=user)
            if Category.query.filter_by(name=name).first():
                flash('Category already exists!', 'error')
                return render_template('admin_dashboard.html', user=user)
            category = Category(name=name)
            db.session.add(category)
            db.session.commit()
            logging.debug(f"Category {name} added successfully")
            flash('Category added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_dashboard.html', user=user)
    except OperationalError as e:
        db.session.rollback()
        logging.error(f"Database error in admin_dashboard route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.'), 500
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in admin_dashboard route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}'), 500

@app.route('/categories')
def categories():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        categories = Category.query.all()
        return render_template('categories.html', user=user, categories=categories)
    except OperationalError as e:
        logging.error(f"Database error in categories route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.'), 500

@app.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
def edit_category(category_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        category = db.session.get(Category, category_id)
        if not category:
            flash('Category not found!', 'error')
            return redirect(url_for('categories'))
        if request.method == 'POST':
            name = request.form.get('name')
            logging.debug(f"Edit category form data: name={name}")
            if not name:
                flash('Category name is required!', 'error')
                return render_template('edit_category.html', user=user, category=category)
            existing_category = Category.query.filter_by(name=name).first()
            if existing_category and existing_category.category_id != category_id:
                flash('Category name already exists!', 'error')
                return render_template('edit_category.html', user=user, category=category)
            category.name = name
            db.session.commit()
            logging.debug(f"Category {category_id} updated successfully")
            flash('Category updated successfully!', 'success')
            return redirect(url_for('categories'))
        return render_template('edit_category.html', user=user, category=category)
    except OperationalError as e:
        db.session.rollback()
        logging.error(f"Database error in edit_category route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.'), 500
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in edit_category route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}'), 500

@app.route('/delete_category/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        category = db.session.get(Category, category_id)
        if not category:
            flash('Category not found!', 'error')
            return redirect(url_for('categories'))
        db.session.delete(category)
        db.session.commit()
        logging.debug(f"Category {category_id} deleted successfully")
        flash('Category deleted successfully!', 'success')
        return redirect(url_for('categories'))
    except OperationalError as e:
        db.session.rollback()
        logging.error(f"Database error in delete_category route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.'), 500
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in delete_category route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}'), 500

@app.route('/view_books/<int:category_id>')
def view_books(category_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        category = db.session.get(Category, category_id)
        if not category:
            flash('Category not found!', 'error')
            return redirect(url_for('categories'))
        return render_template('view_books.html', user=user, category=category)
    except OperationalError as e:
        logging.error(f"Database error in view_books route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.'), 500
    except Exception as e:
        logging.error(f"Unexpected error in view_books route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}'), 500

@app.route('/my_account', methods=['GET', 'POST'])
def my_account():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        if request.method == 'POST':
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            age = request.form.get('age')
            profile_picture = request.files.get('profile_picture')

            if not all([full_name, email]):
                flash('Full name and email are required!', 'error')
                return render_template('my_account.html', user=user)

            if email != user.email and User.query.filter_by(email=email).first():
                flash('Email already exists!', 'error')
                return render_template('my_account.html', user=user)

            try:
                age = int(age) if age else None
            except ValueError:
                flash('Age must be a valid number!', 'error')
                return render_template('my_account.html', user=user)

            if profile_picture and allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                dt_now = dt.now().strftime("%Y%m%d%H%M%S%f")
                file_extension = get_file_extension(profile_picture.filename)
                filename_to_save = f"{full_name}_{dt_now}.{file_extension}"
                file_path = os.path.join(app.config['PROFILE_PIC_UPLOAD_FOLDER'], filename_to_save)
                try:
                    profile_picture.save(file_path)
                    user.profile_picture = file_path
                    logging.debug(f"Profile picture updated at: {file_path}")
                except Exception as e:
                    logging.error(f"Error saving profile picture: {str(e)}")
                    flash(f'Failed to save profile picture: {str(e)}', 'error')
                    return render_template('my_account.html', user=user)

            user.full_name = full_name
            user.email = email
            user.phone = phone
            user.age = age
            db.session.commit()
            logging.debug(f"User {user.email} profile updated successfully")
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('my_account'))

        return render_template('my_account.html', user=user)
    except OperationalError as e:
        db.session.rollback()
        logging.error(f"Database error in my_account route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.'), 500
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in my_account route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}'), 500

@app.route('/all_users')
def all_users():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        all_users = User.query.all()
        return render_template('all_users.html', user=user, all_users=all_users)
    except OperationalError as e:
        logging.error(f"Database error in all_users route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.'), 500

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('login_by_ajax'))

if __name__ == '__main__':
    app.run(debug=True)