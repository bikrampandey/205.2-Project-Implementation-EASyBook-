from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
import time
from datetime import datetime as dt
import logging
from sqlalchemy.exc import OperationalError, SQLAlchemyError

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost:5432/easybook_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24).hex()
PROFILE_PIC_UPLOAD_FOLDER = 'static/profile_pic_uploads/'
CATEGORY_IMAGE_UPLOAD_FOLDER = 'static/category_images/'
BOOK_IMAGE_UPLOAD_FOLDER = 'static/book_images/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'jfif', 'webp', 'avif'}
app.config['PROFILE_PIC_UPLOAD_FOLDER'] = PROFILE_PIC_UPLOAD_FOLDER
app.config['CATEGORY_IMAGE_UPLOAD_FOLDER'] = CATEGORY_IMAGE_UPLOAD_FOLDER
app.config['BOOK_IMAGE_UPLOAD_FOLDER'] = BOOK_IMAGE_UPLOAD_FOLDER

# Ensure upload folders exist
for folder in [PROFILE_PIC_UPLOAD_FOLDER, CATEGORY_IMAGE_UPLOAD_FOLDER, BOOK_IMAGE_UPLOAD_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)
        try:
            os.chmod(folder, 0o755)
        except OSError:
            logging.warning(f"Unable to set permissions on {folder} (likely running on Windows)")

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

    def __init__(self, email, full_name, password, phone=None, age=None, profile_picture=None, is_admin=False):
        self.email = email
        self.full_name = full_name
        self.password = password
        self.phone = phone
        self.age = age
        self.profile_picture = profile_picture
        self.is_admin = is_admin

# Category model
class Category(db.Model):
    __tablename__ = 'categories'
    category_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    image_path = db.Column(db.String(200), default='static/category_images/default_category.jpg')

    def __init__(self, name, description=None, image_path=None):
        self.name = name
        self.description = description
        self.image_path = image_path

# Book model
class Book(db.Model):
    __tablename__ = 'books'
    book_id = db.Column(db.Integer, primary_key=True)
    book_name = db.Column(db.String(100), nullable=False)
    author_name = db.Column(db.String(100), nullable=False)
    publication_year = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Boolean, default=True, nullable=False)  # True = Available, False = Not Available
    description = db.Column(db.String(500))
    image_path = db.Column(db.String(200), default='static/book_images/default_book.jpg')
    category_id = db.Column(db.Integer, db.ForeignKey('categories.category_id'), nullable=False)
    category = db.relationship('Category', backref='books')

    def __init__(self, book_name, author_name, publication_year, status=True, description=None, category_id=None, image_path=None):
        self.book_name = book_name
        self.author_name = author_name
        self.publication_year = publication_year
        self.status = status
        self.description = description
        self.category_id = category_id
        self.image_path = image_path

# BorrowRequest model
class BorrowRequest(db.Model):
    __tablename__ = 'borrow_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.book_id'), nullable=False)
    borrow_date = db.Column(db.Date, nullable=False)
    return_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, approved, rejected
    request_date = db.Column(db.DateTime, default=dt.utcnow, nullable=False)
    return_requested = db.Column(db.Boolean, default=False, nullable=False)  # New field
    user = db.relationship('User', backref='borrow_requests')
    book = db.relationship('Book', backref='borrow_requests')

    def __init__(self, user_id, book_id, borrow_date, return_date, status='pending', return_requested=False):
        self.user_id = user_id
        self.book_id = book_id
        self.borrow_date = borrow_date
        self.return_date = return_date
        self.status = status
        self.return_requested = return_requested

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
        
        books = Book.query.all()
        for book in books:
            print(f"Book: {book.book_name}, ID: {book.book_id}, Image: {book.image_path}, Category ID: {book.category_id}")
            
        categories = Category.query.all()
        for category in categories:
            print(f"Category: {category.name}, ID: {category.category_id}")

@app.route('/')
def index():
        categories = Category.query.all()
        featured_books = Book.query.filter_by(status=True).order_by(Book.book_id.desc()).limit(6).all()
        return render_template('index.html', categories=categories, featured_books=featured_books, user=None)

@app.route('/public_search_books')
def public_search_books():
        term = request.args.get('term', '').lower()
        category_id = request.args.get('category_id')  # Optional category filter
        if category_id:
            category = db.session.get(Category, category_id)
            if not category:
                return jsonify({'error': 'Category not found'})
            books = category.books
        else:
            books = Book.query.all()
        if term:
            books = [book for book in books if term in book.book_name.lower() or term in book.author_name.lower()]
        return jsonify({
            'books': [
                {
                    'book_id': book.book_id,
                    'book_name': book.book_name,
                    'author_name': book.author_name,
                    'status': book.status,
                    'image_path': book.image_path,
                    'description': book.description
                } for book in books
            ]
        })

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            logging.debug(f"Admin login attempt with email: {email}")
            user = User.query.filter_by(email=email).first()  # Fixed query
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
                        return jsonify({'success': False, 'message': 'Invalid admin email or password'})
                else:
                    logging.warning(f"User {email} is not an admin")
                    return jsonify({'success': False, 'message': 'Invalid admin email or password'})
            else:
                logging.warning(f"No user found with email {email}")
                return jsonify({'success': False, 'message': 'Invalid admin email or password'})
        except OperationalError as e:
            logging.error(f"Database error during admin login: {str(e)}")
            return jsonify({'success': False, 'message': 'Database error. Please try again later.'})
        except Exception as e:
            logging.error(f"Unexpected error during admin login: {str(e)}")
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'})
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
            return jsonify({'success': False, 'message': 'Invalid user email or password'})
        except OperationalError as e:
            logging.error(f"Database error during login: {str(e)}")
            return jsonify({'success': False, 'message': 'Database error. Please try again later.'})
        except Exception as e:
            logging.error(f"Unexpected error during login: {str(e)}")
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'})
    return render_template('login.html')

@app.route('/signup_by_category', methods=['GET', 'POST'])
def signup_by_category():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            full_name = request.form.get('name')
            phone = request.form.get('phone')
            age = request.form.get('age')

            logging.debug(f"Form data: email={email}, full_name={full_name}, phone={phone}, age={age}")

            if not all([email, password, confirm_password, full_name]):
                return jsonify({'success': False, 'message': 'All required fields must be filled'})

            if password != confirm_password:
                return jsonify({'success': False, 'message': 'Passwords do not match'})

            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'Email already exists'})

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
                    return jsonify({'success': False, 'message': f'Failed to save profile picture: {str(e)}'})

            try:
                age = int(age) if age else None
            except ValueError:
                return jsonify({'success': False, 'message': 'Age must be a valid number'})

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
            return jsonify({'success': False, 'message': 'Database error. Please try again later.'})
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during signup: {str(e)}")
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'})
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
        categories = Category.query.all()
        return render_template('home.html', categories=categories, user=user)
    except OperationalError as e:
        logging.error(f"Database error in home route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in home route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')
    
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
        all_users = User.query.order_by(User.full_name.asc()).all()
        return render_template('all_users.html', user=user, all_users=all_users)
    except SQLAlchemyError as e:
        logging.error(f"Database error in all_users route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in all_users route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        logging.debug("No user_id in session, redirecting to login_by_ajax")
        return redirect(url_for('login_by_ajax'))
    try:
        logging.debug(f"Fetching user with ID: {session['user_id']}")
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('login_by_ajax'))
        logging.debug(f"Fetching borrow requests for user: {user.email}")
        borrow_requests = BorrowRequest.query.filter_by(user_id=user.user_id).order_by(BorrowRequest.request_date.desc()).all()
        categories = Category.query.all()
        if request.method == 'POST':
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            age = request.form.get('age')
            profile_picture = request.files.get('profile_picture')
            if not all([full_name, email]):
                flash('Full name and email are required!', 'error')
                return render_template('profile.html', user=user, borrow_requests=borrow_requests, categories=categories)
            if User.query.filter_by(email=email).filter(User.user_id != user.user_id).first():
                flash('Email already exists!', 'error')
                return render_template('profile.html', user=user, borrow_requests=borrow_requests, categories=categories)
            try:
                age = int(age) if age else None
            except ValueError:
                flash('Age must be a valid number!', 'error')
                return render_template('profile.html', user=user, borrow_requests=borrow_requests, categories=categories)
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
                    return render_template('profile.html', user=user, borrow_requests=borrow_requests, categories=categories)
            user.full_name = full_name
            user.email = email
            user.phone = phone
            user.age = age
            db.session.commit()
            logging.info(f"User {user.user_id} updated profile successfully")
            flash('Profile updated successfully!', 'success')
        return render_template('profile.html', user=user, borrow_requests=borrow_requests, categories=categories)
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Database error in profile route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in profile route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

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
            description = request.form.get('description')
            category_image = request.files.get('category_image')
            logging.debug(f"Add category form data: name={name}, description={description}")

            if not name:
                return jsonify({'success': False, 'message': 'Category name is required!'})

            if Category.query.filter_by(name=name).first():
                return jsonify({'success': False, 'message': 'Category already exists!'})

            image_path = 'static/category_images/default_category.jpg'
            if category_image and allowed_file(category_image.filename):
                filename = secure_filename(category_image.filename)
                dt_now = dt.now().strftime("%Y%m%d%H%M%S%f")
                file_extension = get_file_extension(category_image.filename)
                filename_to_save = f"{name}_{dt_now}.{file_extension}"
                file_path = os.path.join(app.config['CATEGORY_IMAGE_UPLOAD_FOLDER'], filename_to_save)
                try:
                    category_image.save(file_path)
                    image_path = file_path
                    logging.debug(f"Category image saved at: {file_path}")
                except Exception as e:
                    logging.error(f"Error saving category image: {str(e)}")
                    return jsonify({'success': False, 'message': f'Failed to save category image: {str(e)}'})

            category = Category(name=name, description=description, image_path=image_path)
            db.session.add(category)
            db.session.commit()
            logging.debug(f"Category {name} added successfully")
            return jsonify({'success': True, 'message': 'Category added successfully!'})
        return render_template('admin_dashboard.html', user=user)
    except OperationalError as e:
        db.session.rollback()
        logging.error(f"Database error in admin_dashboard route: {str(e)}")
        return jsonify({'success': False, 'message': 'Database error. Please try again later.'})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in admin_dashboard route: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

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
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in categories route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

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
            description = request.form.get('description')
            category_image = request.files.get('category_image')
            logging.debug(f"Edit category form data: name={name}, description={description}")

            if not name:
                flash('Category name is required!', 'error')
                return render_template('edit_category.html', user=user, category=category)

            existing_category = Category.query.filter_by(name=name).first()
            if existing_category and existing_category.category_id != category_id:
                flash('Category name already exists!', 'error')
                return render_template('edit_category.html', user=user, category=category)

            if category_image and allowed_file(category_image.filename):
                filename = secure_filename(category_image.filename)
                dt_now = dt.now().strftime("%Y%m%d%H%M%S%f")
                file_extension = get_file_extension(category_image.filename)
                filename_to_save = f"{name}_{dt_now}.{file_extension}"
                file_path = os.path.join(app.config['CATEGORY_IMAGE_UPLOAD_FOLDER'], filename_to_save)
                try:
                    category_image.save(file_path)
                    category.image_path = file_path
                    logging.debug(f"Category image updated at: {file_path}")
                except Exception as e:
                    logging.error(f"Error saving category image: {str(e)}")
                    flash(f'Failed to save category image: {str(e)}', 'error')
                    return render_template('edit_category.html', user=user, category=category)

            category.name = name
            category.description = description
            db.session.commit()
            logging.debug(f"Category {category_id} updated successfully")
            flash('Category updated successfully!', 'success')
            return redirect(url_for('categories'))
        return render_template('edit_category.html', user=user, category=category)
    except OperationalError as e:
        db.session.rollback()
        logging.error(f"Database error in edit_category route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in edit_category route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

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
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in delete_category route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/admin_view_books/<int:category_id>')
def admin_view_books(category_id):
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
        return render_template('view_book.html', user=user, category=category)
    except OperationalError as e:
        logging.error(f"Database error in admin_view_books route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in admin_view_books route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/category/<int:category_id>')
def user_category_books(category_id):
    if 'user_id' not in session:
        return redirect(url_for('login_by_ajax'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('login_by_ajax'))
        category = db.session.get(Category, category_id)
        if not category:
            flash('Category not found!', 'error')
            return redirect(url_for('home'))
        return render_template('category_books.html', user=user, category=category)
    except OperationalError as e:
        logging.error(f"Database error in user_category_books route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in user_category_books route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/search_books/<int:category_id>')
def search_books(category_id):
    if 'user_id' not in session:
        return redirect(url_for('login_by_ajax'))
    try:
        term = request.args.get('term', '').lower()
        category = db.session.get(Category, category_id)
        if not category:
            return jsonify({'error': 'Category not found'})
        books = category.books
        if term:
            books = [book for book in books if term in book.book_name.lower() or term in book.author_name.lower()]
        return jsonify({
            'books': [
                {
                    'book_id': book.book_id,
                    'book_name': book.book_name,
                    'author_name': book.author_name,
                    'status': book.status,
                    'image_path': book.image_path
                } for book in books
            ]
        })
    except OperationalError as e:
        logging.error(f"Database error in search_books route: {str(e)}")
        return jsonify({'error': 'Database error'})
    except Exception as e:
        logging.error(f"Unexpected error in search_books route: {str(e)}")
        return jsonify({'error': 'Server error'})

@app.route('/borrow_book/<int:book_id>')
def borrow_book(book_id):
    if 'user_id' not in session:
        logging.debug("No user_id in session, redirecting to login_by_ajax")
        return redirect(url_for('login_by_ajax'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('login_by_ajax'))
        book = db.session.get(Book, book_id)
        if not book:
            logging.error(f"Book not found for book_id: {book_id}")
            flash('Book not found!', 'error')
            return redirect(url_for('home'))
        if not book.status:
            logging.debug(f"Book {book_id} is not available, redirecting to category {book.category_id}")
            flash('This book is not available for borrowing!', 'error')
            return redirect(url_for('user_category_books', category_id=book.category_id))
        logging.debug(f"Rendering borrow_book for book_id {book_id}: {book.book_name}, image_path: {book.image_path}, category_id: {book.category_id}")
        categories = Category.query.all()
        other_books = Book.query.filter_by(category_id=book.category_id).filter(Book.book_id != book_id).all()
        logging.debug(f"Loaded {len(categories)} categories and {len(other_books)} other books")
        return render_template('borrow_book.html', user=user, book=book, categories=categories, other_books=other_books)
    except OperationalError as e:
        logging.error(f"Database error in borrow_book route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in borrow_book route: {str(e)}", exc_info=True)
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/borrow_form/<int:book_id>', methods=['GET', 'POST'])
def borrow_form(book_id):
    if 'user_id' not in session:
        logging.debug("No user_id in session, redirecting to login_by_ajax")
        return redirect(url_for('login_by_ajax'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('login_by_ajax'))
        book = db.session.get(Book, book_id)
        if not book:
            logging.error(f"Book not found for book_id: {book_id}")
            flash('Book not found!', 'error')
            return redirect(url_for('home'))
        if not book.status:
            logging.debug(f"Book {book_id} is not available, redirecting to category {book.category_id}")
            flash('This book is not available for borrowing!', 'error')
            return redirect(url_for('user_category_books', category_id=book.category_id))
        categories = Category.query.all()
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            borrow_date = request.form.get('borrow_date')
            return_date = request.form.get('return_date')
            if not all([name, email, phone, borrow_date, return_date]):
                flash('All fields are required!', 'error')
                return render_template('borrow_form.html', user=user, book=book, categories=categories)
            try:
                from datetime import datetime, timedelta
                borrow_date = datetime.strptime(borrow_date, '%Y-%m-%d').date()
                return_date = datetime.strptime(return_date, '%Y-%m-%d').date()
                if borrow_date < datetime.now().date():
                    flash('Borrow date cannot be in the past!', 'error')
                    return render_template('borrow_form.html', user=user, book=book, categories=categories)
                if return_date <= borrow_date:
                    flash('Return date must be after borrow date!', 'error')
                    return render_template('borrow_form.html', user=user, book=book, categories=categories)
                if (return_date - borrow_date).days > 14:
                    flash('Borrowing period cannot exceed 14 days!', 'error')
                    return render_template('borrow_form.html', user=user, book=book, categories=categories)
                # Check for existing pending/approved requests for this book
                existing_request = BorrowRequest.query.filter_by(
                    book_id=book_id,
                    status='pending'
                ).first() or BorrowRequest.query.filter_by(
                    book_id=book_id,
                    status='approved'
                ).first()
                if existing_request:
                    flash('This book is already requested or borrowed!', 'error')
                    return redirect(url_for('user_category_books', category_id=book.category_id))
                # Create BorrowRequest
                borrow_request = BorrowRequest(
                    user_id=user.user_id,
                    book_id=book_id,
                    borrow_date=borrow_date,
                    return_date=return_date
                )
                db.session.add(borrow_request)
                db.session.commit()
                logging.info(f"Borrow request created: Book={book.book_name}, User={name}, Borrow Date={borrow_date}, Return Date={return_date}, Status=pending")
                flash('Borrow request submitted successfully! Awaiting admin approval.', 'success')
                return redirect(url_for('profile'))  # Redirect to profile
            except ValueError:
                flash('Invalid date format!', 'error')
                return render_template('borrow_form.html', user=user, book=book, categories=categories)
        logging.debug(f"Rendering borrow_form for book_id {book_id}: {book.book_name}")
        return render_template('borrow_form.html', user=user, book=book, categories=categories)
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Database error in borrow_form route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in borrow_form route: {str(e)}", exc_info=True)
        return render_template('error.html', message=f'Server error: {str(e)}')
    
@app.route('/my_account', methods=['GET', 'POST'])
def my_account():
    if 'user_id' not in session or not session.get('is_admin'):
        logging.debug("No user_id or not admin, redirecting to admin_login")
        return redirect(url_for('admin_login'))
    try:
        logging.debug(f"Fetching user with ID: {session['user_id']}")
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        logging.debug(f"Fetching borrow requests for user: {user.email}")
        borrow_requests = BorrowRequest.query.filter_by(user_id=user.user_id).order_by(BorrowRequest.request_date.desc()).all()
        logging.debug(f"Fetching all categories")
        categories = Category.query.all()
        if request.method == 'POST':
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            age = request.form.get('age')
            if not all([full_name, email]):
                flash('Full name and email are required!', 'error')
                return render_template('my_account.html', user=user, borrow_requests=borrow_requests, categories=categories)
            if User.query.filter_by(email=email).filter(User.user_id != user.user_id).first():
                flash('Email already exists!', 'error')
                return render_template('my_account.html', user=user, borrow_requests=borrow_requests, categories=categories)
            try:
                age = int(age) if age else None
            except ValueError:
                flash('Age must be a valid number!', 'error')
                return render_template('my_account.html', user=user, borrow_requests=borrow_requests, categories=categories)
            user.full_name = full_name
            user.email = email
            user.phone = phone
            user.age = age
            db.session.commit()
            logging.info(f"User {user.user_id} updated profile successfully")
            flash('Profile updated successfully!', 'success')
        return render_template('my_account.html', user=user, borrow_requests=borrow_requests, categories=categories)
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Database error in my_account route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in my_account route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/add_book/<int:category_id>', methods=['GET', 'POST'])
def add_book(category_id):
    if 'user_id' not in session or not session.get('is_admin'):
        logging.debug("No user_id or not admin, redirecting to admin_login")
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
            return jsonify({'success': False, 'message': 'Category not found!'})
        if request.method == 'POST':
            book_name = request.form.get('book_name')
            author_name = request.form.get('author_name')
            publication_year = request.form.get('publication_year')
            description = request.form.get('description')
            book_image = request.files.get('book_image')
            logging.debug(f"Add book form data: book_name={book_name}, author_name={author_name}, publication_year={publication_year}")
            if not all([book_name, author_name, publication_year]):
                return jsonify({'success': False, 'message': 'Book name, author name, and publication year are required!'})
            try:
                publication_year = int(publication_year)
                if publication_year < 1000 or publication_year > dt.now().year:
                    return jsonify({'success': False, 'message': 'Invalid publication year!'})
            except ValueError:
                return jsonify({'success': False, 'message': 'Publication year must be a valid number!'})
            image_path = 'static/book_images/default_book.jpg'
            if book_image and allowed_file(book_image.filename):
                filename = secure_filename(book_image.filename)
                dt_now = dt.now().strftime("%Y%m%d%H%M%S%f")
                file_extension = get_file_extension(book_image.filename)
                filename_to_save = f"{book_name}_{dt_now}.{file_extension}"
                file_path = os.path.join(app.config['BOOK_IMAGE_UPLOAD_FOLDER'], filename_to_save)
                try:
                    book_image.save(file_path)
                    image_path = f'static/book_images/{filename_to_save}'
                    logging.debug(f"Book image saved at: {image_path}")
                except Exception as e:
                    logging.error(f"Error saving book image: {str(e)}")
                    return jsonify({'success': False, 'message': f'Failed to save book image: {str(e)}'})
            book = Book(
                book_name=book_name,
                author_name=author_name,
                publication_year=publication_year,
                description=description,
                category_id=category_id,
                image_path=image_path
            )
            db.session.add(book)
            db.session.commit()
            logging.info(f"Book '{book_name}' added to category {category.name}")
            return jsonify({
                'success': True,
                'message': 'Book added successfully!',
                'redirect': url_for('admin_view_books', category_id=category_id)
            })
        return render_template('add_book.html', user=user, category=category, dt=dt)
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Database error in add_book route: {str(e)}")
        return jsonify({'success': False, 'message': 'Database error. Please try again later.'})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in add_book route: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'})
    
@app.route('/borrowed_books')
def borrowed_books():
    if 'user_id' not in session:
        logging.debug("No user_id in session, redirecting to login_by_ajax")
        return redirect(url_for('login_by_ajax'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('login_by_ajax'))
        # Fetch approved borrow requests for the user
        borrow_requests = BorrowRequest.query.filter_by(
            user_id=user.user_id,
            status='approved'
        ).order_by(BorrowRequest.borrow_date.desc()).all()
        categories = Category.query.all()
        logging.debug(f"Loaded {len(borrow_requests)} approved borrow requests for user {user.user_id}")
        return render_template('borrowed_books.html', user=user, borrow_requests=borrow_requests, categories=categories)
    except SQLAlchemyError as e:
        logging.error(f"Database error in borrowed_books route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in borrowed_books route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/request_return/<int:request_id>', methods=['POST'])
def request_return(request_id):
    if 'user_id' not in session:
        logging.debug("No user_id in session, redirecting to login_by_ajax")
        return redirect(url_for('login_by_ajax'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('login_by_ajax'))
        borrow_request = db.session.get(BorrowRequest, request_id)
        if not borrow_request:
            flash('Borrow request not found!', 'error')
            return redirect(url_for('borrowed_books'))
        if borrow_request.user_id != user.user_id:
            flash('You are not authorized to return this book!', 'error')
            return redirect(url_for('borrowed_books'))
        if borrow_request.status != 'approved':
            flash('This book is not currently borrowed!', 'error')
            return redirect(url_for('borrowed_books'))
        if borrow_request.return_requested:
            flash('Return request already submitted!', 'error')
            return redirect(url_for('borrowed_books'))
        # Flag the request for return
        borrow_request.return_requested = True
        db.session.commit()
        logging.info(f"Return request submitted for borrow request {request_id}")
        flash('Return request submitted successfully! Awaiting admin approval.', 'success')
        return redirect(url_for('borrowed_books'))
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Database error in request_return route: {str(e)}")
        flash('Database error. Please try again later.', 'error')
        return redirect(url_for('borrowed_books'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in request_return route: {str(e)}")
        flash(f'Server error: {str(e)}', 'error')
        return redirect(url_for('borrowed_books'))

@app.route('/admin_borrow_requests')
def admin_borrow_requests():
    if 'user_id' not in session or not session.get('is_admin'):
        logging.debug("No user_id or not admin, redirecting to admin_login")
        return redirect(url_for('admin_login'))
    try:
        logging.debug(f"Fetching user with ID: {session['user_id']}")
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        logging.debug(f"Fetching all borrow requests")
        borrow_requests = BorrowRequest.query.order_by(BorrowRequest.request_date.desc()).all()
        return render_template('admin_borrow_requests.html', user=user, borrow_requests=borrow_requests)
    except SQLAlchemyError as e:
        logging.error(f"Database error in admin_borrow_requests route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in admin_borrow_requests route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/approve_borrow_request/<int:request_id>', methods=['POST'])
def approve_borrow_request(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        borrow_request = db.session.get(BorrowRequest, request_id)
        if not borrow_request:
            flash('Borrow request not found!', 'error')
            return redirect(url_for('admin_borrow_requests'))
        if borrow_request.status != 'pending' and not borrow_request.return_requested:
            flash('This request has already been processed!', 'error')
            return redirect(url_for('admin_borrow_requests'))
        book = db.session.get(Book, borrow_request.book_id)
        if borrow_request.return_requested:
            # Approve return request
            if borrow_request.status != 'approved':
                flash('Cannot approve return for non-borrowed book!', 'error')
                return redirect(url_for('admin_borrow_requests'))
            book.status = True  # Make book available
            borrow_request.return_requested = False
            borrow_request.status = 'returned'  # Update status to reflect return
            db.session.commit()
            logging.info(f"Return request approved for borrow request {request_id}, book {book.book_name}")
            flash('Return request approved successfully! Book is now available.', 'success')
            return redirect(url_for('admin_borrow_requests'))
        else:
            # Approve borrow request
            if not book.status:
                flash('This book is no longer available!', 'error')
                borrow_request.status = 'rejected'
                db.session.commit()
                return redirect(url_for('admin_borrow_requests'))
            book.status = False
            borrow_request.status = 'approved'
            db.session.commit()
            logging.info(f"Borrow request {request_id} approved for book {book.book_name}")
            flash('Borrow request approved successfully!', 'success')
            return redirect(url_for('admin_borrow_requests'))
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Database error in approve_borrow_request route: {str(e)}")
        flash('Database error. Please try again later.', 'error')
        return redirect(url_for('admin_borrow_requests'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in approve_borrow_request route: {str(e)}")
        flash(f'Server error: {str(e)}', 'error')
        return redirect(url_for('admin_borrow_requests'))

@app.route('/reject_borrow_request/<int:request_id>', methods=['POST'])
def reject_borrow_request(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            logging.error(f"User not found for user_id: {session['user_id']}")
            session.pop('user_id', None)
            session.pop('is_admin', None)
            return redirect(url_for('admin_login'))
        borrow_request = db.session.get(BorrowRequest, request_id)
        if not borrow_request:
            flash('Borrow request not found!', 'error')
            return redirect(url_for('admin_borrow_requests'))
        if borrow_request.status != 'pending' and not borrow_request.return_requested:
            flash('This request has already been processed!', 'error')
            return redirect(url_for('admin_borrow_requests'))
        if borrow_request.return_requested:
            # Reject return request
            borrow_request.return_requested = False
            db.session.commit()
            logging.info(f"Return request rejected for borrow request {request_id}")
            flash('Return request rejected successfully!', 'success')
            return redirect(url_for('admin_borrow_requests'))
        else:
            # Reject borrow request
            borrow_request.status = 'rejected'
            db.session.commit()
            logging.info(f"Borrow request {request_id} rejected")
            flash('Borrow request rejected successfully!', 'success')
            return redirect(url_for('admin_borrow_requests'))
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Database error in reject_borrow_request route: {str(e)}")
        flash('Database error. Please try again later.', 'error')
        return redirect(url_for('admin_borrow_requests'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error in reject_borrow_request route: {str(e)}")
        flash(f'Server error: {str(e)}', 'error')
        return redirect(url_for('admin_borrow_requests'))
    


@app.route('/public_category/<int:category_id>')
def public_category_books(category_id):
    try:
        category = db.session.get(Category, category_id)
        if not category:
            flash('Category not found!', 'error')
            return redirect(url_for('index'))
        return render_template('public_category_books.html', category=category, user=None)
    except OperationalError as e:
        logging.error(f"Database error in public_category_books route: {str(e)}")
        return render_template('error.html', message='Database error. Please try again later.')
    except Exception as e:
        logging.error(f"Unexpected error in public_category_books route: {str(e)}")
        return render_template('error.html', message=f'Server error: {str(e)}')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login_by_ajax'))

if __name__ == '__main__':
    app.run(debug=True)
