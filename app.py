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

from models import User

@app.route('/')
def index():
    return redirect(url_for('login_by_ajax'))

@app.route('/login_by_ajax', methods=['GET' 'POST'])
def login_by_ajax():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user = User.query.filter_by(email=email, is_admin=False).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.user_id
            session['is_admin'] = False
            return jsonify({'success': True, 'redirect': url_for('user_home')})
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)