import os
import secrets
import logging
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from database import db, Item, User, ApiKey
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Use an absolute path for the database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "inventory.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = 'your-secret-key'
db.init_app(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def loadA_user(user_id):
    return User.query.get(int(user_id))

# Function to initialize the database
def init_db():
    with app.app_context():
        db_path = os.path.join(BASE_DIR, 'inventory.db')
        try:
            if not os.path.exists(db_path):
                logger.info("Database does not exist. Creating new database...")
                db.drop_all()
                db.create_all()
                if not User.query.first():
                    logger.info("No users found. Creating default admin user...")
                    default_user = User(
                        username='admin',
                        password=generate_password_hash('password', method='pbkdf2:sha256'),
                        first_login=True,
                        permissions='read_write'
                    )
                    db.session.add(default_user)
                    db.session.commit()
                    logger.info("Default admin user created successfully.")
            else:
                logger.info("Database exists. Ensuring tables are created...")
                db.create_all()
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise

# Run the database initialization
try:
    init_db()
except Exception as e:
    logger.error(f"Application startup failed: {str(e)}")
    raise

# Helper function to save images
def save_image(file):
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return None

# Helper function to validate API key
def validate_api_key():
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not api_key:
        return None, jsonify({'error': 'API key required'}), 401
    key = ApiKey.query.filter_by(key=api_key).first()
    if not key:
        return None, jsonify({'error': 'Invalid API key'}), 401
    return key.user, None, None

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.first_login:
                return redirect(url_for('change_user_password', user_id=user.id))
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/change_user_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def change_user_password(user_id):
    if current_user.username != 'admin':
        flash('Only the admin can change user passwords')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('change_user_password', user_id=user_id))
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.first_login = True
        db.session.commit()
        flash(f'Password changed successfully for {user.username}')
        if user.id == current_user.id:
            logout_user()
            return redirect(url_for('login'))
        return redirect(url_for('manage_users'))
    
    return render_template('change_password.html', user=user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    if current_user.permissions == 'read' and request.method != 'GET':
        flash('You do not have permission to modify items')
        return redirect(url_for('index'))
    items = Item.query.all()
    layout = session.get('layout', 'card')
    return render_template('index.html', items=items, layout=layout)

@app.route('/toggle_layout')
@login_required
def toggle_layout():
    current_layout = session.get('layout', 'card')
    session['layout'] = 'list' if current_layout == 'card' else 'card'
    return redirect(url_for('index'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_item():
    if current_user.permissions == 'read':
        flash('You do not have permission to add items')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        quantity = float(request.form['quantity'])
        unit = request.form['unit']
        tags = request.form['tags']
        image = save_image(request.files.get('image'))

        item = Item(name=name, description=description, quantity=quantity, unit=unit, tags=tags, image=image)
        db.session.add(item)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_item.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_item(id):
    if current_user.permissions == 'read':
        flash('You do not have permission to edit items')
        return redirect(url_for('index'))
    item = Item.query.get_or_404(id)
    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.quantity = float(request.form['quantity'])
        item.unit = request.form['unit']
        item.tags = request.form['tags']
        if 'image' in request.files:
            item.image = save_image(request.files['image'])
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_item.html', item=item)

@app.route('/delete/<int:id>')
@login_required
def delete_item(id):
    if current_user.permissions == 'read':
        flash('You do not have permission to delete items')
        return redirect(url_for('index'))
    item = Item.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    if query:
        items = Item.query.filter(
            (Item.name.ilike(f'%{query}%')) | (Item.tags.ilike(f'%{query}%'))
        ).all()
    else:
        items = []
    layout = session.get('layout', 'card')
    return render_template('search.html', items=items, query=query, layout=layout)

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.username != 'admin':
        flash('Only the admin can manage users')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        if 'add_user' in request.form:
            username = request.form['username']
            password = request.form['password']
            permissions = request.form['permissions']
            if User.query.filter_by(username=username).first():
                flash('Username already exists')
            else:
                new_user = User(
                    username=username,
                    password=generate_password_hash(password, method='pbkdf2:sha256'),
                    first_login=True,
                    permissions=permissions
                )
                db.session.add(new_user)
                db.session.commit()
                flash('User added successfully')
            return redirect(url_for('manage_users'))
        
        elif 'delete_user' in request.form:
            user_id = request.form['user_id']
            user = User.query.get_or_404(user_id)
            if user.username == 'admin':
                flash('Cannot delete the admin user')
            else:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully')
            return redirect(url_for('manage_users'))
        
        elif 'generate_api_key' in request.form:
            user_id = request.form['user_id']
            user = User.query.get_or_404(user_id)
            api_key = secrets.token_hex(32)
            new_key = ApiKey(key=api_key, user_id=user.id)
            db.session.add(new_key)
            db.session.commit()
            flash(f'API Key generated for {user.username}: {api_key}')
            return redirect(url_for('manage_users'))
        
        elif 'change_password' in request.form:
            user_id = request.form['user_id']
            user = User.query.get_or_404(user_id)
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            if new_password != confirm_password:
                flash('Passwords do not match')
            else:
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                db.session.commit()
                flash(f'Password changed successfully for {user.username}')
                if user.id == current_user.id:
                    logout_user()
                    return redirect(url_for('login'))
            return redirect(url_for('manage_users'))
    
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/api/items', methods=['GET'])
def get_items():
    user, error_response, status = validate_api_key()
    if error_response:
        return error_response, status
    if user.permissions == 'read' or user.permissions == 'read_write':
        items = Item.query.all()
        return jsonify([{
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'quantity': item.quantity,
            'unit': item.unit,
            'image': item.image,
            'tags': item.tags
        } for item in items])
    else:
        return jsonify({'error': 'Insufficient permissions'}), 403

if __name__ == '__main__':
    app.run(debug=False)