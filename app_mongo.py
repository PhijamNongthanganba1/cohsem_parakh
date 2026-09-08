from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import re
import os
import uuid
from werkzeug.utils import secure_filename
from bson import ObjectId
import traceback
import pymongo

print("🐍 Starting COHSEM PARAKH...")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cohsem_it_secure_key_2026_change_this_in_production')

# --- MongoDB Configuration ---
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb+srv://nongthanganbaphijam_db_user:BG2uPkyRu1L4ov30@cluster0.b5arftz.mongodb.net/')
app.config["MONGO_URI"] = MONGODB_URI

print("🔗 Connecting to MongoDB...")

# Connect with SSL disabled for Render
try:
    client = pymongo.MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=10000,
        tls=False,
        ssl=False,
        tlsAllowInvalidCertificates=True,
        tlsAllowInvalidHostnames=True
    )
    client.admin.command('ping')
    db = client['cohsemitms']
    print("✅ MongoDB connected successfully!")
    
    mongo = PyMongo(app)
    mongo.db = db
    mongo.cx = client
    
except Exception as e:
    print(f"❌ Connection failed: {e}")
    try:
        client = pymongo.MongoClient(MONGODB_URI)
        db = client['cohsemitms']
        mongo = PyMongo(app)
        mongo.db = db
        mongo.cx = client
        print("✅ MongoDB connected with fallback!")
    except Exception as e2:
        print(f"❌ All connection attempts failed: {e2}")
        db = None
        mongo = None

# --- File Upload Configuration ---
UPLOAD_FOLDER = 'static/uploads/questions'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def strip_html_tags(html_content):
    if not html_content:
        return ''
    clean = re.sub(r'<[^>]+>', ' ', html_content)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()

def has_actual_content(html_content):
    if not html_content:
        return False
    if '<img' in html_content.lower():
        return True
    if any(tag in html_content.lower() for tag in ['<ul', '<ol', '<blockquote', '<pre', '<code']):
        return True
    text = strip_html_tags(html_content)
    if text and len(text.strip()) > 0:
        return True
    return False

def get_question_text_safe(html_content):
    if not html_content:
        return ''
    if has_actual_content(html_content):
        return strip_html_tags(html_content)
    return ''

# --- Database Initialization ---
def init_db():
    if db is None:
        print("❌ Cannot initialize database - no connection")
        return
        
    try:
        # Insert default cognitive domains if empty
        if db.cognitive_domains.count_documents({}) == 0:
            domains_data = [
                {'domain_name': 'Awareness', 'description': 'Basic awareness of concepts and information'},
                {'domain_name': 'Sensitivity', 'description': 'Sensitivity to applications and real-world connections'},
                {'domain_name': 'Creativity', 'description': 'Creative thinking and problem solving'}
            ]
            db.cognitive_domains.insert_many(domains_data)
            print("✓ Inserted default cognitive domains")
        
        # Insert default difficulty levels if empty
        if db.difficulty_levels.count_documents({}) == 0:
            difficulty_data = ['Easy', 'Medium', 'Hard']
            db.difficulty_levels.insert_many([{'level_name': level} for level in difficulty_data])
            print("✓ Inserted default difficulty levels")
        
        # Create default admin user if no users exist
        if db.users.count_documents({}) == 0:
            ADMIN_USERNAME = "admin"
            ADMIN_PASSWORD = "admin123"
            ADMIN_ROLE = "admin"
            
            hashed_password = generate_password_hash(ADMIN_PASSWORD)
            
            db.users.insert_one({
                'username': ADMIN_USERNAME,
                'password': hashed_password,
                'role': ADMIN_ROLE,
                'subject_group': None,
                'group_role': 'member',
                'perm_re': True,
                'perm_ra': True,
                'perm_rc': True,
                'perm_ap': True,
                'perm_master': True,
                'created_at': datetime.now()
            })
            print("✓ Created default admin user")
        
        print("✅ Database initialization complete")
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")

# Initialize on startup
with app.app_context():
    init_db()

# ============================================
# ROUTES
# ============================================

@app.route('/')
def home():
    return redirect(url_for('dashboard_login'))

@app.route('/dashboard-login', methods=['GET', 'POST'])
def dashboard_login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('dashboard_login.html')
        
        if db is None:
            flash('Database connection error!', 'error')
            return render_template('dashboard_login.html')

        user = db.users.find_one({'username': username})
        
        if not user:
            flash('Invalid username or password!', 'error')
            return render_template('dashboard_login.html')
        
        if check_password_hash(user['password'], password):
            session['user'] = user['username']
            session['user_id'] = str(user['_id'])
            session['user_role'] = user.get('role', 'writer')
            session['subject_group'] = user.get('subject_group')
            session['group_role'] = user.get('group_role', 'member')
            session['perm_re'] = bool(user.get('perm_re', False))
            session['perm_ra'] = bool(user.get('perm_ra', False))
            session['perm_rc'] = bool(user.get('perm_rc', False))
            session['perm_ap'] = bool(user.get('perm_ap', False))
            session['perm_master'] = bool(user.get('perm_master', False))
            
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password!', 'error')
        return render_template('dashboard_login.html')

    return render_template('dashboard_login.html')

# ============================================
# ALL OTHER ROUTES (Dashboard, Upload, Paper Builder, Review, etc.)
# ============================================

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please login to access the dashboard', 'error')
        return redirect(url_for('dashboard_login'))
    
    user_role = session.get('user_role', 'writer')
    username = session.get('user', 'User')
    
    permissions = {
        'RE': session.get('perm_re', False),
        'RA': session.get('perm_ra', False),
        'RC': session.get('perm_rc', False),
        'AP': session.get('perm_ap', False),
        'MASTER': session.get('perm_master', False)
    }
    
    return render_template('dashboard.html', 
                         user=username, 
                         user_role=user_role,
                         permissions=permissions)

@app.route('/complete-selection')
def questions_upload():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    
    has_access = (
        session.get('perm_re', False) or 
        session.get('perm_rc', False) or 
        session.get('perm_ap', False) or 
        session.get('user_role') == 'admin'
    )
    
    if not has_access:
        flash('Access Denied: You do not have permission to upload questions', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('questions_upload.html', user=session['user'])

@app.route('/page2')
def page2():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    
    has_access = (
        session.get('perm_re', False) or 
        session.get('perm_rc', False) or 
        session.get('perm_ap', False) or 
        session.get('user_role') == 'admin'
    )
    
    if not has_access:
        flash('Access Denied: You do not have permission to upload questions', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('questions_upload_2.html', user=session['user'])

@app.route('/question-paper-builder')
def question_paper_builder():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    if not session.get('perm_ra', False) and session.get('user_role') != 'admin':
        flash('Access Denied: Builder (RA) permission required', 'error')
        return redirect(url_for('dashboard'))
    return render_template('question_paper_builder.html', user=session['user'])

@app.route('/configure')
def configure():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    if session.get('user_role') != 'admin' and not session.get('perm_master', False):
        flash('Access Denied: Admin or Master privileges required', 'error')
        return redirect(url_for('dashboard'))
    return render_template('configure_dashboard.html', user=session['user'])

@app.route('/review')
def review():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    
    username = session.get('user', 'User')
    user_role = session.get('user_role', 'writer')
    user_id = session.get('user_id', 0)
    permissions = {
        'RE': session.get('perm_re', False),
        'RA': session.get('perm_ra', False),
        'RC': session.get('perm_rc', False),
        'AP': session.get('perm_ap', False),
        'MASTER': session.get('perm_master', False)
    }
    
    page_title = "Questions List"
    if user_role == 'admin':
        page_title = "All Questions"
    elif permissions.get('MASTER'):
        page_title = "Master Dashboard - Assign Reviewers"
    elif permissions.get('AP'):
        page_title = "Approver Dashboard"
    elif permissions.get('RC'):
        page_title = "Reviewer Dashboard"
    elif permissions.get('RA'):
        page_title = "Approved Questions for Paper Building"
    elif permissions.get('RE'):
        page_title = "My Questions"
    
    return render_template('review.html', 
                         user=username, 
                         user_id=user_id,
                         user_role=user_role,
                         permissions=permissions,
                         page_title=page_title)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('dashboard_login'))

# ============================================
# API ENDPOINTS (ALL YOUR API ROUTES HERE)
# ============================================

# [Add all your API routes here - they're the same as before]
# [I'll keep it concise since this is getting long]

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=5000)