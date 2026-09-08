from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import re
import os
import uuid
from werkzeug.utils import secure_filename
from bson import ObjectId
import traceback
import pymongo
import sys

print(f"🐍 Python version: {sys.version}")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cohsem_it_secure_key_2026_change_this_in_production')

# --- MongoDB Configuration ---
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb+srv://nongthanganbaphijam_db_user:BG2uPkyRu1L4ov30@cluster0.b5arftz.mongodb.net/')

print(f"🔗 Connecting to MongoDB...")

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
    # Test connection
    client.admin.command('ping')
    db = client['cohsemitms']
    print("✅ MongoDB connected successfully!")
    
    mongo = PyMongo(app)
    mongo.db = db
    mongo.cx = client
    
except Exception as e:
    print(f"❌ Connection attempt 1 failed: {e}")
    try:
        client = pymongo.MongoClient(MONGODB_URI)
        db = client['cohsemitms']
        mongo = PyMongo(app)
        mongo.db = db
        mongo.cx = client
        print("✅ MongoDB connected with fallback!")
    except Exception as e2:
        print(f"❌ All connection attempts failed: {e2}")
        # Create a dummy connection for testing
        client = pymongo.MongoClient('mongodb://localhost:27017/')
        db = client['cohsemitms']
        mongo = PyMongo(app)
        mongo.db = db
        mongo.cx = client
        print("⚠️ Using dummy database connection")

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

def get_user_subject_ids(username):
    user = db.users.find_one({'username': username})
    if not user or not user.get('subject_group'):
        return []
    groups = db.subject_groups.find({'group_code': user['subject_group']})
    return [group['subject_id'] for group in groups]

def get_user_grades(username):
    user = db.users.find_one({'username': username})
    if not user or not user.get('subject_group'):
        return []
    groups = db.subject_groups.find({'group_code': user['subject_group']})
    return [group['grade_id'] for group in groups]

def apply_subject_filter(query, user_role, subject_group, subject_id_column='subject_id'):
    if user_role == 'admin':
        return query, []
    if subject_group:
        subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
        if subject_ids:
            query[subject_id_column] = {'$in': subject_ids}
            return query, subject_ids
    query[subject_id_column] = None
    return query, []

# --- Database Initialization ---
def init_db():
    """Initialize MongoDB collections and default data"""
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
        
        # Get domain IDs
        domains = {doc['domain_name']: doc['_id'] for doc in db.cognitive_domains.find()}
        difficulties = {doc['level_name']: doc['_id'] for doc in db.difficulty_levels.find()}
        
        # Insert default knowledge levels if empty
        if db.knowledge_levels.count_documents({}) == 0:
            knowledge_levels = [
                ('Knowledge', 'Basic recall of information and facts', domains.get('Awareness'), difficulties.get('Easy')),
                ('Remembering', 'Retrieving knowledge from memory', domains.get('Awareness'), difficulties.get('Easy')),
                ('Understanding', 'Constructing meaning from information', domains.get('Awareness'), difficulties.get('Easy')),
                ('Comprehension', 'Grasping the meaning of information', domains.get('Awareness'), difficulties.get('Medium')),
                ('Application', 'Apply knowledge to new situations', domains.get('Sensitivity'), difficulties.get('Medium')),
                ('Analysis', 'Break down information into parts', domains.get('Sensitivity'), difficulties.get('Medium')),
                ('Synthesis', 'Combine elements to form a new whole', domains.get('Sensitivity'), difficulties.get('Medium')),
                ('Empathy', "Understanding others' perspectives and feelings", domains.get('Sensitivity'), difficulties.get('Medium')),
                ('Interpretation', 'Explaining and interpreting information', domains.get('Sensitivity'), difficulties.get('Medium')),
                ('Evaluation', 'Make judgments based on criteria and standards', domains.get('Creativity'), difficulties.get('Hard')),
                ('Creation', 'Generate new ideas and products', domains.get('Creativity'), difficulties.get('Hard')),
                ('Critical Thinking', 'Deep analysis and evaluation of information', domains.get('Creativity'), difficulties.get('Hard')),
                ('Innovation', 'Novel approaches and solutions to problems', domains.get('Creativity'), difficulties.get('Hard')),
                ('Design Thinking', 'Human-centered problem solving approach', domains.get('Creativity'), difficulties.get('Hard')),
                ('Reflection', 'Thoughtful consideration and self-assessment', domains.get('Creativity'), difficulties.get('Hard'))
            ]
            
            for level_name, description, domain_id, difficulty_id in knowledge_levels:
                db.knowledge_levels.insert_one({
                    'level_name': level_name,
                    'description': description,
                    'is_active': True,
                    'domain_id': domain_id,
                    'difficulty_id': difficulty_id
                })
            print("✓ Inserted default knowledge levels")
        
        # Insert default question types if empty
        if db.question_types.count_documents({}) == 0:
            question_types = [
                ('Objective', domains.get('Awareness')),
                ('Very Short Answer', domains.get('Awareness')),
                ('Short Answer', domains.get('Sensitivity')),
                ('Long Answer', domains.get('Sensitivity')),
                ('MCQ', domains.get('Creativity'))
            ]
            
            for type_name, cognitive_id in question_types:
                db.question_types.insert_one({
                    'type_name': type_name,
                    'cognitive_id': cognitive_id
                })
            print("✓ Inserted default question types")
        
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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('dashboard_login.html')
        
        try:
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
            else:
                flash('Invalid username or password!', 'error')
                return render_template('dashboard_login.html')
                
        except Exception as e:
            print(f"❌ Login error: {e}")
            flash(f'Login error: {str(e)}', 'error')
            return render_template('dashboard_login.html')

    return render_template('dashboard_login.html')

@app.route('/dashboard-register', methods=['GET', 'POST'])
def dashboard_register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('dashboard_register.html')
        if len(username) < 3:
            flash('Username must be at least 3 characters long!', 'error')
            return render_template('dashboard_register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters long!', 'error')
            return render_template('dashboard_register.html')
        
        if db.users.find_one({'username': username}):
            flash('Username already exists!', 'error')
            return render_template('dashboard_register.html')
        
        hashed_password = generate_password_hash(password)
        try:
            db.users.insert_one({
                'username': username,
                'password': hashed_password,
                'role': 'writer',
                'subject_group': None,
                'group_role': 'member',
                'perm_re': True,
                'perm_ra': False,
                'perm_rc': False,
                'perm_ap': False,
                'perm_master': False,
                'created_at': datetime.now()
            })
            flash('Account created successfully! You can now login.', 'success')
            return redirect(url_for('dashboard_login'))
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
            return render_template('dashboard_register.html')
    return render_template('dashboard_register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return redirect(url_for('dashboard_login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    return redirect(url_for('dashboard_register'))

@app.route('/builder-login', methods=['GET', 'POST'])
def builder_login():
    return redirect(url_for('dashboard_login'))

@app.route('/builder-register', methods=['GET', 'POST'])
def builder_register():
    return redirect(url_for('dashboard_register'))

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
# API ENDPOINTS
# ============================================

@app.route('/api/dashboard-stats')
def dashboard_stats():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        all_subjects = list(db.subjects.find())
        subjects_dict = {str(s['_id']): s for s in all_subjects}
        
        all_grades = list(db.grades.find())
        
        stats = {}
        
        for grade in all_grades:
            grade_id = str(grade['_id'])
            grade_name = grade['grade_name']
            
            pipeline = [
                {'$match': {'grade_id': grade_id}},
                {'$group': {
                    '_id': None,
                    'total': {'$sum': 1},
                    'approved': {'$sum': {'$cond': [{'$eq': ['$status', 'approved']}, 1, 0]}},
                    'unassigned': {'$sum': {'$cond': [{'$or': [{'$eq': ['$status', 'unassigned']}, {'$eq': ['$status', None]}]}, 1, 0]}},
                    'under_review': {'$sum': {'$cond': [{'$eq': ['$status', 'under_review']}, 1, 0]}},
                    'reviewed_completed': {'$sum': {'$cond': [{'$eq': ['$status', 'reviewed_completed']}, 1, 0]}},
                    'rejected': {'$sum': {'$cond': [{'$eq': ['$status', 'rejected']}, 1, 0]}},
                    'master_reviewed': {'$sum': {'$cond': [{'$eq': ['$status', 'master_reviewed']}, 1, 0]}}
                }}
            ]
            grade_stats = list(db.simple_questions.aggregate(pipeline))
            grade_stats = grade_stats[0] if grade_stats else {'total': 0, 'approved': 0, 'unassigned': 0, 'under_review': 0, 'reviewed_completed': 0, 'rejected': 0, 'master_reviewed': 0}
            
            pipeline_subject = [
                {'$match': {'grade_id': grade_id}},
                {'$group': {
                    '_id': '$subject_id',
                    'total': {'$sum': 1},
                    'approved': {'$sum': {'$cond': [{'$eq': ['$status', 'approved']}, 1, 0]}},
                    'unassigned': {'$sum': {'$cond': [{'$or': [{'$eq': ['$status', 'unassigned']}, {'$eq': ['$status', None]}]}, 1, 0]}},
                    'under_review': {'$sum': {'$cond': [{'$eq': ['$status', 'under_review']}, 1, 0]}},
                    'reviewed_completed': {'$sum': {'$cond': [{'$eq': ['$status', 'reviewed_completed']}, 1, 0]}},
                    'rejected': {'$sum': {'$cond': [{'$eq': ['$status', 'rejected']}, 1, 0]}},
                    'master_reviewed': {'$sum': {'$cond': [{'$eq': ['$status', 'master_reviewed']}, 1, 0]}}
                }}
            ]
            subject_stats = list(db.simple_questions.aggregate(pipeline_subject))
            
            subjects_dict_for_grade = {}
            for subj in subject_stats:
                subject_id = subj['_id']
                if subject_id and subject_id in subjects_dict:
                    subjects_dict_for_grade[str(subject_id)] = {
                        'total': subj.get('total', 0),
                        'approved': subj.get('approved', 0),
                        'unassigned': subj.get('unassigned', 0),
                        'under_review': subj.get('under_review', 0),
                        'reviewed_completed': subj.get('reviewed_completed', 0),
                        'rejected': subj.get('rejected', 0),
                        'master_reviewed': subj.get('master_reviewed', 0),
                        'subject_name': subjects_dict[subject_id]['subject_name']
                    }
            
            stats[f'grade_{grade_id}'] = {
                'total': grade_stats.get('total', 0),
                'approved': grade_stats.get('approved', 0),
                'unassigned': grade_stats.get('unassigned', 0),
                'under_review': grade_stats.get('under_review', 0),
                'reviewed_completed': grade_stats.get('reviewed_completed', 0),
                'rejected': grade_stats.get('rejected', 0),
                'master_reviewed': grade_stats.get('master_reviewed', 0),
                'subjects': subjects_dict_for_grade,
                'grade_name': grade_name,
                'grade_id': grade_id
            }
        
        pipeline_recent = [
            {'$lookup': {
                'from': 'grades',
                'localField': 'grade_id',
                'foreignField': '_id',
                'as': 'grade_info'
            }},
            {'$lookup': {
                'from': 'subjects',
                'localField': 'subject_id',
                'foreignField': '_id',
                'as': 'subject_info'
            }},
            {'$lookup': {
                'from': 'chapters',
                'localField': 'chapter_id',
                'foreignField': '_id',
                'as': 'chapter_info'
            }},
            {'$sort': {'created_at': -1}},
            {'$limit': 10}
        ]
        
        if user_role != 'admin' and subject_group:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                pipeline_recent.insert(0, {'$match': {'subject_id': {'$in': subject_ids}}})
            else:
                pipeline_recent.insert(0, {'$match': {'_id': None}})
        
        recent = list(db.simple_questions.aggregate(pipeline_recent))
        stats['recent'] = recent
        
        return jsonify(stats)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/grades', methods=['GET'])
def get_grades():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        if user_role == 'admin':
            grades = list(db.grades.find({}, {'_id': 1, 'grade_name': 1}).sort('_id', 1))
        else:
            subject_groups = list(db.subject_groups.find({'group_code': subject_group}))
            grade_ids = list(set([g['grade_id'] for g in subject_groups if g.get('grade_id')]))
            if grade_ids:
                grades = list(db.grades.find({'_id': {'$in': grade_ids}}))
            else:
                grades = []
        
        for g in grades:
            g['id'] = str(g['_id'])
            del g['_id']
        
        return jsonify({'grades': grades})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/grades', methods=['POST'])
def create_grade():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Grade name is required'}), 400
    
    try:
        result = db.grades.insert_one({'grade_name': name})
        return jsonify({'success': True, 'id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/grades/<grade_id>', methods=['PUT'])
def update_grade(grade_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Grade name is required'}), 400
    
    try:
        result = db.grades.update_one(
            {'_id': ObjectId(grade_id)},
            {'$set': {'grade_name': name}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Grade not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/grades/<grade_id>', methods=['DELETE'])
def delete_grade(grade_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        if db.subjects.count_documents({'grade_id': grade_id}) > 0:
            return jsonify({'error': 'Cannot delete grade with subjects'}), 400
        
        result = db.grades.delete_one({'_id': ObjectId(grade_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Grade not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects', methods=['GET'])
def get_subjects():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        pipeline = [
            {'$lookup': {
                'from': 'grades',
                'localField': 'grade_id',
                'foreignField': '_id',
                'as': 'grade_info'
            }},
            {'$addFields': {
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]}
            }},
            {'$project': {'grade_info': 0}}
        ]
        
        if user_role == 'admin':
            subjects = list(db.subjects.aggregate(pipeline))
        else:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                pipeline.insert(0, {'$match': {'_id': {'$in': subject_ids}}})
                subjects = list(db.subjects.aggregate(pipeline))
            else:
                subjects = []
        
        for s in subjects:
            s['id'] = str(s['_id'])
            s['grade_id'] = str(s['grade_id'])
            del s['_id']
        
        return jsonify({'subjects': subjects})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects', methods=['POST'])
def create_subject():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    name = data.get('name')
    grade_id = data.get('grade_id')
    
    if not name or not grade_id:
        return jsonify({'error': 'Name and grade required'}), 400
    
    try:
        result = db.subjects.insert_one({
            'subject_name': name,
            'grade_id': grade_id
        })
        return jsonify({'success': True, 'id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects/<subject_id>', methods=['PUT'])
def update_subject(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    name = data.get('name')
    grade_id = data.get('grade_id')
    if not name or not grade_id:
        return jsonify({'error': 'Name and grade required'}), 400
    
    try:
        result = db.subjects.update_one(
            {'_id': ObjectId(subject_id)},
            {'$set': {'subject_name': name, 'grade_id': grade_id}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Subject not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects/<subject_id>', methods=['DELETE'])
def delete_subject(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        if db.curricular_goals.count_documents({'subject_id': subject_id}) > 0:
            return jsonify({'error': 'Cannot delete subject with CGs'}), 400
        
        result = db.subjects.delete_one({'_id': ObjectId(subject_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Subject not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# TEXTBOOKS API
# ============================================

@app.route('/api/textbooks', methods=['GET'])
def get_textbooks():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    grade_id = request.args.get('grade_id')
    book_type = request.args.get('book_type')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        query = {}
        
        if user_role != 'admin' and subject_group:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                query['subject_id'] = {'$in': subject_ids}
        
        if subject_id:
            query['subject_id'] = subject_id
        if grade_id:
            query['grade_id'] = grade_id
        if book_type == 'textbook':
            query['is_reference'] = {'$ne': 1}
        elif book_type == 'reference':
            query['is_reference'] = 1
        
        textbooks = list(db.textbooks.find(query).sort('textbook_name', 1))
        
        for t in textbooks:
            t['id'] = str(t['_id'])
            del t['_id']
        
        return jsonify({'textbooks': textbooks})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/textbooks', methods=['POST'])
def create_textbook():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    textbook_name = data.get('textbook_name')
    subject_id = data.get('subject_id')
    grade_id = data.get('grade_id')
    publisher = data.get('publisher', '')
    is_reference = data.get('is_reference', 0)
    
    if not textbook_name or not subject_id or not grade_id:
        return jsonify({'error': 'Textbook name, subject, and grade are required'}), 400
    
    try:
        existing = db.textbooks.find_one({
            'textbook_name': textbook_name,
            'subject_id': subject_id
        })
        if existing:
            return jsonify({'error': 'Book already exists for this subject'}), 400
        
        result = db.textbooks.insert_one({
            'textbook_name': textbook_name,
            'subject_id': subject_id,
            'grade_id': grade_id,
            'publisher': publisher,
            'is_reference': is_reference,
            'created_at': datetime.now()
        })
        return jsonify({'success': True, 'id': str(result.inserted_id), 'message': 'Book saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/textbooks/<textbook_id>', methods=['PUT'])
def update_textbook(textbook_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    textbook_name = data.get('textbook_name')
    subject_id = data.get('subject_id')
    grade_id = data.get('grade_id')
    publisher = data.get('publisher', '')
    is_reference = data.get('is_reference', 0)
    
    if not textbook_name or not subject_id or not grade_id:
        return jsonify({'error': 'Textbook name, subject, and grade are required'}), 400
    
    try:
        result = db.textbooks.update_one(
            {'_id': ObjectId(textbook_id)},
            {'$set': {
                'textbook_name': textbook_name,
                'subject_id': subject_id,
                'grade_id': grade_id,
                'publisher': publisher,
                'is_reference': is_reference
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Book not found'}), 404
        return jsonify({'success': True, 'message': 'Book updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/textbooks/<textbook_id>', methods=['DELETE'])
def delete_textbook(textbook_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        count = db.chapters.count_documents({'textbook_id': textbook_id})
        if count > 0:
            return jsonify({'error': f'Cannot delete textbook because it has {count} chapter(s) associated.'}), 400
        
        result = db.textbooks.delete_one({'_id': ObjectId(textbook_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Book not found'}), 404
        return jsonify({'success': True, 'message': 'Book deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects/<subject_id>/textbooks', methods=['GET'])
def get_subject_textbooks(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    book_type = request.args.get('book_type')
    
    try:
        query = {'subject_id': subject_id}
        
        if book_type == 'textbook':
            query['is_reference'] = {'$ne': 1}
        elif book_type == 'reference':
            query['is_reference'] = 1
        
        textbooks = list(db.textbooks.find(query).sort('textbook_name', 1))
        
        for t in textbooks:
            t['id'] = str(t['_id'])
            del t['_id']
        
        return jsonify({'textbooks': textbooks})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# CHAPTERS API
# ============================================

@app.route('/api/chapters', methods=['GET'])
def get_chapters():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        query = {}
        
        if subject_id:
            query['subject_id'] = subject_id
        
        if user_role != 'admin' and subject_group:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                query['subject_id'] = {'$in': subject_ids}
        
        pipeline = [
            {'$match': query},
            {'$lookup': {
                'from': 'subjects',
                'localField': 'subject_id',
                'foreignField': '_id',
                'as': 'subject_info'
            }},
            {'$lookup': {
                'from': 'grades',
                'localField': 'grade_id',
                'foreignField': '_id',
                'as': 'grade_info'
            }},
            {'$lookup': {
                'from': 'textbooks',
                'localField': 'textbook_id',
                'foreignField': '_id',
                'as': 'textbook_info'
            }},
            {'$addFields': {
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]},
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'textbook_name': {'$arrayElemAt': ['$textbook_info.textbook_name', 0]},
                'publisher': {'$arrayElemAt': ['$textbook_info.publisher', 0]},
                'is_reference': {'$arrayElemAt': ['$textbook_info.is_reference', 0]}
            }},
            {'$project': {'subject_info': 0, 'grade_info': 0, 'textbook_info': 0}},
            {'$sort': {'chapter_number': 1}}
        ]
        
        chapters = list(db.chapters.aggregate(pipeline))
        
        for c in chapters:
            c['id'] = str(c['_id'])
            c['subject_id'] = str(c['subject_id'])
            if c.get('textbook_id'):
                c['textbook_id'] = str(c['textbook_id'])
            del c['_id']
        
        return jsonify({'chapters': chapters})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chapters', methods=['POST'])
def create_chapter():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    subject_id = data.get('subject_id')
    chapter_name = data.get('chapter_name')
    chapter_number = data.get('chapter_number', 0)
    textbook_id = data.get('textbook_id')
    reference_book = data.get('reference_book', '')
    
    if not subject_id or not chapter_name:
        return jsonify({'error': 'Subject and chapter name are required'}), 400
    if not textbook_id:
        return jsonify({'error': 'Textbook selection is required'}), 400
    
    try:
        existing = db.chapters.find_one({
            'subject_id': subject_id,
            'chapter_name': chapter_name
        })
        if existing:
            return jsonify({'error': 'Chapter already exists for this subject'}), 400
        
        subject = db.subjects.find_one({'_id': ObjectId(subject_id)})
        grade_id = subject.get('grade_id') if subject else None
        
        result = db.chapters.insert_one({
            'subject_id': subject_id,
            'chapter_name': chapter_name,
            'chapter_number': chapter_number,
            'textbook_id': textbook_id,
            'reference_book': reference_book,
            'grade_id': grade_id,
            'created_at': datetime.now()
        })
        return jsonify({'success': True, 'id': str(result.inserted_id), 'message': 'Chapter created successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chapters/<chapter_id>', methods=['PUT'])
def update_chapter(chapter_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    subject_id = data.get('subject_id')
    chapter_name = data.get('chapter_name')
    chapter_number = data.get('chapter_number', 0)
    textbook_id = data.get('textbook_id')
    reference_book = data.get('reference_book', '')
    
    if not subject_id or not chapter_name:
        return jsonify({'error': 'Subject and chapter name are required'}), 400
    if not textbook_id:
        return jsonify({'error': 'Textbook selection is required'}), 400
    
    try:
        result = db.chapters.update_one(
            {'_id': ObjectId(chapter_id)},
            {'$set': {
                'subject_id': subject_id,
                'chapter_name': chapter_name,
                'chapter_number': chapter_number,
                'textbook_id': textbook_id,
                'reference_book': reference_book
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Chapter not found'}), 404
        return jsonify({'success': True, 'message': 'Chapter updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chapters/<chapter_id>', methods=['DELETE'])
def delete_chapter(chapter_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        count = db.simple_questions.count_documents({'chapter_id': chapter_id})
        if count > 0:
            return jsonify({'error': f'Cannot delete chapter because it has {count} question(s).'}), 400
        
        result = db.chapters.delete_one({'_id': ObjectId(chapter_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Chapter not found'}), 404
        return jsonify({'success': True, 'message': 'Chapter deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects/<subject_id>/chapters', methods=['GET'])
def get_subject_chapters(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        chapters = list(db.chapters.find({'subject_id': subject_id}).sort('chapter_number', 1))
        
        for c in chapters:
            c['id'] = str(c['_id'])
            c['subject_id'] = str(c['subject_id'])
            if c.get('textbook_id'):
                c['textbook_id'] = str(c['textbook_id'])
            del c['_id']
        
        return jsonify({'chapters': chapters})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# CURRICULAR GOALS API
# ============================================

@app.route('/api/cgs', methods=['GET'])
def get_cgs():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    chapter_id = request.args.get('chapter_id')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        query = {}
        
        if subject_id:
            query['subject_id'] = subject_id
        if chapter_id:
            query['chapter_id'] = chapter_id
        
        if user_role != 'admin' and subject_group:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                query['subject_id'] = {'$in': subject_ids}
        
        pipeline = [
            {'$match': query},
            {'$lookup': {
                'from': 'subjects',
                'localField': 'subject_id',
                'foreignField': '_id',
                'as': 'subject_info'
            }},
            {'$lookup': {
                'from': 'grades',
                'localField': 'grade_id',
                'foreignField': '_id',
                'as': 'grade_info'
            }},
            {'$lookup': {
                'from': 'chapters',
                'localField': 'chapter_id',
                'foreignField': '_id',
                'as': 'chapter_info'
            }},
            {'$addFields': {
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]},
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'chapter_name': {'$arrayElemAt': ['$chapter_info.chapter_name', 0]}
            }},
            {'$project': {'subject_info': 0, 'grade_info': 0, 'chapter_info': 0}},
            {'$sort': {'subject_id': 1}}
        ]
        
        cgs = list(db.curricular_goals.aggregate(pipeline))
        
        for cg in cgs:
            cg['id'] = str(cg['_id'])
            cg['subject_id'] = str(cg['subject_id'])
            if cg.get('chapter_id'):
                cg['chapter_id'] = str(cg['chapter_id'])
            del cg['_id']
        
        return jsonify({'cgs': cgs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cgs', methods=['POST'])
def create_cg():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    subject_id = data.get('subject_id')
    chapter_id = data.get('chapter_id')
    
    if not code or not subject_id:
        return jsonify({'error': 'Code and subject required'}), 400
    
    try:
        dup_query = {'cg_code': code, 'subject_id': subject_id}
        if chapter_id:
            dup_query['chapter_id'] = chapter_id
        else:
            dup_query['chapter_id'] = None
        
        if db.curricular_goals.find_one(dup_query):
            return jsonify({'error': f'Curricular Goal "{code}" already exists for this subject and chapter'}), 400
        
        result = db.curricular_goals.insert_one({
            'cg_code': code,
            'cg_description': description,
            'subject_id': subject_id,
            'chapter_id': chapter_id
        })
        return jsonify({'success': True, 'id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cgs/<cg_id>', methods=['PUT'])
def update_cg(cg_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    subject_id = data.get('subject_id')
    chapter_id = data.get('chapter_id')
    
    if not code or not subject_id:
        return jsonify({'error': 'Code and subject required'}), 400
    
    try:
        result = db.curricular_goals.update_one(
            {'_id': ObjectId(cg_id)},
            {'$set': {
                'cg_code': code,
                'cg_description': description,
                'subject_id': subject_id,
                'chapter_id': chapter_id
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'CG not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cgs/<cg_id>', methods=['DELETE'])
def delete_cg(cg_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        if db.competencies.count_documents({'cg_id': cg_id}) > 0:
            return jsonify({'error': 'Cannot delete CG with competencies'}), 400
        
        result = db.curricular_goals.delete_one({'_id': ObjectId(cg_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'CG not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# COMPETENCIES API
# ============================================

@app.route('/api/competencies', methods=['GET'])
def get_competencies_api():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        pipeline = [
            {'$lookup': {
                'from': 'curricular_goals',
                'localField': 'cg_id',
                'foreignField': '_id',
                'as': 'cg_info'
            }},
            {'$addFields': {
                'cg_code': {'$arrayElemAt': ['$cg_info.cg_code', 0]},
                'subject_id': {'$arrayElemAt': ['$cg_info.subject_id', 0]}
            }},
            {'$project': {'cg_info': 0}},
            {'$match': {'status': 1}}
        ]
        
        if user_role != 'admin' and subject_group:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                pipeline.insert(0, {'$match': {'subject_id': {'$in': subject_ids}}})
        
        comps = list(db.competencies.aggregate(pipeline))
        
        for c in comps:
            c['id'] = str(c['_id'])
            c['cg_id'] = str(c['cg_id'])
            del c['_id']
        
        return jsonify({'competencies': comps})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/competencies', methods=['POST'])
def create_competency():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    cg_id = data.get('cg_id')
    status = data.get('status', 1)
    
    if not code or not cg_id:
        return jsonify({'error': 'Code and CG required'}), 400
    
    try:
        result = db.competencies.insert_one({
            'comp_code': code,
            'comp_description': description,
            'cg_id': cg_id,
            'status': status
        })
        return jsonify({'success': True, 'id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/competencies/<comp_id>', methods=['PUT'])
def update_competency(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    cg_id = data.get('cg_id')
    status = data.get('status', 1)
    
    if not code or not cg_id:
        return jsonify({'error': 'Code and CG required'}), 400
    
    try:
        result = db.competencies.update_one(
            {'_id': ObjectId(comp_id)},
            {'$set': {
                'comp_code': code,
                'comp_description': description,
                'cg_id': cg_id,
                'status': status
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/competencies/<comp_id>', methods=['DELETE'])
def delete_competency(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        if db.simple_questions.count_documents({'comp_id': comp_id}) > 0:
            return jsonify({'error': 'Cannot delete competency with questions'}), 400
        
        result = db.competencies.delete_one({'_id': ObjectId(comp_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/competencies/<comp_id>/toggle', methods=['POST'])
def toggle_competency_status(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    status = data.get('status', 1)
    
    try:
        result = db.competencies.update_one(
            {'_id': ObjectId(comp_id)},
            {'$set': {'status': status}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# SUBJECT GROUPS API
# ============================================

@app.route('/api/subject-groups', methods=['GET'])
def get_subject_groups():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        query = {}
        
        if user_role != 'admin':
            if subject_group:
                query['group_code'] = subject_group
            else:
                return jsonify({'groups': []})
        
        pipeline = [
            {'$match': query},
            {'$lookup': {
                'from': 'grades',
                'localField': 'grade_id',
                'foreignField': '_id',
                'as': 'grade_info'
            }},
            {'$lookup': {
                'from': 'subjects',
                'localField': 'subject_id',
                'foreignField': '_id',
                'as': 'subject_info'
            }},
            {'$addFields': {
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]}
            }},
            {'$project': {'grade_info': 0, 'subject_info': 0}}
        ]
        
        groups = list(db.subject_groups.aggregate(pipeline))
        
        for g in groups:
            g['id'] = str(g['_id'])
            g['grade_id'] = str(g['grade_id'])
            g['subject_id'] = str(g['subject_id'])
            del g['_id']
        
        return jsonify({'groups': groups})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subject-groups', methods=['POST'])
def create_subject_group():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Only Administrators can create subject groups'}), 403
    
    data = request.json
    group_code = data.get('group_code')
    group_name = data.get('group_name')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
    
    if not all([group_code, group_name, grade_id, subject_id]):
        return jsonify({'error': 'All fields are required'}), 400
    
    try:
        existing = db.subject_groups.find_one({'group_code': group_code})
        if existing:
            return jsonify({'error': 'Group code already exists'}), 400
        
        result = db.subject_groups.insert_one({
            'group_code': group_code,
            'group_name': group_name,
            'grade_id': grade_id,
            'subject_id': subject_id,
            'created_at': datetime.now()
        })
        return jsonify({'success': True, 'id': str(result.inserted_id), 'message': 'Group created successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subject-groups/<group_id>', methods=['PUT'])
def update_subject_group(group_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Only Administrators can update subject groups'}), 403
    
    data = request.json
    group_code = data.get('group_code')
    group_name = data.get('group_name')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
    
    try:
        result = db.subject_groups.update_one(
            {'_id': ObjectId(group_id)},
            {'$set': {
                'group_code': group_code,
                'group_name': group_name,
                'grade_id': grade_id,
                'subject_id': subject_id
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify({'success': True, 'message': 'Group updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subject-groups/<group_id>', methods=['DELETE'])
def delete_subject_group(group_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Only Administrators can delete subject groups'}), 403
    
    try:
        group = db.subject_groups.find_one({'_id': ObjectId(group_id)})
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        
        user_count = db.users.count_documents({'subject_group': group.get('group_code')})
        if user_count > 0:
            return jsonify({'error': f'Cannot delete group because it has {user_count} user(s) assigned.'}), 400
        
        result = db.subject_groups.delete_one({'_id': ObjectId(group_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify({'success': True, 'message': 'Group deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# USERS API
# ============================================

@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        pipeline = [
            {'$lookup': {
                'from': 'subject_groups',
                'localField': 'subject_group',
                'foreignField': 'group_code',
                'as': 'group_info'
            }},
            {'$addFields': {
                'group_name': {'$arrayElemAt': ['$group_info.group_name', 0]},
                'group_code': {'$arrayElemAt': ['$group_info.group_code', 0]}
            }},
            {'$project': {'group_info': 0}},
            {'$sort': {'created_at': -1}}
        ]
        
        users = list(db.users.aggregate(pipeline))
        
        for u in users:
            u['id'] = str(u['_id'])
            if '_id' in u:
                del u['_id']
        
        return jsonify({'users': users})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'writer')
    subject_group = data.get('subject_group')
    group_role = data.get('group_role', 'member')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    if db.users.find_one({'username': username}):
        return jsonify({'error': 'Username already exists'}), 400
    
    try:
        hashed_password = generate_password_hash(password)
        
        # Set permissions based on role
        perm_re, perm_ra, perm_rc, perm_ap, perm_master = False, False, False, False, False
        
        if role == 'admin':
            perm_re = perm_ra = perm_rc = perm_ap = perm_master = True
        elif role == 'writer':
            perm_re = True
        elif role == 'master':
            perm_master = True
        elif role == 'reviewer':
            perm_rc = True
        elif role == 'approver':
            perm_ap = True
        elif role == 'builder':
            perm_ra = True
        
        result = db.users.insert_one({
            'username': username,
            'password': hashed_password,
            'role': role,
            'subject_group': subject_group,
            'group_role': group_role,
            'perm_re': perm_re,
            'perm_ra': perm_ra,
            'perm_rc': perm_rc,
            'perm_ap': perm_ap,
            'perm_master': perm_master,
            'created_at': datetime.now()
        })
        
        return jsonify({'success': True, 'message': 'User created successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    username = data.get('username')
    role = data.get('role')
    subject_group = data.get('subject_group')
    group_role = data.get('group_role', 'member')
    perm_re = data.get('perm_re', False)
    perm_ra = data.get('perm_ra', False)
    perm_rc = data.get('perm_rc', False)
    perm_ap = data.get('perm_ap', False)
    perm_master = data.get('perm_master', False)
    
    if not username or not role:
        return jsonify({'error': 'Username and role required'}), 400
    
    try:
        result = db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'username': username,
                'role': role,
                'subject_group': subject_group,
                'group_role': group_role,
                'perm_re': perm_re,
                'perm_ra': perm_ra,
                'perm_rc': perm_rc,
                'perm_ap': perm_ap,
                'perm_master': perm_master
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/reset-password/<user_id>', methods=['POST'])
def reset_user_password(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    new_password = data.get('password')
    if not new_password or len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    try:
        hashed_password = generate_password_hash(new_password)
        result = db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'password': hashed_password}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    if user_id == session.get('user_id'):
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    try:
        result = db.users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-permissions')
def get_user_permissions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({
        'username': session.get('user'),
        'permissions': {
            'RE': session.get('perm_re', False),
            'RA': session.get('perm_ra', False),
            'RC': session.get('perm_rc', False),
            'AP': session.get('perm_ap', False),
            'MASTER': session.get('perm_master', False)
        },
        'subject_group': session.get('subject_group'),
        'group_role': session.get('group_role'),
        'user_role': session.get('user_role'),
        'user_id': session.get('user_id')
    })

# ============================================
# REVIEWERS & APPROVERS
# ============================================

@app.route('/api/reviewers', methods=['GET'])
def get_reviewers():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    current_user_id = session.get('user_id')
    
    try:
        query = {'_id': {'$ne': ObjectId(current_user_id)}}
        
        if user_role == 'admin':
            query['$or'] = [
                {'perm_rc': 1},
                {'role': 'admin'},
                {'role': 'reviewer'}
            ]
        else:
            query['$and'] = [
                {'$or': [
                    {'perm_rc': 1},
                    {'role': 'admin'},
                    {'role': 'reviewer'}
                ]},
                {'subject_group': subject_group}
            ]
        
        users = list(db.users.find(query))
        
        for u in users:
            u['id'] = str(u['_id'])
            if '_id' in u:
                del u['_id']
        
        return jsonify({'reviewers': users})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/approvers', methods=['GET'])
def get_approvers():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    current_user_id = session.get('user_id')
    
    try:
        query = {'_id': {'$ne': ObjectId(current_user_id)}}
        
        if user_role == 'admin':
            query['$or'] = [
                {'perm_ap': 1},
                {'role': 'admin'},
                {'role': 'approver'}
            ]
        else:
            query['$and'] = [
                {'$or': [
                    {'perm_ap': 1},
                    {'role': 'admin'},
                    {'role': 'approver'}
                ]},
                {'subject_group': subject_group}
            ]
        
        users = list(db.users.find(query))
        
        for u in users:
            u['id'] = str(u['_id'])
            if '_id' in u:
                del u['_id']
        
        return jsonify({'approvers': users})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# QUESTION OPERATIONS
# ============================================

@app.route('/api/master-review-question/<question_id>', methods=['POST'])
def master_review_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_master = session.get('perm_master', False)
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and not perm_master:
        return jsonify({'error': 'Master permission required'}), 403
    
    data = request.json
    comment = data.get('comment', '') if data else ''
    reviewer_id = data.get('reviewer_id')
    reviewer_name = data.get('reviewer_name')
    
    try:
        question = db.simple_questions.find_one({'_id': ObjectId(question_id)})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        if reviewer_id:
            reviewer = db.users.find_one({'_id': ObjectId(reviewer_id)})
            if not reviewer:
                return jsonify({'error': 'Reviewer not found'}), 404
            reviewer_name = reviewer.get('username')
        
        if reviewer_name:
            master_comment = f"[ASSIGNED TO REVIEWER: {reviewer_name}] {comment}" if comment else f"[ASSIGNED TO REVIEWER: {reviewer_name}]"
        else:
            master_comment = comment if comment else 'Question assigned for review'
        
        result = db.simple_questions.update_one(
            {'_id': ObjectId(question_id)},
            {'$set': {
                'status': 'under_review',
                'master_reviewed_by': username,
                'master_reviewed_at': datetime.now(),
                'master_reviewed_comment': master_comment,
                'assigned_reviewer_id': reviewer_id,
                'assigned_reviewer_name': reviewer_name,
                'reviewed_by': None,
                'reviewed_comment': None,
                'reviewed_at': None,
                'approved_by': None,
                'approved_at': None
            }}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Question not found'}), 404
        
        return jsonify({'success': True, 'message': f'Question assigned to {reviewer_name or "reviewer"} for review'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/review-question/<question_id>', methods=['POST'])
def review_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_id = session.get('user_id')
    user_role = session.get('user_role', 'writer')
    perm_rc = session.get('perm_rc', False)
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and not perm_rc:
        return jsonify({'error': 'Reviewer (RC) permission required'}), 403
    
    data = request.json
    comment = data.get('comment', '') if data else ''
    approver_id = data.get('approver_id')
    approver_name = data.get('approver_name')
    
    try:
        question = db.simple_questions.find_one({'_id': ObjectId(question_id)})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        if approver_id:
            approver = db.users.find_one({'_id': ObjectId(approver_id)})
            if not approver:
                return jsonify({'error': 'Approver not found'}), 404
            approver_name = approver.get('username')
        
        if approver_name:
            reviewer_comment = f"[ASSIGNED TO APPROVER: {approver_name}] {comment}" if comment else f"[ASSIGNED TO APPROVER: {approver_name}]"
        else:
            reviewer_comment = comment if comment else 'Question passed for approval'
        
        result = db.simple_questions.update_one(
            {'_id': ObjectId(question_id)},
            {'$set': {
                'status': 'reviewed_completed',
                'reviewed_by': username,
                'reviewed_at': datetime.now(),
                'reviewed_comment': reviewer_comment,
                'assigned_approver_id': approver_id,
                'assigned_approver_name': approver_name,
                'approved_by': None,
                'approved_at': None
            }}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Question not found'}), 404
        
        return jsonify({'success': True, 'message': f'Question assigned to {approver_name or "approver"} for approval'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/review-questions')
def get_review_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    user_id = session.get('user_id')
    perm_re = session.get('perm_re', False)
    perm_ra = session.get('perm_ra', False)
    perm_rc = session.get('perm_rc', False)
    perm_ap = session.get('perm_ap', False)
    perm_master = session.get('perm_master', False)
    subject_group = session.get('subject_group')
    
    grade = request.args.get('grade', '')
    subject = request.args.get('subject', '')
    status = request.args.get('status', '')
    search = request.args.get('search', '')
    
    try:
        match = {}
        
        if user_role == 'admin':
            pass
        else:
            permission_filters = []
            
            if perm_re:
                permission_filters.append({
                    '$and': [
                        {'created_by': username},
                        {'status': {'$in': ['unassigned', 'rejected']}}
                    ]
                })
            
            if perm_master:
                permission_filters.append({'status': 'unassigned'})
            
            if perm_rc:
                permission_filters.append({
                    '$and': [
                        {'status': 'under_review'},
                        {'assigned_reviewer_id': user_id}
                    ]
                })
            
            if perm_ap:
                permission_filters.append({
                    '$and': [
                        {'status': 'reviewed_completed'},
                        {'assigned_approver_id': user_id}
                    ]
                })
            
            if perm_ra:
                permission_filters.append({'status': 'approved'})
            
            # Always include user's own questions
            permission_filters.append({'created_by': username})
            
            if permission_filters:
                match['$or'] = permission_filters
            else:
                match['_id'] = None
        
        if grade:
            match['grade_id'] = grade
        if subject:
            match['subject_id'] = subject
        if status:
            match['status'] = status
        if search:
            match['$or'] = [
                {'question_text': {'$regex': search, '$options': 'i'}},
                {'answer': {'$regex': search, '$options': 'i'}}
            ]
        
        # Build pipeline
        pipeline = [
            {'$match': match},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': '_id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': '_id', 'as': 'subject_info'}},
            {'$lookup': {'from': 'chapters', 'localField': 'chapter_id', 'foreignField': '_id', 'as': 'chapter_info'}},
            {'$lookup': {'from': 'competencies', 'localField': 'comp_id', 'foreignField': '_id', 'as': 'comp_info'}},
            {'$lookup': {'from': 'cognitive_domains', 'localField': 'domain_id', 'foreignField': '_id', 'as': 'domain_info'}},
            {'$lookup': {'from': 'knowledge_levels', 'localField': 'knowledge_level_id', 'foreignField': '_id', 'as': 'knowledge_info'}},
            {'$lookup': {'from': 'difficulty_levels', 'localField': 'difficulty_id', 'foreignField': '_id', 'as': 'difficulty_info'}},
            {'$addFields': {
                'grade': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'grade_id': {'$arrayElemAt': ['$grade_info._id', 0]},
                'subject': {'$arrayElemAt': ['$subject_info.subject_name', 0]},
                'subject_id': {'$arrayElemAt': ['$subject_info._id', 0]},
                'chapter': {'$arrayElemAt': ['$chapter_info.chapter_name', 0]},
                'chapter_id': {'$arrayElemAt': ['$chapter_info._id', 0]},
                'competency': {'$arrayElemAt': ['$comp_info.comp_code', 0]},
                'domain_name': {'$arrayElemAt': ['$domain_info.domain_name', 0]},
                'knowledge_level_name': {'$arrayElemAt': ['$knowledge_info.level_name', 0]},
                'difficulty_name': {'$arrayElemAt': ['$difficulty_info.level_name', 0]}
            }},
            {'$project': {
                'grade_info': 0, 'subject_info': 0, 'chapter_info': 0,
                'comp_info': 0, 'domain_info': 0, 'knowledge_info': 0, 'difficulty_info': 0
            }},
            {'$sort': {'created_at': -1}}
        ]
        
        questions = list(db.simple_questions.aggregate(pipeline))
        
        formatted_questions = []
        for q in questions:
            q['id'] = str(q['_id'])
            if '_id' in q:
                del q['_id']
            
            # Determine permissions
            can_edit = False
            can_review = False
            can_approve = False
            can_build = False
            can_delete = user_role == 'admin'
            can_rework = False
            can_master_review = False
            
            is_assigned_reviewer = q.get('assigned_reviewer_id') == user_id
            is_assigned_approver = q.get('assigned_approver_id') == user_id
            is_my_question = q.get('created_by') == username
            
            if perm_re and is_my_question:
                if q.get('status') in ['unassigned', 'rejected', 'rework']:
                    can_edit = True
                if q.get('status') == 'rejected':
                    can_rework = True
            
            if perm_master and q.get('status') == 'unassigned':
                can_master_review = True
            
            if perm_rc and q.get('status') == 'under_review' and is_assigned_reviewer:
                can_review = True
                can_rework = True
            
            if perm_ap and q.get('status') == 'reviewed_completed' and is_assigned_approver:
                can_approve = True
                can_rework = True
            
            if perm_ra and q.get('status') == 'approved':
                can_build = True
            
            if user_role == 'admin':
                can_edit = True
                can_review = True
                can_approve = True
                can_build = True
                can_delete = True
                can_rework = True
                can_master_review = True
            
            q['can_edit'] = can_edit
            q['can_review'] = can_review
            q['can_approve'] = can_approve
            q['can_build'] = can_build
            q['can_delete'] = can_delete
            q['can_rework'] = can_rework
            q['can_master_review'] = can_master_review
            q['is_assigned_to_me'] = is_assigned_reviewer or is_assigned_approver
            q['is_my_question'] = is_my_question
            
            formatted_questions.append(q)
        
        return jsonify({
            'questions': formatted_questions,
            'permissions': {
                'RE': perm_re,
                'RA': perm_ra,
                'RC': perm_rc,
                'AP': perm_ap,
                'MASTER': perm_master
            },
            'subject_group': subject_group,
            'user_role': user_role,
            'user_id': user_id
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/approve-question/<question_id>', methods=['POST'])
def approve_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_id = session.get('user_id')
    user_role = session.get('user_role', 'writer')
    perm_ap = session.get('perm_ap', False)
    
    if user_role != 'admin' and not perm_ap:
        return jsonify({'error': 'Approver (AP) permission required'}), 403
    
    data = request.json
    comment = data.get('comment', '') if data else ''
    
    try:
        question = db.simple_questions.find_one({'_id': ObjectId(question_id)})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        result = db.simple_questions.update_one(
            {'_id': ObjectId(question_id)},
            {'$set': {
                'status': 'approved',
                'reviewed_comment': comment,
                'approved_at': datetime.now(),
                'approved_by': username
            }}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Question not found'}), 404
        
        return jsonify({'success': True, 'message': 'Question approved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rework-question/<question_id>', methods=['POST'])
def rework_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_id = session.get('user_id')
    user_role = session.get('user_role', 'writer')
    perm_re = session.get('perm_re', False)
    perm_rc = session.get('perm_rc', False)
    perm_ap = session.get('perm_ap', False)
    perm_master = session.get('perm_master', False)
    
    data = request.json
    rework_comment = data.get('comment', '') if data else ''
    
    try:
        question = db.simple_questions.find_one({'_id': ObjectId(question_id)})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        comment_with_meta = f"[REWORK by {username} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {rework_comment}"
        
        result = db.simple_questions.update_one(
            {'_id': ObjectId(question_id)},
            {'$set': {
                'status': 'unassigned',
                'reviewed_by': None,
                'reviewed_at': None,
                'reviewed_comment': comment_with_meta,
                'master_reviewed_by': None,
                'master_reviewed_at': None,
                'master_reviewed_comment': None,
                'rejection_reason': None,
                'rejected_by': None,
                'rejected_at': None,
                'approved_by': None,
                'approved_at': None,
                'assigned_reviewer_id': None,
                'assigned_reviewer_name': None,
                'assigned_approver_id': None,
                'assigned_approver_name': None
            }}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Question not found'}), 404
        
        return jsonify({'success': True, 'message': 'Question moved to unassigned for rework'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/update-question/<question_id>', methods=['POST'])
def update_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_re = session.get('perm_re', False)
    
    data = request.json
    question_text = data.get('question_text')
    answer = data.get('answer')
    marks = data.get('marks', 1)
    duration_minutes = data.get('duration_minutes', 0)
    
    if not question_text:
        return jsonify({'error': 'Question text is required'}), 400
    
    if not has_actual_content(question_text):
        return jsonify({'error': 'Question text must have actual content'}), 400
    
    if not answer:
        return jsonify({'error': 'Answer is required'}), 400
    
    try:
        question = db.simple_questions.find_one({'_id': ObjectId(question_id)})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        # Get additional fields
        chapter_id = data.get('chapter_id')
        cg_id = data.get('cg_id')
        comp_id = data.get('comp_id')
        domain_id = data.get('domain_id')
        knowledge_level_id = data.get('knowledge_level_id')
        question_type_id = data.get('question_type_id')
        difficulty_id = data.get('difficulty_id')
        images = data.get('images', '[]')
        language = data.get('language', 'en')
        textbook_id = data.get('textbook_id')
        textbook_name = data.get('textbook_name')
        textbook_publisher = data.get('textbook_publisher')
        textbook_page = data.get('textbook_page')
        reference_book = data.get('reference_book')
        reference_page = data.get('reference_page')
        
        update_data = {
            'question_text': question_text,
            'answer': answer,
            'marks': marks,
            'duration_minutes': duration_minutes,
            'chapter_id': chapter_id,
            'cg_id': cg_id,
            'comp_id': comp_id,
            'domain_id': domain_id,
            'knowledge_level_id': knowledge_level_id,
            'question_type_id': question_type_id,
            'difficulty_id': difficulty_id,
            'images': images,
            'language': language,
            'textbook_id': textbook_id,
            'textbook_name': textbook_name,
            'textbook_publisher': textbook_publisher,
            'textbook_page': textbook_page,
            'reference_book': reference_book,
            'reference_page': reference_page,
            'updated_at': datetime.now()
        }
        
        if data.get('status') is not None:
            update_data['status'] = data.get('status')
        
        result = db.simple_questions.update_one(
            {'_id': ObjectId(question_id)},
            {'$set': update_data}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Question not found'}), 404
        
        return jsonify({'success': True, 'message': 'Question updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/builder-questions', methods=['GET'])
def get_builder_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role', 'writer')
    perm_ra = session.get('perm_ra', False)
    
    if user_role != 'admin' and not perm_ra:
        return jsonify({'error': 'Builder (RA) permission required'}), 403
    
    grade_id = request.args.get('grade_id')
    subject_id = request.args.get('subject_id')
    chapter_ids = request.args.get('chapter_ids')
    cg_ids = request.args.get('cg_ids')
    comp_ids = request.args.get('comp_ids')
    question_ids = request.args.get('question_ids')
    status = request.args.get('status', 'approved')
    count_only = request.args.get('count_only') == 'true'
    
    try:
        match = {}
        
        if status:
            match['status'] = status
        
        if question_ids:
            ids = [int(x.strip()) for x in question_ids.split(',') if x.strip().isdigit()]
            if ids:
                match['_id'] = {'$in': [ObjectId(str(id)) for id in ids]}
        
        if chapter_ids:
            ids = [int(x.strip()) for x in chapter_ids.split(',') if x.strip().isdigit()]
            if ids:
                match['chapter_id'] = {'$in': ids}
        
        if cg_ids:
            ids = [int(x.strip()) for x in cg_ids.split(',') if x.strip().isdigit()]
            if ids:
                match['cg_id'] = {'$in': ids}
        
        if comp_ids:
            ids = [int(x.strip()) for x in comp_ids.split(',') if x.strip().isdigit()]
            if ids:
                match['comp_id'] = {'$in': ids}
        
        if grade_id:
            match['grade_id'] = grade_id
        
        if subject_id:
            match['subject_id'] = subject_id
        
        if count_only:
            chapters = list(db.chapters.find({}))
            result = {}
            for ch in chapters:
                count = db.simple_questions.count_documents({
                    'chapter_id': str(ch['_id']),
                    'status': 'approved'
                })
                result[str(ch['_id'])] = count
            return jsonify({'chapter_counts': result})
        
        pipeline = [
            {'$match': match},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': '_id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': '_id', 'as': 'subject_info'}},
            {'$lookup': {'from': 'chapters', 'localField': 'chapter_id', 'foreignField': '_id', 'as': 'chapter_info'}},
            {'$addFields': {
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]},
                'chapter_name': {'$arrayElemAt': ['$chapter_info.chapter_name', 0]}
            }},
            {'$project': {'grade_info': 0, 'subject_info': 0, 'chapter_info': 0}},
            {'$sort': {'question_type_name': 1, 'difficulty_name': 1}},
            {'$limit': 500}
        ]
        
        questions = list(db.simple_questions.aggregate(pipeline))
        
        for q in questions:
            q['id'] = str(q['_id'])
            if '_id' in q:
                del q['_id']
        
        return jsonify({'questions': questions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# PAGE 1 & PAGE 2 DATA
# ============================================

@app.route('/api/page1-data')
def get_page1_data():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        # Get user's subject IDs
        user_subject_ids = []
        if user_role != 'admin' and subject_group:
            groups = db.subject_groups.find({'group_code': subject_group})
            user_subject_ids = [g['subject_id'] for g in groups]
        
        # Get grades
        if user_role == 'admin':
            grades = list(db.grades.find())
        else:
            if user_subject_ids:
                pipeline = [
                    {'$match': {'_id': {'$in': user_subject_ids}}},
                    {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': '_id', 'as': 'grade_info'}},
                    {'$addFields': {'grade': {'$arrayElemAt': ['$grade_info', 0]}}},
                    {'$group': {'_id': '$grade._id', 'grade_name': {'$first': '$grade.grade_name'}}}
                ]
                grades = list(db.subjects.aggregate(pipeline))
            else:
                grades = []
        
        # Get subjects
        if user_role == 'admin':
            subjects = list(db.subjects.find())
        else:
            if user_subject_ids:
                subjects = list(db.subjects.find({'_id': {'$in': user_subject_ids}}))
            else:
                subjects = []
        
        # Get CGs
        if user_role == 'admin':
            cgs = list(db.curricular_goals.find())
        else:
            if user_subject_ids:
                cgs = list(db.curricular_goals.find({'subject_id': {'$in': user_subject_ids}}))
            else:
                cgs = []
        
        # Get competencies
        if user_role == 'admin':
            competencies = list(db.competencies.find({'status': 1}))
        else:
            if user_subject_ids:
                pipeline = [
                    {'$lookup': {'from': 'curricular_goals', 'localField': 'cg_id', 'foreignField': '_id', 'as': 'cg_info'}},
                    {'$addFields': {'subject_id': {'$arrayElemAt': ['$cg_info.subject_id', 0]}}},
                    {'$match': {'subject_id': {'$in': user_subject_ids}, 'status': 1}},
                    {'$project': {'cg_info': 0}}
                ]
                competencies = list(db.competencies.aggregate(pipeline))
            else:
                competencies = []
        
        # Get question types
        question_types = list(db.question_types.find())
        
        # Get cognitive domains
        cognitive_domains = list(db.cognitive_domains.find())
        
        # Build response
        data = {
            'grades': grades,
            'subjects': subjects,
            'cgs': cgs,
            'competencies': competencies,
            'subjects_by_grade': {},
            'cgs_by_subject': {},
            'comps_by_cg': {},
            'question_types': question_types,
            'cognitive_domains': cognitive_domains
        }
        
        # Group subjects by grade
        for subject in subjects:
            grade_id = subject.get('grade_id')
            if grade_id:
                grade_key = str(grade_id)
                if grade_key not in data['subjects_by_grade']:
                    data['subjects_by_grade'][grade_key] = []
                data['subjects_by_grade'][grade_key].append(subject)
        
        # Group CGs by subject
        for cg in cgs:
            subject_id = cg.get('subject_id')
            if subject_id:
                subject_key = str(subject_id)
                if subject_key not in data['cgs_by_subject']:
                    data['cgs_by_subject'][subject_key] = []
                data['cgs_by_subject'][subject_key].append(cg)
        
        # Group competencies by CG
        for comp in competencies:
            cg_id = comp.get('cg_id')
            if cg_id:
                cg_key = str(cg_id)
                if cg_key not in data['comps_by_cg']:
                    data['comps_by_cg'][cg_key] = []
                data['comps_by_cg'][cg_key].append(comp)
        
        # Clean up ObjectIds
        for grade in data['grades']:
            grade['id'] = str(grade['_id'])
            if '_id' in grade:
                del grade['_id']
        
        for subject in data['subjects']:
            subject['id'] = str(subject['_id'])
            subject['grade_id'] = str(subject['grade_id'])
            if '_id' in subject:
                del subject['_id']
        
        for cg in data['cgs']:
            cg['id'] = str(cg['_id'])
            cg['subject_id'] = str(cg['subject_id'])
            if '_id' in cg:
                del cg['_id']
        
        for comp in data['competencies']:
            comp['id'] = str(comp['_id'])
            comp['cg_id'] = str(comp['cg_id'])
            if '_id' in comp:
                del comp['_id']
        
        for qt in data['question_types']:
            qt['id'] = str(qt['_id'])
            if '_id' in qt:
                del qt['_id']
        
        for cd in data['cognitive_domains']:
            cd['id'] = str(cd['_id'])
            if '_id' in cd:
                del cd['_id']
        
        return jsonify(data)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/page2-data')
def get_page2_data():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    
    try:
        comp_data = None
        if comp_id:
            comp = db.competencies.find_one({'_id': ObjectId(comp_id)})
            if comp:
                comp['id'] = str(comp['_id'])
                if '_id' in comp:
                    del comp['_id']
                comp_data = comp
        
        domains = list(db.cognitive_domains.find())
        for d in domains:
            d['id'] = str(d['_id'])
            if '_id' in d:
                del d['_id']
        
        if not domains:
            domains = [
                {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness of concepts and information'},
                {'id': 2, 'domain_name': 'Sensitivity', 'description': 'Sensitivity to applications and real-world connections'},
                {'id': 3, 'domain_name': 'Creativity', 'description': 'Creative thinking and problem solving'}
            ]
        
        question_types = list(db.question_types.find())
        for qt in question_types:
            qt['id'] = str(qt['_id'])
            if '_id' in qt:
                del qt['_id']
        
        difficulty_levels = list(db.difficulty_levels.find())
        for dl in difficulty_levels:
            dl['id'] = str(dl['_id'])
            if '_id' in dl:
                del dl['_id']
        
        if not difficulty_levels:
            difficulty_levels = [
                {'id': 1, 'level_name': 'Easy'},
                {'id': 2, 'level_name': 'Medium'},
                {'id': 3, 'level_name': 'Hard'}
            ]
        
        data = {
            'domains': domains,
            'question_types_by_domain': {},
            'difficulty_levels': difficulty_levels,
            'comp': comp_data
        }
        
        for qt in question_types:
            cognitive_id = qt.get('cognitive_id')
            if cognitive_id:
                cognitive_key = str(cognitive_id)
                if cognitive_key not in data['question_types_by_domain']:
                    data['question_types_by_domain'][cognitive_key] = []
                data['question_types_by_domain'][cognitive_key].append(qt)
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/knowledge-levels', methods=['GET'])
def get_knowledge_levels():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    domain_id = request.args.get('domain_id')
    difficulty_id = request.args.get('difficulty_id')
    
    try:
        query = {'is_active': True}
        
        if domain_id:
            query['domain_id'] = ObjectId(domain_id)
        elif difficulty_id:
            query['difficulty_id'] = ObjectId(difficulty_id)
        
        levels = list(db.knowledge_levels.find(query))
        
        for l in levels:
            l['id'] = str(l['_id'])
            if '_id' in l:
                del l['_id']
        
        return jsonify({'knowledge_levels': levels})
    except Exception as e:
        return jsonify({'knowledge_levels': []})

@app.route('/api/cognitive-domains', methods=['GET'])
def get_cognitive_domains():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        domains = list(db.cognitive_domains.find())
        for d in domains:
            d['id'] = str(d['_id'])
            if '_id' in d:
                del d['_id']
        
        return jsonify({'domains': domains})
    except Exception as e:
        return jsonify({'domains': []})

# ============================================
# QUESTION CRUD OPERATIONS
# ============================================

@app.route('/api/simple-questions')
def get_simple_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    username = session.get('user')
    subject_group = session.get('subject_group')
    user_role = session.get('user_role')
    
    try:
        match = {'created_by': username}
        
        if user_role != 'admin' and subject_group:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                match['subject_id'] = {'$in': subject_ids}
        
        if comp_id and comp_id != '0':
            match['comp_id'] = comp_id
        
        questions = list(db.simple_questions.find(match).sort('_id', -1).limit(50))
        
        for q in questions:
            q['id'] = str(q['_id'])
            if '_id' in q:
                del q['_id']
            if q.get('images'):
                try:
                    q['images'] = json.loads(q['images'])
                except:
                    q['images'] = []
            else:
                q['images'] = []
        
        return jsonify({'questions': questions})
    except Exception as e:
        return jsonify({'questions': []})

@app.route('/api/page2-questions')
def get_page2_questions():
    return get_simple_questions()

@app.route('/api/create-simple-question', methods=['POST'])
def create_simple_question():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    has_access = (
        session.get('perm_re', False) or 
        session.get('perm_rc', False) or 
        session.get('perm_ap', False) or 
        session.get('user_role') == 'admin'
    )
    
    if not has_access:
        return jsonify({'error': 'You do not have permission to create questions'}), 403
    
    data = request.json
    
    raw_question = data.get('question_text', '')
    raw_answer = data.get('answer', '')
    
    question_text = strip_html_tags(raw_question)
    answer = strip_html_tags(raw_answer)
    
    if not question_text:
        question_text = 'Question content'
    if not answer:
        answer = 'Answer content'
    
    marks = data.get('marks', 1)
    duration_minutes = data.get('duration_minutes', 0)
    comp_id = data.get('comp_id')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
    chapter_id = data.get('chapter_id')
    cg_id = data.get('cg_id')
    domain_id = data.get('domain_id')
    knowledge_level_id = data.get('knowledge_level_id')
    question_type_id = data.get('question_type_id')
    difficulty_id = data.get('difficulty_id')
    competency_code = data.get('competency_code')
    domain_name = data.get('domain_name')
    knowledge_level_name = data.get('knowledge_level_name')
    question_type_name = data.get('question_type_name')
    difficulty_name = data.get('difficulty_name')
    grade_name = data.get('grade_name')
    subject_name = data.get('subject_name')
    chapter_name = data.get('chapter_name')
    chapter_code = data.get('chapter_code')
    cg_code = data.get('cg_code')
    images = data.get('images', '[]')
    language = data.get('language', 'en')
    textbook_id = data.get('textbook_id')
    textbook_name = data.get('textbook_name')
    textbook_publisher = data.get('textbook_publisher')
    textbook_page = data.get('textbook_page')
    reference_book = data.get('reference_book')
    reference_page = data.get('reference_page')
    
    if not question_text:
        return jsonify({'error': 'Question text is required'}), 400
    
    if not answer:
        return jsonify({'error': 'Answer is required'}), 400
    
    subject_group = session.get('subject_group')
    user_role = session.get('user_role')
    
    if user_role != 'admin' and subject_group and subject_id:
        group = db.subject_groups.find_one({'group_code': subject_group, 'subject_id': subject_id})
        if not group:
            return jsonify({'error': 'Access denied to this subject'}), 403
    
    try:
        username = session.get('user', 'Unknown')
        current_time = datetime.now()
        
        # Handle ObjectId conversions for lookups
        if comp_id:
            comp = db.competencies.find_one({'_id': ObjectId(comp_id)})
            if not comp:
                comp_id = None
                competency_code = None
        
        # Build the question document
        question_doc = {
            'question_text': question_text,
            'answer': answer,
            'marks': marks,
            'duration_minutes': duration_minutes,
            'comp_id': comp_id,
            'created_by': username,
            'created_at': current_time,
            'grade_id': grade_id,
            'subject_id': subject_id,
            'chapter_id': chapter_id,
            'cg_id': cg_id,
            'domain_id': domain_id,
            'knowledge_level_id': knowledge_level_id,
            'question_type_id': question_type_id,
            'difficulty_id': difficulty_id,
            'competency_code': competency_code,
            'domain_name': domain_name,
            'knowledge_level_name': knowledge_level_name,
            'question_type_name': question_type_name,
            'difficulty_name': difficulty_name,
            'grade_name': grade_name,
            'subject_name': subject_name,
            'chapter_name': chapter_name,
            'chapter_code': chapter_code,
            'cg_code': cg_code,
            'images': images,
            'language': language,
            'status': 'unassigned',
            'textbook_id': textbook_id,
            'textbook_name': textbook_name,
            'textbook_publisher': textbook_publisher,
            'textbook_page': textbook_page,
            'reference_book': reference_book,
            'reference_page': reference_page
        }
        
        # Remove None values to avoid issues
        question_doc = {k: v for k, v in question_doc.items() if v is not None}
        
        result = db.simple_questions.insert_one(question_doc)
        
        return jsonify({
            'success': True, 
            'message': 'Question saved successfully',
            'id': str(result.inserted_id),
            'language': language,
            'status': 'unassigned'
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/create-question', methods=['POST'])
def create_question():
    return create_simple_question()

@app.route('/api/delete-question/<question_id>', methods=['DELETE'])
def delete_question(question_id):
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        result = db.simple_questions.delete_one({'_id': ObjectId(question_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Question not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# IMAGE UPLOADS
# ============================================

@app.route('/api/upload-question-images', methods=['POST'])
def upload_question_images():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if 'images' not in request.files:
        return jsonify({'error': 'No images provided'}), 400
    
    files = request.files.getlist('images')
    if len(files) == 0:
        return jsonify({'error': 'No images selected'}), 400
    if len(files) > 10:
        return jsonify({'error': 'Maximum 10 images allowed'}), 400
    
    uploaded_urls = []
    for file in files:
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            unique_id = str(uuid.uuid4())[:8]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{unique_id}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_url = f"/static/uploads/questions/{filename}"
            uploaded_urls.append(image_url)
        else:
            return jsonify({'error': f'Invalid file type: {file.filename}'}), 400
    
    return jsonify({'success': True, 'image_urls': uploaded_urls})

@app.route('/api/upload-answer-images', methods=['POST'])
def upload_answer_images():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'images' not in request.files:
        return jsonify({'error': 'No images provided'}), 400
    
    files = request.files.getlist('images')
    if len(files) == 0:
        return jsonify({'error': 'No images selected'}), 400
    if len(files) > 10:
        return jsonify({'error': 'Maximum 10 images allowed'}), 400
    
    uploaded_urls = []
    for file in files:
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            unique_id = str(uuid.uuid4())[:8]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"answer_{timestamp}_{unique_id}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_url = f"/static/uploads/questions/{filename}"
            uploaded_urls.append(image_url)
        else:
            return jsonify({'error': f'Invalid file type: {file.filename}'}), 400
    
    return jsonify({'success': True, 'image_urls': uploaded_urls})

@app.route('/static/uploads/questions/<path:filename>')
def serve_question_image(filename):
    if 'user' not in session:
        return redirect(url_for('dashboard_login'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    return jsonify({'error': 'Image not found'}), 404

# ============================================
# PAPER BLUEPRINTS
# ============================================

@app.route('/api/paper-blueprints', methods=['GET'])
def get_paper_blueprints():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        match = {}
        
        if user_role != 'admin':
            match['created_by'] = username
        
        if user_role != 'admin' and subject_group:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                match['subject_id'] = {'$in': subject_ids}
        
        pipeline = [
            {'$match': match},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': '_id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': '_id', 'as': 'subject_info'}},
            {'$addFields': {
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]}
            }},
            {'$project': {'grade_info': 0, 'subject_info': 0}},
            {'$sort': {'updated_at': -1, 'created_at': -1}}
        ]
        
        blueprints = list(db.paper_blueprints.aggregate(pipeline))
        
        for bp in blueprints:
            bp['id'] = str(bp['_id'])
            if '_id' in bp:
                del bp['_id']
            
            # Parse comma-separated fields
            if bp.get('cg_ids'):
                try:
                    bp['cg_ids'] = [int(x) for x in bp['cg_ids'].split(',') if x]
                except:
                    bp['cg_ids'] = []
            else:
                bp['cg_ids'] = []
            
            if bp.get('comp_ids'):
                try:
                    bp['comp_ids'] = [int(x) for x in bp['comp_ids'].split(',') if x]
                except:
                    bp['comp_ids'] = []
            else:
                bp['comp_ids'] = []
            
            if bp.get('question_ids'):
                try:
                    bp['question_ids'] = [int(x) for x in bp['question_ids'].split(',') if x]
                except:
                    bp['question_ids'] = []
            else:
                bp['question_ids'] = []
            
            # Parse config
            config_data = {}
            if bp.get('config'):
                try:
                    config_data = json.loads(bp['config'])
                except:
                    config_data = {}
            
            if bp.get('cognitive_config'):
                try:
                    cognitive_data = json.loads(bp['cognitive_config'])
                    if cognitive_data:
                        config_data['cognitive'] = cognitive_data
                except:
                    pass
            
            bp['config'] = config_data
        
        return jsonify({'blueprints': blueprints})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/paper-blueprints', methods=['POST'])
def create_paper_blueprint():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user')
    data = request.json
    
    name = data.get('name', 'Unnamed Blueprint')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
    cg_ids = data.get('cg_ids', [])
    comp_ids = data.get('comp_ids', [])
    question_ids = data.get('question_ids', [])
    config = data.get('config', {})
    status = data.get('status', 'draft')
    
    # Extract cognitive config separately
    cognitive_config = config.get('cognitive', {}) if config else {}
    
    # Remove cognitive from main config
    main_config = config.copy() if config else {}
    if 'cognitive' in main_config:
        del main_config['cognitive']
    
    try:
        result = db.paper_blueprints.insert_one({
            'name': name,
            'grade_id': grade_id,
            'subject_id': subject_id,
            'cg_ids': ','.join(map(str, cg_ids)) if cg_ids else None,
            'comp_ids': ','.join(map(str, comp_ids)) if comp_ids else None,
            'question_ids': ','.join(map(str, question_ids)) if question_ids else None,
            'config': json.dumps(main_config) if main_config else None,
            'cognitive_config': json.dumps(cognitive_config) if cognitive_config else None,
            'created_by': username,
            'created_at': datetime.now(),
            'updated_at': datetime.now(),
            'status': status
        })
        return jsonify({'success': True, 'id': str(result.inserted_id), 'message': 'Blueprint saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/paper-blueprints/<blueprint_id>', methods=['GET'])
def get_paper_blueprint(blueprint_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        pipeline = [
            {'$match': {'_id': ObjectId(blueprint_id)}},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': '_id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': '_id', 'as': 'subject_info'}},
            {'$addFields': {
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]}
            }},
            {'$project': {'grade_info': 0, 'subject_info': 0}}
        ]
        
        blueprint = list(db.paper_blueprints.aggregate(pipeline))
        
        if not blueprint:
            return jsonify({'error': 'Blueprint not found'}), 404
        
        bp = blueprint[0]
        bp['id'] = str(bp['_id'])
        if '_id' in bp:
            del bp['_id']
        
        # Parse fields
        if bp.get('cg_ids'):
            try:
                bp['cg_ids'] = [int(x) for x in bp['cg_ids'].split(',') if x]
            except:
                bp['cg_ids'] = []
        else:
            bp['cg_ids'] = []
        
        if bp.get('comp_ids'):
            try:
                bp['comp_ids'] = [int(x) for x in bp['comp_ids'].split(',') if x]
            except:
                bp['comp_ids'] = []
        else:
            bp['comp_ids'] = []
        
        if bp.get('question_ids'):
            try:
                bp['question_ids'] = [int(x) for x in bp['question_ids'].split(',') if x]
            except:
                bp['question_ids'] = []
        else:
            bp['question_ids'] = []
        
        # Parse config
        config_data = {}
        if bp.get('config'):
            try:
                config_data = json.loads(bp['config'])
            except:
                config_data = {}
        
        if bp.get('cognitive_config'):
            try:
                cognitive_data = json.loads(bp['cognitive_config'])
                if cognitive_data:
                    config_data['cognitive'] = cognitive_data
            except:
                pass
        
        bp['config'] = config_data
        
        return jsonify({'blueprint': bp})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/paper-blueprints/<blueprint_id>', methods=['PUT'])
def update_paper_blueprint(blueprint_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    
    name = data.get('name', 'Unnamed Blueprint')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
    cg_ids = data.get('cg_ids', [])
    comp_ids = data.get('comp_ids', [])
    question_ids = data.get('question_ids', [])
    config = data.get('config', {})
    status = data.get('status', 'draft')
    
    # Extract cognitive config separately
    cognitive_config = config.get('cognitive', {}) if config else {}
    
    # Remove cognitive from main config
    main_config = config.copy() if config else {}
    if 'cognitive' in main_config:
        del main_config['cognitive']
    
    try:
        result = db.paper_blueprints.update_one(
            {'_id': ObjectId(blueprint_id)},
            {'$set': {
                'name': name,
                'grade_id': grade_id,
                'subject_id': subject_id,
                'cg_ids': ','.join(map(str, cg_ids)) if cg_ids else None,
                'comp_ids': ','.join(map(str, comp_ids)) if comp_ids else None,
                'question_ids': ','.join(map(str, question_ids)) if question_ids else None,
                'config': json.dumps(main_config) if main_config else None,
                'cognitive_config': json.dumps(cognitive_config) if cognitive_config else None,
                'status': status,
                'updated_at': datetime.now()
            }}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Blueprint not found'}), 404
        
        return jsonify({'success': True, 'id': blueprint_id, 'message': 'Blueprint updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/paper-blueprints/<blueprint_id>', methods=['DELETE'])
def delete_paper_blueprint(blueprint_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        result = db.paper_blueprints.delete_one({'_id': ObjectId(blueprint_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Blueprint not found'}), 404
        return jsonify({'success': True, 'message': 'Blueprint deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# UTILITY ENDPOINTS
# ============================================

@app.route('/api/pending-count')
def get_pending_count():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    try:
        match = {'status': {'$in': ['unassigned', 'under_review']}}
        
        if user_role != 'admin' and subject_group:
            subject_ids = [row['subject_id'] for row in db.subject_groups.find({'group_code': subject_group})]
            if subject_ids:
                match['subject_id'] = {'$in': subject_ids}
        
        count = db.simple_questions.count_documents(match)
        return jsonify({'pending_count': count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug-session')
def debug_session():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({
        'session': dict(session),
        'subject_group': session.get('subject_group'),
        'permissions': {
            'RE': session.get('perm_re', False),
            'RA': session.get('perm_ra', False),
            'RC': session.get('perm_rc', False),
            'AP': session.get('perm_ap', False),
            'MASTER': session.get('perm_master', False)
        }
    })

@app.route('/api/debug-questions')
def debug_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Status counts
        pipeline = [
            {'$group': {
                '_id': '$status',
                'count': {'$sum': 1}
            }}
        ]
        status_counts = list(db.simple_questions.aggregate(pipeline))
        
        # Sample questions
        sample_questions = list(db.simple_questions.find(
            {'status': 'approved'}
        ).limit(10))
        
        for q in sample_questions:
            q['id'] = str(q['_id'])
            if '_id' in q:
                del q['_id']
        
        # Subjects with questions
        pipeline2 = [
            {'$match': {'status': 'approved'}},
            {'$group': {
                '_id': '$subject_id',
                'approved_count': {'$sum': 1}
            }},
            {'$lookup': {
                'from': 'subjects',
                'localField': '_id',
                'foreignField': '_id',
                'as': 'subject_info'
            }},
            {'$addFields': {
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]}
            }},
            {'$project': {'subject_info': 0}},
            {'$sort': {'approved_count': -1}}
        ]
        subjects_with_questions = list(db.simple_questions.aggregate(pipeline2))
        
        total_questions = db.simple_questions.count_documents({})
        
        return jsonify({
            'status_counts': status_counts,
            'sample_approved_questions': sample_questions,
            'subjects_with_questions': subjects_with_questions,
            'total_questions': total_questions
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/cgs')
def debug_cgs():
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        pipeline = [
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': '_id', 'as': 'subject_info'}},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': '_id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'chapters', 'localField': 'chapter_id', 'foreignField': '_id', 'as': 'chapter_info'}},
            {'$addFields': {
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]},
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'chapter_name': {'$arrayElemAt': ['$chapter_info.chapter_name', 0]}
            }},
            {'$project': {'subject_info': 0, 'grade_info': 0, 'chapter_info': 0}},
            {'$sort': {'_id': 1}}
        ]
        cgs = list(db.curricular_goals.aggregate(pipeline))
        
        comps = list(db.competencies.find())
        
        for cg in cgs:
            cg['id'] = str(cg['_id'])
            if '_id' in cg:
                del cg['_id']
        
        for comp in comps:
            comp['id'] = str(comp['_id'])
            if '_id' in comp:
                del comp['_id']
        
        return jsonify({
            'curricular_goals': cgs,
            'competencies': comps,
            'cg_count': len(cgs),
            'comp_count': len(comps)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=5000)