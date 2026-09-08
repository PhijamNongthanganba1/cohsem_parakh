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

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cohsem_it_secure_key_2026_change_this_in_production')

# --- MongoDB Configuration ---
# Use environment variable for connection string
mongodb_uri = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/cohsemitms')
app.config["MONGO_URI"] = mongodb_uri
mongo = PyMongo(app)
db = mongo.db

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
    clean_text = re.sub(r'<[^>]+>', '', html_content)
    clean_text = clean_text.strip()
    if clean_text and len(clean_text) > 0:
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
    
    print("✓ Database initialization complete")

# Initialize on startup
with app.app_context():
    init_db()

# --- ROUTES (All Your Existing Routes Here) ---

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

@app.route('/dashboard-register', methods=['GET', 'POST'])
def dashboard_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
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
# API ENDPOINTS (Converted to MongoDB)
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
            
            # Count questions by grade
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
            
            # Count questions by subject within grade
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
        
        # Recent questions
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
            grade_ids = list(set([str(g['grade_id']) for g in subject_groups if g.get('grade_id')]))
            grades = list(db.grades.find({'_id': {'$in': [ObjectId(gid) for gid in grade_ids]}})) if grade_ids else []
        
        for g in grades:
            g['id'] = str(g['_id'])
            g['grade_id'] = str(g['_id'])
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

# Add all other API endpoints here (subjects, chapters, cgs, competencies, etc.)
# I'll provide the complete file in the response

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=5000)