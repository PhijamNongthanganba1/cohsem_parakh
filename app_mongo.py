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
import ssl

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cohsem_it_secure_key_2026_change_this_in_production')

MONGO_URI = 'mongodb+srv://nongthanganbaphijam_db_user:BG2uPkyRu1L4ov30@cluster0.b5arftz.mongodb.net/?retryWrites=true&w=majority'

class MongoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

app.json_encoder = MongoJSONEncoder

try:
    client = pymongo.MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=30000,
        tlsAllowInvalidCertificates=True,
        tlsAllowInvalidHostnames=True
    )
    client.admin.command('ping')
    db = client['cohsemitms']
    
    app.config["MONGO_URI"] = MONGO_URI
    mongo = PyMongo(app)
    mongo.db = db
    mongo.cx = client
    
except Exception as e:
    sys.exit(1)

# --- File Upload Configuration ---
UPLOAD_FOLDER = 'static/uploads/questions'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_next_id(collection_name):
    """Get next numeric ID for a collection"""
    counter = db.counters.find_one_and_update(
        {'_id': collection_name},
        {'$inc': {'seq': 1}},
        upsert=True,
        return_document=True
    )
    return counter['seq']

def convert_doc(doc):
    """Convert MongoDB document to frontend-friendly format with numeric IDs"""
    if doc is None:
        return None
    if isinstance(doc, list):
        return [convert_doc(item) for item in doc]
    if isinstance(doc, dict):
        result = {}
        for key, value in doc.items():
            if key == '_id':
                result['_id'] = str(value)
            elif key == 'id':
                result[key] = value
            elif isinstance(value, ObjectId):
                result[key] = str(value)
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, list):
                result[key] = [convert_doc(item) if isinstance(item, dict) else item for item in value]
            elif isinstance(value, dict):
                result[key] = convert_doc(value)
            else:
                result[key] = value
        if 'id' not in result and 'id' in doc:
            result['id'] = doc['id']
        for key in ['id', 'grade_id', 'subject_id', 'cg_id', 'chapter_id', 'comp_id', 'textbook_id', 'domain_id', 'difficulty_id', 'knowledge_level_id', 'question_type_id']:
            if key in result and result[key] is not None:
                try:
                    result[key] = int(result[key])
                except:
                    pass
        return result
    return doc

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def clean_editor_html(html_content):
    """
    Remove <p> tags from Quill editor content while preserving the content inside.
    This ensures question and answer text don't have unnecessary paragraph tags.
    """
    if not html_content:
        return ''
    
    clean = re.sub(r'<p[^>]*>', '', html_content)
    clean = re.sub(r'</p>', '', clean)
    
    clean = re.sub(r'<div[^>]*>\s*</div>', '', clean)
    
    clean = re.sub(r'\n\s*\n', '\n', clean)
    clean = re.sub(r'^\s+|\s+$', '', clean)
    
    if clean == '' or clean == '<br>' or clean == '<br/>' or clean == '<br />':
        return ''
    
    return clean

def strip_html_tags(html_content):
    """Strip HTML tags from content for text-only display"""
    if not html_content:
        return ''
    clean = re.sub(r'<[^>]+>', ' ', html_content)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()

def has_actual_content(html_content):
    """Check if HTML content has actual content beyond empty tags"""
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

def init_db():
    try:
        if db.counters.count_documents({}) == 0:
            counters = [
                {'_id': 'grades', 'seq': 0},
                {'_id': 'subjects', 'seq': 0},
                {'_id': 'textbooks', 'seq': 0},
                {'_id': 'chapters', 'seq': 0},
                {'_id': 'curricular_goals', 'seq': 0},
                {'_id': 'competencies', 'seq': 0},
                {'_id': 'subject_groups', 'seq': 0},
                {'_id': 'users', 'seq': 0},
                {'_id': 'simple_questions', 'seq': 0},
                {'_id': 'paper_blueprints', 'seq': 0}
            ]
            db.counters.insert_many(counters)
        
        try:
            db.knowledge_levels.drop_index('id_1')
        except:
            pass
        
        db.grades.create_index('grade_name', unique=True)
        db.grades.create_index('id', unique=True)
        db.subjects.create_index('id', unique=True)
        db.subjects.create_index([('grade_id', 1), ('subject_name', 1)], unique=True)
        db.users.create_index('username', unique=True)
        db.subject_groups.create_index('group_code', unique=True)
        db.curricular_goals.create_index('id', unique=True)
        db.competencies.create_index('id', unique=True)
        db.competencies.create_index([('cg_id', 1), ('comp_code', 1)], unique=True)
        
        try:
            db.knowledge_levels.delete_many({'id': None})
            db.knowledge_levels.create_index('id', unique=True)
        except pymongo.errors.DuplicateKeyError as e:
            db.knowledge_levels.delete_many({'id': None})
            try:
                db.knowledge_levels.drop_index('id_1')
            except:
                pass
            db.knowledge_levels.create_index('id', unique=True)
        
        db.knowledge_levels.create_index([('domain_id', 1), ('level_name', 1)], unique=True)
        
        domains_data = [
            {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness of concepts and information'},
            {'id': 2, 'domain_name': 'Sensitivity', 'description': 'Sensitivity to applications and real-world connections'},
            {'id': 3, 'domain_name': 'Creativity', 'description': 'Creative thinking and problem solving'}
        ]
        
        for domain in domains_data:
            existing = db.cognitive_domains.find_one({'id': domain['id']})
            if not existing:
                db.cognitive_domains.insert_one(domain)
            else:
                if existing.get('domain_name') != domain['domain_name'] or existing.get('description') != domain['description']:
                    db.cognitive_domains.update_one(
                        {'id': domain['id']},
                        {'$set': {'domain_name': domain['domain_name'], 'description': domain['description']}}
                    )
        
        difficulties_data = [
            {'id': 1, 'level_name': 'Easy'},
            {'id': 2, 'level_name': 'Medium'},
            {'id': 3, 'level_name': 'Hard'}
        ]
        
        for diff in difficulties_data:
            existing = db.difficulty_levels.find_one({'id': diff['id']})
            if not existing:
                db.difficulty_levels.insert_one(diff)
        
        knowledge_data = [
            {'id': 1, 'level_name': 'Knowledge', 'description': 'Basic recall of information and facts', 'domain_id': 1, 'difficulty_id': 1, 'is_active': True},
            {'id': 2, 'level_name': 'Remembering', 'description': 'Retrieving knowledge from memory', 'domain_id': 1, 'difficulty_id': 1, 'is_active': True},
            {'id': 3, 'level_name': 'Understanding', 'description': 'Constructing meaning from information', 'domain_id': 1, 'difficulty_id': 1, 'is_active': True},
            {'id': 4, 'level_name': 'Comprehension', 'description': 'Grasping the meaning of information', 'domain_id': 1, 'difficulty_id': 2, 'is_active': True},
            
            {'id': 5, 'level_name': 'Application', 'description': 'Apply knowledge to new situations', 'domain_id': 2, 'difficulty_id': 2, 'is_active': True},
            {'id': 6, 'level_name': 'Analysis', 'description': 'Break down information into parts', 'domain_id': 2, 'difficulty_id': 2, 'is_active': True},
            {'id': 7, 'level_name': 'Synthesis', 'description': 'Combine elements to form a new whole', 'domain_id': 2, 'difficulty_id': 2, 'is_active': True},
            {'id': 8, 'level_name': 'Empathy', 'description': "Understanding others' perspectives and feelings", 'domain_id': 2, 'difficulty_id': 2, 'is_active': True},
            {'id': 9, 'level_name': 'Interpretation', 'description': 'Explaining and interpreting information', 'domain_id': 2, 'difficulty_id': 2, 'is_active': True},
            
            {'id': 10, 'level_name': 'Evaluation', 'description': 'Make judgments based on criteria and standards', 'domain_id': 3, 'difficulty_id': 3, 'is_active': True},
            {'id': 11, 'level_name': 'Creation', 'description': 'Generate new ideas and products', 'domain_id': 3, 'difficulty_id': 3, 'is_active': True},
            {'id': 12, 'level_name': 'Critical Thinking', 'description': 'Deep analysis and evaluation of information', 'domain_id': 3, 'difficulty_id': 3, 'is_active': True},
            {'id': 13, 'level_name': 'Innovation', 'description': 'Novel approaches and solutions to problems', 'domain_id': 3, 'difficulty_id': 3, 'is_active': True},
            {'id': 14, 'level_name': 'Design Thinking', 'description': 'Human-centered problem solving approach', 'domain_id': 3, 'difficulty_id': 3, 'is_active': True},
            {'id': 15, 'level_name': 'Reflection', 'description': 'Thoughtful consideration and self-assessment', 'domain_id': 3, 'difficulty_id': 3, 'is_active': True}
        ]
        
        for level in knowledge_data:
            existing = db.knowledge_levels.find_one({'id': level['id']})
            if not existing:
                db.knowledge_levels.insert_one(level)
            else:
                if existing.get('domain_id') != level['domain_id']:
                    db.knowledge_levels.update_one(
                        {'id': level['id']},
                        {'$set': {
                            'domain_id': level['domain_id'],
                            'difficulty_id': level['difficulty_id'],
                            'description': level['description'],
                            'is_active': level['is_active']
                        }}
                    )
        
        question_types_data = [
            {'id': 1, 'type_name': 'Objective', 'cognitive_id': 1, 'description': 'Objective type questions'},
            {'id': 2, 'type_name': 'Very Short Answer', 'cognitive_id': 1, 'description': 'Very short answer type questions'},
            {'id': 3, 'type_name': 'Short Answer', 'cognitive_id': 2, 'description': 'Short answer type questions'},
            {'id': 4, 'type_name': 'Long Answer', 'cognitive_id': 2, 'description': 'Long answer type questions'},
            {'id': 5, 'type_name': 'MCQ', 'cognitive_id': 3, 'description': 'Multiple choice questions'}
        ]
        
        for qt in question_types_data:
            existing = db.question_types.find_one({'id': qt['id']})
            if not existing:
                db.question_types.insert_one(qt)
        
        if db.users.count_documents({}) == 0:
            hashed_password = generate_password_hash("admin123")
            db.users.insert_one({
                'id': 1,
                'username': 'admin',
                'password': hashed_password,
                'role': 'admin',
                'subject_group': None,
                'group_role': 'member',
                'perm_re': True,
                'perm_ra': True,
                'perm_rc': True,
                'perm_ap': True,
                'perm_master': True,
                'created_at': datetime.now()
            })
            db.counters.update_one({'_id': 'users'}, {'$set': {'seq': 1}})
        
        fix_collection_ids('grades')
        fix_collection_ids('subjects')
        fix_collection_ids('textbooks')
        fix_collection_ids('chapters')
        fix_collection_ids('curricular_goals')
        fix_collection_ids('competencies')
        fix_collection_ids('subject_groups')
        fix_collection_ids('users')
        fix_collection_ids('simple_questions')
        fix_collection_ids('paper_blueprints')
        fix_collection_ids('knowledge_levels')
        
        fix_foreign_keys()
        
        fix_knowledge_levels_domain_id()
        
        verify_domain_data()
        
    except Exception as e:
        traceback.print_exc()

def fix_collection_ids(collection_name):
    """Add numeric 'id' field to documents if missing"""
    collection = db[collection_name]
    counter = db.counters.find_one({'_id': collection_name})
    if not counter:
        db.counters.insert_one({'_id': collection_name, 'seq': 0})
        counter = db.counters.find_one({'_id': collection_name})
    
    seq = counter.get('seq', 0)
    docs = collection.find({'id': {'$exists': False}})
    
    for doc in docs:
        seq += 1
        collection.update_one(
            {'_id': doc['_id']},
            {'$set': {'id': seq}}
        )
    
    if seq > 0:
        db.counters.update_one(
            {'_id': collection_name},
            {'$set': {'seq': seq}}
        )

def fix_foreign_keys():
    """Fix foreign keys to use numeric IDs"""
    subjects = db.subjects.find({})
    for subject in subjects:
        grade_id = subject.get('grade_id')
        if grade_id:
            if isinstance(grade_id, ObjectId):
                grade = db.grades.find_one({'_id': grade_id})
                if grade and 'id' in grade:
                    db.subjects.update_one(
                        {'_id': subject['_id']},
                        {'$set': {'grade_id': grade['id']}}
                    )
            elif isinstance(grade_id, str) and len(grade_id) == 24:
                grade = db.grades.find_one({'_id': ObjectId(grade_id)})
                if grade and 'id' in grade:
                    db.subjects.update_one(
                        {'_id': subject['_id']},
                        {'$set': {'grade_id': grade['id']}}
                    )
    
    cgs = db.curricular_goals.find({})
    for cg in cgs:
        subject_id = cg.get('subject_id')
        if subject_id and isinstance(subject_id, ObjectId):
            subject = db.subjects.find_one({'_id': subject_id})
            if subject and 'id' in subject:
                db.curricular_goals.update_one(
                    {'_id': cg['_id']},
                    {'$set': {'subject_id': subject['id']}}
                )
        
        chapter_id = cg.get('chapter_id')
        if chapter_id and isinstance(chapter_id, ObjectId):
            chapter = db.chapters.find_one({'_id': chapter_id})
            if chapter and 'id' in chapter:
                db.curricular_goals.update_one(
                    {'_id': cg['_id']},
                    {'$set': {'chapter_id': chapter['id']}}
                )
    
    comps = db.competencies.find({})
    for comp in comps:
        cg_id = comp.get('cg_id')
        if cg_id:
            if isinstance(cg_id, ObjectId):
                cg = db.curricular_goals.find_one({'_id': cg_id})
                if cg and 'id' in cg:
                    db.competencies.update_one(
                        {'_id': comp['_id']},
                        {'$set': {'cg_id': cg['id']}}
                    )
            elif isinstance(cg_id, str) and len(cg_id) == 24:
                cg = db.curricular_goals.find_one({'_id': ObjectId(cg_id)})
                if cg and 'id' in cg:
                    db.competencies.update_one(
                        {'_id': comp['_id']},
                        {'$set': {'cg_id': cg['id']}}
                    )

def fix_knowledge_levels_domain_id():
    """Fix knowledge_levels domain_id to be numeric and match cognitive_domains"""
    domains = list(db.cognitive_domains.find({}))
    domain_map = {str(d['_id']): d['id'] for d in domains}
    domain_name_map = {d['domain_name']: d['id'] for d in domains}
    
    levels = list(db.knowledge_levels.find({}))
    fixed_count = 0
    
    for level in levels:
        domain_id = level.get('domain_id')
        if domain_id:
            needs_update = False
            new_domain_id = None
            
            if isinstance(domain_id, ObjectId):
                domain_id_str = str(domain_id)
                if domain_id_str in domain_map:
                    new_domain_id = domain_map[domain_id_str]
                    needs_update = True
            elif isinstance(domain_id, str) and len(domain_id) == 24:
                if domain_id in domain_map:
                    new_domain_id = domain_map[domain_id]
                    needs_update = True
            elif isinstance(domain_id, str) and domain_id in domain_name_map:
                new_domain_id = domain_name_map[domain_id]
                needs_update = True
            elif isinstance(domain_id, int):
                domain_exists = db.cognitive_domains.find_one({'id': domain_id})
                if not domain_exists:
                    level_name = level.get('level_name', '').lower()
                    if 'knowledge' in level_name or 'remember' in level_name or 'understand' in level_name:
                        new_domain_id = 1
                        needs_update = True
                    elif 'application' in level_name or 'analysis' in level_name or 'synthesis' in level_name or 'empathy' in level_name or 'interpretation' in level_name:
                        new_domain_id = 2
                        needs_update = True
                    elif 'evaluation' in level_name or 'creation' in level_name or 'critical' in level_name or 'innovation' in level_name or 'design' in level_name or 'reflection' in level_name:
                        new_domain_id = 3
                        needs_update = True
            
            if needs_update and new_domain_id is not None:
                db.knowledge_levels.update_one(
                    {'_id': level['_id']},
                    {'$set': {'domain_id': new_domain_id}}
                )
                fixed_count += 1

def verify_domain_data():
    """Verify that cognitive domains and knowledge levels are correctly linked"""
    domains = list(db.cognitive_domains.find({}))
    
    levels = list(db.knowledge_levels.find({}))
    
    invalid_levels = []
    for level in levels:
        domain_id = level.get('domain_id')
        if not domain_id:
            invalid_levels.append(level)
        elif isinstance(domain_id, int):
            domain_exists = db.cognitive_domains.find_one({'id': domain_id})
            if not domain_exists:
                invalid_levels.append(level)

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
                session['user_id'] = user.get('id', str(user['_id']))
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
            next_id = get_next_id('users')
            db.users.insert_one({
                'id': next_id,
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
    
    return render_template('review.html', 
                         user=username, 
                         user_id=user_id,
                         user_role=user_role,
                         permissions=permissions)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('dashboard_login'))


@app.route('/api/dashboard-stats')
def dashboard_stats():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        all_subjects = list(db.subjects.find())
        subjects_dict = {s['id']: s for s in all_subjects}
        
        all_grades = list(db.grades.find())
        
        stats = {}
        
        for grade in all_grades:
            grade_id = grade['id']
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
            {'$sort': {'created_at': -1}},
            {'$limit': 10}
        ]
        recent = list(db.simple_questions.aggregate(pipeline_recent))
        recent = convert_doc(recent)
        stats['recent'] = recent
        
        stats = convert_doc(stats)
        return jsonify(stats)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/grades', methods=['GET'])
def get_grades():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        grades = list(db.grades.find({}).sort('id', 1))
        grades = convert_doc(grades)
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
        next_id = get_next_id('grades')
        db.grades.insert_one({
            'id': next_id,
            'grade_name': name
        })
        return jsonify({'success': True, 'id': next_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/grades/<int:grade_id>', methods=['PUT'])
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
            {'id': grade_id},
            {'$set': {'grade_name': name}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Grade not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/grades/<int:grade_id>', methods=['DELETE'])
def delete_grade(grade_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        if db.subjects.count_documents({'grade_id': grade_id}) > 0:
            return jsonify({'error': 'Cannot delete grade with subjects'}), 400
        
        result = db.grades.delete_one({'id': grade_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'Grade not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects', methods=['GET'])
def get_subjects():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        subjects = list(db.subjects.find({}).sort('id', 1))
        subjects = convert_doc(subjects)
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
    
    if not name:
        return jsonify({'error': 'Subject name is required'}), 400
    
    try:
        grade_id_int = None
        if isinstance(grade_id, int):
            grade_id_int = grade_id
        elif isinstance(grade_id, str):
            if grade_id.isdigit():
                grade_id_int = int(grade_id)
            elif len(grade_id) == 24:
                grade = db.grades.find_one({'_id': ObjectId(grade_id)})
                if grade and 'id' in grade:
                    grade_id_int = grade['id']
                else:
                    return jsonify({'error': 'Grade not found'}), 400
            else:
                return jsonify({'error': 'Invalid grade ID format'}), 400
        else:
            return jsonify({'error': 'Invalid grade ID'}), 400
        
        grade = db.grades.find_one({'id': grade_id_int})
        if not grade:
            return jsonify({'error': 'Grade not found'}), 400
        
        existing = db.subjects.find_one({
            'subject_name': name,
            'grade_id': grade_id_int
        })
        
        if existing:
            return jsonify({'error': f'Subject "{name}" already exists for this grade'}), 400
        
        next_id = get_next_id('subjects')
        db.subjects.insert_one({
            'id': next_id,
            'subject_name': name,
            'grade_id': grade_id_int
        })
        
        return jsonify({
            'success': True,
            'id': next_id,
            'grade_id': grade_id_int,
            'subject_name': name
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects/<int:subject_id>', methods=['PUT'])
def update_subject(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    name = data.get('name')
    grade_id = data.get('grade_id')
    
    if not name:
        return jsonify({'error': 'Subject name is required'}), 400
    
    try:
        grade_id_int = int(grade_id)
        
        result = db.subjects.update_one(
            {'id': subject_id},
            {'$set': {'subject_name': name, 'grade_id': grade_id_int}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Subject not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects/<int:subject_id>', methods=['DELETE'])
def delete_subject(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        if db.curricular_goals.count_documents({'subject_id': subject_id}) > 0:
            return jsonify({'error': 'Cannot delete subject with CGs'}), 400
        
        result = db.subjects.delete_one({'id': subject_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'Subject not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/page1-data')
def get_page1_data():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_role = session.get('user_role', 'writer')
        subject_group = session.get('subject_group')
        username = session.get('user', '')
        
        grades = list(db.grades.find({}))
        
        if subject_group and user_role != 'admin':
            group_subjects = list(db.subject_groups.find({'group_code': subject_group}))
            subject_ids = [s['subject_id'] for s in group_subjects]
            
            if subject_ids:
                subjects_in_group = list(db.subjects.find({'id': {'$in': subject_ids}}))
                grade_ids = list(set([s['grade_id'] for s in subjects_in_group]))
                grades = [g for g in grades if g['id'] in grade_ids]
            else:
                grades = []
        
        subjects = list(db.subjects.find({}))
        if subject_group and user_role != 'admin':
            group_subjects = list(db.subject_groups.find({'group_code': subject_group}))
            subject_ids = [s['subject_id'] for s in group_subjects]
            if subject_ids:
                subjects = [s for s in subjects if s['id'] in subject_ids]
        
        cgs = list(db.curricular_goals.find({}))
        if subject_group and user_role != 'admin':
            group_subjects = list(db.subject_groups.find({'group_code': subject_group}))
            subject_ids = [s['subject_id'] for s in group_subjects]
            if subject_ids:
                cgs = [cg for cg in cgs if cg['subject_id'] in subject_ids]
        
        competencies = list(db.competencies.find({}))
        if subject_group and user_role != 'admin':
            cg_ids = [cg['id'] for cg in cgs]
            if cg_ids:
                competencies = [comp for comp in competencies if comp['cg_id'] in cg_ids]
        
        question_types = list(db.question_types.find({}))
        cognitive_domains = list(db.cognitive_domains.find({}))
        
        grades = convert_doc(grades)
        subjects = convert_doc(subjects)
        cgs = convert_doc(cgs)
        competencies = convert_doc(competencies)
        question_types = convert_doc(question_types)
        cognitive_domains = convert_doc(cognitive_domains)
        
        subjects_by_grade = {}
        for s in subjects:
            grade_id = s.get('grade_id')
            if grade_id is not None:
                grade_key = str(grade_id)
                if grade_key not in subjects_by_grade:
                    subjects_by_grade[grade_key] = []
                subjects_by_grade[grade_key].append(s)
        
        cgs_by_subject = {}
        for cg in cgs:
            subject_id = cg.get('subject_id')
            if subject_id is not None:
                subject_key = str(subject_id)
                if subject_key not in cgs_by_subject:
                    cgs_by_subject[subject_key] = []
                cgs_by_subject[subject_key].append(cg)
        
        comps_by_cg = {}
        for comp in competencies:
            cg_id = comp.get('cg_id')
            if cg_id is not None:
                cg_key = str(cg_id)
                if cg_key not in comps_by_cg:
                    comps_by_cg[cg_key] = []
                comps_by_cg[cg_key].append(comp)
        
        data = {
            'grades': grades,
            'subjects': subjects,
            'cgs': cgs,
            'competencies': competencies,
            'subjects_by_grade': subjects_by_grade,
            'cgs_by_subject': cgs_by_subject,
            'comps_by_cg': comps_by_cg,
            'question_types': question_types,
            'cognitive_domains': cognitive_domains,
            'user_role': user_role,
            'subject_group': subject_group
        }
        
        return jsonify(data)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/page2-data')
def get_page2_data():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    user_role = session.get('user_role', 'writer')
    subject_group = session.get('subject_group')
    
    try:
        comp_data = None
        if comp_id:
            comp = db.competencies.find_one({'id': int(comp_id)})
            if comp:
                comp_data = convert_doc(comp)
        
        domains = list(db.cognitive_domains.find({}).sort('id', 1))
        domains = convert_doc(domains)
        
        if not domains:
            domains = [
                {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness of concepts and information'},
                {'id': 2, 'domain_name': 'Sensitivity', 'description': 'Sensitivity to applications and real-world connections'},
                {'id': 3, 'domain_name': 'Creativity', 'description': 'Creative thinking and problem solving'}
            ]
            for domain in domains:
                if not db.cognitive_domains.find_one({'id': domain['id']}):
                    db.cognitive_domains.insert_one(domain)
        
        question_types = list(db.question_types.find({}).sort('cognitive_id', 1))
        question_types = convert_doc(question_types)
        
        question_types_by_domain = {}
        for qt in question_types:
            cognitive_id = qt.get('cognitive_id')
            if cognitive_id:
                cognitive_key = str(cognitive_id)
                if cognitive_key not in question_types_by_domain:
                    question_types_by_domain[cognitive_key] = []
                question_types_by_domain[cognitive_key].append(qt)
        
        difficulty_levels = list(db.difficulty_levels.find({}).sort('id', 1))
        difficulty_levels = convert_doc(difficulty_levels)
        
        if not difficulty_levels:
            difficulty_levels = [
                {'id': 1, 'level_name': 'Easy'},
                {'id': 2, 'level_name': 'Medium'},
                {'id': 3, 'level_name': 'Hard'}
            ]
            for diff in difficulty_levels:
                if not db.difficulty_levels.find_one({'id': diff['id']}):
                    db.difficulty_levels.insert_one(diff)
        
        data = {
            'domains': domains,
            'question_types_by_domain': question_types_by_domain,
            'difficulty_levels': difficulty_levels,
            'comp': comp_data,
            'user_role': user_role,
            'subject_group': subject_group
        }
        
        return jsonify(data)
    except Exception as e:
        traceback.print_exc()
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
            try:
                domain_id_int = int(domain_id)
                query['domain_id'] = domain_id_int
            except:
                return jsonify({'knowledge_levels': []})
        
        if difficulty_id:
            try:
                query['difficulty_id'] = int(difficulty_id)
            except:
                pass
        
        levels = list(db.knowledge_levels.find(query).sort('id', 1))
        
        if not levels:
            default_mapping = [
                {'id': 1, 'level_name': 'Knowledge', 'domain_id': 1, 'domain_name': 'Awareness', 'description': ''},
                {'id': 2, 'level_name': 'Remembering', 'domain_id': 1, 'domain_name': 'Awareness', 'description': ''},
                {'id': 3, 'level_name': 'Understanding', 'domain_id': 1, 'domain_name': 'Awareness', 'description': ''},
                {'id': 4, 'level_name': 'Comprehension', 'domain_id': 1, 'domain_name': 'Awareness', 'description': ''},
                {'id': 5, 'level_name': 'Application', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': ''},
                {'id': 6, 'level_name': 'Analysis', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': ''},
                {'id': 7, 'level_name': 'Synthesis', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': ''},
                {'id': 8, 'level_name': 'Empathy', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': ""},
                {'id': 9, 'level_name': 'Interpretation', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': ''},
                {'id': 10, 'level_name': 'Evaluation', 'domain_id': 3, 'domain_name': 'Creativity', 'description': ''},
                {'id': 11, 'level_name': 'Creation', 'domain_id': 3, 'domain_name': 'Creativity', 'description': ''},
                {'id': 12, 'level_name': 'Critical Thinking', 'domain_id': 3, 'domain_name': 'Creativity', 'description': ''},
                {'id': 13, 'level_name': 'Innovation', 'domain_id': 3, 'domain_name': 'Creativity', 'description': ''},
                {'id': 14, 'level_name': 'Design Thinking', 'domain_id': 3, 'domain_name': 'Creativity', 'description': ''},
                {'id': 15, 'level_name': 'Reflection', 'domain_id': 3, 'domain_name': 'Creativity', 'description': ''}
            ]
            
            if domain_id:
                try:
                    domain_id_int = int(domain_id)
                    levels = [l for l in default_mapping if l.get('domain_id') == domain_id_int]
                except:
                    levels = []
            else:
                levels = default_mapping
            
            for level in levels:
                existing = db.knowledge_levels.find_one({'id': level['id']})
                if not existing:
                    level_copy = level.copy()
                    level_copy.pop('domain_name', None)
                    db.knowledge_levels.insert_one(level_copy)
        
        levels = convert_doc(levels)
        
        return jsonify({'knowledge_levels': levels})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'knowledge_levels': []})

@app.route('/api/cognitive-domains', methods=['GET'])
def get_cognitive_domains():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        domains = list(db.cognitive_domains.find({}).sort('id', 1))
        domains = convert_doc(domains)
        
        if not domains:
            default_domains = [
                {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness of concepts and information'},
                {'id': 2, 'domain_name': 'Sensitivity', 'description': 'Sensitivity to applications and real-world connections'},
                {'id': 3, 'domain_name': 'Creativity', 'description': 'Creative thinking and problem solving'}
            ]
            for domain in default_domains:
                if not db.cognitive_domains.find_one({'id': domain['id']}):
                    db.cognitive_domains.insert_one(domain)
            domains = list(db.cognitive_domains.find({}).sort('id', 1))
            domains = convert_doc(domains)
        
        return jsonify({'domains': domains})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'domains': []})

@app.route('/api/textbooks', methods=['GET'])
def get_textbooks():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    grade_id = request.args.get('grade_id')
    book_type = request.args.get('book_type')
    
    try:
        query = {}
        if subject_id:
            query['subject_id'] = int(subject_id)
        if grade_id:
            query['grade_id'] = int(grade_id)
        if book_type == 'textbook':
            query['is_reference'] = {'$ne': 1}
        elif book_type == 'reference':
            query['is_reference'] = 1
        
        textbooks = list(db.textbooks.find(query).sort('textbook_name', 1))
        textbooks = convert_doc(textbooks)
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
        subject_id_int = int(subject_id)
        grade_id_int = int(grade_id)
        
        existing = db.textbooks.find_one({'textbook_name': textbook_name, 'subject_id': subject_id_int})
        if existing:
            return jsonify({'error': 'Book already exists for this subject'}), 400
        
        next_id = get_next_id('textbooks')
        db.textbooks.insert_one({
            'id': next_id,
            'textbook_name': textbook_name,
            'subject_id': subject_id_int,
            'grade_id': grade_id_int,
            'publisher': publisher,
            'is_reference': is_reference,
            'created_at': datetime.now()
        })
        return jsonify({'success': True, 'id': next_id, 'message': 'Book saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/textbooks/<int:textbook_id>', methods=['PUT'])
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
        subject_id_int = int(subject_id)
        grade_id_int = int(grade_id)
        
        result = db.textbooks.update_one(
            {'id': textbook_id},
            {'$set': {
                'textbook_name': textbook_name,
                'subject_id': subject_id_int,
                'grade_id': grade_id_int,
                'publisher': publisher,
                'is_reference': is_reference
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Book not found'}), 404
        return jsonify({'success': True, 'message': 'Book updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/textbooks/<int:textbook_id>', methods=['DELETE'])
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
        
        result = db.textbooks.delete_one({'id': textbook_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'Book not found'}), 404
        return jsonify({'success': True, 'message': 'Book deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects/<int:subject_id>/textbooks', methods=['GET'])
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
        textbooks = convert_doc(textbooks)
        return jsonify({'textbooks': textbooks})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chapters', methods=['GET'])
def get_chapters():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    
    try:
        query = {}
        if subject_id:
            query['subject_id'] = int(subject_id)
        
        pipeline = [
            {'$match': query},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': 'id', 'as': 'subject_info'}},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': 'id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'textbooks', 'localField': 'textbook_id', 'foreignField': 'id', 'as': 'textbook_info'}},
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
        chapters = convert_doc(chapters)
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
        subject_id_int = int(subject_id)
        textbook_id_int = int(textbook_id)
        
        subject = db.subjects.find_one({'id': subject_id_int})
        grade_id = subject.get('grade_id') if subject else None
        
        existing = db.chapters.find_one({'subject_id': subject_id_int, 'chapter_name': chapter_name})
        if existing:
            return jsonify({'error': 'Chapter already exists for this subject'}), 400
        
        next_id = get_next_id('chapters')
        db.chapters.insert_one({
            'id': next_id,
            'subject_id': subject_id_int,
            'chapter_name': chapter_name,
            'chapter_number': chapter_number,
            'textbook_id': textbook_id_int,
            'reference_book': reference_book,
            'grade_id': grade_id,
            'created_at': datetime.now()
        })
        return jsonify({'success': True, 'id': next_id, 'message': 'Chapter created successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chapters/<int:chapter_id>', methods=['PUT'])
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
        subject_id_int = int(subject_id)
        textbook_id_int = int(textbook_id)
        
        result = db.chapters.update_one(
            {'id': chapter_id},
            {'$set': {
                'subject_id': subject_id_int,
                'chapter_name': chapter_name,
                'chapter_number': chapter_number,
                'textbook_id': textbook_id_int,
                'reference_book': reference_book
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Chapter not found'}), 404
        return jsonify({'success': True, 'message': 'Chapter updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chapters/<int:chapter_id>', methods=['DELETE'])
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
        
        result = db.chapters.delete_one({'id': chapter_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'Chapter not found'}), 404
        return jsonify({'success': True, 'message': 'Chapter deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects/<int:subject_id>/chapters', methods=['GET'])
def get_subject_chapters(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        chapters = list(db.chapters.find({'subject_id': subject_id}).sort('chapter_number', 1))
        chapters = convert_doc(chapters)
        return jsonify({'chapters': chapters})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cgs', methods=['GET'])
def get_cgs():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    chapter_id = request.args.get('chapter_id')
    
    try:
        query = {}
        if subject_id:
            query['subject_id'] = int(subject_id)
        if chapter_id:
            query['chapter_id'] = int(chapter_id)
        
        pipeline = [
            {'$match': query},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': 'id', 'as': 'subject_info'}},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': 'id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'chapters', 'localField': 'chapter_id', 'foreignField': 'id', 'as': 'chapter_info'}},
            {'$addFields': {
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]},
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'chapter_name': {'$arrayElemAt': ['$chapter_info.chapter_name', 0]}
            }},
            {'$project': {'subject_info': 0, 'grade_info': 0, 'chapter_info': 0}},
            {'$sort': {'subject_id': 1}}
        ]
        
        cgs = list(db.curricular_goals.aggregate(pipeline))
        cgs = convert_doc(cgs)
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
        subject_id_int = int(subject_id)
        chapter_id_int = int(chapter_id) if chapter_id else None
        
        dup_query = {'cg_code': code, 'subject_id': subject_id_int}
        if chapter_id_int:
            dup_query['chapter_id'] = chapter_id_int
        else:
            dup_query['chapter_id'] = None
        
        if db.curricular_goals.find_one(dup_query):
            return jsonify({'error': f'Curricular Goal "{code}" already exists'}), 400
        
        next_id = get_next_id('curricular_goals')
        db.curricular_goals.insert_one({
            'id': next_id,
            'cg_code': code,
            'cg_description': description,
            'subject_id': subject_id_int,
            'chapter_id': chapter_id_int
        })
        return jsonify({'success': True, 'id': next_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cgs/<int:cg_id>', methods=['PUT'])
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
        subject_id_int = int(subject_id)
        chapter_id_int = int(chapter_id) if chapter_id else None
        
        result = db.curricular_goals.update_one(
            {'id': cg_id},
            {'$set': {
                'cg_code': code,
                'cg_description': description,
                'subject_id': subject_id_int,
                'chapter_id': chapter_id_int
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'CG not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cgs/<int:cg_id>', methods=['DELETE'])
def delete_cg(cg_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        if db.competencies.count_documents({'cg_id': cg_id}) > 0:
            return jsonify({'error': 'Cannot delete CG with competencies'}), 400
        
        result = db.curricular_goals.delete_one({'id': cg_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'CG not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/competencies', methods=['GET'])
def get_competencies_api():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        pipeline = [
            {'$lookup': {'from': 'curricular_goals', 'localField': 'cg_id', 'foreignField': 'id', 'as': 'cg_info'}},
            {'$addFields': {
                'cg_code': {'$arrayElemAt': ['$cg_info.cg_code', 0]},
                'subject_id': {'$arrayElemAt': ['$cg_info.subject_id', 0]}
            }},
            {'$project': {'cg_info': 0}}
        ]
        
        comps = list(db.competencies.aggregate(pipeline))
        comps = convert_doc(comps)
        
        return jsonify({'competencies': comps})
    except Exception as e:
        traceback.print_exc()
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
        cg_id_int = int(cg_id)
        
        cg = db.curricular_goals.find_one({'id': cg_id_int})
        if not cg:
            return jsonify({'error': 'Curricular Goal not found'}), 400
        
        existing = db.competencies.find_one({
            'comp_code': code,
            'cg_id': cg_id_int
        })
        if existing:
            return jsonify({'error': f'Competency "{code}" already exists for this CG'}), 400
        
        next_id = get_next_id('competencies')
        db.competencies.insert_one({
            'id': next_id,
            'comp_code': code,
            'comp_description': description,
            'cg_id': cg_id_int,
            'status': status
        })
        
        return jsonify({'success': True, 'id': next_id})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/competencies/<int:comp_id>', methods=['PUT'])
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
        cg_id_int = int(cg_id)
        
        result = db.competencies.update_one(
            {'id': comp_id},
            {'$set': {
                'comp_code': code,
                'comp_description': description,
                'cg_id': cg_id_int,
                'status': status
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/competencies/<int:comp_id>', methods=['DELETE'])
def delete_competency(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        if db.simple_questions.count_documents({'comp_id': comp_id}) > 0:
            return jsonify({'error': 'Cannot delete competency with questions'}), 400
        
        result = db.competencies.delete_one({'id': comp_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/competencies/<int:comp_id>/toggle', methods=['POST'])
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
            {'id': comp_id},
            {'$set': {'status': status}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/subject-groups', methods=['GET'])
def get_subject_groups():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        pipeline = [
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': 'id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': 'id', 'as': 'subject_info'}},
            {'$addFields': {
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]}
            }},
            {'$project': {'grade_info': 0, 'subject_info': 0}}
        ]
        
        groups = list(db.subject_groups.aggregate(pipeline))
        groups = convert_doc(groups)
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
        grade_id_int = int(grade_id)
        subject_id_int = int(subject_id)
        
        existing = db.subject_groups.find_one({'group_code': group_code})
        if existing:
            return jsonify({'error': 'Group code already exists'}), 400
        
        next_id = get_next_id('subject_groups')
        db.subject_groups.insert_one({
            'id': next_id,
            'group_code': group_code,
            'group_name': group_name,
            'grade_id': grade_id_int,
            'subject_id': subject_id_int,
            'created_at': datetime.now()
        })
        return jsonify({'success': True, 'id': next_id, 'message': 'Group created successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subject-groups/<int:group_id>', methods=['PUT'])
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
        grade_id_int = int(grade_id)
        subject_id_int = int(subject_id)
        
        result = db.subject_groups.update_one(
            {'id': group_id},
            {'$set': {
                'group_code': group_code,
                'group_name': group_name,
                'grade_id': grade_id_int,
                'subject_id': subject_id_int
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify({'success': True, 'message': 'Group updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subject-groups/<int:group_id>', methods=['DELETE'])
def delete_subject_group(group_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Only Administrators can delete subject groups'}), 403
    
    try:
        group = db.subject_groups.find_one({'id': group_id})
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        
        user_count = db.users.count_documents({'subject_group': group.get('group_code')})
        if user_count > 0:
            return jsonify({'error': f'Cannot delete group because it has {user_count} user(s) assigned.'}), 400
        
        result = db.subject_groups.delete_one({'id': group_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify({'success': True, 'message': 'Group deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        pipeline = [
            {'$lookup': {'from': 'subject_groups', 'localField': 'subject_group', 'foreignField': 'group_code', 'as': 'group_info'}},
            {'$addFields': {'group_name': {'$arrayElemAt': ['$group_info.group_name', 0]}, 'group_code': {'$arrayElemAt': ['$group_info.group_code', 0]}}},
            {'$project': {'group_info': 0}},
            {'$sort': {'created_at': -1}}
        ]
        
        users = list(db.users.aggregate(pipeline))
        users = convert_doc(users)
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
        
        perm_re = perm_ra = perm_rc = perm_ap = perm_master = False
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
        
        next_id = get_next_id('users')
        db.users.insert_one({
            'id': next_id,
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

@app.route('/api/users/<int:user_id>', methods=['PUT'])
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
            {'id': user_id},
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

@app.route('/api/users/reset-password/<int:user_id>', methods=['POST'])
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
            {'id': user_id},
            {'$set': {'password': hashed_password}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    if user_id == session.get('user_id'):
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    try:
        result = db.users.delete_one({'id': user_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/reviewers', methods=['GET'])
def get_reviewers():
    """Get list of users with reviewer permissions"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    current_user_id = session.get('user_id')
    
    if user_role != 'admin' and not session.get('perm_master', False):
        return jsonify({'error': 'Access denied'}), 403    
    try:
        query = {
            '$or': [
                {'perm_rc': True},
                {'role': 'reviewer'},
                {'role': 'admin'}
            ]
        }
        
        if current_user_id:
            query['id'] = {'$ne': current_user_id}
        
        if user_role != 'admin' and subject_group:
            query['subject_group'] = subject_group
        
        reviewers = list(db.users.find(query).sort('username', 1))
        reviewers = convert_doc(reviewers)
        
        return jsonify({'reviewers': reviewers})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/approvers', methods=['GET'])
def get_approvers():
    """Get list of users with approver permissions"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    current_user_id = session.get('user_id')
    
    if user_role != 'admin' and not session.get('perm_master', False) and not session.get('perm_rc', False):
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        query = {
            '$or': [
                {'perm_ap': True},
                {'role': 'approver'},
                {'role': 'admin'}
            ]
        }
        
        if current_user_id:
            query['id'] = {'$ne': current_user_id}
        
        if user_role != 'admin' and subject_group:
            query['subject_group'] = subject_group
        
        approvers = list(db.users.find(query).sort('username', 1))
        approvers = convert_doc(approvers)
        
        return jsonify({'approvers': approvers})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/master-review-question/<int:question_id>', methods=['POST'])
def master_review_question(question_id):
    """Master assigns question to a reviewer"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_master = session.get('perm_master', False)
    subject_group = session.get('subject_group')
    user_id = session.get('user_id')
    
    if user_role != 'admin' and not perm_master:
        return jsonify({'error': 'Master permission required'}), 403
    
    data = request.json
    comment = data.get('comment', '') if data else ''
    reviewer_id = data.get('reviewer_id')
    reviewer_name = data.get('reviewer_name')
    
    if not reviewer_id:
        return jsonify({'error': 'Reviewer selection is required'}), 400
    
    try:
        question = db.simple_questions.find_one({'id': question_id})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        if user_role != 'admin' and subject_group:
            subject_check = db.subject_groups.find_one({
                'group_code': subject_group,
                'subject_id': question.get('subject_id')
            })
            if not subject_check:
                return jsonify({'error': 'Access denied to this question'}), 403
        
        reviewer = db.users.find_one({'id': int(reviewer_id)})
        if not reviewer:
            return jsonify({'error': 'Reviewer not found'}), 404
        
        has_reviewer_perm = (
            reviewer.get('perm_rc') == True or 
            reviewer.get('role') == 'reviewer' or 
            reviewer.get('role') == 'admin'
        )
        
        if not has_reviewer_perm:
            return jsonify({
                'error': f'Selected user "{reviewer.get("username")}" does not have reviewer permissions. Please select a user with Reviewer role or RC permission.'
            }), 400
        
        if user_role != 'admin' and subject_group:
            if reviewer.get('subject_group') != subject_group:
                return jsonify({'error': 'Reviewer must be in the same subject group'}), 400
        
        reviewer_name = reviewer.get('username', reviewer_name)
        
        master_comment = f"[ASSIGNED TO REVIEWER: {reviewer_name}] {comment}" if comment else f"[ASSIGNED TO REVIEWER: {reviewer_name}]"
        
        db.simple_questions.update_one(
            {'id': question_id},
            {'$set': {
                'status': 'under_review',
                'master_reviewed_by': username,
                'master_reviewed_at': datetime.now(),
                'master_reviewed_comment': master_comment,
                'assigned_reviewer_id': int(reviewer_id),
                'assigned_reviewer_name': reviewer_name,
                'reviewed_by': None,
                'reviewed_comment': None,
                'reviewed_at': None,
                'approved_by': None,
                'approved_at': None,
                'assigned_approver_id': None,
                'assigned_approver_name': None
            }}
        )
        
        return jsonify({'success': True, 'message': f'Question assigned to {reviewer_name} for review'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/review-question/<int:question_id>', methods=['POST'])
def review_question(question_id):
    """Reviewer assigns question to an approver"""
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
    
    if not approver_id:
        return jsonify({'error': 'Approver selection is required'}), 400
    
    try:
        question = db.simple_questions.find_one({'id': question_id})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        if user_role != 'admin' and question.get('assigned_reviewer_id') != user_id:
            return jsonify({'error': 'This question is not assigned to you'}), 403
        
        approver = db.users.find_one({'id': int(approver_id)})
        if not approver:
            return jsonify({'error': 'Approver not found'}), 404
        
        has_approver_perm = (
            approver.get('perm_ap') == True or 
            approver.get('role') == 'approver' or 
            approver.get('role') == 'admin'
        )
        
        if not has_approver_perm:
            return jsonify({
                'error': f'Selected user "{approver.get("username")}" does not have approver permissions. Please select a user with Approver role or AP permission.'
            }), 400
        
        if user_role != 'admin' and subject_group:
            if approver.get('subject_group') != subject_group:
                return jsonify({'error': 'Approver must be in the same subject group'}), 400
        
        approver_name = approver.get('username', approver_name)
        
        reviewer_comment = f"[ASSIGNED TO APPROVER: {approver_name}] {comment}" if comment else f"[ASSIGNED TO APPROVER: {approver_name}]"
        
        db.simple_questions.update_one(
            {'id': question_id},
            {'$set': {
                'status': 'reviewed_completed',
                'reviewed_by': username,
                'reviewed_at': datetime.now(),
                'reviewed_comment': reviewer_comment,
                'assigned_approver_id': int(approver_id),
                'assigned_approver_name': approver_name,
                'approved_by': None,
                'approved_at': None
            }}
        )
        
        return jsonify({'success': True, 'message': f'Question assigned to {approver_name} for approval'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/approve-question/<int:question_id>', methods=['POST'])
def approve_question(question_id):
    """Approver approves a question"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_id = session.get('user_id')
    user_role = session.get('user_role', 'writer')
    perm_ap = session.get('perm_ap', False)
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and not perm_ap:
        return jsonify({'error': 'Approver (AP) permission required'}), 403
    
    data = request.json
    comment = data.get('comment', '') if data else ''
    
    try:
        question = db.simple_questions.find_one({'id': question_id})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        if user_role != 'admin' and question.get('assigned_approver_id') != user_id:
            return jsonify({'error': 'This question is not assigned to you'}), 403
        
        db.simple_questions.update_one(
            {'id': question_id},
            {'$set': {
                'status': 'approved',
                'approved_by': username,
                'approved_at': datetime.now(),
                'reviewed_comment': comment if comment else question.get('reviewed_comment', '')
            }}
        )
        
        return jsonify({'success': True, 'message': 'Question approved successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/rework-question/<int:question_id>', methods=['POST'])
def rework_question(question_id):
    """Send a question back for rework"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_id = session.get('user_id')
    user_role = session.get('user_role', 'writer')
    subject_group = session.get('subject_group')
    perm_re = session.get('perm_re', False)
    perm_rc = session.get('perm_rc', False)
    perm_ap = session.get('perm_ap', False)
    perm_master = session.get('perm_master', False)
    
    data = request.json
    rework_comment = data.get('comment', '') if data else ''
    
    if not rework_comment:
        return jsonify({'error': 'Rework comment is required'}), 400
    
    try:
        question = db.simple_questions.find_one({'id': question_id})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        can_rework = False
        
        if user_role == 'admin':
            can_rework = True
        elif perm_master:
            can_rework = question.get('status') != 'approved'
        elif perm_rc:
            if question.get('assigned_reviewer_id') == user_id:
                can_rework = question.get('status') != 'approved'
        elif perm_ap:
            if question.get('assigned_approver_id') == user_id:
                can_rework = question.get('status') != 'approved'
        elif perm_re and question.get('created_by') == username:
            can_rework = question.get('status') in ['rejected', 'rework', 'unassigned']
        
        if not can_rework:
            return jsonify({'error': 'Not authorized to rework this question'}), 403
        
        comment_with_meta = f"[REWORK by {username} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {rework_comment}"
        
        db.simple_questions.update_one(
            {'id': question_id},
            {'$set': {
                'status': 'unassigned',
                'rejection_reason': comment_with_meta,
                'reviewed_by': None,
                'reviewed_at': None,
                'reviewed_comment': None,
                'master_reviewed_by': None,
                'master_reviewed_at': None,
                'master_reviewed_comment': None,
                'rejected_by': username,
                'rejected_at': datetime.now(),
                'approved_by': None,
                'approved_at': None,
                'assigned_reviewer_id': None,
                'assigned_reviewer_name': None,
                'assigned_approver_id': None,
                'assigned_approver_name': None
            }}
        )
        
        return jsonify({'success': True, 'message': 'Question sent back for rework'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/update-question/<int:question_id>', methods=['POST'])
def update_question(question_id):
    """Update question details (for writers to edit their own questions)"""
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
    if not answer:
        return jsonify({'error': 'Answer is required'}), 400
    
    try:
        question = db.simple_questions.find_one({'id': question_id})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        can_edit = False
        if user_role == 'admin':
            can_edit = True
        elif perm_re and question.get('created_by') == username:
            can_edit = question.get('status') in ['unassigned', 'rejected', 'rework']
        
        if not can_edit:
            return jsonify({'error': 'Not authorized to edit this question'}), 403
        
        question_text_cleaned = clean_editor_html(question_text)
        answer_cleaned = clean_editor_html(answer)
        
        db.simple_questions.update_one(
            {'id': question_id},
            {'$set': {
                'question_text': question_text_cleaned,
                'answer': answer_cleaned,
                'marks': marks,
                'duration_minutes': duration_minutes,
                'updated_at': datetime.now()
            }}
        )
        
        return jsonify({'success': True, 'message': 'Question updated successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/builder-questions', methods=['GET'])
def get_builder_questions():
    """Get questions for paper builder (approved questions only)"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role', 'writer')
    perm_ra = session.get('perm_ra', False)
    subject_group = session.get('subject_group')
    
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
        query = {'status': status}
        
        if grade_id:
            query['grade_id'] = int(grade_id)
        
        if subject_id:
            query['subject_id'] = int(subject_id)
        
        if chapter_ids:
            chapter_list = [int(x.strip()) for x in chapter_ids.split(',') if x.strip().isdigit()]
            if chapter_list:
                query['chapter_id'] = {'$in': chapter_list}
        
        if cg_ids:
            cg_list = [int(x.strip()) for x in cg_ids.split(',') if x.strip().isdigit()]
            if cg_list:
                query['cg_id'] = {'$in': cg_list}
        
        if comp_ids:
            comp_list = [int(x.strip()) for x in comp_ids.split(',') if x.strip().isdigit()]
            if comp_list:
                query['comp_id'] = {'$in': comp_list}
        
        if question_ids:
            id_list = [int(x.strip()) for x in question_ids.split(',') if x.strip().isdigit()]
            if id_list:
                query['id'] = {'$in': id_list}
        
        if user_role != 'admin' and subject_group:
            group_subjects = list(db.subject_groups.find({'group_code': subject_group}))
            subject_ids = [s['subject_id'] for s in group_subjects]
            if subject_ids:
                query['subject_id'] = {'$in': subject_ids}
            else:
                return jsonify({'questions': []})
        
        if count_only:
            count = db.simple_questions.count_documents(query)
            return jsonify({'count': count})
        
        questions = list(db.simple_questions.find(query).sort('question_type_name', 1).limit(500))
        questions = convert_doc(questions)
        
        for q in questions:
            if q.get('images'):
                try:
                    q['images'] = json.loads(q['images']) if isinstance(q['images'], str) else q['images']
                except:
                    q['images'] = []
            else:
                q['images'] = []
        
        return jsonify({'questions': questions})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/review-questions')
def get_review_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    user_id = session.get('user_id', 0)
    subject_group = session.get('subject_group')
    
    grade = request.args.get('grade', '')
    subject = request.args.get('subject', '')
    status = request.args.get('status', '')
    search = request.args.get('search', '')
    
    try:
        total_questions = db.simple_questions.count_documents({})
        
        match_conditions = []
        
        if user_role == 'admin':
            pass
        else:
            permission_filters = []
            
            if session.get('perm_re', False):
                permission_filters.append({
                    '$and': [
                        {'created_by': username},
                        {'status': {'$in': ['unassigned', 'rejected', None]}}
                    ]
                })
            
            if session.get('perm_master', False):
                permission_filters.append({'status': 'unassigned'})
            
            if session.get('perm_rc', False):
                permission_filters.append({
                    '$and': [
                        {'status': 'under_review'},
                        {'assigned_reviewer_id': user_id}
                    ]
                })
            
            if session.get('perm_ap', False):
                permission_filters.append({
                    '$and': [
                        {'status': 'reviewed_completed'},
                        {'assigned_approver_id': user_id}
                    ]
                })
            
            if session.get('perm_ra', False):
                permission_filters.append({'status': 'approved'})
            
            permission_filters.append({'created_by': username})
            
            if permission_filters:
                match_conditions.append({'$or': permission_filters})
            else:
                match_conditions.append({'_id': None})
        
        if user_role != 'admin' and subject_group:
            group_subjects = list(db.subject_groups.find({'group_code': subject_group}))
            subject_ids = [s['subject_id'] for s in group_subjects]
            if subject_ids:
                match_conditions.append({'subject_id': {'$in': subject_ids}})
            else:
                match_conditions.append({'_id': None})
        
        if grade:
            match_conditions.append({'grade_id': int(grade)})
        
        if subject:
            match_conditions.append({'subject_id': int(subject)})
        
        if status:
            match_conditions.append({'status': status})
        
        if search:
            match_conditions.append({
                '$or': [
                    {'question_text': {'$regex': search, '$options': 'i'}},
                    {'answer': {'$regex': search, '$options': 'i'}}
                ]
            })
        
        pipeline = []
        
        if match_conditions:
            pipeline.append({'$match': {'$and': match_conditions}})
        
        pipeline.extend([
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': 'id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': 'id', 'as': 'subject_info'}},
            {'$lookup': {'from': 'chapters', 'localField': 'chapter_id', 'foreignField': 'id', 'as': 'chapter_info'}},
            {'$lookup': {'from': 'competencies', 'localField': 'comp_id', 'foreignField': 'id', 'as': 'comp_info'}},
            {'$lookup': {'from': 'cognitive_domains', 'localField': 'domain_id', 'foreignField': 'id', 'as': 'domain_info'}},
            {'$lookup': {'from': 'knowledge_levels', 'localField': 'knowledge_level_id', 'foreignField': 'id', 'as': 'knowledge_info'}},
            {'$lookup': {'from': 'difficulty_levels', 'localField': 'difficulty_id', 'foreignField': 'id', 'as': 'difficulty_info'}},
            {'$addFields': {
                'grade': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'grade_id': {'$arrayElemAt': ['$grade_info.id', 0]},
                'subject': {'$arrayElemAt': ['$subject_info.subject_name', 0]},
                'subject_id': {'$arrayElemAt': ['$subject_info.id', 0]},
                'chapter': {'$arrayElemAt': ['$chapter_info.chapter_name', 0]},
                'chapter_id': {'$arrayElemAt': ['$chapter_info.id', 0]},
                'competency': {'$arrayElemAt': ['$comp_info.comp_code', 0]},
                'domain_name': {'$arrayElemAt': ['$domain_info.domain_name', 0]},
                'knowledge_level_name': {'$arrayElemAt': ['$knowledge_info.level_name', 0]},
                'difficulty_name': {'$arrayElemAt': ['$difficulty_info.level_name', 0]}
            }},
            {'$project': {
                'grade_info': 0, 'subject_info': 0, 'chapter_info': 0, 'comp_info': 0,
                'domain_info': 0, 'knowledge_info': 0, 'difficulty_info': 0
            }},
            {'$sort': {'created_at': -1}}
        ])
        
        questions = list(db.simple_questions.aggregate(pipeline))
        questions = convert_doc(questions)
        
        for q in questions:
            if q.get('images'):
                try:
                    q['images'] = json.loads(q['images']) if isinstance(q['images'], str) else q['images']
                except:
                    q['images'] = []
            else:
                q['images'] = []
            
            is_my = q.get('created_by') == username
            is_assigned_reviewer = q.get('assigned_reviewer_id') == user_id
            is_assigned_approver = q.get('assigned_approver_id') == user_id
            q_status = q.get('status', 'unassigned')
            
            q['can_edit'] = (user_role == 'admin') or (session.get('perm_re', False) and is_my and q_status in ['unassigned', 'rejected', 'rework'])
            q['can_master_review'] = (user_role == 'admin') or (session.get('perm_master', False) and q_status == 'unassigned')
            q['can_review'] = (user_role == 'admin') or (session.get('perm_rc', False) and is_assigned_reviewer and q_status == 'under_review')
            q['can_approve'] = (user_role == 'admin') or (session.get('perm_ap', False) and is_assigned_approver and q_status == 'reviewed_completed')
            q['can_delete'] = (user_role == 'admin')
            q['can_rework'] = (
                user_role == 'admin' or
                (session.get('perm_re', False) and is_my and q_status == 'rejected') or
                (session.get('perm_master', False) and q_status != 'approved') or
                (session.get('perm_rc', False) and is_assigned_reviewer and q_status != 'approved') or
                (session.get('perm_ap', False) and is_assigned_approver and q_status != 'approved')
            )
            q['is_my_question'] = is_my
            q['is_assigned_to_me'] = is_assigned_reviewer or is_assigned_approver
        
        return jsonify({
            'questions': questions,
            'permissions': {
                'RE': session.get('perm_re', False),
                'RA': session.get('perm_ra', False),
                'RC': session.get('perm_rc', False),
                'AP': session.get('perm_ap', False),
                'MASTER': session.get('perm_master', False)
            },
            'subject_group': subject_group,
            'user_role': user_role,
            'user_id': user_id,
            'total_count': total_questions
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500


@app.route('/api/simple-questions')
def get_simple_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    username = session.get('user')
    
    try:
        match = {'created_by': username}
        if comp_id and comp_id != '0':
            match['comp_id'] = int(comp_id)
        
        questions = list(db.simple_questions.find(match).sort('_id', -1).limit(50))
        questions = convert_doc(questions)
        
        for q in questions:
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
    
    question_text = data.get('question_text', '')
    answer = data.get('answer', '')
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
    images = data.get('images', '[]')
    language = data.get('language', 'en')
    textbook_id = data.get('textbook_id')
    textbook_name = data.get('textbook_name')
    textbook_publisher = data.get('textbook_publisher')
    textbook_page = data.get('textbook_page')
    reference_book = data.get('reference_book')
    reference_page = data.get('reference_page')
    
    question_text_cleaned = clean_editor_html(question_text)
    answer_cleaned = clean_editor_html(answer)
    
    if not question_text_cleaned:
        return jsonify({'error': 'Question text is required'}), 400
    
    if not answer_cleaned:
        return jsonify({'error': 'Answer is required'}), 400
    
    try:
        username = session.get('user', 'Unknown')
        current_time = datetime.now()
        
        comp_id_int = int(comp_id) if comp_id else None
        grade_id_int = int(grade_id) if grade_id else None
        subject_id_int = int(subject_id) if subject_id else None
        chapter_id_int = int(chapter_id) if chapter_id else None
        cg_id_int = int(cg_id) if cg_id else None
        domain_id_int = int(domain_id) if domain_id else None
        knowledge_level_id_int = int(knowledge_level_id) if knowledge_level_id else None
        question_type_id_int = int(question_type_id) if question_type_id else None
        difficulty_id_int = int(difficulty_id) if difficulty_id else None
        textbook_id_int = int(textbook_id) if textbook_id else None
        
        question_doc = {
            'question_text': question_text_cleaned,
            'answer': answer_cleaned,
            'marks': marks,
            'duration_minutes': duration_minutes,
            'comp_id': comp_id_int,
            'created_by': username,
            'created_at': current_time,
            'grade_id': grade_id_int,
            'subject_id': subject_id_int,
            'chapter_id': chapter_id_int,
            'cg_id': cg_id_int,
            'domain_id': domain_id_int,
            'knowledge_level_id': knowledge_level_id_int,
            'question_type_id': question_type_id_int,
            'difficulty_id': difficulty_id_int,
            'competency_code': competency_code,
            'domain_name': domain_name,
            'knowledge_level_name': knowledge_level_name,
            'question_type_name': question_type_name,
            'difficulty_name': difficulty_name,
            'grade_name': grade_name,
            'subject_name': subject_name,
            'chapter_name': chapter_name,
            'images': images,
            'language': language,
            'status': 'unassigned',
            'textbook_id': textbook_id_int,
            'textbook_name': textbook_name,
            'textbook_publisher': textbook_publisher,
            'textbook_page': textbook_page,
            'reference_book': reference_book,
            'reference_page': reference_page,
            'question_text_raw': question_text,
            'answer_raw': answer
        }
        
        question_doc = {k: v for k, v in question_doc.items() if v is not None}
        
        next_id = get_next_id('simple_questions')
        question_doc['id'] = next_id
        
        db.simple_questions.insert_one(question_doc)
        
        return jsonify({
            'success': True, 
            'message': 'Question saved successfully',
            'id': next_id,
            'language': language,
            'status': 'unassigned'
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/create-question', methods=['POST'])
def create_question():
    return create_simple_question()

@app.route('/api/delete-question/<int:question_id>', methods=['DELETE'])
def delete_question(question_id):
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        result = db.simple_questions.delete_one({'id': question_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'Question not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

@app.route('/api/paper-blueprints', methods=['GET'])
def get_paper_blueprints():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user')
    user_role = session.get('user_role')
    
    try:
        match = {}
        if user_role != 'admin':
            match['created_by'] = username
        
        pipeline = [
            {'$match': match},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': 'id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': 'id', 'as': 'subject_info'}},
            {'$addFields': {
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]}
            }},
            {'$project': {'grade_info': 0, 'subject_info': 0}},
            {'$sort': {'updated_at': -1, 'created_at': -1}}
        ]
        
        blueprints = list(db.paper_blueprints.aggregate(pipeline))
        blueprints = convert_doc(blueprints)
        
        for bp in blueprints:
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
    
    cognitive_config = config.get('cognitive', {}) if config else {}
    main_config = config.copy() if config else {}
    if 'cognitive' in main_config:
        del main_config['cognitive']
    
    try:
        next_id = get_next_id('paper_blueprints')
        db.paper_blueprints.insert_one({
            'id': next_id,
            'name': name,
            'grade_id': int(grade_id) if grade_id else None,
            'subject_id': int(subject_id) if subject_id else None,
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
        return jsonify({'success': True, 'id': next_id, 'message': 'Blueprint saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/paper-blueprints/<int:blueprint_id>', methods=['GET'])
def get_paper_blueprint(blueprint_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        pipeline = [
            {'$match': {'id': blueprint_id}},
            {'$lookup': {'from': 'grades', 'localField': 'grade_id', 'foreignField': 'id', 'as': 'grade_info'}},
            {'$lookup': {'from': 'subjects', 'localField': 'subject_id', 'foreignField': 'id', 'as': 'subject_info'}},
            {'$addFields': {
                'grade_name': {'$arrayElemAt': ['$grade_info.grade_name', 0]},
                'subject_name': {'$arrayElemAt': ['$subject_info.subject_name', 0]}
            }},
            {'$project': {'grade_info': 0, 'subject_info': 0}}
        ]
        
        blueprint = list(db.paper_blueprints.aggregate(pipeline))
        
        if not blueprint:
            return jsonify({'error': 'Blueprint not found'}), 404
        
        bp = convert_doc(blueprint[0])
        
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

@app.route('/api/paper-blueprints/<int:blueprint_id>', methods=['PUT'])
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
    
    cognitive_config = config.get('cognitive', {}) if config else {}
    main_config = config.copy() if config else {}
    if 'cognitive' in main_config:
        del main_config['cognitive']
    
    try:
        result = db.paper_blueprints.update_one(
            {'id': blueprint_id},
            {'$set': {
                'name': name,
                'grade_id': int(grade_id) if grade_id else None,
                'subject_id': int(subject_id) if subject_id else None,
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

@app.route('/api/paper-blueprints/<int:blueprint_id>', methods=['DELETE'])
def delete_paper_blueprint(blueprint_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        result = db.paper_blueprints.delete_one({'id': blueprint_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'Blueprint not found'}), 404
        return jsonify({'success': True, 'message': 'Blueprint deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/pending-count')
def get_pending_count():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        count = db.simple_questions.count_documents({'status': {'$in': ['unassigned', 'under_review']}})
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

@app.route('/api/debug/user/<username>')
def debug_user(username):
    """Debug endpoint to check user permissions"""
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = db.users.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': user.get('username'),
        'role': user.get('role'),
        'perm_rc': user.get('perm_rc'),
        'perm_ap': user.get('perm_ap'),
        'perm_master': user.get('perm_master'),
        'perm_re': user.get('perm_re'),
        'perm_ra': user.get('perm_ra'),
        'subject_group': user.get('subject_group'),
        'has_reviewer_perm': user.get('perm_rc') == True or user.get('role') in ['reviewer', 'admin'],
        'has_approver_perm': user.get('perm_ap') == True or user.get('role') in ['approver', 'admin'],
        'has_master_perm': user.get('perm_master') == True or user.get('role') in ['master', 'admin']
    })

@app.route('/api/question/<int:question_id>', methods=['GET'])
def get_question(question_id):
    """Get a single question for editing"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        question = db.simple_questions.find_one({'id': question_id})
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        username = session.get('user', '')
        user_role = session.get('user_role', 'writer')
        perm_re = session.get('perm_re', False)
        
        if user_role != 'admin' and not perm_re:
            return jsonify({'error': 'Permission denied'}), 403
        
        question = convert_doc(question)
        
        return jsonify({'question': question})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/questions')
def debug_questions():
    """Debug endpoint to check questions"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        total = db.simple_questions.count_documents({})
        status_counts = {}
        for status in ['approved', 'unassigned', 'under_review', 'reviewed_completed', 'rejected']:
            status_counts[status] = db.simple_questions.count_documents({'status': status})
        
        sample = list(db.simple_questions.find({}).limit(5))
        sample = convert_doc(sample)
        
        return jsonify({
            'total_questions': total,
            'status_counts': status_counts,
            'sample_questions': sample
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=5000)