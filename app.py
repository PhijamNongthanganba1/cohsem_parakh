from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import base64
import io
import traceback
import re
import os
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "cohsem_it_secure_key_2026_change_this_in_production"

UPLOAD_FOLDER = 'static/uploads/questions'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="nong@123",
        database="cohsemitms"
    )

def add_column_if_not_exists(cursor, table, column, definition):
    cursor.execute(f"SHOW COLUMNS FROM {table} LIKE '{column}'")
    exists = cursor.fetchone()
    if not exists:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        return True
    return False

def add_cognitive_config_column():
    """Add cognitive_config column to paper_blueprints if it doesn't exist"""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SHOW COLUMNS FROM paper_blueprints LIKE 'cognitive_config'")
        exists = cur.fetchone()
        if not exists:
            cur.execute("ALTER TABLE paper_blueprints ADD COLUMN cognitive_config TEXT")
            db.commit()
            
            return True
        else:
            
            return True
    except Exception as e:
        
        return False
    finally:
        cur.close()
        db.close()

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
    import re
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
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT subject_group FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if not user or not user['subject_group']:
            return []
        cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (user['subject_group'],))
        subjects = cur.fetchall()
        return [s['subject_id'] for s in subjects]
    except Exception as e:
        return []
    finally:
        cur.close()
        db.close()

def get_user_grades(username):
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT subject_group FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if not user or not user['subject_group']:
            return []
        cur.execute("SELECT grade_id FROM subject_groups WHERE group_code = %s", (user['subject_group'],))
        grades = cur.fetchall()
        return [g['grade_id'] for g in grades]
    except Exception as e:
        return []
    finally:
        cur.close()
        db.close()

def apply_subject_filter(query, user_role, subject_group, subject_id_column='subject_id'):
    if user_role == 'admin':
        return query, []
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            subject_ids = [row['subject_id'] for row in cur.fetchall()]
            if subject_ids:
                placeholders = ','.join(['%s'] * len(subject_ids))
                query += f" AND {subject_id_column} IN ({placeholders})"
                return query, subject_ids
        return query + " AND 1=0", []
    finally:
        cur.close()
        db.close()

def insert_default_reference_data(cur):
    domains_data = [
        ('Awareness', 'Basic awareness of concepts and information'),
        ('Sensitivity', 'Sensitivity to applications and real-world connections'),
        ('Creativity', 'Creative thinking and problem solving')
    ]
    
    for domain_name, description in domains_data:
        cur.execute("""
            INSERT IGNORE INTO cognitive_domains (domain_name, description) 
            VALUES (%s, %s)
        """, (domain_name, description))
    
    cur.execute("SELECT id, domain_name FROM cognitive_domains")
    domains = {row[1]: row[0] for row in cur.fetchall()}
    
    difficulty_data = ['Easy', 'Medium', 'Hard']
    for level in difficulty_data:
        cur.execute("INSERT IGNORE INTO difficulty_levels (level_name) VALUES (%s)", (level,))
    
    cur.execute("SELECT id, level_name FROM difficulty_levels")
    difficulties = {row[1]: row[0] for row in cur.fetchall()}
    
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
        cur.execute("""
            INSERT IGNORE INTO knowledge_levels 
            (level_name, description, is_active, domain_id, difficulty_id) 
            VALUES (%s, %s, %s, %s, %s)
        """, (level_name, description, True, domain_id, difficulty_id))
    
    question_types = [
        ('Objective', domains.get('Awareness')),
        ('Very Short Answer', domains.get('Awareness')),
        ('Short Answer', domains.get('Sensitivity')),
        ('Long Answer', domains.get('Sensitivity')),
        ('MCQ', domains.get('Creativity'))
    ]
    
    for type_name, cognitive_id in question_types:
        cur.execute("""
            INSERT IGNORE INTO question_types (type_name, cognitive_id) 
            VALUES (%s, %s)
        """, (type_name, cognitive_id))

def init_db():
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'writer',
                subject_group VARCHAR(50),
                group_role VARCHAR(50) DEFAULT 'member',
                perm_re BOOLEAN DEFAULT FALSE,
                perm_ra BOOLEAN DEFAULT FALSE,
                perm_rc BOOLEAN DEFAULT FALSE,
                perm_ap BOOLEAN DEFAULT FALSE,
                perm_master BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS grades (
                id INT PRIMARY KEY AUTO_INCREMENT,
                grade_name VARCHAR(50) NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS subjects (
                id INT PRIMARY KEY AUTO_INCREMENT,
                grade_id INT NOT NULL,
                subject_name VARCHAR(100) NOT NULL,
                FOREIGN KEY (grade_id) REFERENCES grades(id) ON DELETE CASCADE,
                INDEX idx_grade_id (grade_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS textbooks (
                id INT PRIMARY KEY AUTO_INCREMENT,
                textbook_name VARCHAR(200) NOT NULL,
                subject_id INT NOT NULL,
                grade_id INT NOT NULL,
                publisher VARCHAR(200),
                is_reference BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
                FOREIGN KEY (grade_id) REFERENCES grades(id) ON DELETE CASCADE,
                UNIQUE KEY unique_textbook_subject (subject_id, textbook_name),
                INDEX idx_subject_id (subject_id),
                INDEX idx_grade_id (grade_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS chapters (
                id INT PRIMARY KEY AUTO_INCREMENT,
                subject_id INT NOT NULL,
                chapter_name VARCHAR(200) NOT NULL,
                chapter_number INT DEFAULT 0,
                textbook_id INT,
                reference_book VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
                FOREIGN KEY (textbook_id) REFERENCES textbooks(id) ON DELETE SET NULL,
                UNIQUE KEY unique_chapter_subject (subject_id, chapter_name),
                INDEX idx_subject_id (subject_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cognitive_domains (
                id INT PRIMARY KEY AUTO_INCREMENT,
                domain_name VARCHAR(100) NOT NULL,
                description TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS difficulty_levels (
                id INT PRIMARY KEY AUTO_INCREMENT,
                level_name VARCHAR(50) NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_levels (
                id INT PRIMARY KEY AUTO_INCREMENT,
                level_name VARCHAR(100) NOT NULL,
                description TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                domain_id INT DEFAULT NULL,
                difficulty_id INT DEFAULT NULL,
                FOREIGN KEY (domain_id) REFERENCES cognitive_domains(id) ON DELETE SET NULL,
                FOREIGN KEY (difficulty_id) REFERENCES difficulty_levels(id) ON DELETE SET NULL,
                INDEX idx_domain_id (domain_id),
                INDEX idx_difficulty_id (difficulty_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS question_types (
                id INT PRIMARY KEY AUTO_INCREMENT,
                type_name VARCHAR(100) NOT NULL,
                cognitive_id INT,
                description TEXT,
                FOREIGN KEY (cognitive_id) REFERENCES cognitive_domains(id) ON DELETE SET NULL,
                INDEX idx_cognitive_id (cognitive_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS curricular_goals (
                id INT PRIMARY KEY AUTO_INCREMENT,
                cg_code VARCHAR(50),
                cg_description TEXT,
                subject_id INT,
                chapter_id INT DEFAULT NULL,
                FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
                FOREIGN KEY (chapter_id) REFERENCES chapters(id) ON DELETE CASCADE,
                INDEX idx_subject_id (subject_id),
                INDEX idx_chapter_id (chapter_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS competencies (
                id INT PRIMARY KEY AUTO_INCREMENT,
                comp_code VARCHAR(50),
                comp_description TEXT,
                cg_id INT,
                status BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (cg_id) REFERENCES curricular_goals(id) ON DELETE CASCADE,
                INDEX idx_cg_id (cg_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS subject_groups (
                id INT PRIMARY KEY AUTO_INCREMENT,
                group_code VARCHAR(50) NOT NULL UNIQUE,
                group_name VARCHAR(100) NOT NULL,
                grade_id INT NOT NULL,
                subject_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (grade_id) REFERENCES grades(id) ON DELETE CASCADE,
                FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
                INDEX idx_group_code (group_code),
                INDEX idx_grade_subject (grade_id, subject_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS simple_questions (
                id INT PRIMARY KEY AUTO_INCREMENT,
                question_text TEXT NOT NULL,
                answer TEXT NOT NULL,
                marks INT DEFAULT 1,
                duration_minutes INT DEFAULT 0,
                comp_id INT,
                created_by VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                grade_id INT,
                subject_id INT,
                chapter_id INT,
                cg_id INT,
                domain_id INT,
                knowledge_level_id INT,
                question_type_id INT,
                difficulty_id INT,
                competency_code VARCHAR(50),
                domain_name VARCHAR(100),
                knowledge_level_name VARCHAR(100),
                question_type_name VARCHAR(100),
                difficulty_name VARCHAR(50),
                grade_name VARCHAR(50),
                subject_name VARCHAR(100),
                chapter_name VARCHAR(200),
                chapter_code VARCHAR(50),
                cg_code VARCHAR(50),
                status VARCHAR(30) DEFAULT 'unassigned',
                rejection_reason TEXT,
                reviewed_by VARCHAR(100),
                reviewed_at TIMESTAMP NULL,
                reviewed_comment TEXT,
                approved_at TIMESTAMP NULL,
                approved_by VARCHAR(100),
                used_in_papers INT DEFAULT 0,
                images TEXT,
                rejected_by VARCHAR(100),
                rejected_at TIMESTAMP NULL,
                updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
                master_reviewed_by VARCHAR(100),
                master_reviewed_at TIMESTAMP NULL,
                master_reviewed_comment TEXT,
                language VARCHAR(20) DEFAULT 'en',
                textbook_id INT,
                textbook_name VARCHAR(200),
                textbook_publisher VARCHAR(200),
                textbook_page VARCHAR(50),
                reference_book VARCHAR(500),
                reference_page VARCHAR(50),
                assigned_reviewer_id INT NULL,
                assigned_reviewer_name VARCHAR(100) NULL,
                assigned_approver_id INT NULL,
                assigned_approver_name VARCHAR(100) NULL,
                FOREIGN KEY (comp_id) REFERENCES competencies(id) ON DELETE SET NULL,
                FOREIGN KEY (grade_id) REFERENCES grades(id) ON DELETE SET NULL,
                FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL,
                FOREIGN KEY (chapter_id) REFERENCES chapters(id) ON DELETE SET NULL,
                FOREIGN KEY (cg_id) REFERENCES curricular_goals(id) ON DELETE SET NULL,
                FOREIGN KEY (domain_id) REFERENCES cognitive_domains(id) ON DELETE SET NULL,
                FOREIGN KEY (knowledge_level_id) REFERENCES knowledge_levels(id) ON DELETE SET NULL,
                FOREIGN KEY (question_type_id) REFERENCES question_types(id) ON DELETE SET NULL,
                FOREIGN KEY (difficulty_id) REFERENCES difficulty_levels(id) ON DELETE SET NULL,
                FOREIGN KEY (textbook_id) REFERENCES textbooks(id) ON DELETE SET NULL,
                INDEX idx_comp_id (comp_id),
                INDEX idx_created_by (created_by),
                INDEX idx_created_at (created_at),
                INDEX idx_status (status),
                INDEX idx_subject_id (subject_id),
                INDEX idx_chapter_id (chapter_id),
                INDEX idx_cg_id (cg_id),
                INDEX idx_domain_id (domain_id),
                INDEX idx_knowledge_level_id (knowledge_level_id),
                INDEX idx_question_type_id (question_type_id),
                INDEX idx_difficulty_id (difficulty_id),
                INDEX idx_assigned_reviewer (assigned_reviewer_id),
                INDEX idx_assigned_approver (assigned_approver_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS paper_blueprints (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                grade_id INT,
                subject_id INT,
                cg_ids TEXT,
                comp_ids TEXT,
                question_ids TEXT,
                config TEXT,
                cognitive_config TEXT,
                created_by VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'draft',
                FOREIGN KEY (grade_id) REFERENCES grades(id) ON DELETE SET NULL,
                FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL,
                INDEX idx_grade_id (grade_id),
                INDEX idx_subject_id (subject_id),
                INDEX idx_created_by (created_by)
            )
        """)

        db.commit()

        add_cognitive_config_column()

        cur.execute("SELECT COUNT(*) as count FROM cognitive_domains")
        domain_count = cur.fetchone()[0]
        
        if domain_count == 0:
            insert_default_reference_data(cur)
            db.commit()

        cur.execute("SELECT COUNT(*) as count FROM users")
        user_count = cur.fetchone()[0]
        
        if user_count == 0:
            ADMIN_USERNAME = "admin"
            ADMIN_PASSWORD = "admin123"
            ADMIN_ROLE = "admin"
            
            hashed_password = generate_password_hash(ADMIN_PASSWORD)
            
            cur.execute("""
                INSERT INTO users (
                    username, password, role, 
                    perm_re, perm_ra, perm_rc, perm_ap, perm_master,
                    created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                ADMIN_USERNAME, 
                hashed_password, 
                ADMIN_ROLE,
                True, True, True, True, True,
                datetime.now()
            ))
            
            db.commit()

    except Exception as e:
        db.rollback()
        
    finally:
        cur.close()
        db.close()


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

        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        
        if not user:
            cur.close()
            db.close()
            flash('Invalid username or password!', 'error')
            return render_template('dashboard_login.html')
        
        if user and check_password_hash(user['password'], password):
            session['user'] = user['username']
            session['user_id'] = user['id']
            session['user_role'] = user.get('role', 'writer')
            session['subject_group'] = user.get('subject_group')
            session['group_role'] = user.get('group_role', 'member')
            session['perm_re'] = bool(user.get('perm_re', False))
            session['perm_ra'] = bool(user.get('perm_ra', False))
            session['perm_rc'] = bool(user.get('perm_rc', False))
            session['perm_ap'] = bool(user.get('perm_ap', False))
            session['perm_master'] = bool(user.get('perm_master', False))
            
            cur.close()
            db.close()
            
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))

        cur.close()
        db.close()
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
        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            cur.close()
            db.close()
            flash('Username already exists!', 'error')
            return render_template('dashboard_register.html')
        hashed_password = generate_password_hash(password)
        try:
            cur.execute("""
                INSERT INTO users (username, password, role, perm_re, created_at) 
                VALUES (%s, %s, %s, %s, %s)
            """, (username, hashed_password, 'writer', True, datetime.now()))
            db.commit()
            cur.close()
            db.close()
            flash('Account created successfully! You can now login.', 'success')
            return redirect(url_for('dashboard_login'))
        except Exception as e:
            db.rollback()
            cur.close()
            db.close()
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


@app.route('/api/dashboard-stats')
def dashboard_stats():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SHOW TABLES LIKE 'simple_questions'")
        if not cur.fetchone():
            return jsonify({})
        
        cur.execute("SELECT id, subject_name, grade_id FROM subjects")
        all_subjects = cur.fetchall()
        subjects_dict = {s['id']: s for s in all_subjects}
        
        cur.execute("SELECT id, grade_name FROM grades ORDER BY id")
        all_grades = cur.fetchall()
        
        stats = {}
        
        for grade in all_grades:
            grade_id = grade['id']
            grade_name = grade['grade_name']
            
            cur.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                    SUM(CASE WHEN status = 'unassigned' THEN 1 ELSE 0 END) as unassigned,
                    SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                    SUM(CASE WHEN status = 'reviewed_completed' THEN 1 ELSE 0 END) as reviewed_completed,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                    SUM(CASE WHEN status = 'master_reviewed' THEN 1 ELSE 0 END) as master_reviewed
                FROM simple_questions 
                WHERE grade_id = %s
            """, (grade_id,))
            grade_stats = cur.fetchone()
            
            cur.execute("""
                SELECT 
                    subject_id,
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                    SUM(CASE WHEN status = 'unassigned' THEN 1 ELSE 0 END) as unassigned,
                    SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                    SUM(CASE WHEN status = 'reviewed_completed' THEN 1 ELSE 0 END) as reviewed_completed,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                    SUM(CASE WHEN status = 'master_reviewed' THEN 1 ELSE 0 END) as master_reviewed
                FROM simple_questions 
                WHERE grade_id = %s
                GROUP BY subject_id
            """, (grade_id,))
            subject_stats = cur.fetchall()
            
            subjects_dict_for_grade = {}
            for subj in subject_stats:
                subject_id = subj['subject_id']
                if subject_id and subject_id in subjects_dict:
                    subjects_dict_for_grade[str(subject_id)] = {
                        'total': subj['total'] or 0,
                        'approved': subj['approved'] or 0,
                        'unassigned': subj['unassigned'] or 0,
                        'under_review': subj['under_review'] or 0,
                        'reviewed_completed': subj['reviewed_completed'] or 0,
                        'rejected': subj['rejected'] or 0,
                        'master_reviewed': subj['master_reviewed'] or 0,
                        'subject_name': subjects_dict[subject_id]['subject_name']
                    }
            
            stats[f'grade_{grade_id}'] = {
                'total': grade_stats['total'] or 0,
                'approved': grade_stats['approved'] or 0,
                'unassigned': grade_stats['unassigned'] or 0,
                'under_review': grade_stats['under_review'] or 0,
                'reviewed_completed': grade_stats['reviewed_completed'] or 0,
                'rejected': grade_stats['rejected'] or 0,
                'master_reviewed': grade_stats['master_reviewed'] or 0,
                'subjects': subjects_dict_for_grade,
                'grade_name': grade_name,
                'grade_id': grade_id
            }
        
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
            
            if user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT sq.id, sq.question_text, 
                           COALESCE(sq.status, 'unassigned') as status,
                           sq.created_by, sq.created_at,
                           g.grade_name, sub.subject_name,
                           ch.chapter_name,
                           sq.reviewed_by, sq.reviewed_at
                    FROM simple_questions sq
                    LEFT JOIN grades g ON sq.grade_id = g.id
                    LEFT JOIN subjects sub ON sq.subject_id = sub.id
                    LEFT JOIN chapters ch ON sq.chapter_id = ch.id
                    WHERE sq.subject_id IN ({placeholders})
                    ORDER BY sq.created_at DESC
                    LIMIT 10
                """, tuple(user_subject_ids))
            else:
                cur.execute("""
                    SELECT sq.id, sq.question_text, 
                           COALESCE(sq.status, 'unassigned') as status,
                           sq.created_by, sq.created_at,
                           g.grade_name, sub.subject_name,
                           ch.chapter_name,
                           sq.reviewed_by, sq.reviewed_at
                    FROM simple_questions sq
                    LEFT JOIN grades g ON sq.grade_id = g.id
                    LEFT JOIN subjects sub ON sq.subject_id = sub.id
                    LEFT JOIN chapters ch ON sq.chapter_id = ch.id
                    ORDER BY sq.created_at DESC
                    LIMIT 10                """)
        else:
            cur.execute("""
                SELECT sq.id, sq.question_text, 
                       COALESCE(sq.status, 'unassigned') as status,
                       sq.created_by, sq.created_at,
                       g.grade_name, sub.subject_name,
                       ch.chapter_name,
                       sq.reviewed_by, sq.reviewed_at
                FROM simple_questions sq
                LEFT JOIN grades g ON sq.grade_id = g.id
                LEFT JOIN subjects sub ON sq.subject_id = sub.id
                LEFT JOIN chapters ch ON sq.chapter_id = ch.id
                ORDER BY sq.created_at DESC
                LIMIT 10
            """)
        recent = cur.fetchall()
        stats['recent'] = recent
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/grades', methods=['GET'])
def get_grades():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if user_role == 'admin':
            cur.execute("SELECT id, grade_name FROM grades ORDER BY id")
        elif user_role == 'master' and subject_group:
            cur.execute("""
                SELECT DISTINCT g.id, g.grade_name 
                FROM grades g
                JOIN subject_groups sg ON g.id = sg.grade_id
                WHERE sg.group_code = %s
                ORDER BY g.id
            """, (subject_group,))
        else:
            cur.execute("""
                SELECT DISTINCT g.id, g.grade_name 
                FROM grades g
                JOIN subject_groups sg ON g.id = sg.grade_id
                WHERE sg.group_code = %s
                ORDER BY g.id
            """, (subject_group,))
        grades = cur.fetchall()
        return jsonify({'grades': grades})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

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
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO grades (grade_name) VALUES (%s)", (name,))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/grades/<int:grade_id>', methods=['PUT'])
def update_grade(grade_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.grade_id = %s
            """, (subject_group, grade_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this grade'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Grade name is required'}), 400
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE grades SET grade_name = %s WHERE id = %s", (name, grade_id))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/grades/<int:grade_id>', methods=['DELETE'])
def delete_grade(grade_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM subjects WHERE grade_id = %s", (grade_id,))
        if cur.fetchone()['count'] > 0:
            return jsonify({'error': 'Cannot delete grade with subjects'}), 400
        cur.execute("DELETE FROM grades WHERE id = %s", (grade_id,))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/subjects', methods=['GET'])
def get_subjects():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if user_role == 'admin':
            cur.execute("""
                SELECT s.id, s.subject_name, s.grade_id, g.grade_name 
                FROM subjects s
                LEFT JOIN grades g ON s.grade_id = g.id
                ORDER BY s.grade_id, s.subject_name
            """)
        elif user_role == 'master' and subject_group:
            cur.execute("""
                SELECT s.id, s.subject_name, s.grade_id, g.grade_name 
                FROM subjects s
                LEFT JOIN grades g ON s.grade_id = g.id
                JOIN subject_groups sg ON s.id = sg.subject_id
                WHERE sg.group_code = %s
                ORDER BY s.grade_id, s.subject_name
            """, (subject_group,))
        else:
            cur.execute("""
                SELECT s.id, s.subject_name, s.grade_id, g.grade_name 
                FROM subjects s
                LEFT JOIN grades g ON s.grade_id = g.id
                JOIN subject_groups sg ON s.id = sg.subject_id
                WHERE sg.group_code = %s
                ORDER BY s.grade_id, s.subject_name
            """, (subject_group,))
        subjects = cur.fetchall()
        return jsonify({'subjects': subjects})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/subjects', methods=['POST'])
def create_subject():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    name = data.get('name')
    grade_id = data.get('grade_id')
    
    if not name or not grade_id:
        return jsonify({'error': 'Name and grade required'}), 400
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.grade_id = %s
            """, (subject_group, grade_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this grade'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO subjects (subject_name, grade_id) VALUES (%s, %s)", (name, grade_id))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/subjects/<int:subject_id>', methods=['PUT'])
def update_subject(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.subject_id = %s
            """, (subject_group, subject_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this subject'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    data = request.json
    name = data.get('name')
    grade_id = data.get('grade_id')
    if not name or not grade_id:
        return jsonify({'error': 'Name and grade required'}), 400
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE subjects SET subject_name = %s, grade_id = %s WHERE id = %s", (name, grade_id, subject_id))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/subjects/<int:subject_id>', methods=['DELETE'])
def delete_subject(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM curricular_goals WHERE subject_id = %s", (subject_id,))
        if cur.fetchone()['count'] > 0:
            return jsonify({'error': 'Cannot delete subject with CGs'}), 400
        cur.execute("DELETE FROM subjects WHERE id = %s", (subject_id,))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/textbooks', methods=['GET'])
def get_textbooks():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    grade_id = request.args.get('grade_id')
    book_type = request.args.get('book_type')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        query = """
            SELECT t.*, s.subject_name, g.grade_name 
            FROM textbooks t
            LEFT JOIN subjects s ON t.subject_id = s.id
            LEFT JOIN grades g ON t.grade_id = g.id
            WHERE 1=1
        """
        params = []
        
        if user_role == 'master' and subject_group:
            query += """ 
                AND t.subject_id IN (
                    SELECT sg.subject_id FROM subject_groups sg 
                    WHERE sg.group_code = %s
                )
            """
            params.append(subject_group)
        elif user_role != 'admin' and subject_group:
            query += """ 
                AND t.subject_id IN (
                    SELECT sg.subject_id FROM subject_groups sg 
                    WHERE sg.group_code = %s
                )
            """
            params.append(subject_group)
        
        if subject_id:
            query += " AND t.subject_id = %s"
            params.append(subject_id)
        if grade_id:
            query += " AND t.grade_id = %s"
            params.append(grade_id)
        if book_type == 'textbook':
            query += " AND (t.is_reference = 0 OR t.is_reference IS NULL)"
        elif book_type == 'reference':
            query += " AND t.is_reference = 1"
            
        query += " ORDER BY t.textbook_name"
        cur.execute(query, params)
        textbooks = cur.fetchall()
        return jsonify({'textbooks': textbooks})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/textbooks', methods=['POST'])
def create_textbook():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
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
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.subject_id = %s
            """, (subject_group, subject_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this subject'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO textbooks (textbook_name, subject_id, grade_id, publisher, is_reference)
            VALUES (%s, %s, %s, %s, %s)
        """, (textbook_name, subject_id, grade_id, publisher, is_reference))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Book saved successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Book already exists for this subject'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/textbooks/<int:textbook_id>', methods=['PUT'])
def update_textbook(textbook_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
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
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.subject_id = %s
            """, (subject_group, subject_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this subject'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE textbooks 
            SET textbook_name = %s, subject_id = %s, grade_id = %s, 
                publisher = %s, is_reference = %s
            WHERE id = %s
        """, (textbook_name, subject_id, grade_id, publisher, is_reference, textbook_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Book not found'}), 404
        return jsonify({'success': True, 'message': 'Book updated successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Book already exists for this subject'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/textbooks/<int:textbook_id>', methods=['DELETE'])
def delete_textbook(textbook_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT COUNT(*) as count FROM chapters WHERE textbook_id = %s", (textbook_id,))
        count = cur.fetchone()[0]
        if count > 0:
            return jsonify({'error': f'Cannot delete textbook because it has {count} chapter(s) associated.'}), 400
            
        cur.execute("DELETE FROM textbooks WHERE id = %s", (textbook_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Book not found'}), 404
        return jsonify({'success': True, 'message': 'Book deleted successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/subjects/<int:subject_id>/textbooks', methods=['GET'])
def get_subject_textbooks(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    book_type = request.args.get('book_type')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if user_role == 'master' and subject_group:
            cur_check = get_db()
            cur_check_cursor = cur_check.cursor(dictionary=True)
            try:
                cur_check_cursor.execute("""
                    SELECT sg.id FROM subject_groups sg
                    WHERE sg.group_code = %s AND sg.subject_id = %s
                """, (subject_group, subject_id))
                if not cur_check_cursor.fetchone():
                    return jsonify({'error': 'Access denied'}), 403
            finally:
                cur_check_cursor.close()
                cur_check.close()
        
        query = """
            SELECT id, textbook_name, publisher, grade_id, is_reference
            FROM textbooks 
            WHERE subject_id = %s
        """
        params = [subject_id]
        
        if book_type == 'textbook':
            query += " AND (is_reference = 0 OR is_reference IS NULL)"
        elif book_type == 'reference':
            query += " AND is_reference = 1"
            
        query += " ORDER BY textbook_name"
        
        cur.execute(query, params)
        textbooks = cur.fetchall()
        return jsonify({'textbooks': textbooks})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/chapters', methods=['GET'])
def get_chapters():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        user_subject_ids = []
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
        
        if subject_id:
            if user_role != 'admin' and user_subject_ids and int(subject_id) not in user_subject_ids:
                return jsonify({'error': 'Access denied'}), 403
            cur.execute("""
                SELECT c.*, s.subject_name, s.grade_id, g.grade_name,
                       t.textbook_name, t.id as textbook_id, t.publisher, t.is_reference
                FROM chapters c 
                LEFT JOIN subjects s ON c.subject_id = s.id 
                LEFT JOIN grades g ON s.grade_id = g.id
                LEFT JOIN textbooks t ON c.textbook_id = t.id
                WHERE c.subject_id = %s 
                ORDER BY c.chapter_number, c.id
            """, (subject_id,))
        else:
            if user_role != 'admin' and user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT c.*, s.subject_name, s.grade_id, g.grade_name,
                           t.textbook_name, t.id as textbook_id, t.publisher, t.is_reference
                    FROM chapters c 
                    LEFT JOIN subjects s ON c.subject_id = s.id 
                    LEFT JOIN grades g ON s.grade_id = g.id
                    LEFT JOIN textbooks t ON c.textbook_id = t.id
                    WHERE c.subject_id IN ({placeholders})
                    ORDER BY g.id, s.subject_name, c.chapter_number, c.id
                """, tuple(user_subject_ids))
            else:
                cur.execute("""
                    SELECT c.*, s.subject_name, s.grade_id, g.grade_name,
                           t.textbook_name, t.id as textbook_id, t.publisher, t.is_reference
                    FROM chapters c 
                    LEFT JOIN subjects s ON c.subject_id = s.id 
                    LEFT JOIN grades g ON s.grade_id = g.id
                    LEFT JOIN textbooks t ON c.textbook_id = t.id
                    ORDER BY g.id, s.subject_name, c.chapter_number, c.id
                """)
        chapters = cur.fetchall()
        return jsonify({'chapters': chapters})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/chapters', methods=['POST'])
def create_chapter():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
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
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.subject_id = %s
            """, (subject_group, subject_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this subject'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO chapters (subject_id, chapter_name, chapter_number, textbook_id, reference_book)
            VALUES (%s, %s, %s, %s, %s)
        """, (subject_id, chapter_name, chapter_number, textbook_id, reference_book))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Chapter created successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Chapter already exists for this subject'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/chapters/<int:chapter_id>', methods=['PUT'])
def update_chapter(chapter_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
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
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.subject_id = %s
            """, (subject_group, subject_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this subject'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE chapters 
            SET subject_id = %s, chapter_name = %s, 
                chapter_number = %s, textbook_id = %s, reference_book = %s
            WHERE id = %s
        """, (subject_id, chapter_name, chapter_number, textbook_id, reference_book, chapter_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Chapter not found'}), 404
        return jsonify({'success': True, 'message': 'Chapter updated successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Chapter already exists for this subject'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/chapters/<int:chapter_id>', methods=['DELETE'])
def delete_chapter(chapter_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT COUNT(*) as count FROM simple_questions WHERE chapter_id = %s", (chapter_id,))
        count = cur.fetchone()[0]
        if count > 0:
            return jsonify({'error': f'Cannot delete chapter because it has {count} question(s).'}), 400
        cur.execute("DELETE FROM chapters WHERE id = %s", (chapter_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Chapter not found'}), 404
        return jsonify({'success': True, 'message': 'Chapter deleted successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/subjects/<int:subject_id>/chapters', methods=['GET'])
def get_subject_chapters(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
            if subject_id not in user_subject_ids:
                return jsonify({'error': 'Access denied'}), 403
        
        cur.execute("""
            SELECT c.id, c.chapter_name, c.chapter_number, c.textbook_id, c.reference_book,
                   t.textbook_name, t.publisher, t.is_reference
            FROM chapters c
            LEFT JOIN textbooks t ON c.textbook_id = t.id
            WHERE c.subject_id = %s 
            ORDER BY c.chapter_number, c.id
        """, (subject_id,))
        chapters = cur.fetchall()
        return jsonify({'chapters': chapters})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/cgs', methods=['GET'])
def get_cgs():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    chapter_id = request.args.get('chapter_id')
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        query = """
            SELECT cg.*, s.subject_name, g.grade_name,
                   ch.chapter_name, ch.id as chapter_id
            FROM curricular_goals cg 
            LEFT JOIN subjects s ON cg.subject_id = s.id 
            LEFT JOIN grades g ON s.grade_id = g.id
            LEFT JOIN chapters ch ON cg.chapter_id = ch.id
            WHERE 1=1
        """
        params = []
        
        if user_role == 'master' and subject_group:
            query += """ 
                AND cg.subject_id IN (
                    SELECT sg.subject_id FROM subject_groups sg 
                    WHERE sg.group_code = %s
                )
            """
            params.append(subject_group)
        elif user_role != 'admin' and subject_group:
            query += """ 
                AND cg.subject_id IN (
                    SELECT sg.subject_id FROM subject_groups sg 
                    WHERE sg.group_code = %s
                )
            """
            params.append(subject_group)
        
        if subject_id:
            query += " AND cg.subject_id = %s"
            params.append(subject_id)
        
        if chapter_id:
            query += " AND (cg.chapter_id = %s OR cg.chapter_id IS NULL)"
            params.append(chapter_id)
        
        query += " ORDER BY cg.subject_id, cg.id"
        
        cur.execute(query, params)
        cgs = cur.fetchall()
        return jsonify({'cgs': cgs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/cgs', methods=['POST'])
def create_cg():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    subject_id = data.get('subject_id')
    chapter_id = data.get('chapter_id')
    
    if not code or not subject_id:
        return jsonify({'error': 'Code and subject required'}), 400
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.subject_id = %s
            """, (subject_group, subject_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this subject'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if chapter_id:
            cur.execute("""
                SELECT id FROM curricular_goals 
                WHERE cg_code = %s AND subject_id = %s AND chapter_id = %s
            """, (code, subject_id, chapter_id))
        else:
            cur.execute("""
                SELECT id FROM curricular_goals 
                WHERE cg_code = %s AND subject_id = %s AND chapter_id IS NULL
            """, (code, subject_id))
        
        if cur.fetchone():
            return jsonify({'error': f'Curricular Goal "{code}" already exists for this subject and chapter'}), 400
        
        cur.execute("""
            INSERT INTO curricular_goals (cg_code, cg_description, subject_id, chapter_id) 
            VALUES (%s, %s, %s, %s)
        """, (code, description, subject_id, chapter_id))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid})
    except mysql.connector.IntegrityError as e:
        db.rollback()
        if 'Duplicate entry' in str(e):
            return jsonify({'error': f'Curricular Goal "{code}" already exists'}), 400
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/cgs/<int:cg_id>', methods=['PUT'])
def update_cg(cg_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    subject_id = data.get('subject_id')
    chapter_id = data.get('chapter_id')
    
    if not code or not subject_id:
        return jsonify({'error': 'Code and subject required'}), 400
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                WHERE sg.group_code = %s AND sg.subject_id = %s
            """, (subject_group, subject_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this subject'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    try:
        if chapter_id:
            cur.execute("""
                SELECT id FROM curricular_goals 
                WHERE cg_code = %s AND subject_id = %s AND chapter_id = %s AND id != %s
            """, (code, subject_id, chapter_id, cg_id))
        else:
            cur.execute("""
                SELECT id FROM curricular_goals 
                WHERE cg_code = %s AND subject_id = %s AND chapter_id IS NULL AND id != %s
            """, (code, subject_id, cg_id))
        
        if cur.fetchone():
            return jsonify({'error': f'Curricular Goal "{code}" already exists for this subject and chapter'}), 400
        
        cur.execute("""
            UPDATE curricular_goals 
            SET cg_code = %s, cg_description = %s, subject_id = %s, chapter_id = %s 
            WHERE id = %s
        """, (code, description, subject_id, chapter_id, cg_id))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/cgs/<int:cg_id>', methods=['DELETE'])
def delete_cg(cg_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM competencies WHERE cg_id = %s", (cg_id,))
        if cur.fetchone()['count'] > 0:
            return jsonify({'error': 'Cannot delete CG with competencies'}), 400
        cur.execute("DELETE FROM curricular_goals WHERE id = %s", (cg_id,))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/competencies', methods=['GET'])
def get_competencies_api():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        query = """
            SELECT c.*, cg.cg_code, cg.subject_id, s.subject_name, g.grade_name 
            FROM competencies c 
            LEFT JOIN curricular_goals cg ON c.cg_id = cg.id 
            LEFT JOIN subjects s ON cg.subject_id = s.id 
            LEFT JOIN grades g ON s.grade_id = g.id 
            WHERE 1=1
        """
        params = []
        
        if user_role == 'master' and subject_group:
            query += """ 
                AND cg.subject_id IN (
                    SELECT sg.subject_id FROM subject_groups sg 
                    WHERE sg.group_code = %s
                )
            """
            params.append(subject_group)
        elif user_role != 'admin' and subject_group:
            query += """ 
                AND cg.subject_id IN (
                    SELECT sg.subject_id FROM subject_groups sg 
                    WHERE sg.group_code = %s
                )
            """
            params.append(subject_group)
        
        query += " AND c.status = 1 ORDER BY c.cg_id, c.id"
        cur.execute(query, params)
        comps = cur.fetchall()
        return jsonify({'competencies': comps})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/competencies', methods=['POST'])
def create_competency():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    cg_id = data.get('cg_id')
    status = data.get('status', 1)
    
    if not code or not cg_id:
        return jsonify({'error': 'Code and CG required'}), 400
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                JOIN curricular_goals cg ON cg.subject_id = sg.subject_id
                WHERE sg.group_code = %s AND cg.id = %s
            """, (subject_group, cg_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this Curricular Goal'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO competencies (comp_code, comp_description, cg_id, status) 
            VALUES (%s, %s, %s, %s)
        """, (code, description, cg_id, status))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/competencies/<int:comp_id>', methods=['PUT'])
def update_competency(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    cg_id = data.get('cg_id')
    status = data.get('status', 1)
    
    if not code or not cg_id:
        return jsonify({'error': 'Code and CG required'}), 400
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                JOIN curricular_goals cg ON cg.subject_id = sg.subject_id
                JOIN competencies c ON c.cg_id = cg.id
                WHERE sg.group_code = %s AND c.id = %s
            """, (subject_group, comp_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this Competency'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE competencies 
            SET comp_code = %s, comp_description = %s, cg_id = %s, status = %s 
            WHERE id = %s
        """, (code, description, cg_id, status, comp_id))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/competencies/<int:comp_id>', methods=['DELETE'])
def delete_competency(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    if user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM simple_questions WHERE comp_id = %s", (comp_id,))
        if cur.fetchone()['count'] > 0:
            return jsonify({'error': 'Cannot delete competency with questions'}), 400
        cur.execute("DELETE FROM competencies WHERE id = %s", (comp_id,))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/competencies/<int:comp_id>/toggle', methods=['POST'])
def toggle_competency_status(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and user_role != 'master':
        return jsonify({'error': 'Admin or Master access required'}), 403
    
    if user_role == 'master' and subject_group:
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT sg.id FROM subject_groups sg
                JOIN curricular_goals cg ON cg.subject_id = sg.subject_id
                JOIN competencies c ON c.cg_id = cg.id
                WHERE sg.group_code = %s AND c.id = %s
            """, (subject_group, comp_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this Competency'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    data = request.json
    status = data.get('status', 1)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE competencies SET status = %s WHERE id = %s", (status, comp_id))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/subject-groups', methods=['GET'])
def get_subject_groups():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if user_role == 'admin':
            cur.execute("""
                SELECT sg.*, g.grade_name, s.subject_name,
                       (SELECT COUNT(*) FROM users WHERE subject_group = sg.group_code) as member_count
                FROM subject_groups sg
                LEFT JOIN grades g ON sg.grade_id = g.id
                LEFT JOIN subjects s ON sg.subject_id = s.id
                ORDER BY sg.grade_id, sg.group_code
            """)
        elif user_role == 'master' and subject_group:
            cur.execute("""
                SELECT sg.*, g.grade_name, s.subject_name,
                       (SELECT COUNT(*) FROM users WHERE subject_group = sg.group_code) as member_count
                FROM subject_groups sg
                LEFT JOIN grades g ON sg.grade_id = g.id
                LEFT JOIN subjects s ON sg.subject_id = s.id
                WHERE sg.group_code = %s
                ORDER BY sg.grade_id, sg.group_code
            """, (subject_group,))
        else:
            cur.execute("""
                SELECT sg.*, g.grade_name, s.subject_name,
                       (SELECT COUNT(*) FROM users WHERE subject_group = sg.group_code) as member_count
                FROM subject_groups sg
                LEFT JOIN grades g ON sg.grade_id = g.id
                LEFT JOIN subjects s ON sg.subject_id = s.id
                WHERE sg.group_code = %s
                ORDER BY sg.grade_id, sg.group_code
            """, (subject_group,))
        groups = cur.fetchall()
        return jsonify({'groups': groups})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

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
    
    if not re.match(r'^[a-zA-Z0-9_\-]+$', group_code):
        return jsonify({'error': 'Group code can only contain letters, numbers, underscores, and hyphens'}), 400
    
    if len(group_code) < 3:
        return jsonify({'error': 'Group code must be at least 3 characters'}), 400
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO subject_groups (group_code, group_name, grade_id, subject_id)
            VALUES (%s, %s, %s, %s)
        """, (group_code, group_name, grade_id, subject_id))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Group created successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Group code already exists'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

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
    
    if not re.match(r'^[a-zA-Z0-9_\-]+$', group_code):
        return jsonify({'error': 'Group code can only contain letters, numbers, underscores, and hyphens'}), 400
    
    if len(group_code) < 3:
        return jsonify({'error': 'Group code must be at least 3 characters'}), 400
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE subject_groups 
            SET group_code = %s, group_name = %s, grade_id = %s, subject_id = %s
            WHERE id = %s
        """, (group_code, group_name, grade_id, subject_id, group_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify({'success': True, 'message': 'Group updated successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Group code already exists'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/subject-groups/<int:group_id>', methods=['DELETE'])
def delete_subject_group(group_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    if user_role != 'admin':
        return jsonify({'error': 'Only Administrators can delete subject groups'}), 403
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT group_code FROM subject_groups WHERE id = %s", (group_id,))
        group = cur.fetchone()
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        
        cur.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE subject_group = (SELECT group_code FROM subject_groups WHERE id = %s)
        """, (group_id,))
        user_count = cur.fetchone()['count']
        if user_count > 0:
            return jsonify({'error': f'Cannot delete group because it has {user_count} user(s) assigned.'}), 400
        
        cur.execute("DELETE FROM subject_groups WHERE id = %s", (group_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify({'success': True, 'message': 'Group deleted successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT u.id, u.username, u.role, u.created_at, 
                   u.subject_group, u.group_role,
                   u.perm_re, u.perm_ra, u.perm_rc, u.perm_ap, u.perm_master,
                   sg.group_name, sg.group_code
            FROM users u
            LEFT JOIN subject_groups sg ON u.subject_group = sg.group_code
            ORDER BY u.created_at DESC
        """)
        users = cur.fetchall()
        return jsonify({'users': users})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

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
    
    perm_re = False
    perm_ra = False
    perm_rc = False
    perm_ap = False
    perm_master = False
    
    if role == 'writer':
        perm_re = True
    elif role == 'master':
        perm_master = True
    elif role == 'reviewer':
        perm_rc = True
    elif role == 'approver':
        perm_ap = True
    elif role == 'builder':
        perm_ra = True
    elif role == 'admin':
        perm_re = True
        perm_ra = True
        perm_rc = True
        perm_ap = True
        perm_master = True
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            return jsonify({'error': 'Username already exists'}), 400
        hashed_password = generate_password_hash(password)
        cur.execute("""
            INSERT INTO users (username, password, role, subject_group, group_role,
                              perm_re, perm_ra, perm_rc, perm_ap, perm_master, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (username, hashed_password, role, subject_group, group_role,
              perm_re, perm_ra, perm_rc, perm_ap, perm_master, datetime.now()))
        db.commit()
        return jsonify({'success': True, 'message': 'User created successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

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
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE users 
            SET username = %s, role = %s, subject_group = %s, group_role = %s,
                perm_re = %s, perm_ra = %s, perm_rc = %s, perm_ap = %s, perm_master = %s
            WHERE id = %s
        """, (username, role, subject_group, group_role, 
              perm_re, perm_ra, perm_rc, perm_ap, perm_master, user_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

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
    hashed_password = generate_password_hash(new_password)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE users 
            SET password = %s 
            WHERE id = %s
        """, (hashed_password, user_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    if user_id == session.get('user_id'):
        return jsonify({'error': 'Cannot delete your own account'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

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


@app.route('/api/reviewers', methods=['GET'])
def get_reviewers():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    current_user_id = session.get('user_id')
    
    if user_role != 'admin' and not session.get('perm_master', False):
        return jsonify({'error': 'Access denied'}), 403
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if user_role == 'admin':
            cur.execute("""
                SELECT u.id, u.username, u.role, u.subject_group, sg.group_name
                FROM users u
                LEFT JOIN subject_groups sg ON u.subject_group = sg.group_code
                WHERE (u.perm_rc = 1 OR u.role IN ('admin', 'reviewer'))
                  AND u.id != %s
                ORDER BY u.username
            """, (current_user_id,))
        else:
            cur.execute("""
                SELECT u.id, u.username, u.role, u.subject_group, sg.group_name
                FROM users u
                LEFT JOIN subject_groups sg ON u.subject_group = sg.group_code
                WHERE (u.perm_rc = 1 OR u.role IN ('admin', 'reviewer'))
                  AND u.subject_group = %s
                  AND u.id != %s
                ORDER BY u.username
            """, (subject_group, current_user_id))
        reviewers = cur.fetchall()
        return jsonify({'reviewers': reviewers})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/approvers', methods=['GET'])
def get_approvers():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    current_user_id = session.get('user_id')
    
    if user_role != 'admin' and not session.get('perm_rc', False):
        return jsonify({'error': 'Access denied'}), 403
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if user_role == 'admin':
            cur.execute("""
                SELECT u.id, u.username, u.role, u.subject_group, sg.group_name
                FROM users u
                LEFT JOIN subject_groups sg ON u.subject_group = sg.group_code
                WHERE (u.perm_ap = 1 OR u.role IN ('admin', 'approver'))
                  AND u.id != %s
                ORDER BY u.username
            """, (current_user_id,))
        else:
            cur.execute("""
                SELECT u.id, u.username, u.role, u.subject_group, sg.group_name
                FROM users u
                LEFT JOIN subject_groups sg ON u.subject_group = sg.group_code
                WHERE (u.perm_ap = 1 OR u.role IN ('admin', 'approver'))
                  AND u.subject_group = %s
                  AND u.id != %s
                ORDER BY u.username
            """, (subject_group, current_user_id))
        approvers = cur.fetchall()
        return jsonify({'approvers': approvers})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/master-review-question/<int:question_id>', methods=['POST'])
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
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        if user_role != 'admin' and subject_group:
            cur.execute("""
                SELECT sq.id, sq.subject_id, sg.group_code
                FROM simple_questions sq
                LEFT JOIN subject_groups sg ON sq.subject_id = sg.subject_id
                WHERE sq.id = %s AND sg.group_code = %s
            """, (question_id, subject_group))
            if not cur.fetchone():
                return jsonify({'error': 'Access denied'}), 403
        
        cur.execute("SELECT * FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        if question['status'] != 'unassigned' and user_role != 'admin':
            return jsonify({'error': 'Only unassigned questions can be assigned to reviewer'}), 400
        
        if reviewer_id:
            if user_role == 'admin':
                cur.execute("SELECT id, username FROM users WHERE id = %s AND (perm_rc = 1 OR role = 'reviewer' OR role = 'admin')", (reviewer_id,))
            else:
                cur.execute("""
                    SELECT u.id, u.username FROM users u
                    WHERE u.id = %s 
                    AND (u.perm_rc = 1 OR u.role = 'reviewer' OR u.role = 'admin')
                    AND u.subject_group = %s
                """, (reviewer_id, subject_group))
            reviewer = cur.fetchone()
            if not reviewer:
                return jsonify({'error': 'Selected reviewer does not have reviewer permission or is not in your group'}), 400
            reviewer_name = reviewer['username']
        
        if reviewer_name:
            master_comment = f"[ASSIGNED TO REVIEWER: {reviewer_name}] {comment}" if comment else f"[ASSIGNED TO REVIEWER: {reviewer_name}]"
        else:
            master_comment = comment if comment else 'Question assigned for review'
        
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'under_review', 
                master_reviewed_by = %s, 
                master_reviewed_at = %s,
                master_reviewed_comment = %s,
                assigned_reviewer_id = %s,
                assigned_reviewer_name = %s,
                reviewed_by = NULL,
                reviewed_comment = NULL,
                reviewed_at = NULL,
                approved_by = NULL,
                approved_at = NULL
            WHERE id = %s
        """, (username, datetime.now(), master_comment, reviewer_id, reviewer_name, question_id))
        db.commit()
        
        return jsonify({'success': True, 'message': f'Question assigned to {reviewer_name or "reviewer"} for review'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/review-question/<int:question_id>', methods=['POST'])
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
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        if user_role != 'admin' and subject_group:
            cur.execute("""
                SELECT sq.id, sq.subject_id, sg.group_code
                FROM simple_questions sq
                LEFT JOIN subject_groups sg ON sq.subject_id = sg.subject_id
                WHERE sq.id = %s AND sg.group_code = %s
            """, (question_id, subject_group))
            if not cur.fetchone():
                return jsonify({'error': 'Access denied'}), 403
        
        cur.execute("SELECT * FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        if user_role != 'admin' and question['assigned_reviewer_id'] != user_id:
            return jsonify({'error': 'This question is not assigned to you'}), 403
        
        if question['status'] != 'under_review' and user_role != 'admin':
            return jsonify({'error': 'Only under review questions can be reviewed'}), 400
        
        if approver_id:
            if user_role == 'admin':
                cur.execute("SELECT id, username FROM users WHERE id = %s AND (perm_ap = 1 OR role = 'approver' OR role = 'admin')", (approver_id,))
            else:
                cur.execute("""
                    SELECT u.id, u.username FROM users u
                    WHERE u.id = %s 
                    AND (u.perm_ap = 1 OR u.role = 'approver' OR u.role = 'admin')
                    AND u.subject_group = %s
                """, (approver_id, subject_group))
            approver = cur.fetchone()
            if not approver:
                return jsonify({'error': 'Selected approver does not have approver permission or is not in your group'}), 400
            approver_name = approver['username']
        
        if approver_name:
            reviewer_comment = f"[ASSIGNED TO APPROVER: {approver_name}] {comment}" if comment else f"[ASSIGNED TO APPROVER: {approver_name}]"
        else:
            reviewer_comment = comment if comment else 'Question passed for approval'
        
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'reviewed_completed', 
                reviewed_by = %s, 
                reviewed_at = %s,
                reviewed_comment = %s,
                assigned_approver_id = %s,
                assigned_approver_name = %s,
                approved_by = NULL,
                approved_at = NULL
            WHERE id = %s
        """, (username, datetime.now(), reviewer_comment, approver_id, approver_name, question_id))
        db.commit()
        
        return jsonify({'success': True, 'message': f'Question assigned to {approver_name or "approver"} for approval'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


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
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        cur.execute("SHOW TABLES LIKE 'simple_questions'")
        if not cur.fetchone():
            return jsonify({'questions': []})
        
        user_subject_ids = []
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
            
            cur.execute("SELECT grade_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            grade_ids = [row['grade_id'] for row in cur.fetchall()]
        
        query = """
            SELECT sq.id, sq.question_text as question, sq.answer, sq.marks, sq.duration_minutes,
                   COALESCE(sq.status, 'unassigned') as status,
                   sq.created_by, sq.created_at,
                   sq.reviewed_by, sq.reviewed_at, sq.reviewed_comment,
                   sq.rejection_reason, sq.approved_by, sq.rejected_by, sq.rejected_at,
                   sq.master_reviewed_by, sq.master_reviewed_at, sq.master_reviewed_comment,
                   sq.assigned_reviewer_id, sq.assigned_reviewer_name,
                   sq.assigned_approver_id, sq.assigned_approver_name,
                   g.grade_name as grade, g.id as grade_id,
                   sub.subject_name as subject, sub.id as subject_id,
                   ch.chapter_name as chapter, ch.id as chapter_id,
                   c.comp_code as competency, sq.images,
                   sq.question_type_name, sq.language,
                   cd.domain_name, kl.level_name as knowledge_level_name,
                   dl.level_name as difficulty_name,
                   sq.textbook_name, sq.textbook_publisher, sq.textbook_page,
                   sq.reference_book, sq.reference_page
            FROM simple_questions sq
            LEFT JOIN grades g ON sq.grade_id = g.id
            LEFT JOIN subjects sub ON sq.subject_id = sub.id
            LEFT JOIN chapters ch ON sq.chapter_id = ch.id
            LEFT JOIN competencies c ON sq.comp_id = c.id
            LEFT JOIN cognitive_domains cd ON sq.domain_id = cd.id
            LEFT JOIN knowledge_levels kl ON sq.knowledge_level_id = kl.id
            LEFT JOIN difficulty_levels dl ON sq.difficulty_id = dl.id
            WHERE 1=1
        """
        params = []
        
        if user_role == 'admin':
            pass
        else:
            permission_filters = []
            
            if perm_re:
                permission_filters.append("(sq.created_by = %s AND sq.status IN ('unassigned', 'rejected'))")
                params.append(username)
            
            if perm_master:
                permission_filters.append("(sq.status = 'unassigned')")
            
            if perm_rc:
                permission_filters.append("(sq.status = 'under_review' AND sq.assigned_reviewer_id = %s)")
                params.append(user_id)
            
            if perm_ap:
                permission_filters.append("(sq.status = 'reviewed_completed' AND sq.assigned_approver_id = %s)")
                params.append(user_id)
            
            if perm_ra:
                permission_filters.append("(sq.status = 'approved')")
            
            permission_filters.append("(sq.created_by = %s)")
            params.append(username)
            
            if permission_filters:
                query += " AND (" + " OR ".join(permission_filters) + ")"
            else:
                query += " AND 1=0"
        
        if user_role != 'admin' and user_subject_ids:
            placeholders = ','.join(['%s'] * len(user_subject_ids))
            query += f" AND sq.subject_id IN ({placeholders})"
            params.extend(user_subject_ids)
        
        if grade:
            query += " AND g.id = %s"
            params.append(grade)
        if subject:
            query += " AND sub.id = %s"
            params.append(subject)
        if status:
            query += " AND sq.status = %s"
            params.append(status)
        if search:
            query += " AND (sq.question_text LIKE %s OR sq.answer LIKE %s)"
            params.extend([f'%{search}%', f'%{search}%'])
        
        query += " ORDER BY sq.created_at DESC"
        cur.execute(query, params)
        questions = cur.fetchall()
        
        formatted_questions = []
        for q in questions:
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
                if q['status'] in ['unassigned', 'rejected', 'rework']:
                    can_edit = True
                if q['status'] == 'rejected':
                    can_rework = True
            
            if perm_master and q['status'] == 'unassigned':
                can_master_review = True
            
            if perm_rc and q['status'] == 'under_review' and is_assigned_reviewer:
                can_review = True
                can_rework = True
            
            if perm_ap and q['status'] == 'reviewed_completed' and is_assigned_approver:
                can_approve = True
                can_rework = True
            
            if perm_ra and q['status'] == 'approved':
                can_build = True
            
            if user_role == 'admin':
                can_edit = True
                can_review = True
                can_approve = True
                can_build = True
                can_delete = True
                can_rework = True
                can_master_review = True
            
            if user_role == 'admin':
                can_rework = True
            elif (perm_master or perm_rc or perm_ap) and q['status'] != 'approved':
                if perm_rc and is_assigned_reviewer:
                    can_rework = True
                elif perm_ap and is_assigned_approver:
                    can_rework = True
                elif perm_master:
                    can_rework = True
            elif perm_re and is_my_question and q['status'] == 'rejected':
                can_rework = True
            
            images = []
            try:
                if q.get('images'):
                    images = json.loads(q['images'])
                    if not isinstance(images, list):
                        images = []
            except:
                images = []
            
            formatted_questions.append({
                'id': q['id'],
                'question': q['question'],
                'answer': q['answer'] or '',
                'marks': q['marks'] or 1,
                'duration_minutes': q['duration_minutes'] or 0,
                'status': q['status'] or 'unassigned',
                'created_by': q['created_by'] or 'Unknown',
                'created_at': q['created_at'].strftime('%Y-%m-%d %H:%M:%S') if q['created_at'] else '',
                'reviewed_by': q['reviewed_by'],
                'reviewed_at': q['reviewed_at'].strftime('%Y-%m-%d %H:%M:%S') if q['reviewed_at'] else None,
                'reviewed_comment': q['reviewed_comment'],
                'rejection_reason': q['rejection_reason'],
                'rejected_by': q['rejected_by'],
                'master_reviewed_by': q['master_reviewed_by'],
                'master_reviewed_at': q['master_reviewed_at'].strftime('%Y-%m-%d %H:%M:%S') if q['master_reviewed_at'] else None,
                'master_reviewed_comment': q['master_reviewed_comment'],
                'assigned_reviewer_id': q['assigned_reviewer_id'],
                'assigned_reviewer_name': q['assigned_reviewer_name'],
                'assigned_approver_id': q['assigned_approver_id'],
                'assigned_approver_name': q['assigned_approver_name'],
                'grade': q['grade'] or 'N/A',
                'grade_id': q['grade_id'],
                'subject': q['subject'] or 'N/A',
                'subject_id': q['subject_id'],
                'chapter': q['chapter'] or 'N/A',
                'chapter_id': q['chapter_id'],
                'competency': q['competency'] or 'N/A',
                'images': images,
                'question_type_name': q['question_type_name'] or 'Objective',
                'language': q.get('language', 'en'),
                'domain_name': q.get('domain_name') or 'N/A',
                'knowledge_level_name': q.get('knowledge_level_name') or 'N/A',
                'difficulty_name': q.get('difficulty_name') or 'N/A',
                'textbook_name': q.get('textbook_name'),
                'textbook_publisher': q.get('textbook_publisher'),
                'textbook_page': q.get('textbook_page'),
                'reference_book': q.get('reference_book'),
                'reference_page': q.get('reference_page'),
                'can_edit': can_edit,
                'can_review': can_review,
                'can_approve': can_approve,
                'can_build': can_build,
                'can_delete': can_delete,
                'can_rework': can_rework,
                'can_master_review': can_master_review,
                'is_assigned_to_me': is_assigned_reviewer or is_assigned_approver,
                'is_my_question': is_my_question,
                'user_group': subject_group
            })
        
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
            'user_id': user_id,
            'user_subject_ids': user_subject_ids
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/approve-question/<int:question_id>', methods=['POST'])
def approve_question(question_id):
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
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        if user_role != 'admin' and subject_group:
            cur.execute("""
                SELECT sq.id, sq.subject_id, sg.group_code
                FROM simple_questions sq
                LEFT JOIN subject_groups sg ON sq.subject_id = sg.subject_id
                WHERE sq.id = %s AND sg.group_code = %s
            """, (question_id, subject_group))
            if not cur.fetchone():
                return jsonify({'error': 'Access denied'}), 403
        
        cur.execute("SELECT * FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        if user_role != 'admin' and question['assigned_approver_id'] != user_id:
            return jsonify({'error': 'This question is not assigned to you'}), 403
        
        if question['status'] != 'reviewed_completed' and user_role != 'admin':
            return jsonify({'error': 'Only reviewed completed questions can be approved'}), 400
        
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'approved', 
                reviewed_comment = %s,
                approved_at = %s,
                approved_by = %s
            WHERE id = %s
        """, (comment, datetime.now(), username, question_id))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Question approved successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/rework-question/<int:question_id>', methods=['POST'])
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
    subject_group = session.get('subject_group')
    
    data = request.json
    rework_comment = data.get('comment', '') if data else ''
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        if user_role != 'admin' and subject_group:
            cur.execute("""
                SELECT sq.id, sq.subject_id, sg.group_code
                FROM simple_questions sq
                LEFT JOIN subject_groups sg ON sq.subject_id = sg.subject_id
                WHERE sq.id = %s AND sg.group_code = %s
            """, (question_id, subject_group))
            if not cur.fetchone():
                return jsonify({'error': 'Access denied'}), 403
        
        cur.execute("SELECT created_by, status, assigned_reviewer_id, assigned_approver_id FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        can_rework = False
        if user_role == 'admin':
            can_rework = True
        elif perm_master:
            can_rework = question['status'] != 'approved'
        elif perm_rc:
            if question['assigned_reviewer_id'] == user_id:
                can_rework = question['status'] != 'approved'
        elif perm_ap:
            if question['assigned_approver_id'] == user_id:
                can_rework = question['status'] != 'approved'
        elif perm_re and question['created_by'] == username:
            can_rework = question['status'] == 'rejected' or question['status'] == 'rework'
        
        if not can_rework:
            return jsonify({'error': 'Not authorized to rework this question'}), 403
        
        comment_with_meta = f"[REWORK by {username} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {rework_comment}"
        
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'unassigned',
                reviewed_by = NULL,
                reviewed_at = NULL,
                reviewed_comment = %s,
                master_reviewed_by = NULL,
                master_reviewed_at = NULL,
                master_reviewed_comment = NULL,
                rejection_reason = NULL,
                rejected_by = NULL,
                rejected_at = NULL,
                approved_by = NULL,
                approved_at = NULL,
                assigned_reviewer_id = NULL,
                assigned_reviewer_name = NULL,
                assigned_approver_id = NULL,
                assigned_approver_name = NULL
            WHERE id = %s
        """, (comment_with_meta, question_id))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Question moved to unassigned for rework'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/update-question/<int:question_id>', methods=['POST'])
def update_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_re = session.get('perm_re', False)
    subject_group = session.get('subject_group')
    
    data = request.json
    question_text = data.get('question_text')
    answer = data.get('answer')
    marks = data.get('marks', 1)
    duration_minutes = data.get('duration_minutes', 0)
    
    if not question_text:
        return jsonify({'error': 'Question text is required'}), 400
    
    if not has_actual_content(question_text):
        return jsonify({'error': 'Question text must have actual content (text, images, or structured content)'}), 400
    
    if not answer:
        return jsonify({'error': 'Answer is required'}), 400
    
    if not has_actual_content(answer):
        return jsonify({'error': 'Answer must have actual content (text, images, or structured content)'}), 400
    
    try:
        marks = int(marks)
        if marks < 0 or marks > 100:
            return jsonify({'error': 'Marks must be between 0 and 100'}), 400
        duration_minutes = int(duration_minutes)
        if duration_minutes < 0 or duration_minutes > 180:
            return jsonify({'error': 'Duration must be between 0 and 180 minutes'}), 400
    except ValueError:
        return jsonify({'error': 'Marks and duration must be valid numbers'}), 400
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        if user_role != 'admin' and subject_group:
            cur.execute("""
                SELECT sq.id, sq.subject_id, sg.group_code, sq.created_by, sq.status
                FROM simple_questions sq
                LEFT JOIN subject_groups sg ON sq.subject_id = sg.subject_id
                WHERE sq.id = %s AND sg.group_code = %s
            """, (question_id, subject_group))
            question_access = cur.fetchone()
            if not question_access:
                return jsonify({'error': 'Access denied'}), 403
        else:
            cur.execute("SELECT created_by, status FROM simple_questions WHERE id = %s", (question_id,))
            question_access = cur.fetchone()
        
        if not question_access:
            return jsonify({'error': 'Question not found'}), 404
        
        can_edit = False
        if user_role == 'admin':
            can_edit = True
        elif perm_re and question_access['created_by'] == username:
            can_edit = question_access['status'] in ['unassigned', 'rejected', 'rework']
        else:
            can_edit = question_access['status'] != 'approved'
        
        if not can_edit:
            return jsonify({'error': 'Not authorized to edit this question'}), 403
        
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
        
        try:
            image_list = json.loads(images) if isinstance(images, str) else images
            filtered_images = []
            for img in image_list:
                if isinstance(img, str):
                    if not img.startswith('data:image') and not img.startswith('blob:'):
                        filtered_images.append(img)
                    elif img.startswith('data:image') and len(img) < 500000:
                        filtered_images.append(img)
            images = json.dumps(filtered_images)
        except:
            pass
        
        update_fields = """
            question_text = %s, answer = %s, marks = %s, duration_minutes = %s,
            chapter_id = %s, cg_id = %s, comp_id = %s,
            domain_id = %s, knowledge_level_id = %s,
            question_type_id = %s, difficulty_id = %s,
            images = %s, language = %s,
            textbook_id = %s, textbook_name = %s, textbook_publisher = %s,
            textbook_page = %s, reference_book = %s, reference_page = %s,
            updated_at = NOW()
        """
        params = [question_text, answer, marks, duration_minutes, 
                  chapter_id, cg_id, comp_id,
                  domain_id, knowledge_level_id,
                  question_type_id, difficulty_id,
                  images, language,
                  textbook_id, textbook_name, textbook_publisher,
                  textbook_page, reference_book, reference_page]
        
        if data.get('status') is not None:
            update_fields += ", status = %s"
            params.append(data.get('status'))
        
        params.append(question_id)
        
        cur.execute(f"""
            UPDATE simple_questions 
            SET {update_fields}
            WHERE id = %s
        """, params)
        db.commit()
        
        return jsonify({'success': True, 'message': 'Question updated successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/builder-questions', methods=['GET'])
def get_builder_questions():
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
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        user_subject_ids = []
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
        
        if count_only:
            query = """
                SELECT ch.id, ch.chapter_name, COUNT(sq.id) as question_count
                FROM chapters ch
                LEFT JOIN simple_questions sq ON sq.chapter_id = ch.id AND sq.status = 'approved'
                WHERE 1=1
            """
            params = []
            
            if subject_id:
                query += " AND ch.subject_id = %s"
                params.append(subject_id)
            
            if user_role != 'admin' and user_subject_ids and subject_id:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                query += f" AND ch.subject_id IN ({placeholders})"
                params.extend(user_subject_ids)
            
            query += " GROUP BY ch.id"
            cur.execute(query, params)
            results = cur.fetchall()
            
            chapter_counts = {str(r['id']): r['question_count'] for r in results}
            return jsonify({'chapter_counts': chapter_counts})
        
        query = """
            SELECT sq.id, sq.question_text, sq.answer, sq.marks, sq.duration_minutes,
                   sq.competency_code, sq.difficulty_name, sq.domain_name,
                   sq.knowledge_level_name, sq.question_type_name, sq.images,
                   g.grade_name, g.id as grade_id,
                   sub.subject_name, sub.id as subject_id,
                   ch.chapter_name, ch.id as chapter_id,
                   sq.cg_code, sq.comp_id,
                   sq.created_by, sq.created_at, sq.approved_at,
                   sq.reviewed_by, sq.reviewed_comment, sq.language,
                   sq.textbook_name, sq.textbook_publisher, sq.textbook_page,
                   sq.reference_book, sq.reference_page
            FROM simple_questions sq
            LEFT JOIN grades g ON sq.grade_id = g.id
            LEFT JOIN subjects sub ON sq.subject_id = sub.id
            LEFT JOIN chapters ch ON sq.chapter_id = ch.id
            WHERE 1=1
        """
        params = []
        
        if status:
            query += " AND sq.status = %s"
            params.append(status)
        
        if question_ids:
            id_list = [int(x.strip()) for x in question_ids.split(',') if x.strip().isdigit()]
            if id_list:
                placeholders = ','.join(['%s'] * len(id_list))
                query += f" AND sq.id IN ({placeholders})"
                params.extend(id_list)
                cur.execute(query, params)
                questions = cur.fetchall()
                return jsonify({'questions': questions})
        
        if user_role != 'admin' and user_subject_ids:
            placeholders = ','.join(['%s'] * len(user_subject_ids))
            query += f" AND sq.subject_id IN ({placeholders})"
            params.extend(user_subject_ids)
        
        if chapter_ids:
            chapter_list = [int(x.strip()) for x in chapter_ids.split(',') if x.strip().isdigit()]
            if chapter_list:
                placeholders = ','.join(['%s'] * len(chapter_list))
                query += f" AND sq.chapter_id IN ({placeholders})"
                params.extend(chapter_list)
        
        if cg_ids:
            cg_list = [int(x.strip()) for x in cg_ids.split(',') if x.strip().isdigit()]
            if cg_list:
                placeholders = ','.join(['%s'] * len(cg_list))
                query += f" AND sq.cg_id IN ({placeholders})"
                params.extend(cg_list)
        
        if comp_ids:
            comp_list = [int(x.strip()) for x in comp_ids.split(',') if x.strip().isdigit()]
            if comp_list:
                placeholders = ','.join(['%s'] * len(comp_list))
                query += f" AND sq.comp_id IN ({placeholders})"
                params.extend(comp_list)
        
        if grade_id:
            query += " AND sq.grade_id = %s"
            params.append(grade_id)
        
        if subject_id:
            if user_role != 'admin' and user_subject_ids and int(subject_id) not in user_subject_ids:
                return jsonify({'error': 'Access denied to this subject'}), 403
            query += " AND sq.subject_id = %s"
            params.append(subject_id)
        
        query += " ORDER BY sq.question_type_name, sq.difficulty_name LIMIT 500"
        cur.execute(query, params)
        questions = cur.fetchall()
        
        return jsonify({'questions': questions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/page1-data')
def get_page1_data():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        user_subject_ids = []
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
        
        if user_role == 'admin':
            cur.execute("SELECT * FROM grades ORDER BY id")
        else:
            if user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT DISTINCT g.* 
                    FROM grades g
                    JOIN subjects s ON g.id = s.grade_id
                    WHERE s.id IN ({placeholders})
                    ORDER BY g.id
                """, tuple(user_subject_ids))
            else:
                cur.execute("SELECT * FROM grades WHERE 1=0")
        grades = cur.fetchall()
        
        if user_role == 'admin':
            cur.execute("""
                SELECT s.*, g.grade_name 
                FROM subjects s 
                LEFT JOIN grades g ON s.grade_id = g.id 
                ORDER BY s.grade_id, s.id
            """)
        else:
            if user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT s.*, g.grade_name 
                    FROM subjects s 
                    LEFT JOIN grades g ON s.grade_id = g.id 
                    WHERE s.id IN ({placeholders})
                    ORDER BY s.grade_id, s.id
                """, tuple(user_subject_ids))
            else:
                cur.execute("SELECT * FROM subjects WHERE 1=0")
        subjects = cur.fetchall()
        
        if user_role == 'admin':
            cur.execute("""
                SELECT cg.*, s.subject_name, s.grade_id, g.grade_name,
                       ch.chapter_name, ch.id as chapter_id
                FROM curricular_goals cg 
                LEFT JOIN subjects s ON cg.subject_id = s.id 
                LEFT JOIN grades g ON s.grade_id = g.id
                LEFT JOIN chapters ch ON cg.chapter_id = ch.id
                ORDER BY cg.subject_id, cg.id
            """)
        else:
            if user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT cg.*, s.subject_name, s.grade_id, g.grade_name,
                           ch.chapter_name, ch.id as chapter_id
                    FROM curricular_goals cg 
                    LEFT JOIN subjects s ON cg.subject_id = s.id 
                    LEFT JOIN grades g ON s.grade_id = g.id
                    LEFT JOIN chapters ch ON cg.chapter_id = ch.id
                    WHERE cg.subject_id IN ({placeholders})
                    ORDER BY cg.subject_id, cg.id
                """, tuple(user_subject_ids))
            else:
                cur.execute("SELECT * FROM curricular_goals WHERE 1=0")
        cgs = cur.fetchall()
        
        if user_role == 'admin':
            cur.execute("""
                SELECT c.*, cg.cg_code, cg.subject_id, s.subject_name, g.grade_name 
                FROM competencies c 
                LEFT JOIN curricular_goals cg ON c.cg_id = cg.id 
                LEFT JOIN subjects s ON cg.subject_id = s.id 
                LEFT JOIN grades g ON s.grade_id = g.id 
                WHERE c.status = 1
                ORDER BY c.cg_id, c.id
            """)
        else:
            if user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT c.*, cg.cg_code, cg.subject_id, s.subject_name, g.grade_name 
                    FROM competencies c 
                    LEFT JOIN curricular_goals cg ON c.cg_id = cg.id 
                    LEFT JOIN subjects s ON cg.subject_id = s.id 
                    LEFT JOIN grades g ON s.grade_id = g.id 
                    WHERE c.status = 1 AND cg.subject_id IN ({placeholders})
                    ORDER BY c.cg_id, c.id
                """, tuple(user_subject_ids))
            else:
                cur.execute("SELECT * FROM competencies WHERE 1=0")
        competencies = cur.fetchall()
        
        cur.execute("SELECT * FROM question_types")
        question_types = cur.fetchall()
        
        cur.execute("SELECT id, domain_name, description FROM cognitive_domains")
        cognitive_domains = cur.fetchall()
        
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
        
        for subject in subjects:
            grade_id = subject.get('grade_id')
            if grade_id:
                key = str(grade_id)
                if key not in data['subjects_by_grade']:
                    data['subjects_by_grade'][key] = []
                data['subjects_by_grade'][key].append(subject)
        
        for cg in cgs:
            subject_id = cg.get('subject_id')
            if subject_id:
                key = str(subject_id)
                if key not in data['cgs_by_subject']:
                    data['cgs_by_subject'][key] = []
                data['cgs_by_subject'][key].append(cg)
        
        for comp in competencies:
            cg_id = comp.get('cg_id')
            if cg_id:
                key = str(cg_id)
                if key not in data['comps_by_cg']:
                    data['comps_by_cg'][key] = []
                data['comps_by_cg'][key].append(comp)
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/page2-data')
def get_page2_data():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        comp_data = None
        if comp_id:
            cur.execute("""
                SELECT c.*, cg.cg_code, cg.cg_description, 
                       s.subject_name, s.id as subject_id, 
                       g.grade_name, g.id as grade_id
                FROM competencies c
                LEFT JOIN curricular_goals cg ON c.cg_id = cg.id
                LEFT JOIN subjects s ON cg.subject_id = s.id
                LEFT JOIN grades g ON s.grade_id = g.id
                WHERE c.id = %s
            """, (comp_id,))
            comp_data = cur.fetchone()
        
        cur.execute("SELECT * FROM cognitive_domains ORDER BY id")
        domains = cur.fetchall()
        if not domains:
            domains = [
                {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness of concepts and information'},
                {'id': 2, 'domain_name': 'Sensitivity', 'description': 'Sensitivity to applications and real-world connections'},
                {'id': 3, 'domain_name': 'Creativity', 'description': 'Creative thinking and problem solving'}
            ]
        
        cur.execute("SELECT * FROM question_types ORDER BY cognitive_id, id")
        question_types = cur.fetchall()
        
        cur.execute("SELECT * FROM difficulty_levels ORDER BY id")
        difficulty_levels = cur.fetchall()
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
            cognitive_id = qt['cognitive_id']
            if cognitive_id not in data['question_types_by_domain']:
                data['question_types_by_domain'][cognitive_id] = []
            data['question_types_by_domain'][cognitive_id].append(qt)
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/knowledge-levels', methods=['GET'])
def get_knowledge_levels():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    domain_id = request.args.get('domain_id')
    difficulty_id = request.args.get('difficulty_id')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if domain_id:
            cur.execute("""
                SELECT kl.*, cd.domain_name 
                FROM knowledge_levels kl
                LEFT JOIN cognitive_domains cd ON kl.domain_id = cd.id
                WHERE kl.is_active = TRUE 
                AND kl.domain_id = %s
                ORDER BY kl.id
            """, (domain_id,))
        elif difficulty_id:
            cur.execute("""
                SELECT kl.*, cd.domain_name 
                FROM knowledge_levels kl
                LEFT JOIN cognitive_domains cd ON kl.domain_id = cd.id
                WHERE kl.is_active = TRUE 
                AND kl.difficulty_id = %s
                ORDER BY kl.id
            """, (difficulty_id,))
        else:
            cur.execute("""
                SELECT kl.*, cd.domain_name 
                FROM knowledge_levels kl
                LEFT JOIN cognitive_domains cd ON kl.domain_id = cd.id
                WHERE kl.is_active = TRUE 
                ORDER BY kl.domain_id, kl.id
            """)
        levels = cur.fetchall()
        
        if not levels:
            default_mapping = [
                {'id': 1, 'level_name': 'Knowledge', 'domain_id': 1, 'domain_name': 'Awareness', 'description': 'Basic recall of information and facts'},
                {'id': 2, 'level_name': 'Remembering', 'domain_id': 1, 'domain_name': 'Awareness', 'description': 'Retrieving knowledge from memory'},
                {'id': 3, 'level_name': 'Understanding', 'domain_id': 1, 'domain_name': 'Awareness', 'description': 'Constructing meaning from information'},
                {'id': 4, 'level_name': 'Comprehension', 'domain_id': 1, 'domain_name': 'Awareness', 'description': 'Grasping the meaning of information'},
                {'id': 5, 'level_name': 'Application', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': 'Apply knowledge to new situations'},
                {'id': 6, 'level_name': 'Analysis', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': 'Break down information into parts'},
                {'id': 7, 'level_name': 'Synthesis', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': 'Combine elements to form a new whole'},
                {'id': 8, 'level_name': 'Empathy', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': "Understanding others' perspectives and feelings"},
                {'id': 9, 'level_name': 'Interpretation', 'domain_id': 2, 'domain_name': 'Sensitivity', 'description': 'Explaining and interpreting information'},
                {'id': 10, 'level_name': 'Evaluation', 'domain_id': 3, 'domain_name': 'Creativity', 'description': 'Make judgments based on criteria and standards'},
                {'id': 11, 'level_name': 'Creation', 'domain_id': 3, 'domain_name': 'Creativity', 'description': 'Generate new ideas and products'},
                {'id': 12, 'level_name': 'Critical Thinking', 'domain_id': 3, 'domain_name': 'Creativity', 'description': 'Deep analysis and evaluation of information'},
                {'id': 13, 'level_name': 'Innovation', 'domain_id': 3, 'domain_name': 'Creativity', 'description': 'Novel approaches and solutions to problems'},
                {'id': 14, 'level_name': 'Design Thinking', 'domain_id': 3, 'domain_name': 'Creativity', 'description': 'Human-centered problem solving approach'},
                {'id': 15, 'level_name': 'Reflection', 'domain_id': 3, 'domain_name': 'Creativity', 'description': 'Thoughtful consideration and self-assessment'}
            ]
            
            if domain_id:
                levels = [l for l in default_mapping if l['domain_id'] == int(domain_id)]
            else:
                levels = default_mapping
        
        return jsonify({'knowledge_levels': levels})
    except Exception as e:
        return jsonify({'knowledge_levels': []})
    finally:
        cur.close()
        db.close()

@app.route('/api/cognitive-domains', methods=['GET'])
def get_cognitive_domains():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, domain_name, description FROM cognitive_domains ORDER BY id")
        domains = cur.fetchall()
        
        if not domains:
            domains = [
                {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness of concepts and information'},
                {'id': 2, 'domain_name': 'Sensitivity', 'description': 'Sensitivity to applications and real-world connections'},
                {'id': 3, 'domain_name': 'Creativity', 'description': 'Creative thinking and problem solving'}
            ]
        
        return jsonify({'domains': domains})
    except Exception as e:
        return jsonify({
            'domains': [
                {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness of concepts and information'},
                {'id': 2, 'domain_name': 'Sensitivity', 'description': 'Sensitivity to applications and real-world connections'},
                {'id': 3, 'domain_name': 'Creativity', 'description': 'Creative thinking and problem solving'}
            ]
        })
    finally:
        cur.close()
        db.close()


@app.route('/api/simple-questions')
def get_simple_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    username = session.get('user')
    subject_group = session.get('subject_group')
    user_role = session.get('user_role')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        user_subject_ids = []
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
        
        query = """
            SELECT id, question_text, answer, marks, duration_minutes,
                   competency_code, difficulty_name, domain_name,
                   knowledge_level_name, question_type_name,
                   grade_name, subject_name, chapter_name, cg_code,
                   created_by, created_at, comp_id,
                   status, rejection_reason, reviewed_by, reviewed_at,
                   images, language,
                   domain_id, knowledge_level_id, question_type_id, difficulty_id,
                   textbook_id, textbook_name, textbook_publisher, textbook_page,
                   reference_book, reference_page
            FROM simple_questions 
            WHERE created_by = %s
        """
        params = [username]
        
        if user_role != 'admin' and user_subject_ids:
            placeholders = ','.join(['%s'] * len(user_subject_ids))
            query += f" AND subject_id IN ({placeholders})"
            params.extend(user_subject_ids)
        
        if comp_id and comp_id != '0':
            query += " AND comp_id = %s"
            params.append(comp_id)
        
        query += " ORDER BY id DESC LIMIT 50"
        cur.execute(query, tuple(params))
        questions = cur.fetchall()
        
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
    finally:
        cur.close()
        db.close()

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
        db_check = get_db()
        cur_check = db_check.cursor(dictionary=True)
        try:
            cur_check.execute("""
                SELECT subject_id FROM subject_groups 
                WHERE group_code = %s AND subject_id = %s
            """, (subject_group, subject_id))
            if not cur_check.fetchone():
                return jsonify({'error': 'Access denied to this subject'}), 403
        finally:
            cur_check.close()
            db_check.close()
    
    db = get_db()
    cur = db.cursor()
    
    try:
        
        if chapter_id:
            cur.execute("SELECT id FROM chapters WHERE id = %s", (chapter_id,))
            if not cur.fetchone():
                chapter_id = None
                chapter_name = None
        
        if cg_id:
            cur.execute("SELECT id FROM curricular_goals WHERE id = %s", (cg_id,))
            if not cur.fetchone():
                cg_id = None
                cg_code = None
        
        if comp_id:
            cur.execute("SELECT id FROM competencies WHERE id = %s", (comp_id,))
            if not cur.fetchone():
                comp_id = None
                competency_code = None
        
        if domain_id:
            cur.execute("SELECT id FROM cognitive_domains WHERE id = %s", (domain_id,))
            if not cur.fetchone():
                domain_id = None
                domain_name = None
        
        if knowledge_level_id:
            cur.execute("SELECT id FROM knowledge_levels WHERE id = %s", (knowledge_level_id,))
            if not cur.fetchone():
                knowledge_level_id = None
                knowledge_level_name = None
        
        if question_type_id:
            cur.execute("SELECT id FROM question_types WHERE id = %s", (question_type_id,))
            if not cur.fetchone():
                question_type_id = None
                question_type_name = None
        
        if difficulty_id:
            cur.execute("SELECT id FROM difficulty_levels WHERE id = %s", (difficulty_id,))
            if not cur.fetchone():
                difficulty_id = None
                difficulty_name = None
        
        if grade_id:
            cur.execute("SELECT id FROM grades WHERE id = %s", (grade_id,))
            if not cur.fetchone():
                grade_id = None
                grade_name = None
        
        if subject_id:
            cur.execute("SELECT id FROM subjects WHERE id = %s", (subject_id,))
            if not cur.fetchone():
                subject_id = None
                subject_name = None
        
        if textbook_id:
            cur.execute("SELECT id FROM textbooks WHERE id = %s", (textbook_id,))
            if not cur.fetchone():
                textbook_id = None
                textbook_name = None
        
        username = session.get('user', 'Unknown')
        current_time = datetime.now()
        
        cur.execute("""
            INSERT INTO simple_questions (
                question_text, answer, marks, duration_minutes, 
                comp_id, created_by, created_at,
                grade_id, subject_id, chapter_id, cg_id, domain_id, 
                knowledge_level_id, question_type_id, difficulty_id,
                competency_code, domain_name, knowledge_level_name,
                question_type_name, difficulty_name, grade_name,
                subject_name, chapter_name, chapter_code, cg_code, 
                images, language, status,
                textbook_id, textbook_name, textbook_publisher,
                textbook_page, reference_book, reference_page
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                %s, %s, %s, 'unassigned', %s, %s, %s, %s, %s, %s
            )
        """, (
            question_text, answer, marks, duration_minutes,
            comp_id, username, current_time,
            grade_id, subject_id, chapter_id, cg_id, domain_id,
            knowledge_level_id, question_type_id, difficulty_id,
            competency_code, domain_name, knowledge_level_name,
            question_type_name, difficulty_name, grade_name,
            subject_name, chapter_name, chapter_code, cg_code,
            images, language,
            textbook_id, textbook_name, textbook_publisher,
            textbook_page, reference_book, reference_page
        ))
        db.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Question saved successfully',
            'id': cur.lastrowid,
            'language': language,
            'status': 'unassigned'
        })
    except mysql.connector.Error as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/create-question', methods=['POST'])
def create_question():
    return create_simple_question()

@app.route('/api/delete-question/<int:question_id>', methods=['DELETE'])
def delete_question(question_id):
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM simple_questions WHERE id = %s", (question_id,))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


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
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        user_subject_ids = []
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
        
        if user_role == 'admin':
            cur.execute("""
                SELECT bp.*, g.grade_name, s.subject_name
                FROM paper_blueprints bp
                LEFT JOIN grades g ON bp.grade_id = g.id
                LEFT JOIN subjects s ON bp.subject_id = s.id
                ORDER BY bp.updated_at DESC, bp.created_at DESC
            """)
        else:
            if user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT bp.*, g.grade_name, s.subject_name
                    FROM paper_blueprints bp
                    LEFT JOIN grades g ON bp.grade_id = g.id
                    LEFT JOIN subjects s ON bp.subject_id = s.id
                    WHERE bp.subject_id IN ({placeholders}) OR bp.created_by = %s
                    ORDER BY bp.updated_at DESC, bp.created_at DESC
                """, tuple(user_subject_ids + [username]))
            else:
                cur.execute("""
                    SELECT bp.*, g.grade_name, s.subject_name
                    FROM paper_blueprints bp
                    LEFT JOIN grades g ON bp.grade_id = g.id
                    LEFT JOIN subjects s ON bp.subject_id = s.id
                    WHERE bp.created_by = %s
                    ORDER BY bp.updated_at DESC, bp.created_at DESC
                """, (username,))
        
        blueprints = cur.fetchall()
        for bp in blueprints:
            bp['cg_ids'] = [int(x) for x in bp['cg_ids'].split(',')] if bp['cg_ids'] else []
            bp['comp_ids'] = [int(x) for x in bp['comp_ids'].split(',')] if bp['comp_ids'] else []
            bp['question_ids'] = [int(x) for x in bp['question_ids'].split(',')] if bp['question_ids'] else []
            
            config_data = {}
            if bp['config']:
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
    finally:
        cur.close()
        db.close()


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
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO paper_blueprints 
            (name, grade_id, subject_id, cg_ids, comp_ids, question_ids, config, cognitive_config, created_by, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            name, grade_id, subject_id,
            ','.join(map(str, cg_ids)) if cg_ids else None,
            ','.join(map(str, comp_ids)) if comp_ids else None,
            ','.join(map(str, question_ids)) if question_ids else None,
            json.dumps(main_config) if main_config else None,
            json.dumps(cognitive_config) if cognitive_config else None,
            username,
            status
        ))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Blueprint saved successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/paper-blueprints/<int:blueprint_id>', methods=['GET'])
def get_paper_blueprint(blueprint_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT bp.*, g.grade_name, s.subject_name
            FROM paper_blueprints bp
            LEFT JOIN grades g ON bp.grade_id = g.id
            LEFT JOIN subjects s ON bp.subject_id = s.id
            WHERE bp.id = %s
        """, (blueprint_id,))
        blueprint = cur.fetchone()
        
        if not blueprint:
            return jsonify({'error': 'Blueprint not found'}), 404
        
        blueprint['cg_ids'] = [int(x) for x in blueprint['cg_ids'].split(',')] if blueprint['cg_ids'] else []
        blueprint['comp_ids'] = [int(x) for x in blueprint['comp_ids'].split(',')] if blueprint['comp_ids'] else []
        blueprint['question_ids'] = [int(x) for x in blueprint['question_ids'].split(',')] if blueprint['question_ids'] else []
        
        config_data = {}
        if blueprint['config']:
            try:
                config_data = json.loads(blueprint['config'])
            except:
                config_data = {}
        
        if blueprint.get('cognitive_config'):
            try:
                cognitive_data = json.loads(blueprint['cognitive_config'])
                if cognitive_data:
                    config_data['cognitive'] = cognitive_data
            except:
                pass
        
        blueprint['config'] = config_data
        
        return jsonify({'blueprint': blueprint})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/paper-blueprints/<int:blueprint_id>', methods=['PUT'])
def update_paper_blueprint(blueprint_id):
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
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE paper_blueprints 
            SET name = %s, grade_id = %s, subject_id = %s, 
                cg_ids = %s, comp_ids = %s, question_ids = %s, 
                config = %s, cognitive_config = %s, status = %s,
                updated_at = NOW()
            WHERE id = %s
        """, (
            name, grade_id, subject_id,
            ','.join(map(str, cg_ids)) if cg_ids else None,
            ','.join(map(str, comp_ids)) if comp_ids else None,
            ','.join(map(str, question_ids)) if question_ids else None,
            json.dumps(main_config) if main_config else None,
            json.dumps(cognitive_config) if cognitive_config else None,
            status,
            blueprint_id
        ))
        db.commit()
        
        if cur.rowcount == 0:
            return jsonify({'error': 'Blueprint not found'}), 404
        
        return jsonify({'success': True, 'id': blueprint_id, 'message': 'Blueprint updated successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/paper-blueprints/<int:blueprint_id>', methods=['DELETE'])
def delete_paper_blueprint(blueprint_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM paper_blueprints WHERE id = %s", (blueprint_id,))
        db.commit()
        
        if cur.rowcount == 0:
            return jsonify({'error': 'Blueprint not found'}), 404
        
        return jsonify({'success': True, 'message': 'Blueprint deleted successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/pending-count')
def get_pending_count():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('user_role')
    subject_group = session.get('subject_group')
    
    db = get_db()
    cur = db.cursor()
    try:
        if user_role == 'admin':
            cur.execute("SELECT COUNT(*) FROM simple_questions WHERE status IN ('unassigned', 'under_review')")
        else:
            cur.execute("""
                SELECT COUNT(*) 
                FROM simple_questions sq
                JOIN subject_groups sg ON sq.subject_id = sg.subject_id
                WHERE sq.status IN ('unassigned', 'under_review') 
                AND sg.group_code = %s
            """, (subject_group,))
        count = cur.fetchone()[0]
        return jsonify({'pending_count': count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

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
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT status, COUNT(*) as count 
            FROM simple_questions 
            GROUP BY status
        """)
        status_counts = cur.fetchall()
        
        cur.execute("""
            SELECT id, question_text, status, subject_id, chapter_id, cg_id, comp_id, 
                   domain_id, knowledge_level_id, question_type_id, difficulty_id, language
            FROM simple_questions 
            WHERE status = 'approved' 
            LIMIT 10
        """)
        sample_questions = cur.fetchall()
        
        cur.execute("""
            SELECT s.id, s.subject_name, COUNT(sq.id) as approved_count
            FROM subjects s
            LEFT JOIN simple_questions sq ON sq.subject_id = s.id AND sq.status = 'approved'
            GROUP BY s.id
            ORDER BY approved_count DESC
        """)
        subjects_with_questions = cur.fetchall()
        
        return jsonify({
            'status_counts': status_counts,
            'sample_approved_questions': sample_questions,
            'subjects_with_questions': subjects_with_questions,
            'total_questions': sum([s['count'] for s in status_counts]) if status_counts else 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/debug/cgs')
def debug_cgs():
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT cg.id, cg.cg_code, cg.cg_description, cg.subject_id, cg.chapter_id,
                   s.subject_name, s.grade_id, g.grade_name,
                   ch.chapter_name,
                   (SELECT COUNT(*) FROM competencies WHERE cg_id = cg.id) as comp_count
            FROM curricular_goals cg
            LEFT JOIN subjects s ON cg.subject_id = s.id
            LEFT JOIN grades g ON s.grade_id = g.id
            LEFT JOIN chapters ch ON cg.chapter_id = ch.id
            ORDER BY cg.id
        """)
        cgs = cur.fetchall()
        
        cur.execute("""
            SELECT c.id, c.comp_code, c.comp_description, c.cg_id, c.status,
                   cg.cg_code, cg.subject_id, cg.chapter_id
            FROM competencies c
            LEFT JOIN curricular_goals cg ON c.cg_id = cg.id
            ORDER BY c.id
        """)
        comps = cur.fetchall()
        
        return jsonify({
            'curricular_goals': cgs,
            'competencies': comps,
            'cg_count': len(cgs),
            'comp_count': len(comps)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=False, port=5000)