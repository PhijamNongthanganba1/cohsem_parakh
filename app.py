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
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    """Get database connection"""
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="nong@123",
        database="cohsem_IT"
    )
def add_column_if_not_exists(cursor, table, column, definition):
    """Helper function to add a column if it doesn't exist"""
    cursor.execute(f"SHOW COLUMNS FROM {table} LIKE '{column}'")
    exists = cursor.fetchone()
    if not exists:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        print(f"Added column {column} to {table}")
        return True
    return False

def init_db():
    """Initialize database tables if they don't exist"""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'writer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        add_column_if_not_exists(cur, 'users', 'subject_group', 'VARCHAR(50)')
        add_column_if_not_exists(cur, 'users', 'group_role', "VARCHAR(50) DEFAULT 'member'")
        add_column_if_not_exists(cur, 'users', 'perm_re', 'BOOLEAN DEFAULT FALSE')
        add_column_if_not_exists(cur, 'users', 'perm_ra', 'BOOLEAN DEFAULT FALSE')
        add_column_if_not_exists(cur, 'users', 'perm_rc', 'BOOLEAN DEFAULT FALSE')
        add_column_if_not_exists(cur, 'users', 'perm_ap', 'BOOLEAN DEFAULT FALSE')
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
                FOREIGN KEY (grade_id) REFERENCES grades(id),
                INDEX idx_grade_id (grade_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chapters (
                id INT PRIMARY KEY AUTO_INCREMENT,
                subject_id INT NOT NULL,
                chapter_code VARCHAR(50),
                chapter_name VARCHAR(200) NOT NULL,
                chapter_number INT DEFAULT 0,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
                INDEX idx_subject_id (subject_id),
                UNIQUE KEY unique_chapter_subject (subject_id, chapter_name)
            )
        """)
        print("Chapters table created or already exists")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_levels (
                id INT PRIMARY KEY AUTO_INCREMENT,
                level_name VARCHAR(100) NOT NULL,
                description TEXT,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS difficulty_levels (
                id INT PRIMARY KEY AUTO_INCREMENT,
                level_name VARCHAR(50) NOT NULL
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
            CREATE TABLE IF NOT EXISTS question_types (
                id INT PRIMARY KEY AUTO_INCREMENT,
                type_name VARCHAR(100) NOT NULL,
                cognitive_id INT,
                description TEXT,
                FOREIGN KEY (cognitive_id) REFERENCES cognitive_domains(id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS curricular_goals (
                id INT PRIMARY KEY AUTO_INCREMENT,
                cg_code VARCHAR(50),
                cg_description TEXT,
                subject_id INT,
                FOREIGN KEY (subject_id) REFERENCES subjects(id),
                INDEX idx_subject_id (subject_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS competencies (
                id INT PRIMARY KEY AUTO_INCREMENT,
                comp_code VARCHAR(50),
                comp_description TEXT,
                cg_id INT,
                status BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (cg_id) REFERENCES curricular_goals(id),
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
                FOREIGN KEY (grade_id) REFERENCES grades(id),
                FOREIGN KEY (subject_id) REFERENCES subjects(id),
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
                status VARCHAR(20) DEFAULT 'under_review',
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
                INDEX idx_comp_id (comp_id),
                INDEX idx_created_by (created_by),
                INDEX idx_created_at (created_at),
                INDEX idx_status (status),
                INDEX idx_subject_id (subject_id),
                INDEX idx_chapter_id (chapter_id)
            )
        """)
        add_column_if_not_exists(cur, 'simple_questions', 'approved_by', 'VARCHAR(100)')
        add_column_if_not_exists(cur, 'simple_questions', 'reviewed_at', 'TIMESTAMP NULL')
        add_column_if_not_exists(cur, 'simple_questions', 'reviewed_comment', 'TEXT')
        add_column_if_not_exists(cur, 'simple_questions', 'approved_at', 'TIMESTAMP NULL')
        add_column_if_not_exists(cur, 'simple_questions', 'used_in_papers', 'INT DEFAULT 0')
        add_column_if_not_exists(cur, 'simple_questions', 'duration_minutes', 'INT DEFAULT 0')
        add_column_if_not_exists(cur, 'simple_questions', 'chapter_id', 'INT')
        add_column_if_not_exists(cur, 'simple_questions', 'chapter_name', 'VARCHAR(200)')
        add_column_if_not_exists(cur, 'simple_questions', 'chapter_code', 'VARCHAR(50)')
        add_column_if_not_exists(cur, 'simple_questions', 'images', 'TEXT')
        add_column_if_not_exists(cur, 'simple_questions', 'updated_at', 'TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP')
        add_column_if_not_exists(cur, 'simple_questions', 'rejected_by', 'VARCHAR(100)')
        add_column_if_not_exists(cur, 'simple_questions', 'rejected_at', 'TIMESTAMP NULL')
        db.commit()
        cur.execute("SELECT COUNT(*) FROM grades")
        if cur.fetchone()[0] == 0:
            print("Inserting default grades and subjects...")
            cur.execute("INSERT INTO grades (grade_name) VALUES ('Grade 11'), ('Grade 12')")
            subjects = [
                (1, 'Physics'), (1, 'Chemistry'), (1, 'Biology'), (1, 'Mathematics'),
                (2, 'Physics'), (2, 'Chemistry'), (2, 'Biology'), (2, 'Mathematics'),
                (1, 'Computer Science'), (2, 'Computer Science'),
                (1, 'Geography'), (2, 'Geography'),
                (1, 'History'), (2, 'History'),
                (1, 'English'), (2, 'English')
            ]
            for grade_id, subject in subjects:
                cur.execute("INSERT INTO subjects (grade_id, subject_name) VALUES (%s, %s)", (grade_id, subject))
            cur.execute("SELECT id, subject_name, grade_id FROM subjects")
            subjects_data = cur.fetchall()
            subject_map = {}
            for s in subjects_data:
                subject_map[(s[2], s[1])] = s[0]
            sample_chapters = [
                (subject_map.get((1, 'Physics'), 1), 'PHY-11-01', 'Physical World', 1, 'Introduction to physics and its scope'),
                (subject_map.get((1, 'Physics'), 1), 'PHY-11-02', 'Units and Measurements', 2, 'SI units, measurement techniques'),
                (subject_map.get((1, 'Chemistry'), 2), 'CHM-11-01', 'Some Basic Concepts of Chemistry', 1, 'Mole concept, stoichiometry'),
                (subject_map.get((1, 'Mathematics'), 4), 'MTH-11-01', 'Sets', 1, 'Sets and their representations'),
                (subject_map.get((1, 'Mathematics'), 4), 'MTH-11-02', 'Relations and Functions', 2, 'Cartesian product, relations, functions'),
                (subject_map.get((2, 'Physics'), 5), 'PHY-12-01', 'Electric Charges and Fields', 1, 'Coulomb\'s law, electric field'),
                (subject_map.get((2, 'Chemistry'), 6), 'CHM-12-01', 'Solutions', 1, 'Types of solutions, concentration terms'),
                (subject_map.get((2, 'Mathematics'), 8), 'MTH-12-01', 'Relations and Functions', 1, 'Types of relations and functions'),
            ]
            for subject_id, code, name, number, desc in sample_chapters:
                if subject_id:
                    cur.execute("""
                        INSERT INTO chapters (subject_id, chapter_code, chapter_name, chapter_number, description)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (subject_id, code, name, number, desc))
            levels = [
                ('Knowledge', 'Recall of specific information'),
                ('Remembering', 'Retrieving knowledge from memory'),
                ('Understanding', 'Constructing meaning'),
                ('Comprehension', 'Grasping the meaning'),
                ('Application', 'Applying knowledge to new situations')
            ]
            for level, desc in levels:
                cur.execute("INSERT INTO knowledge_levels (level_name, description) VALUES (%s, %s)", (level, desc))
            cur.execute("INSERT INTO difficulty_levels (level_name) VALUES ('Easy'), ('Medium'), ('Hard')")
            domains = [
                ('Awareness', 'Basic awareness of concepts'),
                ('Sensitivity', 'Sensitivity to applications'),
                ('Creativity', 'Creative thinking and problem solving')
            ]
            for domain, desc in domains:
                cur.execute("INSERT INTO cognitive_domains (domain_name, description) VALUES (%s, %s)", (domain, desc))
            question_types = [
                ('Objective', 1, 'Multiple choice questions'),
                ('Very Short Answer', 1, 'One word answers'),
                ('Short Answer', 2, 'Brief explanations'),
                ('Long Answer', 3, 'Detailed answers')
            ]
            for type_name, cognitive_id, desc in question_types:
                cur.execute("INSERT INTO question_types (type_name, cognitive_id, description) VALUES (%s, %s, %s)", 
                          (type_name, cognitive_id, desc))
            groups = [
                ('phy_grp_11', 'Physics Group Class 11', 1, 1),
                ('chem_grp_11', 'Chemistry Group Class 11', 1, 2),
                ('bio_grp_11', 'Biology Group Class 11', 1, 3),
                ('math_grp_11', 'Mathematics Group Class 11', 1, 4),
                ('cs_grp_11', 'Computer Science Group Class 11', 1, 9),
                ('phy_grp_12', 'Physics Group Class 12', 2, 5),
                ('chem_grp_12', 'Chemistry Group Class 12', 2, 6),
                ('bio_grp_12', 'Biology Group Class 12', 2, 7),
                ('math_grp_12', 'Mathematics Group Class 12', 2, 8),
                ('cs_grp_12', 'Computer Science Group Class 12', 2, 10)
            ]
            for code, name, grade_id, subject_id in groups:
                cur.execute("""
                    INSERT INTO subject_groups (group_code, group_name, grade_id, subject_id)
                    VALUES (%s, %s, %s, %s)
                """, (code, name, grade_id, subject_id))
            admin_password = generate_password_hash('admin123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, ('admin', admin_password, 'admin', 'leader', True, True, True, True))
            writer_password = generate_password_hash('writer123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, ('writer', writer_password, 'writer', 'member', True, False, False, False))
            reviewer_password = generate_password_hash('reviewer123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, ('reviewer', reviewer_password, 'reviewer', 'member', False, False, True, False))
            approver_password = generate_password_hash('approver123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, ('approver', approver_password, 'approver', 'member', False, False, False, True))
            builder_password = generate_password_hash('builder123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, ('builder', builder_password, 'builder', 'member', False, True, False, False))
            db.commit()
            print("Default data inserted successfully")
        cur.execute("SELECT COUNT(*) FROM simple_questions")
        count = cur.fetchone()[0]
        if count == 0:
            print("Inserting sample questions with chapters...")
            cur.execute("SELECT id, subject_name, grade_id FROM subjects")
            subjects_data = cur.fetchall()
            subject_map = {}
            for s in subjects_data:
                subject_map[(s[2], s[1])] = s[0]
            cur.execute("SELECT id, subject_id, chapter_name FROM chapters")
            chapters_data = cur.fetchall()
            chapter_map = {}
            for c in chapters_data:
                chapter_map[(c[1], c[2])] = c[0]
            sample_questions = [
                (
                    'State Newton\'s First Law of Motion',
                    'An object at rest stays at rest and an object in motion stays in motion with the same speed and in the same direction unless acted upon by an unbalanced force.',
                    2, 5,
                    subject_map.get((1, 'Physics'), 1),
                    chapter_map.get((1, 'Physical World'), None),
                    1,
                    'admin',
                    'approved',
                    'Grade 11',
                    'Physics',
                    'Physical World',
                    'PHY-11-01',
                    'Laws of Motion',
                    'Easy',
                    'Awareness',
                    'Knowledge',
                    'Short Answer',
                    'admin',
                    None
                ),
                (
                    'Solve the quadratic equation: x² - 5x + 6 = 0',
                    'x = 2 or x = 3',
                    2, 5,
                    subject_map.get((1, 'Mathematics'), 4),
                    chapter_map.get((4, 'Sets'), None),
                    1,
                    'admin',
                    'approved',
                    'Grade 11',
                    'Mathematics',
                    'Sets',
                    'MTH-11-01',
                    'Quadratic Equations',
                    'Easy',
                    'Awareness',
                    'Knowledge',
                    'Short Answer',
                    'admin',
                    None
                ),
                (
                    'What is the atomic number of Carbon?',
                    '6',
                    1, 2,
                    subject_map.get((1, 'Chemistry'), 2),
                    chapter_map.get((2, 'Some Basic Concepts of Chemistry'), None),
                    1,
                    'writer',
                    'under_review',
                    'Grade 11',
                    'Chemistry',
                    'Some Basic Concepts of Chemistry',
                    'CHE-11-01',
                    'Atomic Structure',
                    'Easy',
                    'Awareness',
                    'Knowledge',
                    'Objective',
                    None,
                    None
                ),
                (
                    'Explain the process of osmosis',
                    'The movement of solvent molecules through a semipermeable membrane from a region of lower solute concentration to higher solute concentration',
                    3, 10,
                    subject_map.get((1, 'Biology'), 3),
                    None,
                    1,
                    'writer',
                    'under_review',
                    'Grade 11',
                    'Biology',
                    None,
                    'BIO-11-02',
                    'Cell Biology',
                    'Medium',
                    'Sensitivity',
                    'Understanding',
                    'Long Answer',
                    None,
                    None
                ),
                (
                    'What is the capital of France?',
                    'Paris',
                    1, 1,
                    subject_map.get((1, 'Geography'), 11),
                    None,
                    1,
                    'writer',
                    'under_review',
                    'Grade 11',
                    'Geography',
                    None,
                    'GEO-11-01',
                    'World Geography',
                    'Easy',
                    'Awareness',
                    'Knowledge',
                    'Objective',
                    None,
                    None
                ),
                (
                    'Find the derivative of f(x) = x³ + 2x² - 5x + 7',
                    'f\'(x) = 3x² + 4x - 5',
                    2, 8,
                    subject_map.get((2, 'Mathematics'), 8),
                    chapter_map.get((8, 'Relations and Functions'), None),
                    2,
                    'admin',
                    'approved',
                    'Grade 12',
                    'Mathematics',
                    'Relations and Functions',
                    'MTH-12-01',
                    'Calculus',
                    'Medium',
                    'Understanding',
                    'Comprehension',
                    'Short Answer',
                    'admin',
                    None
                ),
                (
                    'State Ohm\'s Law',
                    'The current through a conductor is directly proportional to the voltage across it, provided temperature remains constant. V = IR',
                    2, 4,
                    subject_map.get((2, 'Physics'), 5),
                    chapter_map.get((5, 'Electric Charges and Fields'), None),
                    2,
                    'admin',
                    'approved',
                    'Grade 12',
                    'Physics',
                    'Electric Charges and Fields',
                    'PHY-12-01',
                    'Current Electricity',
                    'Easy',
                    'Awareness',
                    'Knowledge',
                    'Short Answer',
                    'admin',
                    None
                )
            ]
            for q in sample_questions:
                try:
                    (question_text, answer, marks, duration_minutes, subject_id, chapter_id, grade_id,
                     created_by, status, grade_name, subject_name, chapter_name, competency_code,
                     domain_name, difficulty_name, knowledge_level_name, question_type_name,
                     reviewed_by, reviewed_comment) = q
                    cur.execute("""
                        INSERT INTO simple_questions (
                            question_text, answer, marks, duration_minutes, subject_id, chapter_id, grade_id,
                            created_by, status, grade_name, subject_name, chapter_name, competency_code,
                            domain_name, difficulty_name, knowledge_level_name, question_type_name,
                            reviewed_by, reviewed_comment, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """, (question_text, answer, marks, duration_minutes, subject_id, chapter_id, grade_id,
                          created_by, status, grade_name, subject_name, chapter_name, competency_code,
                          domain_name, difficulty_name, knowledge_level_name, question_type_name,
                          reviewed_by, reviewed_comment))
                except Exception as e:
                    print(f"Error inserting sample question: {e}")
            db.commit()
            print(f"Inserted {len(sample_questions)} sample questions")
            cur.execute("""
                UPDATE simple_questions 
                SET approved_at = NOW(), approved_by = reviewed_by 
                WHERE status = 'approved' AND approved_at IS NULL
            """)
            db.commit()
    except Exception as e:
        print(f"Database initialization error: {e}")
        traceback.print_exc()
        db.rollback()
    finally:
        cur.close()
        db.close()
print("Initializing database...")
init_db()
print("Database initialization complete")
@app.route('/')
def home():
    return redirect(url_for('dashboard_login'))
@app.route('/dashboard-login', methods=['GET', 'POST'])
def dashboard_login():
    """Main login page"""
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
    """Registration page - creates basic writer account"""
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
    """Main dashboard page"""
    if 'user' not in session:
        flash('Please login to access the dashboard', 'error')
        return redirect(url_for('dashboard_login'))
    
    user_role = session.get('user_role', 'writer')
    username = session.get('user', 'User')
    
    permissions = {
        'RE': session.get('perm_re', False),
        'RA': session.get('perm_ra', False),
        'RC': session.get('perm_rc', False),
        'AP': session.get('perm_ap', False)
    }
    
    return render_template('dashboard.html', 
                         user=username, 
                         user_role=user_role,
                         permissions=permissions)

@app.route('/complete-selection')
def questions_upload():
    """Question selection page - Requires RE permission"""
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    if not session.get('perm_re', False) and session.get('user_role') != 'admin':
        flash('Access Denied: Writer (RE) permission required', 'error')
        return redirect(url_for('dashboard'))
    return render_template('questions_upload.html', user=session['user'])
@app.route('/page2')
def page2():
    """Question creation page - Requires RE permission"""
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    
    if not session.get('perm_re', False) and session.get('user_role') != 'admin':
        flash('Access Denied: Writer (RE) permission required', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('questions_upload_2.html', user=session['user'])

@app.route('/question-paper-builder')
def question_paper_builder():
    """Question paper builder - Requires RA permission"""
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    if not session.get('perm_ra', False) and session.get('user_role') != 'admin':
        flash('Access Denied: Builder (RA) permission required', 'error')
        return redirect(url_for('dashboard'))
    return render_template('question_paper_builder.html', user=session['user'])
@app.route('/configure')
def configure():
    """Configuration page - Admin only"""
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    
    if session.get('user_role') != 'admin':
        flash('Access Denied: Admin privileges required', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('configure_dashboard.html', user=session['user'])

@app.route('/review')
def review():
    """My List page - Shows questions based on permissions"""
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    username = session.get('user', 'User')
    user_role = session.get('user_role', 'writer')
    permissions = {
        'RE': session.get('perm_re', False),
        'RA': session.get('perm_ra', False),
        'RC': session.get('perm_rc', False),
        'AP': session.get('perm_ap', False)
    }
    page_title = "Questions List"
    if user_role == 'admin':
        page_title = "All Questions"
    elif permissions.get('AP'):
        page_title = "Questions Ready for Approval"
    elif permissions.get('RC'):
        page_title = "Questions Under Review"
    elif permissions.get('RA'):
        page_title = "Approved Questions for Paper Building"
    elif permissions.get('RE'):
        page_title = "My Questions"
    return render_template('review.html', 
                         user=username, 
                         user_role=user_role,
                         permissions=permissions,
                         page_title=page_title)
@app.route('/my-questions')
def my_questions():
    return redirect(url_for('review'))
@app.route('/admin/users')
def admin_users():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    if session.get('user_role') != 'admin':
        flash('Access Denied: Admin privileges required', 'error')
        return redirect(url_for('dashboard'))
    return render_template('admin_users.html', user=session['user'])
@app.route('/admin/question-papers')
def admin_question_papers():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    if session.get('user_role') != 'admin':
        flash('Access Denied: Admin privileges required', 'error')
        return redirect(url_for('dashboard'))
    return render_template('admin_papers.html', user=session['user'])
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('dashboard_login'))
@app.route('/api/dashboard-stats')
def dashboard_stats():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SHOW TABLES LIKE 'simple_questions'")
        if not cur.fetchone():
            return jsonify({})
        cur.execute("SELECT id, subject_name FROM subjects")
        all_subjects = cur.fetchall()
        subjects_dict = {s['id']: s['subject_name'] for s in all_subjects}
        cur.execute("SELECT id, grade_name FROM grades ORDER BY id")
        all_grades = cur.fetchall()
        stats = {}
        class11_stats = {'total': 0, 'approved': 0, 'under_review': 0, 'reviewed_completed': 0, 'rejected': 0, 'subjects': {}}
        class12_stats = {'total': 0, 'approved': 0, 'under_review': 0, 'reviewed_completed': 0, 'rejected': 0, 'subjects': {}}
        for grade in all_grades:
            grade_id = grade['id']
            grade_name = grade['grade_name']
            cur.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                    SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                    SUM(CASE WHEN status = 'reviewed_completed' THEN 1 ELSE 0 END) as reviewed_completed,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
                FROM simple_questions 
                WHERE grade_id = %s
            """, (grade_id,))
            grade_stats = cur.fetchone()
            cur.execute("""
                SELECT 
                    subject_id,
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                    SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                    SUM(CASE WHEN status = 'reviewed_completed' THEN 1 ELSE 0 END) as reviewed_completed,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
                FROM simple_questions 
                WHERE grade_id = %s
                GROUP BY subject_id
            """, (grade_id,))
            subject_stats = cur.fetchall()
            subjects_dict_for_grade = {}
            for subj in subject_stats:
                subject_id = subj['subject_id']
                if subject_id:
                    subjects_dict_for_grade[str(subject_id)] = {
                        'total': subj['total'] or 0,
                        'approved': subj['approved'] or 0,
                        'under_review': subj['under_review'] or 0,
                        'reviewed_completed': subj['reviewed_completed'] or 0,
                        'rejected': subj['rejected'] or 0,
                        'subject_name': subjects_dict.get(subject_id, f'Subject {subject_id}')
                    }
            grade_stat_obj = {
                'total': grade_stats['total'] or 0,
                'approved': grade_stats['approved'] or 0,
                'under_review': grade_stats['under_review'] or 0,
                'reviewed_completed': grade_stats['reviewed_completed'] or 0,
                'rejected': grade_stats['rejected'] or 0,
                'subjects': subjects_dict_for_grade,
                'grade_name': grade_name,
                'grade_id': grade_id
            }
            stats[f'grade_{grade_id}'] = grade_stat_obj
            if grade_id == 1:
                class11_stats = grade_stat_obj
            elif grade_id == 2:
                class12_stats = grade_stat_obj
        stats['class11'] = class11_stats
        stats['class12'] = class12_stats
        cur.execute("""
            SELECT sq.id, sq.question_text, 
                   COALESCE(sq.status, 'under_review') as status,
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
        print(f"Error fetching dashboard stats: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/chapters', methods=['GET'])
def get_chapters():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    subject_id = request.args.get('subject_id')
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if subject_id:
            cur.execute("""
                SELECT c.*, s.subject_name, s.grade_id, g.grade_name
                FROM chapters c 
                LEFT JOIN subjects s ON c.subject_id = s.id 
                LEFT JOIN grades g ON s.grade_id = g.id
                WHERE c.subject_id = %s 
                ORDER BY c.chapter_number, c.id
            """, (subject_id,))
        else:
            cur.execute("""
                SELECT c.*, s.subject_name, s.grade_id, g.grade_name
                FROM chapters c 
                LEFT JOIN subjects s ON c.subject_id = s.id 
                LEFT JOIN grades g ON s.grade_id = g.id
                ORDER BY g.id, s.subject_name, c.chapter_number, c.id
            """)
        chapters = cur.fetchall()
        return jsonify({'chapters': chapters})
    except Exception as e:
        print(f"Error fetching chapters: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/chapters', methods=['POST'])
def create_chapter():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    subject_id = data.get('subject_id')
    chapter_name = data.get('chapter_name')
    chapter_code = data.get('chapter_code')
    chapter_number = data.get('chapter_number', 0)
    description = data.get('description', '')
    if not subject_id or not chapter_name:
        return jsonify({'error': 'Subject and chapter name are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO chapters (subject_id, chapter_name, chapter_code, chapter_number, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (subject_id, chapter_name, chapter_code, chapter_number, description))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Chapter created successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Chapter already exists for this subject'}), 400
    except Exception as e:
        print(f"Error creating chapter: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/chapters/<int:chapter_id>', methods=['PUT'])
def update_chapter(chapter_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    subject_id = data.get('subject_id')
    chapter_name = data.get('chapter_name')
    chapter_code = data.get('chapter_code')
    chapter_number = data.get('chapter_number', 0)
    description = data.get('description', '')
    if not subject_id or not chapter_name:
        return jsonify({'error': 'Subject and chapter name are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE chapters 
            SET subject_id = %s, chapter_name = %s, chapter_code = %s, 
                chapter_number = %s, description = %s
            WHERE id = %s
        """, (subject_id, chapter_name, chapter_code, chapter_number, description, chapter_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Chapter not found'}), 404
        return jsonify({'success': True, 'message': 'Chapter updated successfully'})
    except mysql.connector.IntegrityError:
        return jsonify({'error': 'Chapter already exists for this subject'}), 400
    except Exception as e:
        print(f"Error updating chapter: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/chapters/<int:chapter_id>', methods=['DELETE'])
def delete_chapter(chapter_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT COUNT(*) as count FROM simple_questions WHERE chapter_id = %s", (chapter_id,))
        count = cur.fetchone()[0]
        if count > 0:
            return jsonify({
                'error': f'Cannot delete chapter because it has {count} question(s). Delete those questions first.'
            }), 400
        cur.execute("DELETE FROM chapters WHERE id = %s", (chapter_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Chapter not found'}), 404
        return jsonify({'success': True, 'message': 'Chapter deleted successfully'})
    except Exception as e:
        print(f"Error deleting chapter: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subjects/<int:subject_id>/chapters', methods=['GET'])
def get_subject_chapters(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT id, chapter_name, chapter_code, chapter_number, description
            FROM chapters 
            WHERE subject_id = %s 
            ORDER BY chapter_number, id
        """, (subject_id,))
        chapters = cur.fetchall()
        return jsonify({'chapters': chapters})
    except Exception as e:
        print(f"Error fetching subject chapters: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subject-groups', methods=['GET'])
def get_subject_groups():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT sg.*, g.grade_name, s.subject_name,
                   (SELECT COUNT(*) FROM users WHERE subject_group = sg.group_code) as member_count
            FROM subject_groups sg
            LEFT JOIN grades g ON sg.grade_id = g.id
            LEFT JOIN subjects s ON sg.subject_id = s.id
            ORDER BY sg.grade_id, sg.group_code
        """)
        groups = cur.fetchall()
        return jsonify({'groups': groups})
    except Exception as e:
        print(f"Error fetching subject groups: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subject-groups', methods=['POST'])
def create_subject_group():
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    group_code = data.get('group_code')
    group_name = data.get('group_name')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
    if not all([group_code, group_name, grade_id, subject_id]):
        return jsonify({'error': 'All fields are required'}), 400
    if not re.match(r'^[a-z]+_(grp_)?\d+(_[a-zA-Z0-9]+)?$', group_code):
        return jsonify({'error': 'Group code must be in format: subject_grp_class (e.g., phy_grp_11) or subject_grp_class_suffix (e.g., phy_grp_11_hi)'}), 400
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
        print(f"Error creating subject group: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subject-groups/<int:group_id>', methods=['PUT'])
def update_subject_group(group_id):
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    group_code = data.get('group_code')
    group_name = data.get('group_name')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
    if not re.match(r'^[a-z]+_(grp_)?\d+(_[a-zA-Z0-9]+)?$', group_code):
        return jsonify({'error': 'Group code must be in format: subject_grp_class (e.g., phy_grp_11) or subject_grp_class_suffix (e.g., phy_grp_11_hi)'}), 400
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
        print(f"Error updating subject group: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subject-groups/<int:group_id>', methods=['DELETE'])
def delete_subject_group(group_id):
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE subject_group = (SELECT group_code FROM subject_groups WHERE id = %s)
        """, (group_id,))
        user_count = cur.fetchone()['count']
        if user_count > 0:
            return jsonify({
                'error': f'Cannot delete group because it has {user_count} user(s) assigned. Remove those users from this group first.'
            }), 400
        cur.execute("DELETE FROM subject_groups WHERE id = %s", (group_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify({'success': True, 'message': 'Group deleted successfully'})
    except Exception as e:
        print(f"Error deleting subject group: {e}")
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
                   u.perm_re, u.perm_ra, u.perm_rc, u.perm_ap,
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
    if not username or not role:
        return jsonify({'error': 'Username and role required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE users 
            SET username = %s, role = %s, subject_group = %s, group_role = %s,
                perm_re = %s, perm_ra = %s, perm_rc = %s, perm_ap = %s
            WHERE id = %s
        """, (username, role, subject_group, group_role, 
              perm_re, perm_ra, perm_rc, perm_ap, user_id))
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
    if role == 'writer':
        perm_re = True
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
                              perm_re, perm_ra, perm_rc, perm_ap, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (username, hashed_password, role, subject_group, group_role,
              perm_re, perm_ra, perm_rc, perm_ap, datetime.now()))
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
            'AP': session.get('perm_ap', False)
        },
        'subject_group': session.get('subject_group'),
        'group_role': session.get('group_role'),
        'user_role': session.get('user_role')
    })
@app.route('/api/review-questions')
def get_review_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_re = session.get('perm_re', False)
    perm_ra = session.get('perm_ra', False)
    perm_rc = session.get('perm_rc', False)
    perm_ap = session.get('perm_ap', False)
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
        query = """
            SELECT sq.id, sq.question_text as question, sq.answer, sq.marks, sq.duration_minutes,
                   COALESCE(sq.status, 'under_review') as status,
                   sq.created_by, sq.created_at,
                   sq.reviewed_by, sq.reviewed_at, sq.reviewed_comment,
                   sq.rejection_reason, sq.approved_by, sq.rejected_by, sq.rejected_at,
                   g.grade_name as grade, g.id as grade_id,
                   sub.subject_name as subject, sub.id as subject_id,
                   ch.chapter_name as chapter, ch.id as chapter_id,
                   c.comp_code as competency, sq.images,
                   sq.question_type_name
            FROM simple_questions sq
            LEFT JOIN grades g ON sq.grade_id = g.id
            LEFT JOIN subjects sub ON sq.subject_id = sub.id
            LEFT JOIN chapters ch ON sq.chapter_id = ch.id
            LEFT JOIN competencies c ON sq.comp_id = c.id
            WHERE 1=1
        """
        params = []
        if user_role == 'admin':
            pass
        else:
            permission_filters = []
            if perm_re:
                permission_filters.append("(sq.created_by = %s AND sq.status IN ('under_review', 'rejected'))")
                params.append(username)
            if perm_rc:
                permission_filters.append("(sq.status = 'under_review')")
            if perm_ap:
                permission_filters.append("(sq.status = 'reviewed_completed')")
            if perm_ra:
                permission_filters.append("(sq.status = 'approved')")
            if permission_filters:
                query += " AND (" + " OR ".join(permission_filters) + ")"
            else:
                query += " AND 1=0"
            if subject_group:
                cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
                group_subjects = [row['subject_id'] for row in cur.fetchall()]
                if group_subjects:
                    placeholders = ','.join(['%s'] * len(group_subjects))
                    query += f" AND sq.subject_id IN ({placeholders})"
                    params.extend(group_subjects)
        if grade:
            query += " AND g.id = %s"
            params.append(grade)
        if subject:
            query += " AND sub.id = %s"
            params.append(subject)
        if status:
            if status == 'under_review':
                query += " AND (sq.status = 'under_review')"
            elif status == 'reviewed_completed':
                query += " AND sq.status = 'reviewed_completed'"
            else:
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
            if perm_re and q['created_by'] == username:
                if q['status'] in ['under_review', None]:
                    can_edit = True
                if q['status'] == 'rejected':
                    can_rework = True
            if perm_rc and q['status'] == 'under_review':
                can_review = True
            if perm_ap and q['status'] == 'reviewed_completed':
                can_approve = True
            if perm_ra and q['status'] == 'approved':
                can_build = True
            if user_role == 'admin':
                can_edit = True
                can_review = True
                can_approve = True
                can_build = True
                can_delete = True
                can_rework = True
            if user_role in ['reviewer', 'approver'] and q['status'] != 'approved':
                can_rework = True
            formatted_questions.append({
                'id': q['id'],
                'question': q['question'],
                'answer': q['answer'] or '',
                'marks': q['marks'] or 1,
                'duration_minutes': q['duration_minutes'] or 0,
                'status': q['status'] or 'under_review',
                'created_by': q['created_by'] or 'Unknown',
                'created_at': q['created_at'].strftime('%Y-%m-%d %H:%M:%S') if q['created_at'] else '',
                'reviewed_by': q['reviewed_by'],
                'reviewed_at': q['reviewed_at'].strftime('%Y-%m-%d %H:%M:%S') if q['reviewed_at'] else None,
                'reviewed_comment': q['reviewed_comment'],
                'rejection_reason': q['rejection_reason'],
                'rejected_by': q['rejected_by'],
                'grade': q['grade'] or 'N/A',
                'grade_id': q['grade_id'],
                'subject': q['subject'] or 'N/A',
                'subject_id': q['subject_id'],
                'chapter': q['chapter'] or 'N/A',
                'chapter_id': q['chapter_id'],
                'competency': q['competency'] or 'N/A',
                'images': q['images'] or '[]',
                'question_type_name': q['question_type_name'] or 'Objective',
                'can_edit': can_edit,
                'can_review': can_review,
                'can_approve': can_approve,
                'can_build': can_build,
                'can_delete': can_delete,
                'can_rework': can_rework
            })
        return jsonify({
            'questions': formatted_questions,
            'permissions': {
                'RE': perm_re,
                'RA': perm_ra,
                'RC': perm_rc,
                'AP': perm_ap
            },
            'subject_group': subject_group,
            'user_role': user_role
        })
    except Exception as e:
        print(f"Error fetching review questions: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/review-question/<int:question_id>', methods=['POST'])
def review_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_rc = session.get('perm_rc', False)
    if user_role != 'admin' and not perm_rc:
        return jsonify({'error': 'You need Reviewer (RC) permission to review questions'}), 403
    data = request.json
    comment = data.get('comment', '') if data else ''
    db = get_db()
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT * FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        if question['status'] != 'under_review' and user_role != 'admin':
            return jsonify({'error': 'Only questions under review can be reviewed'}), 400
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'reviewed_completed', 
                reviewed_by = %s, 
                reviewed_at = %s,
                reviewed_comment = %s,
                rejection_reason = NULL,
                rejected_by = NULL,
                rejected_at = NULL
            WHERE id = %s
        """, (username, datetime.now(), comment, question_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Failed to update question'}), 500
        return jsonify({'success': True, 'message': 'Question marked as reviewed completed'})
    except Exception as e:
        print(f"Error in review_question: {e}")
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/approve-question/<int:question_id>', methods=['POST'])
def approve_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_ap = session.get('perm_ap', False)
    if user_role != 'admin' and not perm_ap:
        return jsonify({'error': 'You need Approver (AP) permission to approve questions'}), 403
    data = request.json
    comment = data.get('comment', '') if data else ''
    db = get_db()
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT * FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        if question['status'] != 'reviewed_completed' and user_role != 'admin':
            return jsonify({'error': 'Only reviewed completed questions can be approved'}), 400
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'approved', 
                reviewed_by = %s, 
                reviewed_at = %s,
                reviewed_comment = %s,
                approved_at = %s,
                approved_by = %s,
                rejection_reason = NULL,
                rejected_by = NULL,
                rejected_at = NULL
            WHERE id = %s
        """, (username, datetime.now(), comment, datetime.now(), username, question_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Failed to update question'}), 500
        return jsonify({'success': True, 'message': 'Question approved successfully'})
    except Exception as e:
        print(f"Error in approve_question: {e}")
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/rework-question/<int:question_id>', methods=['POST'])
def rework_question(question_id):
    """Allow writer/reviewer/approver/admin to resubmit a question for review"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_re = session.get('perm_re', False)
    perm_rc = session.get('perm_rc', False)
    perm_ap = session.get('perm_ap', False)
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        cur.execute("SELECT created_by, status FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        can_rework = False
        
        if user_role == 'admin':
            can_rework = True
        elif perm_rc or perm_ap:
            # Reviewers and Approvers can rework ANY non-approved question
            can_rework = question['status'] != 'approved'
        elif perm_re and question['created_by'] == username:
            can_rework = question['status'] == 'rejected'
        
        if not can_rework:
            return jsonify({'error': 'You are not authorized to rework this question'}), 403
        
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'under_review',
                reviewed_by = NULL,
                reviewed_at = NULL,
                reviewed_comment = NULL,
                rejection_reason = NULL,
                rejected_by = NULL,
                rejected_at = NULL,
                approved_by = NULL,
                approved_at = NULL
            WHERE id = %s
        """, (question_id,))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Question resubmitted for review'})
        
    except Exception as e:
        print(f"Error in rework_question: {e}")
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

# ============ UPDATE QUESTION ENDPOINT - FIXED FOR REVIEWERS AND APPROVERS ============

@app.route('/api/update-question/<int:question_id>', methods=['POST'])
def update_question(question_id):
    """Update a question - Allows reviewers/approvers to update during rework"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    username = session.get('user', '')
    user_role = session.get('user_role', 'writer')
    perm_re = session.get('perm_re', False)
    perm_rc = session.get('perm_rc', False)
    perm_ap = session.get('perm_ap', False)
    data = request.json
    question_text = data.get('question')
    answer = data.get('answer')
    marks = data.get('marks', 1)
    duration_minutes = data.get('duration_minutes', 0)
    if not question_text:
        return jsonify({'error': 'Question text is required'}), 400
    if not answer:
        return jsonify({'error': 'Answer is required'}), 400
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
        cur.execute("SELECT created_by, status FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        can_edit = False
        if user_role == 'admin':
            can_edit = True
        elif perm_re and question['created_by'] == username:
            can_edit = question['status'] in ['under_review', 'rejected']
        elif perm_rc or perm_ap:
            can_edit = question['status'] != 'approved'
        if not can_edit:
            return jsonify({'error': 'You are not authorized to edit this question'}), 403
        cur.execute("""
            UPDATE simple_questions 
            SET question_text = %s, answer = %s, marks = %s, duration_minutes = %s,
                updated_at = NOW()
            WHERE id = %s
        """, (question_text, answer, marks, duration_minutes, question_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Failed to update question'}), 500
        return jsonify({'success': True, 'message': 'Question updated successfully'})
    except Exception as e:
        print(f"Error updating question: {e}")
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/builder-questions')
def get_builder_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    user_role = session.get('user_role', 'writer')
    perm_ra = session.get('perm_ra', False)
    if user_role != 'admin' and not perm_ra:
        return jsonify({'error': 'Access denied. Builder (RA) permission required.'}), 403
    comp_id = request.args.get('comp_id')
    grade_id = request.args.get('grade_id')
    subject_id = request.args.get('subject_id')
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        query = """
            SELECT sq.id, sq.question_text, sq.answer, sq.marks, sq.duration_minutes,
                   sq.competency_code, sq.difficulty_name, sq.domain_name,
                   sq.knowledge_level_name, sq.question_type_name, sq.images,
                   g.grade_name, g.id as grade_id,
                   sub.subject_name, sub.id as subject_id,
                   ch.chapter_name, ch.id as chapter_id,
                   sq.cg_code, sq.comp_id,
                   sq.created_by, sq.created_at, sq.approved_at,
                   sq.reviewed_by, sq.reviewed_comment
            FROM simple_questions sq
            LEFT JOIN grades g ON sq.grade_id = g.id
            LEFT JOIN subjects sub ON sq.subject_id = sub.id
            LEFT JOIN chapters ch ON sq.chapter_id = ch.id
            WHERE sq.status = 'approved'
        """
        params = []
        if comp_id:
            query += " AND sq.comp_id = %s"
            params.append(comp_id)
        if grade_id:
            query += " AND sq.grade_id = %s"
            params.append(grade_id)
        if subject_id:
            query += " AND sq.subject_id = %s"
            params.append(subject_id)
        subject_group = session.get('subject_group')
        if subject_group and user_role != 'admin':
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            group_subjects = [row['subject_id'] for row in cur.fetchall()]
            if group_subjects:
                placeholders = ','.join(['%s'] * len(group_subjects))
                query += f" AND sq.subject_id IN ({placeholders})"
                params.extend(group_subjects)
        query += " ORDER BY sq.question_type_name, sq.difficulty_name LIMIT 500"
        cur.execute(query, params)
        questions = cur.fetchall()
        return jsonify({'questions': questions})
    except Exception as e:
        print(f"Error fetching builder questions: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/upload-question-images', methods=['POST'])
def upload_question_images():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    perm_re = session.get('perm_re', False)
    if not perm_re and session.get('user_role') != 'admin':
        return jsonify({'error': 'Writer (RE) permission required'}), 403
    if 'images' not in request.files:
        return jsonify({'error': 'No images provided'}), 400
    files = request.files.getlist('images')
    if len(files) == 0:
        return jsonify({'error': 'No images selected'}), 400
    if len(files) > 10:
        return jsonify({'error': 'Maximum 10 images allowed per question'}), 400
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
            return jsonify({'error': f'Invalid file type: {file.filename}. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400
    return jsonify({
        'success': True,
        'image_urls': uploaded_urls,
        'count': len(uploaded_urls)
    })
@app.route('/static/uploads/questions/<path:filename>')
def serve_question_image(filename):
    if 'user' not in session:
        return redirect(url_for('dashboard_login'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        for user_folder in os.listdir(app.config['UPLOAD_FOLDER']):
            user_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], user_folder)
            if os.path.isdir(user_folder_path):
                alt_path = os.path.join(user_folder_path, filename)
                if os.path.exists(alt_path):
                    file_path = alt_path
                    break
    if os.path.exists(file_path):
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'jpg'
        mime_types = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'webp': 'image/webp'
        }
        return send_file(file_path, mimetype=mime_types.get(ext, 'image/jpeg'))
    return jsonify({'error': 'Image not found'}), 404
@app.route('/api/create-simple-question', methods=['POST'])
def create_simple_question():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    perm_re = session.get('perm_re', False)
    if not perm_re and session.get('user_role') != 'admin':
        return jsonify({'error': 'Writer (RE) permission required'}), 403
    data = request.json
    question_text = data.get('question_text')
    answer = data.get('answer')  
    marks = data.get('marks', 1)
    duration_minutes = data.get('duration_minutes', 0)
    comp_id = data.get('comp_id')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
    chapter_id = data.get('chapter_id')
    cg_id = data.get('cg_id')
    domain_id = data.get('domain_id') or data.get('cognitive_id')
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
    if not question_text:
        return jsonify({'error': 'Question text is required'}), 400
    if not answer:
        return jsonify({'error': 'Answer is required'}), 400
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
    cur = db.cursor()
    try:
        insert_sql = """
        INSERT INTO simple_questions (
            question_text, answer, marks, duration_minutes, 
            comp_id, created_by, created_at,
            grade_id, subject_id, chapter_id, cg_id, domain_id, 
            knowledge_level_id, question_type_id, difficulty_id,
            competency_code, domain_name, knowledge_level_name,
            question_type_name, difficulty_name, grade_name,
            subject_name, chapter_name, chapter_code, cg_code, 
            images, status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        insert_values = (
            question_text, answer, marks, duration_minutes,
            comp_id, session['user'], datetime.now(),
            grade_id, subject_id, chapter_id, cg_id, domain_id,
            knowledge_level_id, question_type_id, difficulty_id,
            competency_code, domain_name, knowledge_level_name,
            question_type_name, difficulty_name, grade_name,
            subject_name, chapter_name, chapter_code, cg_code,
            images, 'under_review'
        )
        cur.execute(insert_sql, insert_values)
        db.commit()
        question_id = cur.lastrowid
        print(f"Question saved with ID: {question_id}")
        print(f"  Chapter ID: {chapter_id}, Chapter Name: {chapter_name}")
        print(f"  Images: {images}")
        return jsonify({
            'success': True,
            'message': 'Question submitted for review',
            'question_id': question_id,
            'status': 'under_review',
            'duration_minutes': duration_minutes,
            'chapter_id': chapter_id,
            'chapter_name': chapter_name,
            'images': images
        })
    except Exception as e:
        print(f"Error creating simple question: {e}")
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/page1-data')
def get_page1_data():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM grades ORDER BY id")
        grades = cur.fetchall()
        cur.execute("""
            SELECT s.*, g.grade_name 
            FROM subjects s 
            LEFT JOIN grades g ON s.grade_id = g.id 
            ORDER BY s.grade_id, s.id
        """)
        subjects_data = cur.fetchall()
        cur.execute("""
            SELECT cg.*, s.subject_name, s.grade_id, g.grade_name 
            FROM curricular_goals cg 
            LEFT JOIN subjects s ON cg.subject_id = s.id 
            LEFT JOIN grades g ON s.grade_id = g.id 
            ORDER BY cg.subject_id, cg.id
        """)
        cgs_data = cur.fetchall()
        cur.execute("""
            SELECT c.*, cg.cg_code, cg.subject_id, s.subject_name, g.grade_name 
            FROM competencies c 
            LEFT JOIN curricular_goals cg ON c.cg_id = cg.id 
            LEFT JOIN subjects s ON cg.subject_id = s.id 
            LEFT JOIN grades g ON s.grade_id = g.id 
            WHERE c.status = 1
            ORDER BY c.cg_id, c.id
        """)
        comps_data = cur.fetchall()
        navigation_data = {
            'grades': grades,
            'subjects': subjects_data,
            'cgs': cgs_data,
            'competencies': comps_data,
            'subjects_by_grade': {},
            'cgs_by_subject': {},
            'comps_by_cg': {}
        }
        for subject in subjects_data:
            grade_id = subject.get('grade_id')
            if grade_id is not None:
                grade_key = str(grade_id)
                if grade_key not in navigation_data['subjects_by_grade']:
                    navigation_data['subjects_by_grade'][grade_key] = []
                navigation_data['subjects_by_grade'][grade_key].append(subject)
        for cg in cgs_data:
            subject_id = cg.get('subject_id')
            if subject_id is not None:
                subject_key = str(subject_id)
                if subject_key not in navigation_data['cgs_by_subject']:
                    navigation_data['cgs_by_subject'][subject_key] = []
                navigation_data['cgs_by_subject'][subject_key].append(cg)
        for comp in comps_data:
            cg_id = comp.get('cg_id')
            if cg_id is not None:
                cg_key = str(cg_id)
                if cg_key not in navigation_data['comps_by_cg']:
                    navigation_data['comps_by_cg'][cg_key] = []
                navigation_data['comps_by_cg'][cg_key].append(comp)
        return jsonify(navigation_data)
    except Exception as e:
        print(f"Error in get_page1-data: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/knowledge-levels')
def get_knowledge_levels():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM knowledge_levels WHERE is_active = TRUE ORDER BY id")
        levels = cur.fetchall()
        if not levels:
            levels = [
                {'id': 1, 'level_name': 'Knowledge'},
                {'id': 2, 'level_name': 'Remembering'},
                {'id': 3, 'level_name': 'Understanding'},
                {'id': 4, 'level_name': 'Comprehension'}
            ]
        return jsonify({'knowledge_levels': levels})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'knowledge_levels': [
            {'id': 1, 'level_name': 'Knowledge'},
            {'id': 2, 'level_name': 'Remembering'},
            {'id': 3, 'level_name': 'Understanding'},
            {'id': 4, 'level_name': 'Comprehension'}
        ]})
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
                {'id': 1, 'domain_name': 'Awareness'},
                {'id': 2, 'domain_name': 'Sensitivity'},
                {'id': 3, 'domain_name': 'Creativity'}
            ]
        cur.execute("SELECT * FROM question_types ORDER BY cognitive_id, id")
        question_types_data = cur.fetchall()
        difficulty_levels = []
        try:
            cur.execute("SHOW TABLES LIKE 'difficulty_levels'")
            table_exists = cur.fetchone()
            if table_exists:
                cur.execute("SELECT * FROM difficulty_levels ORDER BY id")
                difficulty_levels = cur.fetchall()
            if not difficulty_levels:
                difficulty_levels = [
                    {'id': 1, 'level_name': 'Easy'},
                    {'id': 2, 'level_name': 'Medium'},
                    {'id': 3, 'level_name': 'Hard'}
                ]
        except Exception as e:
            print(f"Error fetching difficulty levels: {str(e)}")
            difficulty_levels = [
                {'id': 1, 'level_name': 'Easy'},
                {'id': 2, 'level_name': 'Medium'},
                {'id': 3, 'level_name': 'Hard'}
            ]
        navigation_data = {
            'domains': domains,
            'question_types_by_domain': {},
            'difficulty_levels': difficulty_levels,
            'comp': comp_data
        }
        for qtype in question_types_data:
            cognitive_id = qtype['cognitive_id']
            if cognitive_id not in navigation_data['question_types_by_domain']:
                navigation_data['question_types_by_domain'][cognitive_id] = []
            navigation_data['question_types_by_domain'][cognitive_id].append(qtype)
        return jsonify(navigation_data)
    except Exception as e:
        print(f"Error in get_page2-data: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/simple-questions')
def get_simple_questions():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    comp_id = request.args.get('comp_id')
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        query = """
        SELECT id, question_text, answer, marks, duration_minutes,
               competency_code, difficulty_name, domain_name,
               knowledge_level_name, question_type_name,
               grade_name, subject_name, chapter_name, cg_code,
               created_by, created_at, comp_id,
               status, rejection_reason, reviewed_by, reviewed_at,
               images
        FROM simple_questions 
        WHERE created_by = %s
        """
        params = [session['user']]
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
        print(f"Error loading simple questions: {e}")
        traceback.print_exc()
        return jsonify({'questions': []})
    finally:
        cur.close()
        db.close()
@app.route('/api/page2-questions')
def get_page2_questions():
    return get_simple_questions()
@app.route('/api/create-question', methods=['POST'])
def create_question():
    return create_simple_question()
@app.route('/api/subjects')
def get_subjects():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT s.id, s.subject_name, s.grade_id, g.grade_name 
            FROM subjects s
            LEFT JOIN grades g ON s.grade_id = g.id
            ORDER BY s.grade_id, s.subject_name
        """)
        subjects = cur.fetchall()
        return jsonify({'subjects': subjects})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/grades')
def get_grades():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, grade_name FROM grades ORDER BY id")
        grades = cur.fetchall()
        return jsonify({'grades': grades})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/pending-count')
def get_pending_count():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            SELECT COUNT(*) as count 
            FROM simple_questions 
            WHERE status = 'under_review'
        """)
        count = cur.fetchone()[0]
        return jsonify({'under_review': count})
    except Exception as e:
        print(f"Error fetching under_review count: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/debug-session')
def debug_session():
    return jsonify({
        'session': dict(session),
        'has_user': 'user' in session,
        'user': session.get('user'),
        'user_role': session.get('user_role'),
        'permissions': {
            'RE': session.get('perm_re', False),
            'RA': session.get('perm_ra', False),
            'RC': session.get('perm_rc', False),
            'AP': session.get('perm_ap', False)
        },
        'subject_group': session.get('subject_group')
    })
@app.route('/api/debug/chapters', methods=['GET'])
def debug_chapters():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT c.*, s.subject_name, s.grade_id, g.grade_name,
                   (SELECT COUNT(*) FROM simple_questions WHERE chapter_id = c.id) as question_count
            FROM chapters c
            LEFT JOIN subjects s ON c.subject_id = s.id
            LEFT JOIN grades g ON s.grade_id = g.id
            ORDER BY s.subject_name, c.chapter_number
        """)
        chapters = cur.fetchall()
        cur.execute("""
            SELECT id, question_text, chapter_id, chapter_name, chapter_code, subject_id
            FROM simple_questions 
            WHERE chapter_id IS NOT NULL
            LIMIT 20
        """)
        questions_with_chapters = cur.fetchall()
        return jsonify({
            'chapters': chapters,
            'questions_with_chapters': questions_with_chapters,
            'total_chapters': len(chapters),
            'total_questions_with_chapters': len(questions_with_chapters)
        })
    except Exception as e:
        print(f"Error in debug_chapters: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/user-view-info')
def user_view_info():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    username = session.get('user')
    perm_re = session.get('perm_re', False)
    perm_ra = session.get('perm_ra', False)
    perm_rc = session.get('perm_rc', False)
    perm_ap = session.get('perm_ap', False)
    conditions = []
    params = []
    if perm_re:
        conditions.append("(created_by = %s AND status IN ('under_review', 'rejected'))")
        params.append(username)
    if perm_rc:
        conditions.append("(status = 'under_review')")
    if perm_ap:
        conditions.append("(status = 'reviewed_completed')")
    if perm_ra:
        conditions.append("(status = 'approved')")
    if not conditions:
        conditions.append("1=0")
    query = f"""
        SELECT status, COUNT(*) as count
        FROM simple_questions
        WHERE {' OR '.join(conditions)}
        GROUP BY status
    """
    cur.execute(query, params)
    visible_counts = cur.fetchall()
    cur.execute("""
        SELECT status, COUNT(*) as count
        FROM simple_questions
        GROUP BY status
    """)
    all_counts = cur.fetchall()
    cur.close()
    db.close()
    view_type = {
        'writer_view': perm_re and not any([perm_ra, perm_rc, perm_ap]),
        'reviewer_view': perm_rc and not any([perm_re, perm_ra, perm_ap]),
        'approver_view': perm_ap and not any([perm_re, perm_ra, perm_rc]),
        'builder_view': perm_ra and not any([perm_re, perm_rc, perm_ap]),
        'admin_view': all([perm_re, perm_ra, perm_rc, perm_ap]),
        'mixed_view': sum([perm_re, perm_ra, perm_rc, perm_ap]) > 1 and not all([perm_re, perm_ra, perm_rc, perm_ap])
    }
    return jsonify({
        'user': username,
        'role': session.get('user_role'),
        'permissions': {
            'RE': perm_re,
            'RA': perm_ra,
            'RC': perm_rc,
            'AP': perm_ap
        },
        'visible_questions': visible_counts,
        'all_questions': all_counts,
        'view_type': view_type,
        'recommended_qlist_button': get_qlist_button_name(perm_re, perm_ra, perm_rc, perm_ap, session.get('user_role'))
    })
def get_qlist_button_name(perm_re, perm_ra, perm_rc, perm_ap, user_role):
    if user_role == 'admin':
        return 'Q-LIST (ALL)'
    if perm_ap and not perm_rc and not perm_re and not perm_ra:
        return 'Q-APPROVE'
    if perm_rc and not perm_ap and not perm_re and not perm_ra:
        return 'Q-REVIEW'
    if perm_ra and not perm_re and not perm_rc and not perm_ap:
        return 'Q-BUILD'
    if perm_re and not perm_ra and not perm_rc and not perm_ap:
        return 'Q-MY'
    return 'Q-LIST'
@app.route('/api/generate-paper', methods=['POST'])
def generate_paper():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.json
    questions = data.get('questions', [])
    paper_config = data.get('config', {})
    if not questions:
        return jsonify({'error': 'No questions selected'}), 400
    try:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
        except ImportError:
            print("Warning: ReportLab not installed. Returning mock PDF response.")
            return jsonify({
                'success': True,
                'pdf': base64.b64encode(b"Mock PDF content").decode('utf-8'),
                'filename': f"question_paper_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                'mock': True
            })
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, 
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#2c3e50'),
            alignment=1,
            spaceAfter=30
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#3498db'),
            spaceAfter=12,
            spaceBefore=20
        )
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=6
        )
        story = []
        story.append(Paragraph("COHSEM | PARAKH", title_style))
        story.append(Paragraph(f"Question Paper - {paper_config.get('grade', '')} {paper_config.get('subject', '')}", heading_style))
        total_duration = sum(q.get('duration_minutes', 0) for q in questions)
        story.append(Paragraph(f"Total Time: {total_duration} minutes", heading_style))
        meta_data = [
            [f"Date: {datetime.now().strftime('%d-%m-%Y')}", f"Time: {total_duration} minutes"],
            [f"Total Marks: {paper_config.get('total_marks', 0)}", f"Questions: {len(questions)}"]
        ]
        meta_table = Table(meta_data, colWidths=[3*inch, 3*inch])
        meta_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#666666')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 20))
        from collections import defaultdict
        by_type = defaultdict(list)
        for q in questions:
            q_type = q.get('question_type_name', 'Objective')
            by_type[q_type].append(q)
        for q_type, type_questions in by_type.items():
            story.append(Paragraph(f"Section: {q_type}", heading_style))
            for idx, q in enumerate(type_questions, 1):
                q_text = f"<b>Q{idx}.</b> {q.get('question_text', '')} <b>[{q.get('marks', 1)} marks]</b> <i>({q.get('duration_minutes', 0)} min)</i>"
                story.append(Paragraph(q_text, normal_style))
                if idx < len(type_questions):
                    story.append(Spacer(1, 12))
            story.append(Spacer(1, 20))
        doc.build(story)
        pdf_value = buffer.getvalue()
        buffer.close()
        pdf_base64 = base64.b64encode(pdf_value).decode('utf-8')
        return jsonify({
            'success': True,
            'pdf': pdf_base64,
            'filename': f"question_paper_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        })
    except Exception as e:
        print(f"Error generating PDF: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
@app.route('/api/grades', methods=['GET'])
def get_grades_api():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, grade_name FROM grades ORDER BY id")
        grades = cur.fetchall()
        return jsonify({'grades': grades})
    except Exception as e:
        print(f"Error fetching grades: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/grades', methods=['POST'])
def create_grade():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Grade name is required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO grades (grade_name) VALUES (%s)", (name,))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Grade created successfully'})
    except Exception as e:
        print(f"Error creating grade: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/grades/<int:grade_id>', methods=['PUT'])
def update_grade(grade_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Grade name is required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE grades SET grade_name = %s WHERE id = %s", (name, grade_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Grade not found'}), 404
        return jsonify({'success': True, 'message': 'Grade updated successfully'})
    except Exception as e:
        print(f"Error updating grade: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/grades/<int:grade_id>', methods=['DELETE'])
def delete_grade(grade_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM subjects WHERE grade_id = %s", (grade_id,))
        subject_count = cur.fetchone()['count']
        if subject_count > 0:
            cur.execute("SELECT subject_name FROM subjects WHERE grade_id = %s LIMIT 5", (grade_id,))
            subjects = cur.fetchall()
            subject_names = ', '.join([s['subject_name'] for s in subjects])
            if subject_count > 5:
                subject_names += f' and {subject_count - 5} more...'
            return jsonify({
                'error': f'Cannot delete grade because it has {subject_count} subject(s): {subject_names}. Delete those subjects first.'
            }), 400
        cur.execute("SELECT COUNT(*) as count FROM subject_groups WHERE grade_id = %s", (grade_id,))
        group_count = cur.fetchone()['count']
        if group_count > 0:
            return jsonify({
                'error': f'Cannot delete grade because it is used in {group_count} subject group(s). Delete those groups first.'
            }), 400
        cur.execute("SELECT COUNT(*) as count FROM simple_questions WHERE grade_id = %s", (grade_id,))
        question_count = cur.fetchone()['count']
        if question_count > 0:
            return jsonify({
                'error': f'Cannot delete grade because it has {question_count} question(s). Delete those questions first.'
            }), 400
        cur.execute("DELETE FROM grades WHERE id = %s", (grade_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Grade not found'}), 404
        return jsonify({'success': True, 'message': 'Grade deleted successfully'})
    except Exception as e:
        print(f"Error deleting grade: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subjects', methods=['GET'])
def get_subjects_api():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT s.*, g.grade_name 
            FROM subjects s 
            LEFT JOIN grades g ON s.grade_id = g.id 
            ORDER BY s.grade_id, s.subject_name
        """)
        subjects = cur.fetchall()
        return jsonify({'subjects': subjects})
    except Exception as e:
        print(f"Error fetching subjects: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subjects', methods=['POST'])
def create_subject():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    grade_id = data.get('grade_id')
    if not name or not grade_id:
        return jsonify({'error': 'Subject name and grade are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO subjects (subject_name, grade_id) VALUES (%s, %s)", (name, grade_id))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Subject created successfully'})
    except Exception as e:
        print(f"Error creating subject: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subjects/<int:subject_id>', methods=['PUT'])
def update_subject(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    grade_id = data.get('grade_id')
    if not name or not grade_id:
        return jsonify({'error': 'Subject name and grade are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE subjects SET subject_name = %s, grade_id = %s WHERE id = %s", (name, grade_id, subject_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Subject not found'}), 404
        return jsonify({'success': True, 'message': 'Subject updated successfully'})
    except Exception as e:
        print(f"Error updating subject: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/subjects/<int:subject_id>', methods=['DELETE'])
def delete_subject(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM curricular_goals WHERE subject_id = %s", (subject_id,))
        cg_count = cur.fetchone()['count']
        if cg_count > 0:
            return jsonify({
                'error': f'Cannot delete subject because it has {cg_count} curricular goal(s). Delete those first.'
            }), 400
        cur.execute("SELECT COUNT(*) as count FROM chapters WHERE subject_id = %s", (subject_id,))
        chapter_count = cur.fetchone()['count']
        if chapter_count > 0:
            return jsonify({
                'error': f'Cannot delete subject because it has {chapter_count} chapter(s). Delete those first.'
            }), 400
        cur.execute("SELECT COUNT(*) as count FROM subject_groups WHERE subject_id = %s", (subject_id,))
        group_count = cur.fetchone()['count']
        if group_count > 0:
            return jsonify({
                'error': f'Cannot delete subject because it is used in {group_count} subject group(s). Delete those groups first.'
            }), 400
        cur.execute("SELECT COUNT(*) as count FROM simple_questions WHERE subject_id = %s", (subject_id,))
        question_count = cur.fetchone()['count']
        if question_count > 0:
            return jsonify({
                'error': f'Cannot delete subject because it has {question_count} question(s). Delete those questions first.'
            }), 400
        cur.execute("DELETE FROM subjects WHERE id = %s", (subject_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Subject not found'}), 404
        return jsonify({'success': True, 'message': 'Subject deleted successfully'})
    except Exception as e:
        print(f"Error deleting subject: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/cgs', methods=['GET'])
def get_cgs():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT cg.*, s.subject_name, g.grade_name 
            FROM curricular_goals cg 
            LEFT JOIN subjects s ON cg.subject_id = s.id 
            LEFT JOIN grades g ON s.grade_id = g.id 
            ORDER BY cg.subject_id, cg.id
        """)
        cgs = cur.fetchall()
        return jsonify({'cgs': cgs})
    except Exception as e:
        print(f"Error fetching CGs: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/cgs', methods=['POST'])
def create_cg():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    subject_id = data.get('subject_id')
    if not code or not subject_id:
        return jsonify({'error': 'CG code and subject are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO curricular_goals (cg_code, cg_description, subject_id) 
            VALUES (%s, %s, %s)
        """, (code, description, subject_id))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'CG created successfully'})
    except Exception as e:
        print(f"Error creating CG: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/cgs/<int:cg_id>', methods=['PUT'])
def update_cg(cg_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    subject_id = data.get('subject_id')
    if not code or not subject_id:
        return jsonify({'error': 'CG code and subject are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE curricular_goals 
            SET cg_code = %s, cg_description = %s, subject_id = %s 
            WHERE id = %s
        """, (code, description, subject_id, cg_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'CG not found'}), 404
        return jsonify({'success': True, 'message': 'CG updated successfully'})
    except Exception as e:
        print(f"Error updating CG: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/cgs/<int:cg_id>', methods=['DELETE'])
def delete_cg(cg_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM competencies WHERE cg_id = %s", (cg_id,))
        comp_count = cur.fetchone()['count']
        if comp_count > 0:
            return jsonify({
                'error': f'Cannot delete CG because it has {comp_count} competence' + ('y' if comp_count == 1 else 'ies') + '. Delete those competencies first.'
            }), 400
        cur.execute("SELECT COUNT(*) as count FROM simple_questions WHERE cg_id = %s", (cg_id,))
        question_count = cur.fetchone()['count']
        if question_count > 0:
            return jsonify({
                'error': f'Cannot delete CG because it has {question_count} question(s). Delete those questions first.'
            }), 400
        cur.execute("DELETE FROM curricular_goals WHERE id = %s", (cg_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'CG not found'}), 404
        return jsonify({'success': True, 'message': 'CG deleted successfully'})
    except Exception as e:
        print(f"Error deleting CG: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/competencies', methods=['GET'])
def get_competencies_api():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT c.*, cg.cg_code, cg.subject_id, s.subject_name, g.grade_name 
            FROM competencies c 
            LEFT JOIN curricular_goals cg ON c.cg_id = cg.id 
            LEFT JOIN subjects s ON cg.subject_id = s.id 
            LEFT JOIN grades g ON s.grade_id = g.id 
            ORDER BY c.cg_id, c.id
        """)
        competencies = cur.fetchall()
        return jsonify({'competencies': competencies})
    except Exception as e:
        print(f"Error fetching competencies: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/competencies', methods=['POST'])
def create_competency():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    cg_id = data.get('cg_id')
    status = data.get('status', 1)
    if not code or not cg_id:
        return jsonify({'error': 'Competency code and CG are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO competencies (comp_code, comp_description, cg_id, status) 
            VALUES (%s, %s, %s, %s)
        """, (code, description, cg_id, status))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Competency created successfully'})
    except Exception as e:
        print(f"Error creating competency: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/competencies/<int:comp_id>', methods=['PUT'])
def update_competency(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    cg_id = data.get('cg_id')
    status = data.get('status', 1)
    if not code or not cg_id:
        return jsonify({'error': 'Competency code and CG are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE competencies 
            SET comp_code = %s, comp_description = %s, cg_id = %s, status = %s 
            WHERE id = %s
        """, (code, description, cg_id, status, comp_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True, 'message': 'Competency updated successfully'})
    except Exception as e:
        print(f"Error updating competency: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/competencies/<int:comp_id>', methods=['DELETE'])
def delete_competency(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM simple_questions WHERE comp_id = %s", (comp_id,))
        question_count = cur.fetchone()['count']
        if question_count > 0:
            return jsonify({
                'error': f'Cannot delete competency because it has {question_count} question(s). Delete those questions first.'
            }), 400
        cur.execute("DELETE FROM competencies WHERE id = %s", (comp_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True, 'message': 'Competency deleted successfully'})
    except Exception as e:
        print(f"Error deleting competency: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/competencies/<int:comp_id>/toggle', methods=['POST'])
def toggle_competency_status(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    status = data.get('status', 1)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE competencies SET status = %s WHERE id = %s", (status, comp_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Competency not found'}), 404
        return jsonify({'success': True, 'message': 'Competency status updated successfully'})
    except Exception as e:
        print(f"Error toggling competency status: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/question-types', methods=['GET'])
def get_question_types():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT qt.*, cd.domain_name 
            FROM question_types qt 
            LEFT JOIN cognitive_domains cd ON qt.cognitive_id = cd.id 
            ORDER BY qt.cognitive_id, qt.id
        """)
        types = cur.fetchall()
        return jsonify({'question_types': types})
    except Exception as e:
        print(f"Error fetching question types: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/question-types', methods=['POST'])
def create_question_type():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    cognitive_id = data.get('cognitive_id')
    description = data.get('description', '')
    if not name or not cognitive_id:
        return jsonify({'error': 'Type name and cognitive domain are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO question_types (type_name, cognitive_id, description) 
            VALUES (%s, %s, %s)
        """, (name, cognitive_id, description))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Question type created successfully'})
    except Exception as e:
        print(f"Error creating question type: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/question-types/<int:type_id>', methods=['PUT'])
def update_question_type(type_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    cognitive_id = data.get('cognitive_id')
    description = data.get('description', '')
    if not name or not cognitive_id:
        return jsonify({'error': 'Type name and cognitive domain are required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE question_types 
            SET type_name = %s, cognitive_id = %s, description = %s 
            WHERE id = %s
        """, (name, cognitive_id, description, type_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Question type not found'}), 404
        return jsonify({'success': True, 'message': 'Question type updated successfully'})
    except Exception as e:
        print(f"Error updating question type: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/question-types/<int:type_id>', methods=['DELETE'])
def delete_question_type(type_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM question_types WHERE id = %s", (type_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Question type not found'}), 404
        return jsonify({'success': True, 'message': 'Question type deleted successfully'})
    except Exception as e:
        print(f"Error deleting question type: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/difficulty-levels', methods=['GET'])
def get_difficulty_levels():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM difficulty_levels ORDER BY id")
        levels = cur.fetchall()
        return jsonify({'difficulty_levels': levels})
    except Exception as e:
        print(f"Error fetching difficulty levels: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/difficulty-levels', methods=['POST'])
def create_difficulty_level():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Level name is required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO difficulty_levels (level_name) VALUES (%s)", (name,))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Difficulty level created successfully'})
    except Exception as e:
        print(f"Error creating difficulty level: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/difficulty-levels/<int:level_id>', methods=['PUT'])
def update_difficulty_level(level_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Level name is required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE difficulty_levels SET level_name = %s WHERE id = %s", (name, level_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Difficulty level not found'}), 404
        return jsonify({'success': True, 'message': 'Difficulty level updated successfully'})
    except Exception as e:
        print(f"Error updating difficulty level: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/difficulty-levels/<int:level_id>', methods=['DELETE'])
def delete_difficulty_level(level_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM difficulty_levels WHERE id = %s", (level_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Difficulty level not found'}), 404
        return jsonify({'success': True, 'message': 'Difficulty level deleted successfully'})
    except Exception as e:
        print(f"Error deleting difficulty level: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
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
        cur.execute("SELECT * FROM cognitive_domains ORDER BY id")
        domains = cur.fetchall()
        return jsonify({'cognitive_domains': domains})
    except Exception as e:
        print(f"Error fetching cognitive domains: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/cognitive-domains', methods=['POST'])
def create_cognitive_domain():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    description = data.get('description', '')
    if not name:
        return jsonify({'error': 'Domain name is required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO cognitive_domains (domain_name, description) VALUES (%s, %s)", (name, description))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Cognitive domain created successfully'})
    except Exception as e:
        print(f"Error creating cognitive domain: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/cognitive-domains/<int:domain_id>', methods=['PUT'])
def update_cognitive_domain(domain_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    description = data.get('description', '')
    if not name:
        return jsonify({'error': 'Domain name is required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE cognitive_domains SET domain_name = %s, description = %s WHERE id = %s", (name, description, domain_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Cognitive domain not found'}), 404
        return jsonify({'success': True, 'message': 'Cognitive domain updated successfully'})
    except Exception as e:
        print(f"Error updating cognitive domain: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/cognitive-domains/<int:domain_id>', methods=['DELETE'])
def delete_cognitive_domain(domain_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM question_types WHERE cognitive_id = %s", (domain_id,))
        count = cur.fetchone()[0]
        if count > 0:
            return jsonify({'error': 'Cannot delete domain with existing question types'}), 400
        cur.execute("DELETE FROM cognitive_domains WHERE id = %s", (domain_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Cognitive domain not found'}), 404
        return jsonify({'success': True, 'message': 'Cognitive domain deleted successfully'})
    except Exception as e:
        print(f"Error deleting cognitive domain: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/knowledge-levels', methods=['GET'])
def get_knowledge_levels_api():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM knowledge_levels ORDER BY id")
        levels = cur.fetchall()
        return jsonify({'knowledge_levels': levels})
    except Exception as e:
        print(f"Error fetching knowledge levels: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/knowledge-levels', methods=['POST'])
def create_knowledge_level():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    description = data.get('description', '')
    is_active = data.get('is_active', 1)
    if not name:
        return jsonify({'error': 'Level name is required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO knowledge_levels (level_name, description, is_active) 
            VALUES (%s, %s, %s)
        """, (name, description, is_active))
        db.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'message': 'Knowledge level created successfully'})
    except Exception as e:
        print(f"Error creating knowledge level: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/knowledge-levels/<int:level_id>', methods=['PUT'])
def update_knowledge_level(level_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    description = data.get('description', '')
    is_active = data.get('is_active', 1)
    if not name:
        return jsonify({'error': 'Level name is required'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            UPDATE knowledge_levels 
            SET level_name = %s, description = %s, is_active = %s 
            WHERE id = %s
        """, (name, description, is_active, level_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Knowledge level not found'}), 404
        return jsonify({'success': True, 'message': 'Knowledge level updated successfully'})
    except Exception as e:
        print(f"Error updating knowledge level: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/knowledge-levels/<int:level_id>', methods=['DELETE'])
def delete_knowledge_level(level_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM knowledge_levels WHERE id = %s", (level_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Knowledge level not found'}), 404
        return jsonify({'success': True, 'message': 'Knowledge level deleted successfully'})
    except Exception as e:
        print(f"Error deleting knowledge level: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/knowledge-levels/<int:level_id>/toggle', methods=['POST'])
def toggle_knowledge_level(level_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    is_active = data.get('is_active', 1)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE knowledge_levels SET is_active = %s WHERE id = %s", (is_active, level_id))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Knowledge level not found'}), 404
        return jsonify({'success': True, 'message': 'Knowledge level status updated successfully'})
    except Exception as e:
        print(f"Error toggling knowledge level: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
@app.route('/api/delete-question/<int:question_id>', methods=['DELETE'])
def delete_question(question_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM simple_questions WHERE id = %s", (question_id,))
        db.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Question not found'}), 404
        return jsonify({'success': True, 'message': 'Question deleted successfully'})
    except Exception as e:
        print(f"Error deleting question: {e}")
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=5000)