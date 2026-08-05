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
        database="cohsem_IT"
    )

def add_column_if_not_exists(cursor, table, column, definition):
    cursor.execute(f"SHOW COLUMNS FROM {table} LIKE '{column}'")
    exists = cursor.fetchone()
    if not exists:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        print(f"Added column {column} to {table}")
        return True
    return False

def add_foreign_key_if_not_exists(cursor, table, column, ref_table, ref_column):
    try:
        cursor.execute(f"""
            SELECT CONSTRAINT_NAME 
            FROM information_schema.KEY_COLUMN_USAGE 
            WHERE TABLE_NAME = '{table}' 
            AND COLUMN_NAME = '{column}'
            AND REFERENCED_TABLE_NAME = '{ref_table}'
        """)
        if not cursor.fetchone():
            cursor.execute(f"""
                ALTER TABLE {table} 
                ADD FOREIGN KEY ({column}) REFERENCES {ref_table}({ref_column})
            """)
            print(f"Added foreign key {column} -> {ref_table}.{ref_column}")
            return True
    except Exception as e:
        print(f"Note: Could not add foreign key: {e}")
    return False

def add_chapter_id_to_cgs():
    """Add chapter_id column to curricular_goals table"""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SHOW COLUMNS FROM curricular_goals LIKE 'chapter_id'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE curricular_goals ADD COLUMN chapter_id INT DEFAULT NULL")
            print("Added chapter_id column to curricular_goals")
            
            try:
                cur.execute("""
                    ALTER TABLE curricular_goals 
                    ADD FOREIGN KEY (chapter_id) REFERENCES chapters(id) ON DELETE CASCADE
                """)
                print("Added foreign key constraint on chapter_id")
            except Exception as e:
                print(f"Note: Could not add foreign key: {e}")
            
            db.commit()
            return True
        return False
    except Exception as e:
        print(f"Error adding chapter_id to curricular_goals: {e}")
        db.rollback()
        return False
    finally:
        cur.close()
        db.close()

def strip_html_tags(html_content):
    """Strip HTML tags and return plain text"""
    if not html_content:
        return ''
    import re
    clean = re.sub(r'<[^>]+>', ' ', html_content)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()

def has_actual_content(html_content):
    """Check if HTML content has actual text or meaningful content"""
    if not html_content:
        return False
    
    # Check for images
    if '<img' in html_content.lower():
        return True
    
    # Check for structured content
    if any(tag in html_content.lower() for tag in ['<ul', '<ol', '<blockquote', '<pre', '<code']):
        return True
    
    # Check for text content
    text = strip_html_tags(html_content)
    
    # Allow single <p><br></p> as empty, but require some text
    # Check if there's any meaningful text (not just whitespace)
    if text and len(text.strip()) > 0:
        return True
    
    # Also check if there are any non-empty tags with content
    # This handles cases like <p> </p> which might have whitespace
    import re
    # Remove all HTML tags and check for any remaining content
    clean_text = re.sub(r'<[^>]+>', '', html_content)
    clean_text = clean_text.strip()
    if clean_text and len(clean_text) > 0:
        return True
    
    return False

def get_question_text_safe(html_content):
    """Extract safe question text, ensuring there's always some content"""
    if not html_content:
        return '<p><br></p>'
    if has_actual_content(html_content):
        return html_content
    return '<p><br></p>'

def get_cg_count():
    """Get total count of Curricular Goals"""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM curricular_goals")
        return cur.fetchone()[0]
    except:
        return 0
    finally:
        cur.close()
        db.close()

def get_comp_count():
    """Get total count of Competencies"""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM competencies")
        return cur.fetchone()[0]
    except:
        return 0
    finally:
        cur.close()
        db.close()

def get_question_count():
    """Get total count of Questions"""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM simple_questions")
        return cur.fetchone()[0]
    except:
        return 0
    finally:
        cur.close()
        db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    try:
        # Create users table
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
        add_column_if_not_exists(cur, 'users', 'perm_master', 'BOOLEAN DEFAULT FALSE')

        # Create grades table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS grades (
                id INT PRIMARY KEY AUTO_INCREMENT,
                grade_name VARCHAR(50) NOT NULL
            )
        """)

        # Create subjects table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS subjects (
                id INT PRIMARY KEY AUTO_INCREMENT,
                grade_id INT NOT NULL,
                subject_name VARCHAR(100) NOT NULL,
                FOREIGN KEY (grade_id) REFERENCES grades(id),
                INDEX idx_grade_id (grade_id)
            )
        """)

        # Create chapters table
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
                INDEX idx_subject_id (subject_id),
                UNIQUE KEY unique_chapter_subject (subject_id, chapter_name)
            )
        """)

        # Create textbooks table with is_reference column
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
                FOREIGN KEY (grade_id) REFERENCES grades(id),
                UNIQUE KEY unique_textbook_subject (subject_id, textbook_name),
                INDEX idx_subject_id (subject_id),
                INDEX idx_grade_id (grade_id)
            )
        """)
        add_column_if_not_exists(cur, 'textbooks', 'is_reference', 'BOOLEAN DEFAULT FALSE')

        # Create cognitive_domains table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cognitive_domains (
                id INT PRIMARY KEY AUTO_INCREMENT,
                domain_name VARCHAR(100) NOT NULL,
                description TEXT
            )
        """)

        # Create difficulty_levels table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS difficulty_levels (
                id INT PRIMARY KEY AUTO_INCREMENT,
                level_name VARCHAR(50) NOT NULL
            )
        """)

        # Create knowledge_levels table with domain_id and difficulty_id
        cur.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_levels (
                id INT PRIMARY KEY AUTO_INCREMENT,
                level_name VARCHAR(100) NOT NULL,
                description TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                domain_id INT DEFAULT NULL,
                difficulty_id INT DEFAULT NULL
            )
        """)
        
        add_column_if_not_exists(cur, 'knowledge_levels', 'domain_id', 'INT DEFAULT NULL')
        add_column_if_not_exists(cur, 'knowledge_levels', 'difficulty_id', 'INT DEFAULT NULL')

        # Create question_types table with cognitive_id
        cur.execute("""
            CREATE TABLE IF NOT EXISTS question_types (
                id INT PRIMARY KEY AUTO_INCREMENT,
                type_name VARCHAR(100) NOT NULL,
                cognitive_id INT,
                description TEXT,
                FOREIGN KEY (cognitive_id) REFERENCES cognitive_domains(id)
            )
        """)

        # Create curricular_goals table with chapter_id
        cur.execute("""
            CREATE TABLE IF NOT EXISTS curricular_goals (
                id INT PRIMARY KEY AUTO_INCREMENT,
                cg_code VARCHAR(50),
                cg_description TEXT,
                subject_id INT,
                chapter_id INT DEFAULT NULL,
                FOREIGN KEY (subject_id) REFERENCES subjects(id),
                INDEX idx_subject_id (subject_id),
                INDEX idx_chapter_id (chapter_id)
            )
        """)
        
        # Add chapter_id column if it doesn't exist (for existing databases)
        add_column_if_not_exists(cur, 'curricular_goals', 'chapter_id', 'INT DEFAULT NULL')

        # Create competencies table
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

        # Create subject_groups table
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

        # Create simple_questions table with all proper columns
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
                status VARCHAR(30) DEFAULT 'under_review',
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
                INDEX idx_difficulty_id (difficulty_id)
            )
        """)
        
        # Add all necessary columns to simple_questions
        add_column_if_not_exists(cur, 'simple_questions', 'master_reviewed_by', 'VARCHAR(100)')
        add_column_if_not_exists(cur, 'simple_questions', 'master_reviewed_at', 'TIMESTAMP NULL')
        add_column_if_not_exists(cur, 'simple_questions', 'master_reviewed_comment', 'TEXT')
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
        add_column_if_not_exists(cur, 'simple_questions', 'cg_id', 'INT')
        add_column_if_not_exists(cur, 'simple_questions', 'cg_code', 'VARCHAR(50)')
        add_column_if_not_exists(cur, 'simple_questions', 'language', "VARCHAR(20) DEFAULT 'en'")
        add_column_if_not_exists(cur, 'simple_questions', 'domain_id', 'INT')
        add_column_if_not_exists(cur, 'simple_questions', 'knowledge_level_id', 'INT')
        add_column_if_not_exists(cur, 'simple_questions', 'question_type_id', 'INT')
        add_column_if_not_exists(cur, 'simple_questions', 'difficulty_id', 'INT')
        add_column_if_not_exists(cur, 'simple_questions', 'textbook_id', 'INT')
        add_column_if_not_exists(cur, 'simple_questions', 'textbook_name', 'VARCHAR(200)')
        add_column_if_not_exists(cur, 'simple_questions', 'textbook_publisher', 'VARCHAR(200)')
        add_column_if_not_exists(cur, 'simple_questions', 'textbook_page', 'VARCHAR(50)')
        add_column_if_not_exists(cur, 'simple_questions', 'reference_book', 'VARCHAR(500)')
        add_column_if_not_exists(cur, 'simple_questions', 'reference_page', 'VARCHAR(50)')

        db.commit()

        # Check if grades exist
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

            # Get all subjects for CG creation
            cur.execute("SELECT id, subject_name, grade_id FROM subjects")
            all_subjects = cur.fetchall()
            subject_map = {}
            for s in all_subjects:
                subject_map[(s[2], s[1])] = s[0]

            # Add sample textbooks with is_reference flag
            sample_textbooks = [
                ('NCERT Physics Part 1', subject_map.get((1, 'Physics'), 1), 1, 'NCERT', 0),
                ('NCERT Physics Part 2', subject_map.get((1, 'Physics'), 1), 1, 'NCERT', 0),
                ('NCERT Chemistry Part 1', subject_map.get((1, 'Chemistry'), 2), 1, 'NCERT', 0),
                ('NCERT Mathematics', subject_map.get((1, 'Mathematics'), 4), 1, 'NCERT', 0),
                ('NCERT Biology', subject_map.get((1, 'Biology'), 3), 1, 'NCERT', 0),
                ('Concepts of Physics by H.C. Verma', subject_map.get((1, 'Physics'), 1), 1, 'H.C. Verma', 1),
                ('Organic Chemistry by Morrison & Boyd', subject_map.get((1, 'Chemistry'), 2), 1, 'Morrison & Boyd', 1),
                ('Higher Algebra by Hall & Knight', subject_map.get((1, 'Mathematics'), 4), 1, 'Hall & Knight', 1),
                ('Molecular Biology of the Cell', subject_map.get((1, 'Biology'), 3), 1, 'Alberts', 1),
                ('NCERT Physics Part 1', subject_map.get((2, 'Physics'), 5), 2, 'NCERT', 0),
                ('NCERT Chemistry Part 1', subject_map.get((2, 'Chemistry'), 6), 2, 'NCERT', 0),
                ('NCERT Mathematics', subject_map.get((2, 'Mathematics'), 8), 2, 'NCERT', 0),
                ('NCERT Biology', subject_map.get((2, 'Biology'), 7), 2, 'NCERT', 0),
                ('Concepts of Physics by H.C. Verma', subject_map.get((2, 'Physics'), 5), 2, 'H.C. Verma', 1),
                ('Organic Chemistry by Morrison & Boyd', subject_map.get((2, 'Chemistry'), 6), 2, 'Morrison & Boyd', 1),
            ]
            for textbook_name, subject_id, grade_id, publisher, is_reference in sample_textbooks:
                if subject_id:
                    cur.execute("""
                        INSERT INTO textbooks (textbook_name, subject_id, grade_id, publisher, is_reference)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (textbook_name, subject_id, grade_id, publisher, is_reference))

            sample_chapters = [
                (subject_map.get((1, 'Physics'), 1), 'Physical World', 1, None, ''),
                (subject_map.get((1, 'Physics'), 1), 'Units and Measurements', 2, None, ''),
                (subject_map.get((1, 'Chemistry'), 2), 'Some Basic Concepts of Chemistry', 1, None, ''),
                (subject_map.get((1, 'Mathematics'), 4), 'Sets', 1, None, ''),
                (subject_map.get((1, 'Mathematics'), 4), 'Relations and Functions', 2, None, ''),
                (subject_map.get((1, 'Biology'), 3), 'The Living World', 1, None, ''),
                (subject_map.get((2, 'Physics'), 5), 'Electric Charges and Fields', 1, None, ''),
            ]
            for subject_id, name, number, textbook_id, ref_book in sample_chapters:
                if subject_id:
                    cur.execute("""
                        INSERT INTO chapters (subject_id, chapter_name, chapter_number, textbook_id, reference_book)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (subject_id, name, number, textbook_id, ref_book))

            # Create Curricular Goals for ALL subjects with chapter association
            print("Creating Curricular Goals for all subjects...")
            cg_counter = 1
            for subject in all_subjects:
                subject_id = subject[0]
                subject_name = subject[1]
                grade_id = subject[2]
                
                # Get chapters for this subject
                cur.execute("SELECT id, chapter_name FROM chapters WHERE subject_id = %s", (subject_id,))
                subject_chapters = cur.fetchall()
                
                if subject_chapters:
                    for chapter in subject_chapters[:2]:  # Create CGs for first 2 chapters
                        chapter_id = chapter[0]
                        chapter_name = chapter[1]
                        cg_codes = [
                            (f'CG-{cg_counter:03d}', f'Basic Knowledge and Understanding - {chapter_name}', subject_id, chapter_id),
                            (f'CG-{cg_counter+1:03d}', f'Application and Analysis - {chapter_name}', subject_id, chapter_id),
                            (f'CG-{cg_counter+2:03d}', f'Synthesis and Evaluation - {chapter_name}', subject_id, chapter_id)
                        ]
                        for code, desc, subj_id, ch_id in cg_codes:
                            cur.execute("""
                                INSERT INTO curricular_goals (cg_code, cg_description, subject_id, chapter_id)
                                VALUES (%s, %s, %s, %s)
                            """, (code, desc, subj_id, ch_id))
                        cg_counter += 3
                else:
                    # Fallback: create CGs without chapter association
                    cg_codes = [
                        (f'CG-{cg_counter:03d}', f'Basic Knowledge and Understanding - {subject_name}', subject_id, None),
                        (f'CG-{cg_counter+1:03d}', f'Application and Analysis - {subject_name}', subject_id, None),
                        (f'CG-{cg_counter+2:03d}', f'Synthesis and Evaluation - {subject_name}', subject_id, None)
                    ]
                    for code, desc, subj_id, ch_id in cg_codes:
                        cur.execute("""
                            INSERT INTO curricular_goals (cg_code, cg_description, subject_id, chapter_id)
                            VALUES (%s, %s, %s, %s)
                        """, (code, desc, subj_id, ch_id))
                    cg_counter += 3
            
            print(f"Created CGs for {len(all_subjects)} subjects")

            # Create Competencies for ALL CGs
            print("Creating Competencies for all CGs...")
            cur.execute("SELECT id, cg_code FROM curricular_goals")
            all_cgs = cur.fetchall()
            
            comp_counter = 1
            for cg in all_cgs:
                cg_id = cg[0]
                cg_code = cg[1]
                
                comps = [
                    (f'COMP-{comp_counter:03d}', f'Recall and Remember for {cg_code}', cg_id, 1),
                    (f'COMP-{comp_counter+1:03d}', f'Understand and Explain for {cg_code}', cg_id, 1),
                    (f'COMP-{comp_counter+2:03d}', f'Apply and Analyze for {cg_code}', cg_id, 1),
                ]
                for code, desc, cg_id_val, status in comps:
                    cur.execute("""
                        INSERT INTO competencies (comp_code, comp_description, cg_id, status)
                        VALUES (%s, %s, %s, %s)
                    """, (code, desc, cg_id_val, status))
                comp_counter += 3
            
            print(f"Created Competencies for {len(all_cgs)} CGs")

            # ===== COGNITIVE DOMAINS =====
            print("Inserting Cognitive Domains...")
            domains_data = [
                ('Awareness', 'Basic awareness of concepts and information'),
                ('Sensitivity', 'Sensitivity to applications and real-world connections'),
                ('Creativity', 'Creative thinking and problem solving')
            ]
            for domain_name, description in domains_data:
                cur.execute("""
                    INSERT INTO cognitive_domains (domain_name, description) 
                    VALUES (%s, %s)
                """, (domain_name, description))
            
            # Get domain IDs
            cur.execute("SELECT id, domain_name FROM cognitive_domains")
            domains = {row[1]: row[0] for row in cur.fetchall()}

            # ===== DIFFICULTY LEVELS =====
            print("Inserting Difficulty Levels...")
            cur.execute("INSERT INTO difficulty_levels (level_name) VALUES ('Easy'), ('Medium'), ('Hard')")
            
            cur.execute("SELECT id, level_name FROM difficulty_levels")
            difficulties = {row[1]: row[0] for row in cur.fetchall()}

            # ===== KNOWLEDGE LEVELS WITH DOMAIN ASSOCIATIONS =====
            print("Inserting Knowledge Levels with Domain associations...")
            knowledge_levels = [
                # Awareness Domain (domain_id = 1)
                ('Knowledge', 'Basic recall of information and facts', 'Awareness', 'Easy'),
                ('Remembering', 'Retrieving knowledge from memory', 'Awareness', 'Easy'),
                ('Understanding', 'Constructing meaning from information', 'Awareness', 'Easy'),
                ('Comprehension', 'Grasping the meaning of information', 'Awareness', 'Medium'),
                
                # Sensitivity Domain (domain_id = 2)
                ('Application', 'Apply knowledge to new situations', 'Sensitivity', 'Medium'),
                ('Analysis', 'Break down information into parts', 'Sensitivity', 'Medium'),
                ('Synthesis', 'Combine elements to form a new whole', 'Sensitivity', 'Medium'),
                ('Empathy', "Understanding others' perspectives and feelings", 'Sensitivity', 'Medium'),
                ('Interpretation', 'Explaining and interpreting information', 'Sensitivity', 'Medium'),
                
                # Creativity Domain (domain_id = 3)
                ('Evaluation', 'Make judgments based on criteria and standards', 'Creativity', 'Hard'),
                ('Creation', 'Generate new ideas and products', 'Creativity', 'Hard'),
                ('Critical Thinking', 'Deep analysis and evaluation of information', 'Creativity', 'Hard'),
                ('Innovation', 'Novel approaches and solutions to problems', 'Creativity', 'Hard'),
                ('Design Thinking', 'Human-centered problem solving approach', 'Creativity', 'Hard'),
                ('Reflection', 'Thoughtful consideration and self-assessment', 'Creativity', 'Hard')
            ]
            
            for level_name, description, domain_name, difficulty_name in knowledge_levels:
                domain_id = domains.get(domain_name)
                difficulty_id = difficulties.get(difficulty_name)
                cur.execute("""
                    INSERT INTO knowledge_levels (level_name, description, is_active, domain_id, difficulty_id) 
                    VALUES (%s, %s, %s, %s, %s)
                """, (level_name, description, True, domain_id, difficulty_id))

            # ===== QUESTION TYPES WITH DOMAIN ASSOCIATIONS =====
            print("Inserting Question Types with Domain associations...")
            question_types = [
                # Awareness Domain
                ('Multiple Choice', 'Awareness', 'Select the correct answer from given options - tests basic recall'),
                ('True/False', 'Awareness', 'Determine if the statement is true or false - tests understanding'),
                ('Fill in the Blanks', 'Awareness', 'Complete the missing words - tests knowledge and remembering'),
                ('Match the Following', 'Awareness', 'Match items from two columns - tests comprehension'),
                ('Very Short Answer', 'Awareness', 'One word or one sentence answers - tests quick recall'),
                ('Short Answer', 'Awareness', 'Brief explanations in 2-3 sentences - tests understanding'),
                
                # Sensitivity Domain
                ('Short Essay', 'Sensitivity', 'Write a brief essay explaining concepts - tests application'),
                ('Case Study Analysis', 'Sensitivity', 'Analyze a given case study - tests analysis and application'),
                ('Problem Solving', 'Sensitivity', 'Solve given problems using learned concepts - tests application'),
                ('Diagram Based', 'Sensitivity', 'Interpret or draw diagrams - tests analysis and synthesis'),
                ('Data Interpretation', 'Sensitivity', 'Interpret given data or graphs - tests analysis'),
                ('Practical Based', 'Sensitivity', 'Apply knowledge to practical situations - tests application'),
                ('Scenario Based', 'Sensitivity', 'Respond to real-world scenarios - tests sensitivity and empathy'),
                ('Comparative Analysis', 'Sensitivity', 'Compare and contrast concepts - tests analysis and synthesis'),
                
                # Creativity Domain
                ('Long Essay', 'Creativity', 'Write detailed essays with arguments - tests evaluation and creation'),
                ('Creative Writing', 'Creativity', 'Creative expression and original writing - tests creation'),
                ('Project Based', 'Creativity', 'Design and present a project - tests innovation and design thinking'),
                ('Debate/Discussion', 'Creativity', 'Present arguments and counter-arguments - tests critical thinking'),
                ('Research Based', 'Creativity', 'Research and present findings - tests evaluation and synthesis'),
                ('Design Challenge', 'Creativity', 'Design solutions to complex problems - tests innovation'),
                ('Reflective Journal', 'Creativity', 'Reflect on learning and experiences - tests reflection'),
                ('Critical Analysis', 'Creativity', 'Critically analyze texts or arguments - tests critical thinking'),
                ('Portfolio Development', 'Creativity', 'Create a portfolio of work - tests creation and evaluation'),
                ('Peer Review', 'Creativity', 'Review and provide feedback on others\' work - tests evaluation')
            ]
            
            for type_name, domain_name, description in question_types:
                domain_id = domains.get(domain_name)
                cur.execute("""
                    INSERT INTO question_types (type_name, cognitive_id, description) 
                    VALUES (%s, %s, %s)
                """, (type_name, domain_id, description))

            # Add subject groups
            groups = [
                ('phy_grp_11', 'Physics Group Class 11', 1, subject_map.get((1, 'Physics'), 1)),
                ('chem_grp_11', 'Chemistry Group Class 11', 1, subject_map.get((1, 'Chemistry'), 2)),
                ('bio_grp_11', 'Biology Group Class 11', 1, subject_map.get((1, 'Biology'), 3)),
                ('math_grp_11', 'Mathematics Group Class 11', 1, subject_map.get((1, 'Mathematics'), 4)),
                ('cs_grp_11', 'Computer Science Group Class 11', 1, subject_map.get((1, 'Computer Science'), 9)),
                ('phy_grp_12', 'Physics Group Class 12', 2, subject_map.get((2, 'Physics'), 5)),
                ('chem_grp_12', 'Chemistry Group Class 12', 2, subject_map.get((2, 'Chemistry'), 6)),
                ('bio_grp_12', 'Biology Group Class 12', 2, subject_map.get((2, 'Biology'), 7)),
                ('math_grp_12', 'Mathematics Group Class 12', 2, subject_map.get((2, 'Mathematics'), 8)),
                ('cs_grp_12', 'Computer Science Group Class 12', 2, subject_map.get((2, 'Computer Science'), 10))
            ]
            for code, name, grade_id, subject_id in groups:
                if subject_id:
                    cur.execute("""
                        INSERT INTO subject_groups (group_code, group_name, grade_id, subject_id)
                        VALUES (%s, %s, %s, %s)
                    """, (code, name, grade_id, subject_id))

            # Create default users
            admin_password = generate_password_hash('admin123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap, perm_master, subject_group)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, ('admin', admin_password, 'admin', 'leader', True, True, True, True, True, None))

            writer_password = generate_password_hash('writer123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap, perm_master, subject_group)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, ('writer', writer_password, 'writer', 'member', True, False, False, False, False, 'phy_grp_11'))

            master_password = generate_password_hash('master123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap, perm_master, subject_group)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, ('master', master_password, 'master', 'member', False, False, False, False, True, 'phy_grp_11'))

            reviewer_password = generate_password_hash('reviewer123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap, perm_master, subject_group)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, ('reviewer', reviewer_password, 'reviewer', 'member', False, False, True, False, False, 'phy_grp_11'))

            approver_password = generate_password_hash('approver123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap, perm_master, subject_group)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, ('approver', approver_password, 'approver', 'member', False, False, False, True, False, 'phy_grp_11'))

            builder_password = generate_password_hash('builder123')
            cur.execute("""
                INSERT INTO users (username, password, role, group_role, perm_re, perm_ra, perm_rc, perm_ap, perm_master, subject_group)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, ('builder', builder_password, 'builder', 'member', False, True, False, False, False, 'phy_grp_11'))

            db.commit()
            print("Default data inserted successfully")

    except Exception as e:
        print(f"Database initialization error: {e}")
        traceback.print_exc()
        db.rollback()
    finally:
        cur.close()
        db.close()

def fix_missing_cgs_and_comps():
    """Force create missing CGs and Competencies for all subjects with chapter association"""
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, subject_name FROM subjects")
        subjects = cur.fetchall()
        
        if not subjects:
            print("No subjects found")
            return
        
        print(f"Found {len(subjects)} subjects. Checking for missing CGs and Competencies...")
        
        for subject in subjects:
            # Get chapters for this subject
            cur.execute("SELECT id, chapter_name FROM chapters WHERE subject_id = %s", (subject['id'],))
            subject_chapters = cur.fetchall()
            
            if not subject_chapters:
                print(f"No chapters found for subject {subject['subject_name']}, skipping CG creation")
                continue
            
            for chapter in subject_chapters:
                cur.execute("""
                    SELECT COUNT(*) as count FROM curricular_goals 
                    WHERE subject_id = %s AND chapter_id = %s
                """, (subject['id'], chapter['id']))
                cg_count = cur.fetchone()['count']
                
                if cg_count == 0:
                    print(f"Creating CGs for chapter {chapter['chapter_name']} (Subject: {subject['subject_name']})")
                    sample_cgs = [
                        (f'CG-{subject["id"]:03d}-{chapter["id"]:03d}-01', f'Basic Knowledge and Understanding - {chapter["chapter_name"]}', subject['id'], chapter['id']),
                        (f'CG-{subject["id"]:03d}-{chapter["id"]:03d}-02', f'Application and Analysis - {chapter["chapter_name"]}', subject['id'], chapter['id']),
                        (f'CG-{subject["id"]:03d}-{chapter["id"]:03d}-03', f'Synthesis and Evaluation - {chapter["chapter_name"]}', subject['id'], chapter['id']),
                    ]
                    for code, desc, subj_id, ch_id in sample_cgs:
                        cur.execute("""
                            INSERT INTO curricular_goals (cg_code, cg_description, subject_id, chapter_id)
                            VALUES (%s, %s, %s, %s)
                        """, (code, desc, subj_id, ch_id))
                    db.commit()
                    print(f"Created 3 CGs for chapter {chapter['chapter_name']}")
        
        # Also create CGs for subjects that have no chapters
        for subject in subjects:
            cur.execute("SELECT COUNT(*) as count FROM chapters WHERE subject_id = %s", (subject['id'],))
            chapter_count = cur.fetchone()['count']
            
            if chapter_count == 0:
                cur.execute("SELECT COUNT(*) as count FROM curricular_goals WHERE subject_id = %s", (subject['id'],))
                cg_count = cur.fetchone()['count']
                
                if cg_count == 0:
                    print(f"Creating CGs for subject {subject['subject_name']} (no chapters found)")
                    sample_cgs = [
                        (f'CG-{subject["id"]:03d}-01', f'Basic Knowledge and Understanding - {subject["subject_name"]}', subject['id'], None),
                        (f'CG-{subject["id"]:03d}-02', f'Application and Analysis - {subject["subject_name"]}', subject['id'], None),
                        (f'CG-{subject["id"]:03d}-03', f'Synthesis and Evaluation - {subject["subject_name"]}', subject['id'], None),
                    ]
                    for code, desc, subj_id, ch_id in sample_cgs:
                        cur.execute("""
                            INSERT INTO curricular_goals (cg_code, cg_description, subject_id, chapter_id)
                            VALUES (%s, %s, %s, %s)
                        """, (code, desc, subj_id, ch_id))
                    db.commit()
                    print(f"Created 3 CGs for {subject['subject_name']}")
        
        # Create Competencies for all CGs that don't have them
        cur.execute("SELECT id, cg_code FROM curricular_goals")
        all_cgs = cur.fetchall()
        
        for cg in all_cgs:
            cur.execute("SELECT COUNT(*) as count FROM competencies WHERE cg_id = %s", (cg['id'],))
            comp_count = cur.fetchone()['count']
            
            if comp_count == 0:
                print(f"Creating Competencies for CG {cg['cg_code']}")
                sample_comps = [
                    (f'COMP-{cg["id"]:03d}-A', f'Recall and Remember for {cg["cg_code"]}', cg['id'], 1),
                    (f'COMP-{cg["id"]:03d}-B', f'Understand and Explain for {cg["cg_code"]}', cg['id'], 1),
                    (f'COMP-{cg["id"]:03d}-C', f'Apply and Analyze for {cg["cg_code"]}', cg['id'], 1),
                ]
                for code, desc, cg_id, status in sample_comps:
                    cur.execute("""
                        INSERT INTO competencies (comp_code, comp_description, cg_id, status)
                        VALUES (%s, %s, %s, %s)
                    """, (code, desc, cg_id, status))
                db.commit()
                print(f"Created 3 Competencies for CG {cg['cg_code']}")
        
        cur.execute("SELECT COUNT(*) as count FROM curricular_goals")
        total_cgs = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) as count FROM competencies")
        total_comps = cur.fetchone()['count']
        print(f"Final counts: {total_cgs} CGs, {total_comps} Competencies")
        
    except Exception as e:
        print(f"Error fixing missing CGs and Competencies: {e}")
        traceback.print_exc()
        db.rollback()
    finally:
        cur.close()
        db.close()

def ensure_approved_questions():
    """Ensure there are approved questions in the database"""
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) as count FROM simple_questions WHERE status = 'approved'")
        result = cur.fetchone()
        count = result['count'] if result else 0
        
        if count > 0:
            print(f"Found {count} approved questions")
            return
        
        print("No approved questions found. Creating sample approved questions...")
        
        cur.execute("SELECT id, subject_name FROM subjects")
        subjects = cur.fetchall()
        
        if not subjects:
            print("No subjects found")
            return
        
        all_cgs = []
        for subject in subjects:
            cur.execute("SELECT id, cg_code, chapter_id FROM curricular_goals WHERE subject_id = %s", (subject['id'],))
            cgs = cur.fetchall()
            if not cgs:
                default_cgs = [
                    (f'DEF-CG-{subject["id"]}-01', f'Default CG 1 - {subject["subject_name"]}', subject['id'], None),
                    (f'DEF-CG-{subject["id"]}-02', f'Default CG 2 - {subject["subject_name"]}', subject['id'], None),
                ]
                for code, desc, subj_id, ch_id in default_cgs:
                    cur.execute("""
                        INSERT INTO curricular_goals (cg_code, cg_description, subject_id, chapter_id)
                        VALUES (%s, %s, %s, %s)
                    """, (code, desc, subj_id, ch_id))
                db.commit()
                cur.execute("SELECT id, cg_code, chapter_id FROM curricular_goals WHERE subject_id = %s", (subject['id'],))
                cgs = cur.fetchall()
            all_cgs.extend(cgs)
        
        if not all_cgs:
            print("No CGs found or created")
            return
        
        all_comps = []
        for cg in all_cgs:
            cur.execute("SELECT id, comp_code FROM competencies WHERE cg_id = %s", (cg['id'],))
            comps = cur.fetchall()
            if not comps:
                default_comps = [
                    (f'DEF-COMP-{cg["id"]}-A', f'Default Competency A for {cg["cg_code"]}', cg['id'], 1),
                    (f'DEF-COMP-{cg["id"]}-B', f'Default Competency B for {cg["cg_code"]}', cg['id'], 1),
                ]
                for code, desc, cg_id, status in default_comps:
                    cur.execute("""
                        INSERT INTO competencies (comp_code, comp_description, cg_id, status)
                        VALUES (%s, %s, %s, %s)
                    """, (code, desc, cg_id, status))
                db.commit()
                cur.execute("SELECT id, comp_code FROM competencies WHERE cg_id = %s", (cg['id'],))
                comps = cur.fetchall()
            all_comps.extend(comps)
        
        if not all_comps:
            print("No Competencies found or created")
            return
        
        all_chapters = []
        for subject in subjects:
            cur.execute("SELECT id, chapter_name FROM chapters WHERE subject_id = %s", (subject['id'],))
            chapters = cur.fetchall()
            if not chapters:
                default_chapters = [
                    (subject['id'], 'Chapter 1', 1, None, ''),
                    (subject['id'], 'Chapter 2', 2, None, ''),
                    (subject['id'], 'Chapter 3', 3, None, '')
                ]
                for subj_id, name, num, textbook_id, ref_book in default_chapters:
                    cur.execute("""
                        INSERT INTO chapters (subject_id, chapter_name, chapter_number, textbook_id, reference_book)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (subj_id, name, num, textbook_id, ref_book))
                db.commit()
                cur.execute("SELECT id, chapter_name FROM chapters WHERE subject_id = %s", (subject['id'],))
                chapters = cur.fetchall()
            all_chapters.extend(chapters)
        
        sample_questions = [
            ('What is Newton\'s First Law?', 'An object remains at rest or in uniform motion unless acted upon by an external force.', 2, 5),
            ('Define acceleration.', 'Rate of change of velocity with respect to time.', 1, 3),
            ('What is the SI unit of force?', 'Newton (N)', 1, 2),
            ('State the law of conservation of energy.', 'Energy cannot be created or destroyed.', 2, 5),
            ('What is the difference between speed and velocity?', 'Speed is scalar, velocity is vector.', 2, 4),
        ]
        
        # Get domain and knowledge level IDs
        cur.execute("SELECT id FROM cognitive_domains LIMIT 1")
        domain = cur.fetchone()
        domain_id = domain['id'] if domain else 1
        
        cur.execute("SELECT id FROM knowledge_levels LIMIT 1")
        knowledge_level = cur.fetchone()
        knowledge_level_id = knowledge_level['id'] if knowledge_level else 1
        
        cur.execute("SELECT id FROM question_types LIMIT 1")
        question_type = cur.fetchone()
        question_type_id = question_type['id'] if question_type else 1
        
        cur.execute("SELECT id FROM difficulty_levels LIMIT 1")
        difficulty = cur.fetchone()
        difficulty_id = difficulty['id'] if difficulty else 1
        
        # Get textbooks for reference
        cur.execute("SELECT id, textbook_name, is_reference FROM textbooks LIMIT 5")
        sample_textbooks = cur.fetchall()
        
        question_counter = 0
        for subject in subjects:
            # Get chapters for this subject
            cur.execute("SELECT id, chapter_name FROM chapters WHERE subject_id = %s", (subject['id'],))
            subject_chapters = cur.fetchall()
            
            if not subject_chapters:
                continue
                
            for i, (q_text, ans, marks, duration) in enumerate(sample_questions):
                chapter = subject_chapters[i % len(subject_chapters)] if subject_chapters else None
                cg = all_cgs[i % len(all_cgs)] if all_cgs else None
                comp = all_comps[i % len(all_comps)] if all_comps else None
                textbook = sample_textbooks[i % len(sample_textbooks)] if sample_textbooks else None
                
                if not cg:
                    cur.execute("SELECT id, cg_code FROM curricular_goals WHERE subject_id = %s LIMIT 1", (subject['id'],))
                    cg = cur.fetchone()
                    if not cg:
                        continue
                
                if not comp:
                    cur.execute("SELECT id, comp_code FROM competencies WHERE cg_id = %s LIMIT 1", (cg['id'],))
                    comp = cur.fetchone()
                    if not comp:
                        continue
                
                if not chapter:
                    cur.execute("SELECT id, chapter_name FROM chapters WHERE subject_id = %s LIMIT 1", (subject['id'],))
                    chapter = cur.fetchone()
                    if not chapter:
                        continue
                
                # Determine if textbook or reference
                textbook_id = None
                textbook_name = None
                reference_book = None
                if textbook:
                    if textbook['is_reference'] == 1:
                        reference_book = textbook['textbook_name']
                    else:
                        textbook_id = textbook['id']
                        textbook_name = textbook['textbook_name']
                
                cur.execute("""
                    INSERT INTO simple_questions 
                    (question_text, answer, marks, duration_minutes, 
                     subject_id, grade_id, chapter_id, chapter_name,
                     cg_id, cg_code, comp_id, competency_code,
                     domain_id, knowledge_level_id, question_type_id, difficulty_id,
                     status, created_by, created_at, language,
                     textbook_id, textbook_name, reference_book)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s)
                """, (
                    q_text, ans, marks, duration,
                    subject['id'], 1,
                    chapter['id'], chapter['chapter_name'],
                    cg['id'], cg['cg_code'],
                    comp['id'], comp['comp_code'],
                    domain_id, knowledge_level_id, question_type_id, difficulty_id,
                    'approved', 'admin', 'en',
                    textbook_id, textbook_name, reference_book
                ))
                question_counter += 1
        
        db.commit()
        print(f"Added {question_counter} sample approved questions")
        
    except Exception as e:
        print(f"Error ensuring approved questions: {e}")
        traceback.print_exc()
        db.rollback()
    finally:
        cur.close()
        db.close()

def fix_question_relationships():
    """Fix missing relationships in questions"""
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, question_text, subject_id, chapter_name, cg_code, competency_code FROM simple_questions WHERE status = 'approved' LIMIT 10")
        questions = cur.fetchall()
        print(f"Found {len(questions)} approved questions to check")
        
        cur.execute("""
            UPDATE simple_questions sq
            JOIN chapters ch ON ch.chapter_name = sq.chapter_name AND ch.subject_id = sq.subject_id
            SET sq.chapter_id = ch.id
            WHERE sq.chapter_id IS NULL AND sq.chapter_name IS NOT NULL AND sq.chapter_name != ''
        """)
        updated_chapters = cur.rowcount
        print(f"Updated {updated_chapters} questions with chapter_id")
        
        cur.execute("""
            UPDATE simple_questions sq
            JOIN curricular_goals cg ON cg.cg_code = sq.cg_code AND cg.subject_id = sq.subject_id
            SET sq.cg_id = cg.id
            WHERE sq.cg_id IS NULL AND sq.cg_code IS NOT NULL AND sq.cg_code != ''
        """)
        updated_cgs = cur.rowcount
        print(f"Updated {updated_cgs} questions with cg_id")
        
        cur.execute("""
            UPDATE simple_questions sq
            JOIN competencies c ON c.comp_code = sq.competency_code
            SET sq.comp_id = c.id
            WHERE sq.comp_id IS NULL AND sq.competency_code IS NOT NULL AND sq.competency_code != ''
        """)
        updated_comps = cur.rowcount
        print(f"Updated {updated_comps} questions with comp_id")
        
        # Update domain_id and knowledge_level_id if possible
        cur.execute("""
            UPDATE simple_questions sq
            JOIN cognitive_domains cd ON cd.domain_name = sq.domain_name
            SET sq.domain_id = cd.id
            WHERE sq.domain_id IS NULL AND sq.domain_name IS NOT NULL AND sq.domain_name != ''
        """)
        updated_domains = cur.rowcount
        print(f"Updated {updated_domains} questions with domain_id")
        
        cur.execute("""
            UPDATE simple_questions sq
            JOIN knowledge_levels kl ON kl.level_name = sq.knowledge_level_name
            SET sq.knowledge_level_id = kl.id
            WHERE sq.knowledge_level_id IS NULL AND sq.knowledge_level_name IS NOT NULL AND sq.knowledge_level_name != ''
        """)
        updated_knowledge = cur.rowcount
        print(f"Updated {updated_knowledge} questions with knowledge_level_id")
        
        cur.execute("""
            UPDATE simple_questions sq
            JOIN question_types qt ON qt.type_name = sq.question_type_name
            SET sq.question_type_id = qt.id
            WHERE sq.question_type_id IS NULL AND sq.question_type_name IS NOT NULL AND sq.question_type_name != ''
        """)
        updated_types = cur.rowcount
        print(f"Updated {updated_types} questions with question_type_id")
        
        cur.execute("""
            UPDATE simple_questions sq
            JOIN difficulty_levels dl ON dl.level_name = sq.difficulty_name
            SET sq.difficulty_id = dl.id
            WHERE sq.difficulty_id IS NULL AND sq.difficulty_name IS NOT NULL AND sq.difficulty_name != ''
        """)
        updated_difficulties = cur.rowcount
        print(f"Updated {updated_difficulties} questions with difficulty_id")
        
        db.commit()
        
        cur.execute("""
            SELECT COUNT(*) as count FROM simple_questions 
            WHERE status = 'approved' 
            AND chapter_id IS NOT NULL 
            AND cg_id IS NOT NULL 
            AND comp_id IS NOT NULL
            AND domain_id IS NOT NULL
            AND knowledge_level_id IS NOT NULL
            AND question_type_id IS NOT NULL
            AND difficulty_id IS NOT NULL
        """)
        fully_linked = cur.fetchone()['count']
        print(f"Questions with all relationships linked: {fully_linked}")
        
    except Exception as e:
        print(f"Error fixing relationships: {e}")
        traceback.print_exc()
        db.rollback()
    finally:
        cur.close()
        db.close()

def add_sample_relationships_to_questions():
    """Add sample relationships to existing questions"""
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, chapter_name FROM chapters WHERE subject_id = 1")
        chapters = cur.fetchall()
        
        cur.execute("SELECT id, cg_code FROM curricular_goals WHERE subject_id = 1")
        cgs = cur.fetchall()
        
        cur.execute("SELECT id, comp_code FROM competencies")
        comps = cur.fetchall()
        
        cur.execute("SELECT id FROM cognitive_domains LIMIT 1")
        domain = cur.fetchone()
        domain_id = domain['id'] if domain else 1
        
        cur.execute("SELECT id FROM knowledge_levels LIMIT 1")
        knowledge_level = cur.fetchone()
        knowledge_level_id = knowledge_level['id'] if knowledge_level else 1
        
        cur.execute("SELECT id FROM question_types LIMIT 1")
        question_type = cur.fetchone()
        question_type_id = question_type['id'] if question_type else 1
        
        cur.execute("SELECT id FROM difficulty_levels LIMIT 1")
        difficulty = cur.fetchone()
        difficulty_id = difficulty['id'] if difficulty else 1
        
        if not chapters or not cgs or not comps:
            print("Missing required data for relationships")
            return
        
        cur.execute("SELECT id FROM simple_questions WHERE subject_id = 1 AND status = 'approved'")
        questions = cur.fetchall()
        
        if not questions:
            print("No questions found for subject 1")
            return
        
        for i, q in enumerate(questions):
            chapter = chapters[i % len(chapters)]
            cg = cgs[i % len(cgs)]
            comp = comps[i % len(comps)]
            
            cur.execute("""
                UPDATE simple_questions 
                SET chapter_id = %s, chapter_name = %s,
                    cg_id = %s, cg_code = %s,
                    comp_id = %s, competency_code = %s,
                    domain_id = %s, knowledge_level_id = %s,
                    question_type_id = %s, difficulty_id = %s
                WHERE id = %s
            """, (chapter['id'], chapter['chapter_name'], 
                  cg['id'], cg['cg_code'], 
                  comp['id'], comp['comp_code'],
                  domain_id, knowledge_level_id,
                  question_type_id, difficulty_id,
                  q['id']))
        
        db.commit()
        print(f"Updated {len(questions)} questions with relationships")
        
    except Exception as e:
        print(f"Error adding sample relationships: {e}")
        traceback.print_exc()
        db.rollback()
    finally:
        cur.close()
        db.close()

def get_user_subject_ids(username):
    """Get all subject IDs that the user has access to based on their subject group"""
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
        print(f"Error getting user subject IDs: {e}")
        return []
    finally:
        cur.close()
        db.close()

def get_user_grades(username):
    """Get all grade IDs that the user has access to based on their subject group"""
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
        print(f"Error getting user grades: {e}")
        return []
    finally:
        cur.close()
        db.close()

def apply_subject_filter(query, user_role, subject_group, subject_id_column='subject_id'):
    """Apply subject group filtering to a query"""
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


# ============ ROUTES ============

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
    if not session.get('perm_re', False) and session.get('user_role') != 'admin':
        flash('Access Denied: Writer (RE) permission required', 'error')
        return redirect(url_for('dashboard'))
    return render_template('questions_upload.html', user=session['user'])

@app.route('/page2')
def page2():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    if not session.get('perm_re', False) and session.get('user_role') != 'admin':
        flash('Access Denied: Writer (RE) permission required', 'error')
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
    if session.get('user_role') != 'admin':
        flash('Access Denied: Admin privileges required', 'error')
        return redirect(url_for('dashboard'))
    return render_template('configure_dashboard.html', user=session['user'])

@app.route('/review')
def review():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('dashboard_login'))
    
    username = session.get('user', 'User')
    user_role = session.get('user_role', 'writer')
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
        page_title = "Questions for Master Review"
    elif permissions.get('AP'):
        page_title = "Questions Ready for Approval"
    elif permissions.get('RC'):
        page_title = "Questions for Reviewer Review"
    elif permissions.get('RA'):
        page_title = "Approved Questions for Paper Building"
    elif permissions.get('RE'):
        page_title = "My Questions"
    
    return render_template('review.html', 
                         user=username, 
                         user_role=user_role,
                         permissions=permissions,
                         page_title=page_title)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('dashboard_login'))


# ============ API ROUTES ============

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
        
        user_subject_ids = []
        if user_role != 'admin' and subject_group:
            cur.execute("SELECT subject_id FROM subject_groups WHERE group_code = %s", (subject_group,))
            user_subject_ids = [row['subject_id'] for row in cur.fetchall()]
        
        cur.execute("SELECT id, subject_name, grade_id FROM subjects")
        all_subjects = cur.fetchall()
        subjects_dict = {s['id']: s for s in all_subjects}
        
        cur.execute("SELECT id, grade_name FROM grades ORDER BY id")
        all_grades = cur.fetchall()
        
        stats = {}
        
        for grade in all_grades:
            grade_id = grade['id']
            grade_name = grade['grade_name']
            
            if user_role != 'admin' and user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                        SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                        SUM(CASE WHEN status = 'reviewed_completed' THEN 1 ELSE 0 END) as reviewed_completed,
                        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                        SUM(CASE WHEN status = 'master_reviewed' THEN 1 ELSE 0 END) as master_reviewed,
                        SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END) as draft
                    FROM simple_questions 
                    WHERE grade_id = %s AND subject_id IN ({placeholders})
                """, tuple([grade_id] + user_subject_ids))
            else:
                cur.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                        SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                        SUM(CASE WHEN status = 'reviewed_completed' THEN 1 ELSE 0 END) as reviewed_completed,
                        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                        SUM(CASE WHEN status = 'master_reviewed' THEN 1 ELSE 0 END) as master_reviewed,
                        SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END) as draft
                    FROM simple_questions 
                    WHERE grade_id = %s
                """, (grade_id,))
            grade_stats = cur.fetchone()
            
            if user_role != 'admin' and user_subject_ids:
                placeholders = ','.join(['%s'] * len(user_subject_ids))
                cur.execute(f"""
                    SELECT 
                        subject_id,
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                        SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                        SUM(CASE WHEN status = 'reviewed_completed' THEN 1 ELSE 0 END) as reviewed_completed,
                        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                        SUM(CASE WHEN status = 'master_reviewed' THEN 1 ELSE 0 END) as master_reviewed,
                        SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END) as draft
                    FROM simple_questions 
                    WHERE grade_id = %s AND subject_id IN ({placeholders})
                    GROUP BY subject_id
                """, tuple([grade_id] + user_subject_ids))
            else:
                cur.execute("""
                    SELECT 
                        subject_id,
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                        SUM(CASE WHEN status = 'under_review' THEN 1 ELSE 0 END) as under_review,
                        SUM(CASE WHEN status = 'reviewed_completed' THEN 1 ELSE 0 END) as reviewed_completed,
                        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                        SUM(CASE WHEN status = 'master_reviewed' THEN 1 ELSE 0 END) as master_reviewed,
                        SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END) as draft
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
                        'under_review': subj['under_review'] or 0,
                        'reviewed_completed': subj['reviewed_completed'] or 0,
                        'rejected': subj['rejected'] or 0,
                        'master_reviewed': subj['master_reviewed'] or 0,
                        'draft': subj['draft'] or 0,
                        'subject_name': subjects_dict[subject_id]['subject_name']
                    }
            
            stats[f'grade_{grade_id}'] = {
                'total': grade_stats['total'] or 0,
                'approved': grade_stats['approved'] or 0,
                'under_review': grade_stats['under_review'] or 0,
                'reviewed_completed': grade_stats['reviewed_completed'] or 0,
                'rejected': grade_stats['rejected'] or 0,
                'master_reviewed': grade_stats['master_reviewed'] or 0,
                'draft': grade_stats['draft'] or 0,
                'subjects': subjects_dict_for_grade,
                'grade_name': grade_name,
                'grade_id': grade_id
            }
        
        if user_role != 'admin' and user_subject_ids:
            placeholders = ','.join(['%s'] * len(user_subject_ids))
            cur.execute(f"""
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
                WHERE sq.subject_id IN ({placeholders})
                ORDER BY sq.created_at DESC
                LIMIT 10
            """, tuple(user_subject_ids))
        else:
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
        print(f"Error fetching chapters: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/chapters', methods=['POST'])
def create_chapter():
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
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
        print(f"Error creating chapter: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/chapters/<int:chapter_id>', methods=['PUT'])
def update_chapter(chapter_id):
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
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
        print(f"Error updating chapter: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/chapters/<int:chapter_id>', methods=['DELETE'])
def delete_chapter(chapter_id):
    if 'user' not in session or session.get('user_role') != 'admin':
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
        print(f"Error fetching subject chapters: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


# ============ TEXTBOOK API ENDPOINTS ============

@app.route('/api/textbooks', methods=['GET'])
def get_textbooks():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    grade_id = request.args.get('grade_id')
    book_type = request.args.get('book_type')  # 'textbook' or 'reference'
    
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
        print(f"Error fetching textbooks: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/textbooks', methods=['POST'])
def create_textbook():
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    textbook_name = data.get('textbook_name')
    subject_id = data.get('subject_id')
    grade_id = data.get('grade_id')
    publisher = data.get('publisher', '')
    is_reference = data.get('is_reference', 0)  # 0 = textbook, 1 = reference book
    
    if not textbook_name or not subject_id or not grade_id:
        return jsonify({'error': 'Textbook name, subject, and grade are required'}), 400
    
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
        print(f"Error creating textbook: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/textbooks/<int:textbook_id>', methods=['PUT'])
def update_textbook(textbook_id):
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    textbook_name = data.get('textbook_name')
    subject_id = data.get('subject_id')
    grade_id = data.get('grade_id')
    publisher = data.get('publisher', '')
    is_reference = data.get('is_reference', 0)
    
    if not textbook_name or not subject_id or not grade_id:
        return jsonify({'error': 'Textbook name, subject, and grade are required'}), 400
    
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
        print(f"Error updating textbook: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/textbooks/<int:textbook_id>', methods=['DELETE'])
def delete_textbook(textbook_id):
    if 'user' not in session or session.get('user_role') != 'admin':
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
        print(f"Error deleting textbook: {e}")
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/subjects/<int:subject_id>/textbooks', methods=['GET'])
def get_subject_textbooks(subject_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    book_type = request.args.get('book_type')  # 'textbook' or 'reference'
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
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
        print(f"Error fetching subject textbooks: {e}")
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
        return jsonify({'error': 'Invalid group code format'}), 400
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
        return jsonify({'error': 'Invalid group code format'}), 400
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
            return jsonify({'error': f'Cannot delete group because it has {user_count} user(s) assigned.'}), 400
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
        
        query = """
            SELECT sq.id, sq.question_text as question, sq.answer, sq.marks, sq.duration_minutes,
                   COALESCE(sq.status, 'under_review') as status,
                   sq.created_by, sq.created_at,
                   sq.reviewed_by, sq.reviewed_at, sq.reviewed_comment,
                   sq.rejection_reason, sq.approved_by, sq.rejected_by, sq.rejected_at,
                   sq.master_reviewed_by, sq.master_reviewed_at, sq.master_reviewed_comment,
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
                permission_filters.append("(sq.created_by = %s AND sq.status IN ('under_review', 'rejected', 'draft'))")
                params.append(username)
            if perm_master:
                permission_filters.append("(sq.status = 'under_review')")
            if perm_rc:
                permission_filters.append("(sq.status = 'master_reviewed')")
            if perm_ap:
                permission_filters.append("(sq.status = 'reviewed_completed')")
            if perm_ra:
                permission_filters.append("(sq.status = 'approved')")
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
            
            if perm_re and q['created_by'] == username:
                if q['status'] in ['under_review', None, 'draft']:
                    can_edit = True
                if q['status'] == 'rejected':
                    can_rework = True
                if q['status'] == 'draft':
                    can_edit = True
                    can_rework = True
            
            if perm_master and q['status'] == 'under_review':
                can_master_review = True
            
            if perm_rc and q['status'] == 'master_reviewed':
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
                can_master_review = True
            
            if user_role in ['reviewer', 'approver', 'master'] and q['status'] != 'approved':
                can_rework = True
            
            # Parse images
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
                'status': q['status'] or 'under_review',
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
                'can_master_review': can_master_review
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
            'user_role': user_role
        })
    except Exception as e:
        print(f"Error fetching review questions: {e}")
        traceback.print_exc()
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
        
        if question['status'] != 'under_review' and user_role != 'admin':
            return jsonify({'error': 'Only under review questions can be master reviewed'}), 400
        
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'master_reviewed', 
                master_reviewed_by = %s, 
                master_reviewed_at = %s,
                master_reviewed_comment = %s
            WHERE id = %s
        """, (username, datetime.now(), comment, question_id))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Question marked as master reviewed'})
    except Exception as e:
        print(f"Error in master_review_question: {e}")
        traceback.print_exc()
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
    user_role = session.get('user_role', 'writer')
    perm_rc = session.get('perm_rc', False)
    subject_group = session.get('subject_group')
    
    if user_role != 'admin' and not perm_rc:
        return jsonify({'error': 'Reviewer (RC) permission required'}), 403
    
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
        
        if question['status'] != 'master_reviewed' and user_role != 'admin':
            return jsonify({'error': 'Only master reviewed questions can be reviewed'}), 400
        
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'reviewed_completed', 
                reviewed_by = %s, 
                reviewed_at = %s,
                reviewed_comment = %s
            WHERE id = %s
        """, (username, datetime.now(), comment, question_id))
        db.commit()
        
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
        print(f"Error in approve_question: {e}")
        traceback.print_exc()
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
        
        cur.execute("SELECT created_by, status FROM simple_questions WHERE id = %s", (question_id,))
        question = cur.fetchone()
        if not question:
            return jsonify({'error': 'Question not found'}), 404
        
        can_rework = False
        if user_role == 'admin':
            can_rework = True
        elif perm_master or perm_rc or perm_ap:
            can_rework = question['status'] != 'approved'
        elif perm_re and question['created_by'] == username:
            can_rework = question['status'] in ['rejected', 'draft']
        
        if not can_rework:
            return jsonify({'error': 'Not authorized to rework this question'}), 403
        
        comment_with_meta = f"[REWORK by {username} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {rework_comment}"
        
        cur.execute("""
            UPDATE simple_questions 
            SET status = 'draft',
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
                approved_at = NULL
            WHERE id = %s
        """, (comment_with_meta, question_id))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Question moved to draft for rework'})
    except Exception as e:
        print(f"Error in rework_question: {e}")
        traceback.print_exc()
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
    status = data.get('status')
    
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
            can_edit = question_access['status'] in ['draft', 'under_review', 'rejected']
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
        
        # Textbook/Reference fields
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
        
        if status is not None:
            update_fields += ", status = %s"
            params.append(status)
        
        params.append(question_id)
        
        cur.execute(f"""
            UPDATE simple_questions 
            SET {update_fields}
            WHERE id = %s
        """, params)
        db.commit()
        
        return jsonify({'success': True, 'message': 'Question updated successfully'})
    except Exception as e:
        print(f"Error updating question: {e}")
        traceback.print_exc()
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
        print(f"Error fetching builder questions: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/cgs-for-chapters', methods=['GET'])
def get_cgs_for_chapters():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    chapter_ids = request.args.get('chapter_ids')
    
    if not subject_id:
        return jsonify({'error': 'Subject ID required'}), 400
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        check_query = """
            SELECT COUNT(*) as count FROM simple_questions 
            WHERE subject_id = %s AND status = 'approved'
        """
        cur.execute(check_query, (subject_id,))
        total_approved = cur.fetchone()['count']
        
        if total_approved == 0:
            return jsonify({'cgs': []})
        
        query = """
            SELECT DISTINCT cg.id, cg.cg_code, cg.cg_description,
                   COUNT(sq.id) as question_count
            FROM curricular_goals cg
            JOIN simple_questions sq ON sq.cg_id = cg.id
            WHERE sq.subject_id = %s AND sq.status = 'approved'
        """
        params = [subject_id]
        
        if chapter_ids:
            chapter_list = [int(x.strip()) for x in chapter_ids.split(',') if x.strip().isdigit()]
            if chapter_list:
                placeholders = ','.join(['%s'] * len(chapter_list))
                query += f" AND sq.chapter_id IN ({placeholders})"
                params.extend(chapter_list)
        
        query += " GROUP BY cg.id ORDER BY cg.cg_code"
        cur.execute(query, params)
        cgs = cur.fetchall()
        
        if not cgs and chapter_ids:
            fallback_query = """
                SELECT DISTINCT cg.id, cg.cg_code, cg.cg_description,
                       COUNT(sq.id) as question_count
                FROM curricular_goals cg
                JOIN simple_questions sq ON sq.cg_id = cg.id
                WHERE sq.subject_id = %s AND sq.status = 'approved'
                GROUP BY cg.id ORDER BY cg.cg_code
            """
            cur.execute(fallback_query, (subject_id,))
            cgs = cur.fetchall()
        
        return jsonify({'cgs': cgs})
    except Exception as e:
        print(f"Error getting CGs for chapters: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e), 'cgs': []}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/competencies-for-cgs', methods=['GET'])
def get_competencies_for_cgs():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    cg_ids = request.args.get('cg_ids')
    
    if not cg_ids:
        return jsonify({'error': 'CG IDs required', 'competencies': []}), 400
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cg_list = [int(x.strip()) for x in cg_ids.split(',') if x.strip().isdigit()]
        
        if not cg_list:
            return jsonify({'competencies': []})
        
        placeholders = ','.join(['%s'] * len(cg_list))
        
        query = f"""
            SELECT DISTINCT c.id, c.comp_code, c.comp_description,
                   COUNT(sq.id) as question_count
            FROM competencies c
            JOIN simple_questions sq ON sq.comp_id = c.id
            WHERE sq.cg_id IN ({placeholders}) AND sq.status = 'approved' AND c.status = 1
            GROUP BY c.id
            ORDER BY c.comp_code
        """
        cur.execute(query, cg_list)
        competencies = cur.fetchall()
        
        return jsonify({'competencies': competencies})
    except Exception as e:
        print(f"Error getting competencies for CGs: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e), 'competencies': []}), 500
    finally:
        cur.close()
        db.close()


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
        traceback.print_exc()
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

@app.route('/static/uploads/questions/<path:filename>')
def serve_question_image(filename):
    if 'user' not in session:
        return redirect(url_for('dashboard_login'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path)
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
    status = data.get('status', 'draft')
    
    # Textbook/Reference fields
    textbook_id = data.get('textbook_id')
    textbook_name = data.get('textbook_name')
    textbook_publisher = data.get('textbook_publisher')
    textbook_page = data.get('textbook_page')
    reference_book = data.get('reference_book')
    reference_page = data.get('reference_page')
    
    if not question_text:
        return jsonify({'error': 'Question text is required'}), 400
    
    if not has_actual_content(question_text):
        return jsonify({'error': 'Question text must have actual content (text, images, or structured content)'}), 400
    
    if not answer:
        return jsonify({'error': 'Answer is required'}), 400
    
    if not has_actual_content(answer):
        return jsonify({'error': 'Answer must have actual content (text, images, or structured content)'}), 400
    
    db_check = get_db()
    cur_check = db_check.cursor()
    try:
        cur_check.execute("SHOW COLUMNS FROM simple_questions LIKE 'language'")
        if not cur_check.fetchone():
            cur_check.execute("ALTER TABLE simple_questions ADD COLUMN language VARCHAR(20) DEFAULT 'en'")
            db_check.commit()
            print("Added language column to simple_questions")
    except Exception as e:
        print(f"Error adding language column: {e}")
    finally:
        cur_check.close()
        db_check.close()
    
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
        cur.execute("""
            INSERT INTO simple_questions (
                question_text, answer, marks, duration_minutes, 
                comp_id, created_by, created_at,
                grade_id, subject_id, chapter_id, cg_id, domain_id, 
                knowledge_level_id, question_type_id, difficulty_id,
                competency_code, domain_name, knowledge_level_name,
                question_type_name, difficulty_name, grade_name,
                subject_name, chapter_name, chapter_code, cg_code, 
                images, status, language,
                textbook_id, textbook_name, textbook_publisher,
                textbook_page, reference_book, reference_page
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            question_text, answer, marks, duration_minutes,
            comp_id, session['user'], datetime.now(),
            grade_id, subject_id, chapter_id, cg_id, domain_id,
            knowledge_level_id, question_type_id, difficulty_id,
            competency_code, domain_name, knowledge_level_name,
            question_type_name, difficulty_name, grade_name,
            subject_name, chapter_name, chapter_code, cg_code,
            images, status, language,
            textbook_id, textbook_name, textbook_publisher,
            textbook_page, reference_book, reference_page
        ))
        db.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Question saved successfully',
            'id': cur.lastrowid,
            'language': language,
            'status': status
        })
    except Exception as e:
        print(f"Error creating question: {e}")
        traceback.print_exc()
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/create-question', methods=['POST'])
def create_question():
    return create_simple_question()


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
        
        # Get question types for domains
        cur.execute("SELECT * FROM question_types")
        question_types = cur.fetchall()
        
        data = {
            'grades': grades,
            'subjects': subjects,
            'cgs': cgs,
            'competencies': competencies,
            'subjects_by_grade': {},
            'cgs_by_subject': {},
            'comps_by_cg': {},
            'question_types': question_types
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
        print(f"Error in page1-data: {e}")
        traceback.print_exc()
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
        traceback.print_exc()
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
        print(f"Error fetching cognitive domains: {e}")
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
        print(f"Error in page2-data: {e}")
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
        print(f"Error loading questions: {e}")
        traceback.print_exc()
        return jsonify({'questions': []})
    finally:
        cur.close()
        db.close()

@app.route('/api/page2-questions')
def get_page2_questions():
    return get_simple_questions()

@app.route('/api/subjects')
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

@app.route('/api/grades')
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
    if 'user' not in session or session.get('user_role') != 'admin':
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
        return jsonify({'success': True, 'id': cur.lastrowid})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/grades/<int:grade_id>', methods=['PUT'])
def update_grade(grade_id):
    if 'user' not in session or session.get('user_role') != 'admin':
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
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/grades/<int:grade_id>', methods=['DELETE'])
def delete_grade(grade_id):
    if 'user' not in session or session.get('user_role') != 'admin':
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

@app.route('/api/subjects', methods=['POST'])
def create_subject():
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    grade_id = data.get('grade_id')
    if not name or not grade_id:
        return jsonify({'error': 'Name and grade required'}), 400
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
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
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
    if 'user' not in session or session.get('user_role') != 'admin':
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

@app.route('/api/cgs', methods=['GET'])
def get_cgs():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    subject_id = request.args.get('subject_id')
    chapter_id = request.args.get('chapter_id')
    
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
        print(f"Error fetching CGs: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/cgs', methods=['POST'])
def create_cg():
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    subject_id = data.get('subject_id')
    chapter_id = data.get('chapter_id')
    
    if not code or not subject_id:
        return jsonify({'error': 'Code and subject required'}), 400
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        # Check if CG with same code already exists for this subject and chapter
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
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    subject_id = data.get('subject_id')
    chapter_id = data.get('chapter_id')
    
    if not code or not subject_id:
        return jsonify({'error': 'Code and subject required'}), 400
    
    db = get_db()
    cur = db.cursor()
    try:
        # Check for duplicates excluding current CG
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
    if 'user' not in session or session.get('user_role') != 'admin':
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
        comps = cur.fetchall()
        return jsonify({'competencies': comps})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/competencies', methods=['POST'])
def create_competency():
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    cg_id = data.get('cg_id')
    status = data.get('status', 1)
    if not code or not cg_id:
        return jsonify({'error': 'Code and CG required'}), 400
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
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    code = data.get('code')
    description = data.get('description', '')
    cg_id = data.get('cg_id')
    status = data.get('status', 1)
    if not code or not cg_id:
        return jsonify({'error': 'Code and CG required'}), 400
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
    if 'user' not in session or session.get('user_role') != 'admin':
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
    if 'user' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
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
            cur.execute("SELECT COUNT(*) FROM simple_questions WHERE status IN ('under_review', 'master_reviewed')")
        else:
            cur.execute("""
                SELECT COUNT(*) 
                FROM simple_questions sq
                JOIN subject_groups sg ON sq.subject_id = sg.subject_id
                WHERE sq.status IN ('under_review', 'master_reviewed') 
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

@app.route('/api/upload-answer-images', methods=['POST'])
def upload_answer_images():
    """Upload images specifically for answers"""
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

# ============ MAIN ============
if __name__ == '__main__':
    print("=" * 60)
    print("COHSEM IT Database Initialization")
    print("=" * 60)
    
    print("1. Initializing database...")
    init_db()
    
    print("2. Adding chapter_id to curricular_goals if missing...")
    add_chapter_id_to_cgs()
    
    print("3. Fixing missing CGs and Competencies...")
    fix_missing_cgs_and_comps()
    
    print("4. Ensuring approved questions...")
    ensure_approved_questions()
    
    print("5. Fixing question relationships...")
    fix_question_relationships()
    
    print("6. Adding sample relationships...")
    add_sample_relationships_to_questions()
    
    print("-" * 60)
    print(f"Final counts:")
    print(f"  - Curricular Goals: {get_cg_count()}")
    print(f"  - Competencies: {get_comp_count()}")
    print(f"  - Questions: {get_question_count()}")
    print("=" * 60)
    print("Database initialization complete!")
    print("Starting Flask application on http://localhost:5000")
    print("=" * 60)
    
    app.run(host='0.0.0.0', debug=False, port=5000)