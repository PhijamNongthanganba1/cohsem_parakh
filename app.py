from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'secret_key_123')  # Use environment variable


def get_db():
    # Check for Render's database URL or local development
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        try:
            # Handle different database URL formats
            if database_url.startswith('mysql://'):
                # Remove mysql:// prefix
                db_string = database_url.replace('mysql://', '')
                # Split user:password@host:port/database
                if '@' in db_string:
                    user_pass, host_port_db = db_string.split('@')
                    user, password = user_pass.split(':')
                    
                    if '/' in host_port_db:
                        host_port, database = host_port_db.split('/')
                        if ':' in host_port:
                            host, port = host_port.split(':')
                            port = int(port)
                        else:
                            host = host_port
                            port = 3306
                    else:
                        host = host_port_db
                        port = 3306
                        database = ''
                    
                    return mysql.connector.connect(
                        host=host,
                        user=user,
                        password=password,
                        database=database,
                        port=port,
                        ssl_disabled=True  # Disable SSL for now, enable for production
                    )
            else:
                # Try direct parsing for other formats
                parsed = urlparse(database_url)
                return mysql.connector.connect(
                    host=parsed.hostname,
                    user=parsed.username,
                    password=parsed.password,
                    database=parsed.path[1:] if parsed.path.startswith('/') else parsed.path,
                    port=parsed.port or 3306,
                    ssl_disabled=True
                )
        except Exception as e:
            print(f"Error parsing DATABASE_URL: {e}")
            # Fallback to local development
            return mysql.connector.connect(
                host="localhost",
                user="root",
                password="nong@123",
                database="cohsem_IT"
            )
    else:
        # Local development fallback
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="nong@123",
            database="cohsem_IT"
        )


@app.route('/')
def home():
    return redirect(url_for('dashboard'))


@app.route("/register", methods=["GET", "POST"])
def register():
    msg = None
    success = None

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db()
        cur = db.cursor()

        # Check username exists
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            msg = "Username already exists!"
            success = None
        else:
            from werkzeug.security import generate_password_hash
            hashed_password = generate_password_hash(password)

            cur.execute("""
                INSERT INTO users (username, password, role)
                VALUES (%s, %s, 'uploader')
            """, (username, hashed_password))
            db.commit()

            success = "Registration successful!"
            msg = None

    return render_template("register.html", msg=msg, success=success)



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db()
        cur = db.cursor(dictionary=True)

        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()

        from werkzeug.security import check_password_hash

        # User not found
        if not user:
            return render_template("login.html", msg="User not found! Please register first.")

        # Wrong password
        if not check_password_hash(user["password"], password):
            return render_template("login.html", msg="Invalid password!")

        # Login success
        session["username"] = username
        session["role"] = user["role"]
        return render_template("complete_selection.html", success="Login successful!")

    return render_template("login.html")



@app.route('/builder-login', methods=['GET','POST'])
def builder_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close()
        db.close()

        if user and check_password_hash(user['password'], password):
            allowed_roles = ['builder', 'admin', 'teacher']
            if user.get('role') in allowed_roles:
                session['user'] = user['username']
                session['login_type'] = 'builder'
                return redirect(url_for('question_paper_builder'))
            else:
                return "Access Denied: You don't have permission to build question papers"

        return "Invalid Login"

    return render_template('builder_login.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('login_type', None)
    return redirect(url_for('dashboard'))


@app.route('/complete-selection')
def complete_selection():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('complete_selection.html', user=session['user'])


@app.route('/page3')
def page3():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('compressed_page3.html', user=session['user'])


@app.route('/question-paper-builder')
def question_paper_builder():
    if 'user' not in session:
        return redirect(url_for('builder_login'))
    
    if session.get('login_type') != 'builder':
        return redirect(url_for('builder_login'))
    
    return render_template('question_paper_builder.html', user=session['user'])


@app.route('/builder-register', methods=['GET','POST'])
def builder_register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = 'builder'  

        db = get_db()
        cur = db.cursor()
        
        try:
            cur.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (%s, %s, %s, %s)",
                (username, password, role, datetime.now())
            )
            db.commit()
            cur.close()
            db.close()
            
            return redirect(url_for('builder_login'))
            
        except Exception as e:
            db.rollback()
            cur.close()
            db.close()
            return f"Registration failed: {str(e)}"

    return render_template('builder_register.html')


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
        print(f"Error in get_page1_data: {str(e)}")
        return jsonify({
            'grades': [
                {'id': 1, 'grade_name': 'Grade 11'},
                {'id': 2, 'grade_name': 'Grade 12'}
            ],
            'subjects': [
                {'id': 1, 'subject_name': 'Physics', 'grade_id': 1},
                {'id': 2, 'subject_name': 'Chemistry', 'grade_id': 1},
                {'id': 3, 'subject_name': 'Mathematics', 'grade_id': 1}
            ],
            'cgs': [
                {'id': 1, 'cg_code': 'CG-1', 'cg_description': 'Curricular Goal 1', 'subject_id': 1},
                {'id': 2, 'cg_code': 'CG-2', 'cg_description': 'Curricular Goal 2', 'subject_id': 1}
            ],
            'competencies': [
                {'id': 1, 'comp_code': 'C-1.1', 'comp_description': 'First Competency', 'cg_id': 1, 'status': 1},
                {'id': 2, 'comp_code': 'C-1.2', 'comp_description': 'Second Competency', 'cg_id': 1, 'status': 1},
                {'id': 3, 'comp_code': 'C-2.1', 'comp_description': 'Third Competency', 'cg_id': 2, 'status': 1}
            ],
            'subjects_by_grade': {
                '1': [
                    {'id': 1, 'subject_name': 'Physics', 'grade_id': 1},
                    {'id': 2, 'subject_name': 'Chemistry', 'grade_id': 1},
                    {'id': 3, 'subject_name': 'Mathematics', 'grade_id': 1}
                ]
            },
            'cgs_by_subject': {
                '1': [
                    {'id': 1, 'cg_code': 'CG-1', 'cg_description': 'Curricular Goal 1', 'subject_id': 1},
                    {'id': 2, 'cg_code': 'CG-2', 'cg_description': 'Curricular Goal 2', 'subject_id': 1}
                ]
            },
            'comps_by_cg': {
                '1': [
                    {'id': 1, 'comp_code': 'C-1.1', 'comp_description': 'First Competency', 'cg_id': 1, 'status': 1},
                    {'id': 2, 'comp_code': 'C-1.2', 'comp_description': 'Second Competency', 'cg_id': 1, 'status': 1}
                ],
                '2': [
                    {'id': 3, 'comp_code': 'C-2.1', 'comp_description': 'Third Competency', 'cg_id': 2, 'status': 1}
                ]
            }
        })
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
                {'id': 1, 'level_name': 'Knowledge', 'description': 'Recall of specific information'},
                {'id': 2, 'level_name': 'Remembering', 'description': 'Retrieving knowledge from memory'},
                {'id': 3, 'level_name': 'Understanding', 'description': 'Constructing meaning'},
                {'id': 4, 'level_name': 'Comprehension', 'description': 'Grasping the meaning'}
            ]
        
        return jsonify({'knowledge_levels': levels})
        
    except Exception as e:
        return jsonify({'knowledge_levels': [
            {'id': 1, 'level_name': 'Knowledge', 'description': 'Recall of specific information'},
            {'id': 2, 'level_name': 'Remembering', 'description': 'Retrieving knowledge from memory'},
            {'id': 3, 'level_name': 'Understanding', 'description': 'Constructing meaning'},
            {'id': 4, 'level_name': 'Comprehension', 'description': 'Grasping the meaning'}
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
        
        cur.execute("SELECT * FROM cognitive_domains WHERE domain_name != 'Knowledge' ORDER BY id")
        domains = cur.fetchall()
        
        if not domains:
            domains = [
                {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness level'},
                {'id': 2, 'domain_name': 'Understanding', 'description': 'Understanding concepts'},
                {'id': 3, 'domain_name': 'Application', 'description': 'Applying knowledge'}
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
                    {'id': 1, 'level_name': 'Easy', 'description': 'Basic questions that test fundamental knowledge'},
                    {'id': 2, 'level_name': 'Medium', 'description': 'Moderately challenging questions'},
                    {'id': 3, 'level_name': 'Hard', 'description': 'Advanced questions that test deep understanding'}
                ]
        except Exception as e:
            print(f"Error fetching difficulty levels: {str(e)}")
            difficulty_levels = [
                {'id': 1, 'level_name': 'Easy', 'description': 'Basic questions'},
                {'id': 2, 'level_name': 'Medium', 'description': 'Moderate questions'},
                {'id': 3, 'level_name': 'Hard', 'description': 'Advanced questions'}
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
        print(f"Error in get_page2_data: {str(e)}")
        return jsonify({
            'domains': [
                {'id': 1, 'domain_name': 'Awareness', 'description': 'Basic awareness level'},
                {'id': 2, 'domain_name': 'Understanding', 'description': 'Understanding concepts'},
                {'id': 3, 'domain_name': 'Application', 'description': 'Applying knowledge'}
            ],
            'question_types_by_domain': {
                1: [{'id': 1, 'type_name': 'Objective', 'cognitive_id': 1, 'description': 'Objective question'}],
                2: [{'id': 2, 'type_name': 'Subjective', 'cognitive_id': 2, 'description': 'Subjective question'}],
                3: [{'id': 3, 'type_name': 'Application', 'cognitive_id': 3, 'description': 'Application question'}]
            },
            'difficulty_levels': [
                {'id': 1, 'level_name': 'Easy', 'description': 'Basic questions'},
                {'id': 2, 'level_name': 'Medium', 'description': 'Moderate questions'},
                {'id': 3, 'level_name': 'Hard', 'description': 'Advanced questions'}
            ],
            'comp': None
        })
    finally:
        cur.close()
        db.close()


@app.route('/api/simple-questions')
def get_simple_questions():
    """Get questions from simple_questions table"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        query = """
        SELECT id, question_text, answer, 
               competency_code, difficulty_name, domain_name,
               knowledge_level_name, question_type_name,
               grade_name, subject_name, cg_code,
               created_by, created_at, comp_id
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
        
        return jsonify({'questions': questions})
        
    except Exception as e:
        print(f"Error loading simple questions: {e}")
        return jsonify({'questions': []})
    finally:
        cur.close()
        db.close()


@app.route('/api/create-simple-question', methods=['POST'])
def create_simple_question():
    """Create question in simple_questions table"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    
    question_text = data.get('question_text')
    answer = data.get('answer')  
    comp_id = data.get('comp_id')
    grade_id = data.get('grade_id')
    subject_id = data.get('subject_id')
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
    cg_code = data.get('cg_code')
    
    if not question_text:
        return jsonify({'error': 'Question text is required'}), 400
    if not answer:
        return jsonify({'error': 'Answer is required'}), 400
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        insert_sql = """
        INSERT INTO simple_questions (
            question_text, answer, comp_id, created_by, created_at,
            grade_id, subject_id, cg_id, domain_id, 
            knowledge_level_id, question_type_id, difficulty_id,
            competency_code, domain_name, knowledge_level_name,
            question_type_name, difficulty_name, grade_name,
            subject_name, cg_code
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        insert_values = (
            question_text, answer, comp_id, session['user'], datetime.now(),
            grade_id, subject_id, cg_id, domain_id,
            knowledge_level_id, question_type_id, difficulty_id,
            competency_code, domain_name, knowledge_level_name,
            question_type_name, difficulty_name, grade_name,
            subject_name, cg_code
        )
        
        cur.execute(insert_sql, insert_values)
        db.commit()
        
        question_id = cur.lastrowid
        
        return jsonify({
            'success': True,
            'message': 'Question saved successfully',
            'question_id': question_id,
            'data': {
                'question': question_text,
                'answer': answer,
                'competency': competency_code
            }
        })
        
    except Exception as e:
        print(f"Error creating simple question: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/fix-simple-table', methods=['POST'])
def fix_simple_table():
    """DROP and RECREATE simple_questions table with correct structure"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor()
    
    try:
        results = []
        
        cur.execute("SHOW TABLES LIKE 'simple_questions'")
        if cur.fetchone():
            try:
                cur.execute("SELECT COUNT(*) as count FROM simple_questions")
                count_result = cur.fetchone()
                row_count = count_result['count'] if count_result else 0
                results.append({'status': 'info', 'message': f'Table has {row_count} rows to be deleted'})
            except:
                pass
            
            cur.execute("DROP TABLE simple_questions")
            db.commit()
            results.append({'status': 'success', 'message': 'Dropped old simple_questions table'})
        
        create_sql = """
        CREATE TABLE simple_questions (
            id INT PRIMARY KEY AUTO_INCREMENT,
            question_text TEXT NOT NULL,
            answer TEXT NOT NULL,
            comp_id INT,
            created_by VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            grade_id INT,
            subject_id INT,
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
            cg_code VARCHAR(50),
            INDEX idx_comp_id (comp_id),
            INDEX idx_created_by (created_by),
            INDEX idx_created_at (created_at)
        )
        """
        
        cur.execute(create_sql)
        db.commit()
        
        results.append({'status': 'success', 'message': 'Created new simple_questions table with correct structure'})
        
        cur.execute("DESCRIBE simple_questions")
        columns = cur.fetchall()
        column_info = [f"{col['Field']} ({col['Type']})" for col in columns]
        results.append({'status': 'info', 'message': 'Table columns:', 'columns': column_info})
        
        return jsonify({'results': results})
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/page3-questions')
def get_page3_questions():
    """Get questions from simple_questions table (for backward compatibility)"""
    return get_simple_questions()


@app.route('/api/create-question', methods=['POST'])
def create_question():
    """Create question in simple_questions table (for backward compatibility)"""
    return create_simple_question()


@app.route('/api/toggle-competency/<int:comp_id>')
def api_toggle_competency(comp_id):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        cur.execute("SELECT status FROM competencies WHERE id = %s", (comp_id,))
        result = cur.fetchone()
        
        if not result:
            return jsonify({'error': 'Competency not found'}), 404
        
        new_status = 0 if result['status'] == 1 else 1
        cur.execute("UPDATE competencies SET status = %s WHERE id = %s", (new_status, comp_id))
        db.commit()
        
        return jsonify({'success': True, 'new_status': new_status})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/debug-tables')
def debug_tables():
    """Debug endpoint to check table structure"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        debug_info = {}
        
        cur.execute("SHOW TABLES LIKE 'simple_questions'")
        if cur.fetchone():
            cur.execute("DESCRIBE simple_questions")
            columns = cur.fetchall()
            debug_info['simple_questions_structure'] = [
                {'Field': col['Field'], 'Type': col['Type'], 'Null': col['Null']} 
                for col in columns
            ]
            
            cur.execute("SELECT COUNT(*) as count FROM simple_questions")
            count_result = cur.fetchone()
            debug_info['simple_questions_count'] = count_result['count']
            
            column_names = [col['Field'].lower() for col in columns]
            debug_info['has_cognitive_id'] = 'cognitive_id' in column_names
            debug_info['has_domain_id'] = 'domain_id' in column_names
        else:
            debug_info['simple_questions_exists'] = False
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        cur.close()
        db.close()


@app.route('/api/clear-session-selections', methods=['POST'])
def clear_session_selections():
    """Clear any stored session selections (for debugging)"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    keys_to_remove = []
    for key in session:
        if key.startswith('selected_'):
            keys_to_remove.append(key)
    
    for key in keys_to_remove:
        session.pop(key, None)
    
    return jsonify({'success': True, 'message': f'Cleared {len(keys_to_remove)} selection keys'})


@app.route('/api/get-full-navigation')
def get_full_navigation():
    """Get complete navigation data including backward compatibility"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return get_page1_data()


@app.route('/api/get-selection-by-id')
def get_selection_by_id():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    grade_id = request.args.get('grade_id')
    subject_id = request.args.get('subject_id')
    cg_id = request.args.get('cg_id')
    comp_id = request.args.get('comp_id')
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        result = {}
        
        if grade_id:
            cur.execute("SELECT * FROM grades WHERE id = %s", (grade_id,))
            result['grade'] = cur.fetchone()
        
        if subject_id:
            cur.execute("SELECT * FROM subjects WHERE id = %s", (subject_id,))
            result['subject'] = cur.fetchone()
        
        if cg_id:
            cur.execute("SELECT * FROM curricular_goals WHERE id = %s", (cg_id,))
            result['cg'] = cur.fetchone()
        
        if comp_id:
            cur.execute("""
                SELECT c.*, cg.cg_code, s.subject_name, g.grade_name 
                FROM competencies c
                LEFT JOIN curricular_goals cg ON c.cg_id = cg.id
                LEFT JOIN subjects s ON cg.subject_id = s.id
                LEFT JOIN grades g ON s.grade_id = g.id
                WHERE c.id = %s
            """, (comp_id,))
            result['competency'] = cur.fetchone()
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error getting selection by ID: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/check-database-tables')
def check_database_tables():
    """Check and report on all required database tables"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        tables_to_check = [
            'grades', 'subjects', 'curricular_goals', 'competencies',
            'cognitive_domains', 'question_types', 'difficulty_levels',
            'knowledge_levels', 'simple_questions', 'users'
        ]
        
        results = {}
        
        for table in tables_to_check:
            cur.execute(f"SHOW TABLES LIKE '{table}'")
            exists = cur.fetchone() is not None
            
            if exists:
                cur.execute(f"DESCRIBE {table}")
                columns = cur.fetchall()
                cur.execute(f"SELECT COUNT(*) as count FROM {table}")
                count_result = cur.fetchone()
                
                results[table] = {
                    'exists': True,
                    'columns': [col['Field'] for col in columns],
                    'row_count': count_result['count'] if count_result else 0
                }
            else:
                results[table] = {'exists': False}
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        cur.close()
        db.close()


@app.route('/api/initialize-difficulty-levels', methods=['POST'])
def initialize_difficulty_levels():
    """Initialize difficulty_levels table with default values"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute("SHOW TABLES LIKE 'difficulty_levels'")
        if not cur.fetchone():
            create_sql = """
            CREATE TABLE difficulty_levels (
                id INT PRIMARY KEY AUTO_INCREMENT,
                level_name VARCHAR(50) NOT NULL,
                description TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            cur.execute(create_sql)
            db.commit()
            print("Created difficulty_levels table")
        
        cur.execute("SELECT COUNT(*) as count FROM difficulty_levels")
        count_result = cur.fetchone()
        row_count = count_result['count'] if count_result else 0
        
        if row_count == 0:
            default_levels = [
                ('Easy', 'Basic questions that test fundamental knowledge'),
                ('Medium', 'Moderately challenging questions'),
                ('Hard', 'Advanced questions that test deep understanding')
            ]
            
            insert_sql = "INSERT INTO difficulty_levels (level_name, description) VALUES (%s, %s)"
            cur.executemany(insert_sql, default_levels)
            db.commit()
            
            print(f"Inserted {len(default_levels)} default difficulty levels")
            
            return jsonify({
                'success': True,
                'message': 'Difficulty levels table initialized with default values',
                'levels_added': len(default_levels)
            })
        else:
            cur.execute("SELECT * FROM difficulty_levels ORDER BY id")
            existing_levels = cur.fetchall()
            
            return jsonify({
                'success': True,
                'message': f'Difficulty levels table already has {row_count} rows',
                'existing_levels': existing_levels
            })
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/get-complete-selections')
def get_complete_selections():
    """Get complete selection data for a specific competency"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    if not comp_id:
        return jsonify({'error': 'competency ID is required'}), 400
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        cur.execute("""
            SELECT 
                c.id as comp_id, c.comp_code, c.comp_description,
                cg.id as cg_id, cg.cg_code, cg.cg_description,
                s.id as subject_id, s.subject_name,
                g.id as grade_id, g.grade_name
            FROM competencies c
            LEFT JOIN curricular_goals cg ON c.cg_id = cg.id
            LEFT JOIN subjects s ON cg.subject_id = s.id
            LEFT JOIN grades g ON s.grade_id = g.id
            WHERE c.id = %s
        """, (comp_id,))
        
        result = cur.fetchone()
        if not result:
            return jsonify({'error': 'Competency not found'}), 404
        
        return jsonify({
            'success': True,
            'selections': result
        })
        
    except Exception as e:
        print(f"Error getting complete selections: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/debug-localstorage')
def debug_localstorage():
    """Debug endpoint to see what would be in localStorage"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    comp_id = request.args.get('comp_id')
    debug_info = {
        'note': 'This is what should be stored in localStorage when going to page 3',
        'expected_keys': [
            'selectedCompId', 'selectedCompCode', 'selectedCompDesc',
            'selectedGradeId', 'selectedGradeName',
            'selectedSubjectId', 'selectedSubjectName',
            'selectedCGId', 'selectedCGCode',
            'selectedDomainId', 'selectedDomainName',
            'selectedKnowledgeLevelId', 'selectedKnowledgeLevelName',
            'selectedQuestionTypeId', 'selectedQuestionTypeName',
            'selectedDifficultyId', 'selectedDifficultyName',
            'restoreSelections'
        ],
        'current_session_user': session.get('user')
    }
    
    if comp_id:
        db = get_db()
        cur = db.cursor(dictionary=True)
        
        try:
            cur.execute("""
                SELECT 
                    c.id as comp_id, c.comp_code, c.comp_description,
                    cg.id as cg_id, cg.cg_code,
                    s.id as subject_id, s.subject_name,
                    g.id as grade_id, g.grade_name
                FROM competencies c
                LEFT JOIN curricular_goals cg ON c.cg_id = cg.id
                LEFT JOIN subjects s ON cg.subject_id = s.id
                LEFT JOIN grades g ON s.grade_id = g.id
                WHERE c.id = %s
            """, (comp_id,))
            
            comp_data = cur.fetchone()
            if comp_data:
                debug_info['competency_data'] = comp_data
            
            cur.execute("SELECT * FROM difficulty_levels ORDER BY id")
            difficulty_levels = cur.fetchall()
            debug_info['database_difficulty_levels'] = difficulty_levels
                
        except Exception as e:
            debug_info['error'] = str(e)
        finally:
            cur.close()
            db.close()
    
    return jsonify(debug_info)


@app.route('/api/restore-selections', methods=['POST'])
def restore_selections():
    """API endpoint to restore selections from localStorage data"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    
    try:
        if not data.get('comp_id'):
            return jsonify({'error': 'Competency ID is required'}), 400
        
        comp_id = data['comp_id']
        
        db = get_db()
        cur = db.cursor(dictionary=True)
        
        cur.execute("""
            SELECT 
                c.*,
                cg.cg_code, cg.cg_description,
                s.subject_name, s.id as subject_id,
                g.grade_name, g.id as grade_id
            FROM competencies c
            LEFT JOIN curricular_goals cg ON c.cg_id = cg.id
            LEFT JOIN subjects s ON cg.subject_id = s.id
            LEFT JOIN grades g ON s.grade_id = g.id
            WHERE c.id = %s
        """, (comp_id,))
        
        comp_data = cur.fetchone()
        
        if not comp_data:
            return jsonify({'error': 'Competency not found'}), 404
        
        domain_data = None
        if data.get('domain_id'):
            cur.execute("SELECT * FROM cognitive_domains WHERE id = %s", (data['domain_id'],))
            domain_data = cur.fetchone()
        
        knowledge_data = None
        if data.get('knowledge_level_id'):
            cur.execute("SELECT * FROM knowledge_levels WHERE id = %s", (data['knowledge_level_id'],))
            knowledge_data = cur.fetchone()
        
        type_data = None
        if data.get('question_type_id'):
            cur.execute("SELECT * FROM question_types WHERE id = %s", (data['question_type_id'],))
            type_data = cur.fetchone()
        
        difficulty_data = None
        if data.get('difficulty_id'):
            cur.execute("SELECT * FROM difficulty_levels WHERE id = %s", (data['difficulty_id'],))
            difficulty_data = cur.fetchone()
        
        response_data = {
            'success': True,
            'selections': {
                'grade': {
                    'id': comp_data.get('grade_id'),
                    'grade_name': comp_data.get('grade_name')
                } if comp_data.get('grade_id') else None,
                'subject': {
                    'id': comp_data.get('subject_id'),
                    'subject_name': comp_data.get('subject_name')
                } if comp_data.get('subject_id') else None,
                'cg': {
                    'id': comp_data.get('cg_id'),
                    'cg_code': comp_data.get('cg_code'),
                    'cg_description': comp_data.get('cg_description')
                } if comp_data.get('cg_id') else None,
                'comp': {
                    'id': comp_data.get('id'),
                    'comp_code': comp_data.get('comp_code'),
                    'comp_description': comp_data.get('comp_description')
                },
                'domain': domain_data,
                'knowledge': knowledge_data,
                'type': type_data,
                'difficulty': difficulty_data
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Error in restore_selections: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/api/get-all-difficulty-levels')
def get_all_difficulty_levels():
    """Get all difficulty levels (fallback endpoint)"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        cur.execute("SELECT * FROM difficulty_levels ORDER BY id")
        difficulty_levels = cur.fetchall()
        
        if not difficulty_levels:
            difficulty_levels = [
                {'id': 1, 'level_name': 'Easy', 'description': 'Basic questions'},
                {'id': 2, 'level_name': 'Medium', 'description': 'Moderate questions'},
                {'id': 3, 'level_name': 'Hard', 'description': 'Advanced questions'}
            ]
        
        return jsonify({
            'success': True,
            'difficulty_levels': difficulty_levels
        })
        
    except Exception as e:
        return jsonify({
            'success': True,
            'difficulty_levels': [
                {'id': 1, 'level_name': 'Easy', 'description': 'Basic questions'},
                {'id': 2, 'level_name': 'Medium', 'description': 'Moderate questions'},
                {'id': 3, 'level_name': 'Hard', 'description': 'Advanced questions'}
            ]
        })
    finally:
        cur.close()
        db.close()



@app.route('/configure')
def configure():
    """Simple configuration/dashboard page"""
    return render_template('configure.html')


@app.route('/configure/fix-tables')
def configure_fix_tables():
    """Quick access to fix database tables"""
    return redirect('/api/fix-simple-table')


@app.route('/configure/check-tables')
def configure_check_tables():
    """Quick access to check database tables"""
    return redirect('/api/check-database-tables')


@app.route('/configure/init-difficulty')
def configure_init_difficulty():
    """Quick access to initialize difficulty levels"""
    return redirect('/api/initialize-difficulty-levels')


@app.route('/configure/debug')
def configure_debug():
    """Debug information page"""
    return redirect('/api/debug-tables')




# @app.route("/")
# def home():
#     return render_template("index.html")



if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)