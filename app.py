import os
import json
import random
import base64
import pandas as pd
import secrets 
import string  
from collections import defaultdict 
from io import BytesIO
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, IntegerField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from sqlalchemy import func, text 
from models import db, User, Question, ExerciseSession, AnswerTransaction, TopicSetting 

app = Flask(__name__)

# ==========================================
# Database Connection Fix สำหรับ Render.com
# ==========================================
db_url = os.environ.get('DATABASE_URL', 'postgresql://localhost/mathdb')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'd16aae0acc60c55a8886fc6e9c6b04f5') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Config สำหรับการอัปโหลดรูป (เผื่อเหลือเผื่อขาด ยังเก็บไว้)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'svg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

if os.environ.get('RENDER'): 
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,  
    "pool_recycle": 300,    
    "pool_size": 10,
    "max_overflow": 20
}

db.init_app(app)
csrf = CSRFProtect(app) 

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    student_id = IntegerField('Student ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password')
    def validate_student_id(self, field):
        if field.data <= 6000000:
            raise ValidationError('รหัสนักศึกษาต้องมากกว่า 6,000,000')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])

class UploadForm(FlaskForm):
    file = FileField('JSON File', validators=[DataRequired()])

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access Denied: สำหรับผู้ดูแลระบบเท่านั้น')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_super_admin:
            flash('Access Denied: สำหรับ Super Admin เท่านั้น')
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def create_initial_admin():
    admin = User.query.filter_by(is_super_admin=True).first()
    if not admin:
        hashed_pw = generate_password_hash('admin1234', method='scrypt')
        new_admin = User(username='superadmin', password=hashed_pw, student_id=0, is_admin=True, is_super_admin=True)
        db.session.add(new_admin)
        db.session.commit()

def calculate_weighted_score(transactions):
    if not transactions: return 0
    scores = [(t.difficulty + 1 if t.is_correct else t.difficulty - 1) for t in transactions]
    count = len(scores)
    if count <= 5: raw_score = sum(scores) / count
    else: raw_score = (0.8 * (sum(scores[-5:]) / 5)) + (0.2 * (sum(scores[:-5]) / len(scores[:-5])))
    return max(1, min(5, raw_score))

def get_hidden_topics():
    hidden = TopicSetting.query.filter_by(is_hidden=True).all()
    return {(h.subject, h.topic) for h in hidden}

# ==========================================
# ดำเนินการอัปเดตโครงสร้าง Database อัตโนมัติ
# ==========================================
with app.app_context():
    db.create_all()
    try:
        db.session.execute(text("ALTER TABLE questions ADD COLUMN image_data TEXT;"))
        db.session.commit()
    except Exception:
        db.session.rollback()

    create_initial_admin()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username นี้ถูกใช้ไปแล้ว')
        else:
            hashed_pw = generate_password_hash(form.password.data, method='scrypt')
            new_user = User(username=form.username.data, password=hashed_pw, student_id=form.student_id.data, is_admin=False)
            db.session.add(new_user)
            db.session.commit()
            flash('สมัครสมาชิกสำเร็จ กรุณาเข้าสู่ระบบ')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard' if current_user.is_admin else 'index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            if user.is_admin:
                flash('Admin กรุณาเข้าสู่ระบบที่ /admin')
                return redirect(url_for('admin_login'))
            login_user(user)
            return redirect(url_for('index'))
        flash('Username หรือ Password ไม่ถูกต้อง')
    return render_template('login.html', form=form)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin: return redirect(url_for('admin_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.is_admin and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('เข้าสู่ระบบล้มเหลว')
    return render_template('admin_login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('รหัสผ่านเดิมไม่ถูกต้อง')
        else:
            current_user.password = generate_password_hash(form.password.data, method='scrypt')
            db.session.commit()
            flash('เปลี่ยนรหัสผ่านเรียบร้อย')
            return redirect(url_for('index'))
    return render_template('profile.html', form=form)


# ======================== ADMIN ROUTES ======================== #

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    upload_form = UploadForm()
    
    if upload_form.validate_on_submit():
        file = upload_form.file.data
        if file:
            try:
                data = json.load(file)
                for item in data:
                    subj = item.get('subject', 'General')
                    top = item['topic']
                    
                    if not current_user.is_super_admin and current_user.allowed_subjects:
                        if subj not in current_user.allowed_subjects: continue
                    
                    q = Question(
                        subject=subj, topic=top, question_text=item['question'],
                        choices=item['choices'], correct_idx=item['correctAnswerIndex'], difficulty=item['difficulty']
                    )
                    db.session.add(q)
                    db.session.flush() 
                    
                    # --- แปลง SVG จาก JSON เป็น Base64 เก็บลง Database ---
                    svg_content = item.get('svg')
                    if svg_content and isinstance(svg_content, str) and svg_content.strip():
                        if 'xmlns=' not in svg_content:
                            svg_content = svg_content.replace('<svg', '<svg xmlns="http://www.w3.org/2000/svg"', 1)
                        
                        base64_svg = base64.b64encode(svg_content.encode('utf-8')).decode('utf-8')
                        q.image_data = f"data:image/svg+xml;base64,{base64_svg}"

                    setting = TopicSetting.query.filter_by(subject=subj, topic=top).first()
                    if not setting:
                        db.session.add(TopicSetting(subject=subj, topic=top, is_hidden=True))
                        
                db.session.commit()
                flash('Import ข้อมูลเรียบร้อย (ข้อสอบถูกซ่อนเป็นค่าเริ่มต้น)')
            except Exception as e:
                db.session.rollback()
                flash(f'เกิดข้อผิดพลาด: {str(e)}')

    # === [FIX] ตรรกะการตรวจสอบสิทธิ์ว่าต้องจำกัดวิชาหรือไม่ ===
    if current_user.is_super_admin or not current_user.allowed_subjects:
        all_topics_query = db.session.query(Question.subject, Question.topic).distinct().all()
    else:
        allowed = current_user.allowed_subjects
        all_topics_query = db.session.query(Question.subject, Question.topic)\
            .filter(Question.subject.in_(allowed)).distinct().all()

    settings = TopicSetting.query.all()
    hidden_map = {(s.subject, s.topic): s.is_hidden for s in settings}
    
    topics_status = []
    for subj, top in all_topics_query:
        topics_status.append({
            'subject': subj,
            'topic': top,
            'is_hidden': hidden_map.get((subj, top), True)
        })
    
    return render_template('admin.html', upload_form=upload_form, topics_status=topics_status)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.filter_by(is_admin=False).order_by(User.id).all()
    admins = User.query.filter_by(is_admin=True).all() if current_user.is_super_admin else []
    return render_template('admin_users.html', users=users, admins=admins)

@app.route('/api/admin/reset_password', methods=['POST'])
@admin_required
def admin_reset_password():
    data = request.json
    user = User.query.get(data.get('user_id'))
    if not user: return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    new_raw_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(8))
    user.password = generate_password_hash(new_raw_password, method='scrypt')
    db.session.commit()
    return jsonify({'status': 'ok', 'new_password': new_raw_password, 'username': user.username})

@app.route('/api/super/manage_admin', methods=['POST'])
@super_admin_required
def manage_admin():
    data = request.json
    username = data.get('username')
    subjects = data.get('subjects')
    
    user = User.query.filter_by(username=username).first()
    if not user:
        hashed_pw = generate_password_hash('password1234', method='scrypt')
        user = User(username=username, password=hashed_pw, student_id=0, is_admin=True, allowed_subjects=subjects)
        db.session.add(user)
    else:
        user.is_admin = True
        user.allowed_subjects = subjects
    db.session.commit()
    return jsonify({'status': 'ok'})

@app.route('/api/admin/toggle_topic', methods=['POST'])
@admin_required
def admin_toggle_topic():
    data = request.json
    subj, topic_name = data.get('subject'), data.get('topic')
    setting = TopicSetting.query.filter_by(subject=subj, topic=topic_name).first()
    if not setting:
        setting = TopicSetting(subject=subj, topic=topic_name, is_hidden=True)
        db.session.add(setting)
    else:
        setting.is_hidden = not setting.is_hidden
    db.session.commit()
    return jsonify({'status': 'ok', 'is_hidden': setting.is_hidden})

@app.route('/api/admin/move_topic', methods=['POST'])
@admin_required
def admin_move_topic():
    data = request.json
    old_subject = data.get('old_subject')
    topic = data.get('topic')
    new_subject = data.get('new_subject')

    if not old_subject or not topic or not new_subject:
        return jsonify({'status': 'error', 'message': 'ข้อมูลไม่ครบถ้วน'}), 400

    # === [FIX] ตรรกะการตรวจสอบสิทธิ์ ===
    if not current_user.is_super_admin and current_user.allowed_subjects:
        allowed = current_user.allowed_subjects
        if old_subject not in allowed or new_subject not in allowed:
            return jsonify({'status': 'error', 'message': 'ไม่มีสิทธิ์จัดการหรือย้ายไปยังวิชาดังกล่าว'}), 403

    try:
        questions = Question.query.filter_by(subject=old_subject, topic=topic).all()
        for q in questions:
            q.subject = new_subject

        existing_setting = TopicSetting.query.filter_by(subject=new_subject, topic=topic).first()
        old_setting = TopicSetting.query.filter_by(subject=old_subject, topic=topic).first()
        
        if existing_setting:
            if old_setting:
                db.session.delete(old_setting) 
        else:
            if old_setting:
                old_setting.subject = new_subject 

        sessions = ExerciseSession.query.filter_by(subject=old_subject, topic=topic).all()
        for s in sessions:
            s.subject = new_subject

        db.session.commit()
        return jsonify({'status': 'ok', 'message': f'ย้ายหัวข้อ "{topic}" ไปยังวิชา "{new_subject}" สำเร็จแล้ว'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/bulk_manage_questions', methods=['POST'])
@admin_required
def bulk_manage_questions():
    data = request.json
    action = data.get('action')
    q_ids = data.get('question_ids', [])
    new_value = data.get('new_value', '').strip()

    if not q_ids:
        return jsonify({'status': 'error', 'message': 'กรุณาเลือกข้อสอบอย่างน้อย 1 ข้อ'}), 400

    questions = Question.query.filter(Question.id.in_(q_ids)).all()

    # === [FIX] ตรรกะการตรวจสอบสิทธิ์ ===
    if not current_user.is_super_admin and current_user.allowed_subjects:
        allowed = current_user.allowed_subjects
        for q in questions:
            if q.subject not in allowed:
                return jsonify({'status': 'error', 'message': f'ไม่มีสิทธิ์จัดการข้อสอบ ID {q.id}'}), 403
        if action == 'move_subject' and new_value not in allowed:
            return jsonify({'status': 'error', 'message': 'ไม่มีสิทธิ์ย้ายไปยังวิชาเป้าหมาย'}), 403

    try:
        if action == 'delete':
            AnswerTransaction.query.filter(AnswerTransaction.question_id.in_(q_ids)).delete(synchronize_session=False)
            Question.query.filter(Question.id.in_(q_ids)).delete(synchronize_session=False)
        elif action == 'move_subject':
            if not new_value: return jsonify({'status': 'error', 'message': 'กรุณาระบุชื่อวิชาใหม่'}), 400
            for q in questions:
                q.subject = new_value
                if not TopicSetting.query.filter_by(subject=new_value, topic=q.topic).first():
                    db.session.add(TopicSetting(subject=new_value, topic=q.topic, is_hidden=True))
        elif action == 'change_topic':
            if not new_value: return jsonify({'status': 'error', 'message': 'กรุณาระบุชื่อหัวข้อใหม่'}), 400
            for q in questions:
                q.topic = new_value
                if not TopicSetting.query.filter_by(subject=q.subject, topic=new_value).first():
                    db.session.add(TopicSetting(subject=q.subject, topic=new_value, is_hidden=True))
        else:
            return jsonify({'status': 'error', 'message': 'รูปแบบคำสั่ง (Action) ไม่ถูกต้อง'}), 400

        db.session.commit()
        return jsonify({'status': 'ok', 'message': 'ดำเนินการเสร็จสิ้นเรียบร้อย'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/update_question', methods=['POST'])
@admin_required
def update_question():
    data = request.json
    q_id = data.get('q_id')
    question_text = data.get('question_text', '').strip()
    choices = data.get('choices', [])
    correct_idx = data.get('correct_idx')
    difficulty = data.get('difficulty')

    if not q_id or not question_text or not choices or correct_idx is None or difficulty is None:
        return jsonify({'status': 'error', 'message': 'ข้อมูลไม่ครบถ้วน'}), 400

    q = Question.query.get(q_id)
    if not q:
        return jsonify({'status': 'error', 'message': 'ไม่พบข้อสอบในระบบ'}), 404

    # === [FIX] ตรรกะการตรวจสอบสิทธิ์ ===
    if not current_user.is_super_admin and current_user.allowed_subjects:
        allowed = current_user.allowed_subjects
        if q.subject not in allowed:
            return jsonify({'status': 'error', 'message': 'ไม่มีสิทธิ์แก้ไขข้อสอบวิชานี้'}), 403

    try:
        q.question_text = question_text
        q.choices = choices
        q.correct_idx = int(correct_idx)
        q.difficulty = int(difficulty)
        
        db.session.commit()
        return jsonify({'status': 'ok', 'message': 'บันทึกการแก้ไขเรียบร้อยแล้ว'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/view_questions', methods=['GET'])
@admin_required
def view_questions():
    subj = request.args.get('subject')
    top = request.args.get('topic')
    questions = Question.query.filter_by(subject=subj, topic=top).order_by(Question.id).all()
    return render_template('admin_questions.html', subject=subj, topic=top, questions=questions)

@app.route('/api/admin/upload_image/<int:q_id>', methods=['POST'])
@admin_required
def upload_image(q_id):
    if 'image' not in request.files: return jsonify({'status': 'error', 'message': 'No file part'}), 400
    file = request.files['image']
    
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        mime_type = 'image/svg+xml' if ext == 'svg' else f'image/{ext}'
        
        file_data = file.read()
        base64_data = base64.b64encode(file_data).decode('utf-8')
        image_data_uri = f"data:{mime_type};base64,{base64_data}"
        
        q = Question.query.get(q_id)
        q.image_data = image_data_uri
        db.session.commit()
        return jsonify({'status': 'ok', 'image_data': image_data_uri})
        
    return jsonify({'status': 'error', 'message': 'Invalid file type'}), 400


# =============== ADMIN EXPORT & STATS ROUTES =============== #

@app.route('/admin/export/sessions')
@admin_required
def export_sessions():
    results = db.session.query(ExerciseSession, User)\
        .join(User, ExerciseSession.user_id == User.id)\
        .filter(User.is_admin == False)\
        .order_by(ExerciseSession.created_at.desc()).all()
    
    data = []
    for sess, user in results:
        data.append({
            'Session ID': sess.id,
            'Username': user.username,
            'Student ID': user.student_id,
            'Subject': sess.subject,
            'Topic': sess.topic,
            'Avg Score': round(sess.total_score_avg, 2),
            'Time': sess.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    df = pd.DataFrame(data)
    output = BytesIO()
    if not df.empty:
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Sessions')
    else:
        df = pd.DataFrame(columns=['Session ID', 'Username', 'Student ID', 'Subject', 'Topic', 'Avg Score', 'Time'])
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Sessions')

    output.seek(0)
    return send_file(output, download_name="student_sessions.xlsx", as_attachment=True)

@app.route('/admin/export/transactions')
@admin_required
def export_transactions():
    results = db.session.query(AnswerTransaction, ExerciseSession, User, Question)\
        .join(ExerciseSession, AnswerTransaction.session_id == ExerciseSession.id)\
        .join(User, ExerciseSession.user_id == User.id)\
        .join(Question, AnswerTransaction.question_id == Question.id)\
        .filter(User.is_admin == False)\
        .order_by(AnswerTransaction.timestamp.desc()).all()
    
    data = []
    for trans, sess, user, quest in results:
        data.append({
            'Trans ID': trans.id,
            'Username': user.username,
            'Student ID': user.student_id,
            'Subject': sess.subject,
            'Topic': sess.topic,
            'Question ID': trans.question_id,
            'Difficulty': trans.difficulty,
            'Is Correct': 'Correct' if trans.is_correct else 'Wrong',
            'Time': trans.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
        
    df = pd.DataFrame(data)
    output = BytesIO()
    if not df.empty:
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Transactions')
    else:
        df = pd.DataFrame(columns=['Trans ID', 'Username', 'Student ID', 'Subject', 'Topic', 'Question ID', 'Difficulty', 'Is Correct', 'Time'])
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Transactions')
            
    output.seek(0)
    return send_file(output, download_name="student_transactions.xlsx", as_attachment=True)

@app.route('/admin/backup')
@super_admin_required
def backup_database():
    questions = Question.query.all()
    backup_data = []
    for q in questions:
        q_dict = {
            'subject': q.subject, 
            'topic': q.topic, 
            'question': q.question_text,
            'choices': q.choices,
            'correctAnswerIndex': q.correct_idx, 
            'difficulty': q.difficulty,
            'image_data': q.image_data 
        }
        backup_data.append(q_dict)

    output = BytesIO()
    output.write(json.dumps(backup_data, ensure_ascii=False, indent=2).encode('utf-8'))
    output.seek(0)
    return send_file(output, download_name="backup_questions.json", as_attachment=True, mimetype='application/json')

@app.route('/admin/stats')
@admin_required
def admin_stats():
    most_active = db.session.query(User.username, User.student_id, func.count(ExerciseSession.id).label('count'))\
        .join(ExerciseSession, User.id == ExerciseSession.user_id)\
        .filter(User.is_admin == False).group_by(User.id).order_by(db.desc('count')).limit(10).all()
        
    subquery = db.session.query(ExerciseSession.user_id).distinct()
    inactive_users = User.query.filter(User.is_admin == False, ~User.id.in_(subquery)).all()
    
    user_scores = db.session.query(User.username, User.student_id, func.avg(ExerciseSession.total_score_avg).label('avg'))\
        .join(ExerciseSession, User.id == ExerciseSession.user_id)\
        .filter(User.is_admin == False).group_by(User.id).all()
        
    top_scores = sorted(user_scores, key=lambda x: x.avg, reverse=True)[:10]
    risk_scores = sorted([u for u in user_scores if u.avg < 2.5], key=lambda x: x.avg)

    return render_template('admin_stats.html', active=most_active, inactive=inactive_users, top=top_scores, risk=risk_scores)


# ======================== USER API & ROUTES ======================== #

@app.route('/')
@login_required
def index():
    if current_user.is_admin: return redirect(url_for('admin_dashboard'))

    # กรองวิชาที่นักเรียนจะเห็น
    if current_user.is_super_admin or not current_user.allowed_subjects:
        all_topics_query = db.session.query(Question.subject, Question.topic).distinct().all()
    else:
        allowed = current_user.allowed_subjects
        all_topics_query = db.session.query(Question.subject, Question.topic).filter(Question.subject.in_(allowed)).distinct().all()

    hidden_topics = get_hidden_topics()
    
    subject_topics = defaultdict(list)
    visible_topics_flat = []
    
    for subj, top in all_topics_query:
        if (subj, top) not in hidden_topics:
            subject_topics[subj].append(top)
            visible_topics_flat.append((subj, top))
    
    sessions = ExerciseSession.query.filter_by(user_id=current_user.id).order_by(ExerciseSession.created_at).all()
    visible_sessions = [s for s in sessions if (s.subject, s.topic) not in hidden_topics]
    
    grouped = defaultdict(list)
    for s in visible_sessions: grouped[(s.subject, s.topic)].append(s)

    summary_chart_data = {'labels': [], 'data': []}
    topic_scores = {}

    for (subj, topic) in visible_topics_flat:
        sess_list = grouped.get((subj, topic), [])
        score = sum(s.total_score_avg for s in sess_list[-3:]) / len(sess_list[-3:]) if sess_list else 0
        summary_chart_data['labels'].append(f"[{subj}] {topic}")
        summary_chart_data['data'].append(round(score, 2))
        topic_scores[(subj, topic)] = score

    challenge = min(topic_scores, key=topic_scores.get) if topic_scores else (visible_topics_flat[0] if visible_topics_flat else None)

    graphs_data = []
    for (subj, topic), sess_list in grouped.items():
        graphs_data.append({
            'topic': f"[{subj}] {topic}",
            'latest_timestamp': max(s.created_at for s in sess_list),
            'labels': [s.created_at.strftime('%d/%m %H:%M') for s in sess_list],
            'scores': [s.total_score_avg for s in sess_list],
            'count': len(sess_list)
        })
    graphs_data.sort(key=lambda x: x['latest_timestamp'], reverse=True)
    
    return render_template('index.html', subject_topics=dict(subject_topics), graphs_data=graphs_data, challenge=challenge, summary_chart_data=summary_chart_data)

@app.route('/quiz/<subject>/<topic>')
@login_required
def quiz_page(subject, topic):
    if current_user.is_admin: return redirect(url_for('admin_dashboard'))
    if (subject, topic) in get_hidden_topics():
        flash(f'หัวข้อ "{topic}" วิชา {subject} ปิดปรับปรุงอยู่')
        return redirect(url_for('index'))

    num_questions = request.args.get('num', 15, type=int)
    sess = ExerciseSession(user_id=current_user.id, subject=subject, topic=topic, total_score_avg=0)
    db.session.add(sess)
    db.session.commit()
    
    return render_template('quiz.html', session_id=sess.id, subject=subject, topic=topic, max_q=num_questions)

@app.route('/api/get_question', methods=['POST'])
@login_required
def get_question():
    data = request.json
    session_id, subject, topic = data['session_id'], data['subject'], data['topic']
    
    transactions = AnswerTransaction.query.filter_by(session_id=session_id).all()
    used_q_ids = [t.question_id for t in transactions]
    done_count = len(transactions)
    
    target_diff = 3
    if done_count == 0: target_diff = 2
    elif done_count == 1: target_diff = 3
    elif done_count == 2: target_diff = 4
    else:
        target_diff = int(round(calculate_weighted_score(transactions)))
        target_diff = max(1, min(5, target_diff))

    selected_q = Question.query.filter(Question.subject==subject, Question.topic==topic, Question.difficulty==target_diff, ~Question.id.in_(used_q_ids)).order_by(func.random()).first()
    if not selected_q:
        selected_q = Question.query.filter(Question.subject==subject, Question.topic==topic, ~Question.id.in_(used_q_ids)).order_by(func.abs(Question.difficulty - target_diff), func.random()).first()

    if not selected_q: return jsonify({'status': 'finished'})

    original_choices = selected_q.choices 
    indexed_choices = list(enumerate(original_choices))
    random.shuffle(indexed_choices)
    
    return jsonify({
        'status': 'ok', 'q_id': selected_q.id, 'text': selected_q.question_text,
        'image_data': selected_q.image_data,
        'choices': [item[1] for item in indexed_choices],
        'mapping_indices': [item[0] for item in indexed_choices], 
        'difficulty': selected_q.difficulty, 'progress': done_count + 1
    })

@app.route('/api/submit_answer', methods=['POST'])
@login_required
def submit_answer():
    data = request.json
    q = Question.query.get(data['q_id'])
    is_correct = (data['choice_idx'] == q.correct_idx)
    db.session.add(AnswerTransaction(session_id=data['session_id'], question_id=q.id, difficulty=q.difficulty, is_correct=is_correct, choice_selected=data['choice_idx']))
    db.session.commit()
    return jsonify({'correct': is_correct, 'correct_idx': q.correct_idx})

@app.route('/api/finish_session', methods=['POST'])
@login_required
def finish_session():
    session_id = request.json['session_id']
    transactions = AnswerTransaction.query.filter_by(session_id=session_id).all()
    stats = {i: {'cor':0, 'wro':0} for i in range(1, 6)}
    for t in transactions:
        if t.is_correct: stats[t.difficulty]['cor'] += 1
        else: stats[t.difficulty]['wro'] += 1
            
    final_avg = calculate_weighted_score(transactions)
    sess = ExerciseSession.query.get(session_id)
    sess.total_score_avg = final_avg
    db.session.commit()
    return jsonify({'avg_score': final_avg, 'stats': stats})

if __name__ == '__main__':
    app.run(debug=True)