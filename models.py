from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.dialects.postgresql import JSON

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    student_id = db.Column(db.BigInteger, nullable=True) 
    is_admin = db.Column(db.Boolean, default=False) 
    is_super_admin = db.Column(db.Boolean, default=False)
    allowed_subjects = db.Column(JSON, nullable=True) # สำหรับ Admin
    
# [เพิ่มใหม่] ตารางจับคู่นักเรียนกับวิชาที่เข้าถึงได้ (Many-to-Many แบบง่าย)
class StudentSubjectAccess(db.Model):
    __tablename__ = 'student_subject_access'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)

class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False, default='General')
    topic = db.Column(db.String(100), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True) 
    image_data = db.Column(db.Text, nullable=True) 
    choices = db.Column(JSON, nullable=False)
    correct_idx = db.Column(db.Integer, nullable=False)
    difficulty = db.Column(db.Integer, nullable=False)

class ExerciseSession(db.Model):
    __tablename__ = 'exercise_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    subject = db.Column(db.String(100), nullable=False, default='General')
    topic = db.Column(db.String(100))
    total_score_avg = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class AnswerTransaction(db.Model):
    __tablename__ = 'answer_transactions'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('exercise_sessions.id'))
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'))
    difficulty = db.Column(db.Integer)
    is_correct = db.Column(db.Boolean)
    choice_selected = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class TopicSetting(db.Model):
    __tablename__ = 'topic_settings'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False, default='General')
    topic = db.Column(db.String(100), nullable=False) 
    is_hidden = db.Column(db.Boolean, default=True)