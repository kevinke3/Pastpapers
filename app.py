import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from config import Config

app = Flask(__name__, static_folder='static', template_folder='static/html')
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class PastPaper(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    course_code = db.Column(db.String(20), nullable=False)
    course_name = db.Column(db.String(200), nullable=False)
    university = db.Column(db.String(200), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    semester = db.Column(db.String(20))
    filename = db.Column(db.String(300), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=False)
    downloads = db.Column(db.Integer, default=0)
    
    uploader = db.relationship('User', backref=db.backref('papers', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('browse'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/browse')
def browse():
    papers = PastPaper.query.filter_by(is_approved=True).all()
    return render_template('browse.html', papers=papers)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Avoid filename collisions
            counter = 1
            while os.path.exists(filepath):
                name, ext = os.path.splitext(filename)
                filename = f"{name}_{counter}{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                counter += 1
            
            file.save(filepath)
            
            paper = PastPaper(
                title=request.form.get('title'),
                course_code=request.form.get('course_code'),
                course_name=request.form.get('course_name'),
                university=request.form.get('university'),
                year=int(request.form.get('year')),
                semester=request.form.get('semester'),
                filename=filename,
                uploader_id=current_user.id
            )
            
            db.session.add(paper)
            db.session.commit()
            
            flash('Paper uploaded successfully! Waiting for admin approval.', 'success')
            return redirect(url_for('browse'))
        else:
            flash('Only PDF files are allowed', 'error')
    
    return render_template('upload.html')

@app.route('/download/<int:paper_id>')
def download(paper_id):
    paper = PastPaper.query.get_or_404(paper_id)
    if not paper.is_approved and (not current_user.is_authenticated or current_user.id != paper.uploader_id):
        flash('Paper not available', 'error')
        return redirect(url_for('browse'))
    
    paper.downloads += 1
    db.session.commit()
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], paper.filename, as_attachment=True)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    pending_papers = PastPaper.query.filter_by(is_approved=False).all()
    approved_papers = PastPaper.query.filter_by(is_approved=True).all()
    
    return render_template('admin.html', pending_papers=pending_papers, approved_papers=approved_papers)

@app.route('/admin/approve/<int:paper_id>')
@login_required
def approve_paper(paper_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    paper = PastPaper.query.get_or_404(paper_id)
    paper.is_approved = True
    db.session.commit()
    
    flash('Paper approved', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/reject/<int:paper_id>')
@login_required
def reject_paper(paper_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    paper = PastPaper.query.get_or_404(paper_id)
    
    # Delete the file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], paper.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    db.session.delete(paper)
    db.session.commit()
    
    flash('Paper rejected and deleted', 'success')
    return redirect(url_for('admin'))

# Initialize database
with app.app_context():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('instance', exist_ok=True)
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@university.edu', is_admin=True)
        admin.set_password('admin123')  # Change this in production!
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)