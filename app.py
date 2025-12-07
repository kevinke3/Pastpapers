import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from sqlalchemy import func, desc
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
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
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
    rejection_reason = db.Column(db.Text)
    
    uploader = db.relationship('User', backref=db.backref('papers', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Admin decorator
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    # Show some stats on homepage
    total_papers = PastPaper.query.filter_by(is_approved=True).count()
    total_users = User.query.count()
    recent_papers = PastPaper.query.filter_by(is_approved=True).order_by(PastPaper.upload_date.desc()).limit(5).all()
    
    return render_template('index.html', 
                          total_papers=total_papers, 
                          total_users=total_users,
                          recent_papers=recent_papers)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Account is deactivated. Please contact administrator.', 'error')
                return redirect(url_for('login'))
            
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Logged in successfully!', 'success')
            
            # Redirect to admin panel if admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('browse'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Statistics
    total_users = User.query.count()
    total_papers = PastPaper.query.count()
    approved_papers = PastPaper.query.filter_by(is_approved=True).count()
    pending_papers = PastPaper.query.filter_by(is_approved=False).count()
    total_downloads = db.session.query(func.sum(PastPaper.downloads)).scalar() or 0
    
    # Recent activity
    recent_papers = PastPaper.query.order_by(PastPaper.upload_date.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    # Daily uploads (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    daily_uploads = db.session.query(
        func.date(PastPaper.upload_date).label('date'),
        func.count(PastPaper.id).label('count')
    ).filter(PastPaper.upload_date >= seven_days_ago)\
     .group_by(func.date(PastPaper.upload_date))\
     .order_by(func.date(PastPaper.upload_date))\
     .all()
    
    # Top universities
    top_universities = db.session.query(
        PastPaper.university,
        func.count(PastPaper.id).label('count')
    ).filter_by(is_approved=True)\
     .group_by(PastPaper.university)\
     .order_by(desc('count'))\
     .limit(10)\
     .all()
    
    return render_template('admin_dashboard.html',
                          total_users=total_users,
                          total_papers=total_papers,
                          approved_papers=approved_papers,
                          pending_papers=pending_papers,
                          total_downloads=total_downloads,
                          recent_papers=recent_papers,
                          recent_users=recent_users,
                          daily_uploads=daily_uploads,
                          top_universities=top_universities)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/toggle_active/<int:user_id>')
@login_required
@admin_required
def toggle_user_active(user_id):
    if user_id == current_user.id:
        flash('Cannot deactivate your own account', 'error')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    status = "activated" if user.is_active else "deactivated"
    flash(f'User {user.username} {status}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle_admin/<int:user_id>')
@login_required
@admin_required
def toggle_user_admin(user_id):
    if user_id == current_user.id:
        flash('Cannot change your own admin status', 'error')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = "promoted to admin" if user.is_admin else "demoted from admin"
    flash(f'User {user.username} {status}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    # Delete user's papers
    papers = PastPaper.query.filter_by(uploader_id=user_id).all()
    for paper in papers:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], paper.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        db.session.delete(paper)
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} deleted successfully', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/papers')
@login_required
@admin_required
def admin_papers():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('q', '')
    
    # Build query
    query = PastPaper.query
    
    if status_filter == 'approved':
        query = query.filter_by(is_approved=True)
    elif status_filter == 'pending':
        query = query.filter_by(is_approved=False)
    
    if search_query:
        query = query.filter(
            (PastPaper.title.contains(search_query)) |
            (PastPaper.course_code.contains(search_query)) |
            (PastPaper.course_name.contains(search_query)) |
            (PastPaper.university.contains(search_query))
        )
    
    papers = query.order_by(PastPaper.upload_date.desc())\
                 .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin_papers.html', papers=papers, 
                          status_filter=status_filter, search_query=search_query)

@app.route('/admin/papers/approve/<int:paper_id>', methods=['POST'])
@login_required
@admin_required
def approve_paper(paper_id):
    paper = PastPaper.query.get_or_404(paper_id)
    paper.is_approved = True
    paper.rejection_reason = None
    db.session.commit()
    
    flash(f'Paper "{paper.title}" approved', 'success')
    return redirect(request.referrer or url_for('admin_papers'))

@app.route('/admin/papers/reject/<int:paper_id>', methods=['POST'])
@login_required
@admin_required
def reject_paper(paper_id):
    paper = PastPaper.query.get_or_404(paper_id)
    rejection_reason = request.form.get('rejection_reason', '')
    
    paper.is_approved = False
    paper.rejection_reason = rejection_reason
    
    db.session.commit()
    
    flash(f'Paper "{paper.title}" rejected', 'success')
    return redirect(request.referrer or url_for('admin_papers'))

@app.route('/admin/papers/delete/<int:paper_id>')
@login_required
@admin_required
def delete_paper(paper_id):
    paper = PastPaper.query.get_or_404(paper_id)
    
    # Delete the file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], paper.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    db.session.delete(paper)
    db.session.commit()
    
    flash(f'Paper "{paper.title}" deleted', 'success')
    return redirect(request.referrer or url_for('admin_papers'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    if request.method == 'POST':
        # Handle settings update
        new_admin_password = request.form.get('new_admin_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_admin_password and new_admin_password == confirm_password:
            current_user.set_password(new_admin_password)
            db.session.commit()
            flash('Admin password updated successfully', 'success')
        elif new_admin_password:
            flash('Passwords do not match', 'error')
        
        return redirect(url_for('admin_settings'))
    
    return render_template('admin_settings.html')

@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    # For now, return basic logs
    # In production, you'd want to implement proper logging
    return render_template('admin_logs.html')

# API endpoints for admin dashboard
@app.route('/api/admin/stats')
@login_required
@admin_required
def api_admin_stats():
    stats = {
        'total_users': User.query.count(),
        'total_papers': PastPaper.query.count(),
        'approved_papers': PastPaper.query.filter_by(is_approved=True).count(),
        'pending_papers': PastPaper.query.filter_by(is_approved=False).count(),
        'total_downloads': db.session.query(func.sum(PastPaper.downloads)).scalar() or 0,
        'today_uploads': PastPaper.query.filter(
            func.date(PastPaper.upload_date) == datetime.utcnow().date()
        ).count()
    }
    return jsonify(stats)

# Initialize database
with app.app_context():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('instance', exist_ok=True)
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', 
                    email='admin@university.edu', 
                    is_admin=True,
                    is_active=True)
        admin.set_password('admin123')  # Change this in production!
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)