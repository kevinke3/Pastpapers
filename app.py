import os
import time
import json
import logging
from functools import wraps
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, desc
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ========== MODELS ==========

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

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    level = db.Column(db.String(20), nullable=False)  # INFO, WARNING, ERROR, CRITICAL
    module = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    user = db.relationship('User', backref=db.backref('logs', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== LOGGING SYSTEM ==========

def setup_logging():
    """Setup application logging"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler for rotating logs
    file_handler = RotatingFileHandler(
        'logs/unipapers.log',
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    # Add handler to Flask's logger
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    
    # Also add to root logger
    logging.getLogger().addHandler(file_handler)

setup_logging()

def log_activity(level, module, message, user_id=None, request_obj=None):
    """Log activity to database"""
    try:
        log = SystemLog(
            level=level,
            module=module,
            message=message,
            user_id=user_id,
            ip_address=request_obj.remote_addr if request_obj else None,
            user_agent=request_obj.user_agent.string if request_obj else None
        )
        db.session.add(log)
        db.session.commit()
        
        # Also log to file
        logger = logging.getLogger(module)
        if level == 'INFO':
            logger.info(message)
        elif level == 'WARNING':
            logger.warning(message)
        elif level == 'ERROR':
            logger.error(message)
        elif level == 'CRITICAL':
            logger.critical(message)
            
    except Exception as e:
        app.logger.error(f"Failed to log activity: {e}")

# ========== UTILITY FUNCTIONS ==========

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required', 'error')
            log_activity('WARNING', 'Auth', f'Unauthorized admin access attempt by {current_user.username if current_user.is_authenticated else "anonymous"}', 
                        current_user.id if current_user.is_authenticated else None, request)
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Inject pending count for admin notifications
@app.context_processor
def inject_pending_count():
    if current_user.is_authenticated and current_user.is_admin:
        pending_count = PastPaper.query.filter_by(is_approved=False).count()
        return dict(pending_count=pending_count)
    return dict(pending_count=0)

# ========== BASIC USER ROUTES ==========

@app.route('/')
def home():
    total_papers = PastPaper.query.filter_by(is_approved=True).count()
    total_users = User.query.count()
    recent_papers = PastPaper.query.filter_by(is_approved=True).order_by(PastPaper.upload_date.desc()).limit(5).all()
    
    log_activity('INFO', 'System', 'Homepage accessed', 
                current_user.id if current_user.is_authenticated else None, request)
    
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
                log_activity('WARNING', 'Auth', f'Login attempt for deactivated account: {username}', request_obj=request)
                return redirect(url_for('login'))
            
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Logged in successfully!', 'success')
            log_activity('INFO', 'Auth', f'User logged in: {username}', user.id, request)
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('browse'))
        else:
            flash('Invalid username or password', 'error')
            log_activity('WARNING', 'Auth', f'Failed login attempt for: {username}', request_obj=request)
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            log_activity('WARNING', 'Auth', f'Registration attempt with existing username: {username}', request_obj=request)
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            log_activity('WARNING', 'Auth', f'Registration attempt with existing email: {email}', request_obj=request)
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        log_activity('INFO', 'Auth', f'New user registered: {username} ({email})', user.id, request)
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash('Logged out successfully', 'success')
    log_activity('INFO', 'Auth', f'User logged out: {username}')
    return redirect(url_for('home'))

@app.route('/browse')
def browse():
    papers = PastPaper.query.filter_by(is_approved=True).all()
    log_activity('INFO', 'Browse', 'Papers browsed', 
                current_user.id if current_user.is_authenticated else None, request)
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
            log_activity('INFO', 'Upload', 
                        f'Paper uploaded: {paper.title} ({paper.course_code}) by {current_user.username}',
                        current_user.id, request)
            
            return redirect(url_for('browse'))
        else:
            flash('Only PDF files are allowed', 'error')
            log_activity('WARNING', 'Upload', 
                        f'Invalid file type attempted by {current_user.username}',
                        current_user.id, request)
    
    return render_template('upload.html')

@app.route('/download/<int:paper_id>')
def download(paper_id):
    paper = PastPaper.query.get_or_404(paper_id)
    if not paper.is_approved and (not current_user.is_authenticated or current_user.id != paper.uploader_id):
        flash('Paper not available', 'error')
        log_activity('WARNING', 'Download', 
                    f'Unauthorized download attempt for paper ID: {paper_id}',
                    current_user.id if current_user.is_authenticated else None, request)
        return redirect(url_for('browse'))
    
    paper.downloads += 1
    db.session.commit()
    
    log_activity('INFO', 'Download', 
                f'Paper downloaded: {paper.title} (ID: {paper.id}) by {current_user.username if current_user.is_authenticated else "anonymous"}',
                current_user.id if current_user.is_authenticated else None, request)
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], paper.filename, as_attachment=True)

# ========== ADMIN ROUTES ==========

@app.route('/admin')
@login_required
@admin_required
def admin():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_papers = PastPaper.query.count()
    approved_papers = PastPaper.query.filter_by(is_approved=True).count()
    pending_papers = PastPaper.query.filter_by(is_approved=False).count()
    total_downloads = db.session.query(func.sum(PastPaper.downloads)).scalar() or 0
    
    recent_papers = PastPaper.query.order_by(PastPaper.upload_date.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    daily_uploads = db.session.query(
        func.date(PastPaper.upload_date).label('date'),
        func.count(PastPaper.id).label('count')
    ).filter(PastPaper.upload_date >= seven_days_ago)\
     .group_by(func.date(PastPaper.upload_date))\
     .order_by(func.date(PastPaper.upload_date))\
     .all()
    
    top_universities = db.session.query(
        PastPaper.university,
        func.count(PastPaper.id).label('count')
    ).filter_by(is_approved=True)\
     .group_by(PastPaper.university)\
     .order_by(desc('count'))\
     .limit(10)\
     .all()
    
    log_activity('INFO', 'Admin', 'Admin dashboard accessed', current_user.id, request)
    
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
    log_activity('INFO', 'Admin', 'User management accessed', current_user.id, request)
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
    log_activity('INFO', 'Admin', f'User {user.username} {status} by {current_user.username}', current_user.id, request)
    
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
    log_activity('INFO', 'Admin', f'User {user.username} {status} by {current_user.username}', current_user.id, request)
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    username = user.username
    
    # Delete user's papers
    papers = PastPaper.query.filter_by(uploader_id=user_id).all()
    for paper in papers:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], paper.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        db.session.delete(paper)
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} deleted successfully', 'success')
    log_activity('INFO', 'Admin', f'User {username} deleted by {current_user.username}', current_user.id, request)
    
    return redirect(url_for('admin_users'))

@app.route('/admin/papers')
@login_required
@admin_required
def admin_papers():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('q', '')
    
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
    
    log_activity('INFO', 'Admin', 'Paper management accessed', current_user.id, request)
    
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
    log_activity('INFO', 'Admin', 
                f'Paper approved: {paper.title} (ID: {paper.id}) by {current_user.username}',
                current_user.id, request)
    
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
    log_activity('INFO', 'Admin', 
                f'Paper rejected: {paper.title} (ID: {paper.id}) by {current_user.username}. Reason: {rejection_reason}',
                current_user.id, request)
    
    return redirect(request.referrer or url_for('admin_papers'))

@app.route('/admin/papers/delete/<int:paper_id>')
@login_required
@admin_required
def delete_paper(paper_id):
    paper = PastPaper.query.get_or_404(paper_id)
    title = paper.title
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], paper.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    db.session.delete(paper)
    db.session.commit()
    
    flash(f'Paper "{title}" deleted', 'success')
    log_activity('INFO', 'Admin', 
                f'Paper deleted: {title} (ID: {paper_id}) by {current_user.username}',
                current_user.id, request)
    
    return redirect(request.referrer or url_for('admin_papers'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    if request.method == 'POST':
        new_admin_password = request.form.get('new_admin_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_admin_password and new_admin_password == confirm_password:
            current_user.set_password(new_admin_password)
            db.session.commit()
            flash('Admin password updated successfully', 'success')
            log_activity('INFO', 'Admin', 'Admin password updated', current_user.id, request)
        elif new_admin_password:
            flash('Passwords do not match', 'error')
        
        return redirect(url_for('admin_settings'))
    
    return render_template('admin_settings.html')

@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    log_activity('INFO', 'Admin', 'Logs page accessed', current_user.id, request)
    return render_template('admin_logs.html')

# ========== API ENDPOINTS ==========

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

# Real-time logs API
@app.route('/api/admin/logs')
@login_required
@admin_required
def api_admin_logs():
    """Get paginated logs with optional filtering"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    level = request.args.get('level', '')
    search = request.args.get('search', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    query = SystemLog.query
    
    if level and level != 'all':
        query = query.filter_by(level=level.upper())
    
    if search:
        query = query.filter(
            SystemLog.message.contains(search) |
            SystemLog.module.contains(search)
        )
    
    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(SystemLog.timestamp >= start)
        except ValueError:
            pass
    
    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d')
            end = end.replace(hour=23, minute=59, second=59)
            query = query.filter(SystemLog.timestamp <= end)
        except ValueError:
            pass
    
    logs = query.order_by(SystemLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    log_list = []
    for log in logs.items:
        log_list.append({
            'id': log.id,
            'timestamp': log.timestamp.isoformat(),
            'level': log.level,
            'module': log.module,
            'message': log.message,
            'username': log.user.username if log.user else 'System',
            'ip_address': log.ip_address,
            'user_agent': log.user_agent[:100] if log.user_agent else None
        })
    
    return jsonify({
        'logs': log_list,
        'total': logs.total,
        'pages': logs.pages,
        'current_page': logs.page,
        'has_next': logs.has_next,
        'has_prev': logs.has_prev
    })

# Server-Sent Events endpoint for real-time log streaming
@app.route('/api/admin/logs/stream')
@login_required
@admin_required
def stream_logs():
    """Server-Sent Events endpoint for real-time log streaming"""
    def generate():
        last_id = 0
        
        while True:
            # Get new logs since last_id
            new_logs = SystemLog.query.filter(
                SystemLog.id > last_id
            ).order_by(SystemLog.timestamp.asc()).limit(10).all()
            
            if new_logs:
                for log in new_logs:
                    last_id = log.id
                    yield f"data: {json.dumps({
                        'id': log.id,
                        'timestamp': log.timestamp.isoformat(),
                        'level': log.level,
                        'module': log.module,
                        'message': log.message,
                        'username': log.user.username if log.user else 'System'
                    })}\n\n"
            
            time.sleep(2)
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

# Get log statistics
@app.route('/api/admin/logs/stats')
@login_required
@admin_required
def api_log_stats():
    """Get log statistics"""
    today = datetime.utcnow().date()
    
    stats = {
        'total_logs': SystemLog.query.count(),
        'today_logs': SystemLog.query.filter(
            func.date(SystemLog.timestamp) == today
        ).count(),
        'error_logs': SystemLog.query.filter_by(level='ERROR').count(),
        'warning_logs': SystemLog.query.filter_by(level='WARNING').count(),
        'info_logs': SystemLog.query.filter_by(level='INFO').count(),
        'recent_activity': []
    }
    
    recent_modules = db.session.query(
        SystemLog.module,
        func.count(SystemLog.id).label('count')
    ).filter(
        SystemLog.timestamp >= datetime.utcnow() - timedelta(days=1)
    ).group_by(SystemLog.module).order_by(desc('count')).limit(5).all()
    
    stats['recent_activity'] = [
        {'module': module, 'count': count}
        for module, count in recent_modules
    ]
    
    return jsonify(stats)

# Clear logs endpoint
@app.route('/api/admin/logs/clear', methods=['POST'])
@login_required
@admin_required
def clear_logs():
    """Clear all logs from database (admin only)"""
    try:
        count = SystemLog.query.count()
        
        SystemLog.query.delete()
        db.session.commit()
        
        log_activity('INFO', 'Admin', 
                    f'All logs cleared from database ({count} entries) by {current_user.username}',
                    current_user.id, request)
        
        return jsonify({
            'success': True,
            'message': f'Cleared {count} log entries',
            'cleared_count': count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to clear logs: {e}")
        log_activity('ERROR', 'Admin', f'Failed to clear logs: {e}', current_user.id, request)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ========== DATABASE INITIALIZATION ==========

with app.app_context():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('instance', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # For development: drop and recreate tables
    # Remove db.drop_all() in production!
    db.drop_all()
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
        
        # Log initial setup
        log_activity('INFO', 'System', 'Application initialized and admin user created')
        
        print("✓ Admin user created: username='admin', password='admin123'")
        print("✓ Please change the admin password immediately!")
        print("✓ Database initialized with logging system")

if __name__ == '__main__':
    app.run(debug=True)