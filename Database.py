from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# ✅ Signup Table
class Signup(db.Model):
    __tablename__ = "signups"
    id = db.Column(db.Integer, primary_key=True)
    gmail = db.Column(db.String(40), unique=True, nullable=False)
    otp = db.Column(db.String(50), nullable=False)

# ✅ System Scan Table
class SystemScan(db.Model):
    __tablename__ = "system_scan"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), nullable=False)
    hostname = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(20), nullable=False)
    os = db.Column(db.String(50))
    os_version = db.Column(db.String(100))
    processor = db.Column(db.String(100))
    machine = db.Column(db.String(50))
    running_processes = db.Column(db.Integer)
    memory_usage = db.Column(db.String(20))
    cpu_usage = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())

# ✅ Network Scan Table
class NetworkScan(db.Model):
    __tablename__ = "network_scan"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), nullable=False)
    ip_address = db.Column(db.String(20), nullable=False)
    open_ports = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())

# ✅ Web Scan Table
class WebScan(db.Model):
    __tablename__ = "web_scan"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(255))
    missing_headers = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())

# ✅ Initialize Database
def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
