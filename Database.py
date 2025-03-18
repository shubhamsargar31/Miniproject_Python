
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Signup(db.Model):
    __tablename__ = "signups"
    id = db.Column(db.Integer, primary_key=True)
    gmail = db.Column(db.String(40), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=False)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # Web Scanner / Network Scanner
    vulnerabilities = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    scan_date = db.Column(db.DateTime, default=db.func.now())

    def __init__(self, target_url, scan_type, vulnerabilities, risk_level):
        self.target_url = target_url
        self.scan_type = scan_type
        self.vulnerabilities = vulnerabilities
        self.risk_level = risk_level
