from flask import Flask, render_template, request, session, jsonify, redirect, url_for
from flask_mail import Mail, Message
import random
import json
import nmap
import requests
from bs4 import BeautifulSoup
import os
import platform
import socket
import psutil
from Database import db, init_db,Signup,WebScan,NetworkScan,SystemScan


app = Flask(__name__)
app.secret_key = "your_secret_key"

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:shubham123@localhost:5432/sign_up'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


init_db(app)


try:
    with open('config.json', 'r') as f:
        params = json.load(f).get('param', {})
except (FileNotFoundError, json.JSONDecodeError):
    params = {}


app.config.update({
    'MAIL_SERVER': 'smtp.gmail.com',
    'MAIL_PORT': 587,
    'MAIL_USERNAME': params.get('gmail-user', ''),
    'MAIL_PASSWORD': params.get('gmail-password', ''),
    'MAIL_USE_TLS': True,
    'MAIL_USE_SSL': False,
    'MAIL_DEFAULT_SENDER': params.get('gmail-user', '')
})

mail = Mail(app)

# ------------------ Routes ------------------ #

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/scanner')
def scanner_page():
    return render_template('scanner.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# ------------------ OTP Verification ------------------ #

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form.get('email')
    if not email:
        return jsonify({"message": "Please enter a valid email!", "status": "error"})

    otp_code = str(random.randint(100000, 999999))
    session['otp'] = otp_code
    session['email'] = email

    user = Signup.query.filter_by(gmail=email).first()
    if user:
        user.otp = otp_code
    else:
        user = Signup(gmail=email, otp=otp_code)
        db.session.add(user)

    db.session.commit()

    try:
        msg = Message('Your OTP for Verification', recipients=[email])
        msg.body = f"Your OTP is {otp_code}. It will expire in 1 minute."
        mail.send(msg)
        return jsonify({"message": "OTP Sent Successfully! Check your email.", "status": "success"})
    except Exception as e:
        print("Error sending OTP:", str(e))
        return jsonify({"message": f"Error sending OTP: {str(e)}", "status": "error"})

@app.route('/validate', methods=['POST'])
def validate():
    email = session.get('email')
    entered_otp = request.form.get('otp')
    if not entered_otp or not email:
        return jsonify({"message": "Please enter the OTP!", "status": "error"})

    user = Signup.query.filter_by(gmail=email).first()
    if user and user.otp == entered_otp:
        session.pop('otp', None)
        return jsonify({"message": "OTP Verified! Signup Successful...", "status": "success", "redirect": url_for('scanner_page')})

    return jsonify({"message": "Invalid OTP, please try again.", "status": "error"})

# ------------------ System Scanner ------------------ #
@app.route("/scan_system", methods=["POST"])
def system_scan():
    email = session.get('email')  
    if not email:
        return jsonify({"error": "User not logged in!"}), 401

    system_name = request.form.get("systemName")
    if not system_name:
        return jsonify({"error": "No system name provided"}), 400

    try:
        ip_address = socket.gethostbyname(system_name)
        system_info = {
            "email": email,
            "Hostname": system_name,
            "IP Address": ip_address,
            "OS": platform.system(),
            "OS Version": platform.version(),
            "Processor": platform.processor(),
            "Machine": platform.machine(),
            "Running Processes": len(psutil.pids()),
            "Memory Usage": f"{psutil.virtual_memory().percent}%",
            "CPU Usage": f"{psutil.cpu_percent(interval=1)}%"
        }

        # ✅ Store Scan Data in Database
        scan = SystemScan(email=email, hostname=system_name, ip_address=ip_address,
                          os=system_info["OS"], os_version=system_info["OS Version"],
                          processor=system_info["Processor"], machine=system_info["Machine"],
                          running_processes=system_info["Running Processes"],
                          memory_usage=system_info["Memory Usage"], cpu_usage=system_info["CPU Usage"])
        db.session.add(scan)
        db.session.commit()

        return jsonify({"result": system_info})

    except socket.gaierror:
        return jsonify({"error": "Invalid system name or IP address"}), 400

# ------------------ Network Scanner ------------------ #
@app.route("/start_scan", methods=["POST"])
def start_scan():
    email = session.get('email')  
    if not email:
        return jsonify({"error": "User not logged in!"}), 401

    ip = request.form.get("ipAddress")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments="-T4 -F")
        open_ports = list(scanner[ip].all_protocols()) if ip in scanner.all_hosts() else []


        scan = NetworkScan(email=email, ip_address=ip, open_ports=", ".join(open_ports))
        db.session.add(scan)
        db.session.commit()

        return jsonify({"result": {"open_ports": open_ports}})
    
    except Exception as e:
        return jsonify({"error": str(e)})

# ------------------ Web Scanner ------------------ #
@app.route("/scan_website", methods=["POST"])
def website_scan():
    email = session.get('email')  # ✅ Get logged-in user's email
    if not email:
        return jsonify({"error": "User not logged in!"}), 401

    url = request.form.get("website")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else "No Title Found"
        headers = response.headers
        missing_headers = [h for h in ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"] if h not in headers]

        # ✅ Store Scan Data in Database
        scan = WebScan(email=email, website=url, title=title, missing_headers=", ".join(missing_headers))
        db.session.add(scan)
        db.session.commit()

        return jsonify({"result": {"title": title, "missing_headers": missing_headers}})
    
    except Exception as e:
        return jsonify({"error": str(e)})
# ------------------ Logout ------------------ #

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ------------------ Run Flask App ------------------ #

if __name__ == "__main__":
    app.run(debug=True)
