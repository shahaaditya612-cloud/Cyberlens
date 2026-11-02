import os
import re
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

app = Flask(__name__)
app.secret_key = "cyberlens_secret_key_secure_2026"

USERS_DB = [
    {"id": 1, "name": "Shweta Sah", "email": "shweta@gmail.com", "password": "password123", "role": "admin"}
]
SCANS_DB = []

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html', active_tab='login')

@app.route('/login', methods=['POST'])
def login():
    data = request.json or request.form
    email = data.get('email')
    password = data.get('password')
    
    for user in USERS_DB:
        if user['email'] == email and user['password'] == password:
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            return jsonify({"success": True, "message": "Login successful", "role": user['role']})
            
    return jsonify({"success": False, "message": "Invalid email or password"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.json or request.form
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    for user in USERS_DB:
        if user['email'] == email:
            return jsonify({"success": False, "message": "Email already registered"}), 400
            
    new_user = {
        "id": len(USERS_DB) + 1,
        "name": name if name else "Shweta Sah",
        "email": email,
        "password": password,
        "role": "user"
    }
    USERS_DB.append(new_user)
    session['user_id'] = new_user['id']
    session['user_name'] = new_user['name']
    session['user_role'] = new_user['role']
    
    return jsonify({"success": True, "message": "Registration successful", "role": new_user['role']})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('index.html', active_tab='dashboard', user_name=session.get('user_name'), user_role=session.get('user_role'))

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"success": False, "message": "URL cannot be empty"}), 400
        
    reasons = []
    score = 100
    
    if not url.startswith('https://'):
        reasons.append("Missing HTTPS protocol (Not secure)")
        score -= 25
    if '@' in url:
        reasons.append("Contains '@' symbol which can be used to obfuscate true destination")
        score -= 30
    if len(url) > 75:
        reasons.append("Unusually long domain or URL path length")
        score -= 15
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        reasons.append("Uses raw IP address instead of a domain name")
        score -= 35
    
    suspicious_keywords = ['login', 'verify', 'update', 'free', 'secure', 'account', 'banking', 'signin']
    found_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
    if found_keywords:
        reasons.append(f"Contains high-risk phishing keywords: {', '.join(found_keywords)}")
        score -= 25

    if score >= 85:
        result_category = "Safe"
    elif score >= 50:
        result_category = "Suspicious"
    else:
        result_category = "High Risk"
        
    if not reasons:
        reasons.append("No obvious warning signs detected. Structure appears standard.")

    scan_record = {
        "id": len(SCANS_DB) + 1,
        "user_id": session.get('user_id', 1),
        "url": url,
        "result": result_category,
        "score": max(score, 0),
        "reasons": reasons,
        "date": "2026-10-26"
    }
    SCANS_DB.append(scan_record)
    
    return jsonify({"success": True, "data": scan_record})

@app.route('/api/scans', methods=['GET'])
def get_scans():
    return jsonify({"success": True, "scans": SCANS_DB})

@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    global SCANS_DB
    SCANS_DB[:] = [s for s in SCANS_DB if s['id'] != scan_id]
    return jsonify({"success": True, "message": "Record deleted"})

@app.route('/api/scans/clear', methods=['POST'])
def clear_scans():
    global SCANS_DB
    SCANS_DB.clear()
    return jsonify({"success": True, "message": "All history cleared"})

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    if session.get('user_role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    return jsonify({"success": True, "users": USERS_DB})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
