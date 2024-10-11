import os
import time
from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import json
from collections import Counter
from datetime import datetime
import threading
import subprocess

from modules.scanning import *

app = Flask(__name__)
app.secret_key = 'PoPoParrot'  


# Change to python3 if not on windows

def run_scanner():
    subprocess.run(['python.exe' if os.name == "nt" else "python3", 'main.py'])


script_thread = threading.Thread(target=run_scanner)

script_thread.start()

# Load authentication credentials
def load_credentials():
    try:
        with open('config/auth.json', 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

credentials = load_credentials()

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check credentials
        if username == credentials.get("username") and password == credentials.get("password"):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

# Route for the home page
@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('welcome.html')

# Route to get IP data in JSON format
@app.route('/api/ip_data')
def ip_data():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        with open('saves/ips.json', 'r') as file:
            data = json.load(file)

        # Add geolocation and DNS info to the response
        for ip in data:
            ip_info = data[ip]
            # Assuming ip_info already contains these fields
            # Modify as necessary to extract geolocation and DNS info
            ip_info['geolocation'] = ip_info.get('geolocation', {})
            ip_info['dns_info'] = ip_info.get('dns_info', {})
        
        return jsonify(data)
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({})

# Route to handle form submission and initiate IP scan
@app.route('/run_ip_scan', methods=['POST'])
def run_ip_scan():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    ip = request.form['ip']
    scan_result = scan_ip(ip)
    
    # Save the scan result to JSON file (append without overwriting)
    try:
        with open('saves/ips.json', 'r') as file:
            ip_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        ip_data = {}

    ip_data[ip] = scan_result
    with open('saves/ips.json', 'w') as file:

        json.dump(ip_data, file, indent=4)

    # Redirect to display results on a new page
    return redirect(url_for('display_scan_result', ip=ip))

# Route to display scan result
@app.route('/scan_result/<ip>')
def display_scan_result(ip):
    try:
        with open('saves/ips.json', 'r') as file:
            ip_data = json.load(file)
            scan_result = ip_data.get(ip, {})
        return render_template('scan_result.html', scan_result=scan_result)
    except (FileNotFoundError, json.JSONDecodeError):
        return render_template('scan_result.html', scan_result={})


# Route to get summary data based on day and hour
@app.route('/api/summary')
def summary():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        with open('saves/ips.json', 'r') as file:
            data = json.load(file)
        
        # Create a list to hold timestamps
        timestamps = [ip_info["timestamp"] for ip_info in data.values()]

        # Extract hours and days from timestamps
        hour_counts = Counter(datetime.fromisoformat(ts).strftime("%Y-%m-%d %H") for ts in timestamps)
        day_counts = Counter(datetime.fromisoformat(ts).strftime("%Y-%m-%d") for ts in timestamps)

        summary_data = {
            "hourly": dict(hour_counts),
            "daily": dict(day_counts)
        }
        return jsonify(summary_data)
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({})

# Route to display IP data
@app.route('/display_ip_data')
def display_ip_data():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    try:
        with open('saves/ips.json', 'r') as file:
            data = json.load(file)
        
        return render_template('ip_data.html', ip_data=data)
    except (FileNotFoundError, json.JSONDecodeError):
        return render_template('ip_data.html', ip_data={})

    
@app.route('/analytics')
def analytics():
    if 'logged_in' not in session:
        return redirect(url_for('login')) 
    return render_template('index.html', ip_data={})

@app.route('/scan_center')
def scan_center():
    if 'logged_in' not in session:
        return redirect(url_for('login')) 
    return render_template('scan_center.html', ip_data={})

# Route to rescan an IP address
@app.route('/rescan', methods=['POST'])
def rescan():
    ip = request.form.get('ip')
    if ip:
        # Run the scan.py script with the specified IP
        subprocess.Popen(['python.exe', 'scripts/rescan.py', '-ip', ip])
    return redirect(url_for('display_ip_data'))

# scan for IP cameras with dorks
@app.route('/ip-scan', methods=['POST'])
def ip_scan():
    try:
        subprocess.run(["python.exe", "scripts/dork.py"], check=True)
        return jsonify({"message": "Scan started"}), 200
    except Exception as e:
        return jsonify({"message": "Failed to start scan", "error": str(e)}), 500


# Route to log out
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
