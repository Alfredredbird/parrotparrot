from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import json
from collections import Counter
from datetime import datetime
import threading
import subprocess

app = Flask(__name__)
app.secret_key = 'PoPoParrot'  



# Load authentication credentials
def load_credentials():
    try:
        with open('auth.json', 'r') as file:
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
    return render_template('index.html')

# Route to get IP data in JSON format
@app.route('/api/ip_data')
def ip_data():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        with open('ips.json', 'r') as file:
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

# Route to get summary data based on day and hour
@app.route('/api/summary')
def summary():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        with open('ips.json', 'r') as file:
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

# Route to log out
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
