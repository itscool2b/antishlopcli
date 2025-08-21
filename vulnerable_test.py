#!/usr/bin/env python3
import os
import sqlite3
import hashlib
import subprocess
import pickle
import yaml
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"
JWT_SECRET = "supersecret"

# SQL Injection vulnerability
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"  # Direct string interpolation
    cursor.execute(query)
    return cursor.fetchone()

# Command Injection
def backup_file(filename):
    os.system(f"cp {filename} /backup/")  # Unsanitized input

# Path Traversal
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    return open(f"/uploads/{filename}", 'rb').read()  # No path validation

# XSS vulnerability
@app.route('/search')
def search():
    query = request.args.get('q', '')
    template = f"<h1>Results for: {query}</h1>"  # Direct template injection
    return render_template_string(template)

# Insecure deserialization
def load_config(data):
    return pickle.loads(data)  # Arbitrary code execution

# YAML bomb potential
def parse_config(yaml_data):
    return yaml.load(yaml_data)  # Unsafe YAML loading

# Weak cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is broken

# Information disclosure
def debug_info():
    return {
        'env': dict(os.environ),  # Leaks environment variables
        'cwd': os.getcwd(),
        'user': os.getlogin()
    }

# SSRF vulnerability
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # No URL validation
    return response.text

# Insecure random
import random
def generate_token():
    return str(random.randint(1000, 9999))  # Predictable random

# Race condition
user_balance = 1000
def withdraw(amount):
    if user_balance >= amount:  # Check
        time.sleep(0.1)  # Vulnerable gap
        user_balance -= amount  # Use
    return user_balance

# Buffer overflow potential (if this were C)
def process_input(data):
    # Simulating unsafe operations
    eval(data)  # Code injection
    exec(f"result = {data}")  # More code injection

# Logging sensitive data
import logging
def login(username, password):
    logging.info(f"Login attempt: {username}:{password}")  # Logs password
    
# Insecure file permissions
def create_temp_file():
    with open('/tmp/sensitive.txt', 'w') as f:  # World readable
        f.write("credit_card=4111111111111111")

# Integer overflow simulation
def calculate_price(quantity, price):
    return quantity * price  # No bounds checking

# Directory listing
@app.route('/files')
def list_files():
    return os.listdir('/')  # Directory traversal info

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # Debug mode in production