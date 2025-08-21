#!/usr/bin/env python3
"""Test file with multiple security vulnerabilities"""

import os
import sqlite3
import hashlib
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

# SQL Injection
def get_user(username):
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()

# Command Injection
def backup_file(filename):
    os.system(f"cp {filename} /backup/")

# XSS vulnerability
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"<h1>Results for: {query}</h1>"

# Weak cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Information disclosure
def debug_info():
    return {
        'env': dict(os.environ),
        'secret_key': API_KEY
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')