# Simple test file
password = "hardcoded_password123"

def connect_db():
    return f"mysql://root:{password}@localhost/db"
