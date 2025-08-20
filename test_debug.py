from antishlopcli.agent import Agent

# Test file content
file_content = '''# Simple test file
password = "hardcoded_password123"

def connect_db():
    return f"mysql://root:{password}@localhost/db"
'''

print("Testing Agent with hardcoded password...")
result = Agent(file_content)
print("\nResult:")
print(result)
print(f"\nResult type: {type(result)}")
print(f"Result length: {len(result) if result else 0}")