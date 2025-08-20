from antishlopcli.agent import Agent, State

file_content = '''# Simple test file
password = "hardcoded_password123"

def connect_db():
    return f"mysql://root:{password}@localhost/db"
'''

# Create state manually and test planner
state = State()
state['context'] = []
state['file_content'] = file_content
state['plan'] = ""
state['selected_tools'] = []
state['reflection'] = False
state['final_report'] = ""
state['tool_trace'] = []
state['reflection_reason'] = "Initial analysis required"
state['vulnerabilities'] = []
state['complete'] = ""

# Test just the planner
from antishlopcli.agent import planner_node
print("Testing planner node...")
state = planner_node(state)
print(f"Selected tools: {state['selected_tools']}")
print(f"Plan: {state['plan']}")

# Test execution
if state['selected_tools']:
    from antishlopcli.agent import execute_node
    print("\nTesting execute node...")
    state = execute_node(state)
    print(f"Vulnerabilities found: {len(state['vulnerabilities'])}")
    if state['vulnerabilities']:
        print("Vulnerabilities:")
        for v in state['vulnerabilities']:
            print(f"  - {v}")