from antishlopcli.prompts import secrets_detector_prompt
from langchain_openai import ChatOpenAI
import os
from dotenv import load_dotenv

load_dotenv()

file_content = '''# Simple test file
password = "hardcoded_password123"
api_key = "sk-1234567890abcdef"

def connect_db():
    return f"mysql://root:{password}@localhost/db"
'''

llm = ChatOpenAI(api_key=os.getenv('OPENAI_API_KEY'), model='gpt-4', temperature=0)

formatted_prompt = secrets_detector_prompt.format(context=[], file_content=file_content)
print("Calling LLM to detect secrets...")
response = llm.invoke(formatted_prompt)
print("Response:")
print(response.content)