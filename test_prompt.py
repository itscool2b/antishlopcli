from langchain.prompts import PromptTemplate

# Test if PromptTemplate works correctly
test_prompt = PromptTemplate.from_template("""
Test prompt with variables:
Context: {context}
Reason: {reason}
""")

try:
    result = test_prompt.format(context="test context", reason="test reason")
    print("Success! Result:")
    print(result)
except Exception as e:
    print(f"Error: {e}")
    print(f"Error type: {type(e)}")