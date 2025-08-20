from antishlopcli.prompts import planner_prompt

# Test the actual planner prompt
test_state = {
    'context': [],
    'file_content': 'test code content',
    'tool_trace': [],
    'reflection': False,
    'reflection_reason': 'Initial analysis'
}

try:
    result = planner_prompt.format(
        context=test_state['context'],
        reason=test_state['reflection_reason'],
        tool_trace=test_state['tool_trace'],
        reflection=test_state['reflection'],
        file_content=test_state['file_content']
    )
    print("Success! Prompt formatted correctly")
    print(f"Result length: {len(result)}")
    print(f"First 200 chars: {result[:200]}")
except Exception as e:
    print(f"Error: {e}")
    print(f"Error type: {type(e)}")
    import traceback
    traceback.print_exc()