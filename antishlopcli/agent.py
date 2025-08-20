import os
from typing import Dict, TypedDict, Any, List
import json
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from prompts import (
    planner_prompt,
    static_vulnerability_scanner_prompt,
    secrets_detector_prompt,
    dependency_vulnerability_checker_prompt,
    auth_analyzer_prompt,
    input_validation_analyzer_prompt,
    crypto_analyzer_prompt,
    data_security_analyzer_prompt,
    config_security_checker_prompt,
    business_logic_analyzer_prompt,
    error_handling_analyzer_prompt,
    code_quality_security_prompt,
    infrastructure_security_prompt,
    api_security_analyzer_prompt,
    filesystem_security_prompt,
    concurrency_analyzer_prompt,
    reflection_prompt,
    summation_prompt
)

load_dotenv()

llm = ChatOpenAI(api_key=os.getenv('OPENAI_API_KEY'), mode='gpt-4.1', temperature=0, top_p=0)

class State(TypedDict):

    context: list[str]
    file_content: str
    plan: str
    selected_tools: list[str]
    reflection: bool
    final_report: str
    tool_trace: list[str]
    reflection_reason: str
    vulnerabilities: list[dict]
    complete: str

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

def parse_planner_response(response_content: str) -> Dict[str, Any]:
    """Parser for planner agent response"""
    try:
        planner_result = json.loads(response_content.strip())
        
        # Validate required fields
        if not isinstance(planner_result, dict):
            print(f"Warning: Expected dict, got {type(planner_result)}")
            return {"selected_tools": [], "plan": ""}
        
        # Check for required fields
        if "selected_tools" not in planner_result:
            print("Warning: Missing 'selected_tools' field in planner response")
            planner_result["selected_tools"] = []
            
        if "plan" not in planner_result:
            print("Warning: Missing 'plan' field in planner response")
            planner_result["plan"] = ""
        
        # Validate selected_tools is a list
        if not isinstance(planner_result["selected_tools"], list):
            print(f"Warning: selected_tools should be list, got {type(planner_result['selected_tools'])}")
            planner_result["selected_tools"] = []
        
        # Validate plan is a string
        if not isinstance(planner_result["plan"], str):
            print(f"Warning: plan should be string, got {type(planner_result['plan'])}")
            planner_result["plan"] = str(planner_result["plan"])
        
        print(f"Planner selected {len(planner_result['selected_tools'])} tools")
        return planner_result
        
    except json.JSONDecodeError as e:
        print(f"Error parsing planner JSON response: {e}")
        print(f"Response content: {response_content}")
        return {"selected_tools": [], "plan": ""}


def parse_security_tool_response(response_content: str, tool_name: str = "") -> List[Dict[str, Any]]:
    """Generic parser for all security tool responses"""
    try:
        vulnerabilities = json.loads(response_content)
        
        if not isinstance(vulnerabilities, list):
            print(f"Warning: {tool_name} - Expected list, got {type(vulnerabilities)}")
            return []
        
        # Check if empty array
        if len(vulnerabilities) == 0:
            print(f"{tool_name}: No vulnerabilities detected")
            return []
        
        print(f"{tool_name}: Found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities
        
    except json.JSONDecodeError as e:
        print(f"Error parsing {tool_name} JSON response: {e}")
        return []

def static_vulnerability_scanner(state):
    
    formatted_prompt = static_vulnerability_scanner_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"static_vulnerability_scanner")

    state['vulnerabilities'].extend(vulns)

    return state


def secrets_detector(state):
    
    formatted_prompt = secrets_detector_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"secrets_detector")

    state['vulnerabilities'].extend(vulns)
    
    return state

def dependency_vulnerability_checker(state):
    
    formatted_prompt = dependency_vulnerability_checker_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"dependency_vulnerability_checker")

    state['vulnerabilities'].extend(vulns)
    
    return state

def auth_analyzer(state):
    
    formatted_prompt = auth_analyzer_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"auth_analyzer")

    state['vulnerabilities'].extend(vulns)
    
    return state

def input_validation_analyzer(state):
    
    formatted_prompt = input_validation_analyzer_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"input_validation_analyzer")

    state['vulnerabilities'].extend(vulns)
    
    return state

def crypto_analyzer(state):
    
    formatted_prompt = crypto_analyzer_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"crypto_analyzer")

    state['vulnerabilities'].extend(vulns)
    
    return state

def data_security_analyzer(state):
    
    formatted_prompt = data_security_analyzer_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"data_security_analyzer")

    state['vulnerabilities'].extend(vulns)
    
    return state

def config_security_checker(state):
    
    formatted_prompt = config_security_checker_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"config_security_checker")

    state['vulnerabilities'].extend(vulns)
    
    return state

def business_logic_analyzer(state):
    
    formatted_prompt = business_logic_analyzer_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"business_logic_analyzer")

    state['vulnerabilities'].extend(vulns)
    
    return state

def error_handling_analyzer(state):
    
    formatted_prompt = error_handling_analyzer_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"error_handling_analyzer")

    state['vulnerabilities'].extend(vulns)
    
    return state

def code_quality_security(state):
    
    formatted_prompt = code_quality_security_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"code_quality_security")

    state['vulnerabilities'].extend(vulns)
    
    return state

def infrastructure_security(state):
    
    formatted_prompt = infrastructure_security_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"infrastructure_security")

    state['vulnerabilities'].extend(vulns)
    
    return state

def api_security_analyzer(state):
    
    formatted_prompt = api_security_analyzer_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"api_security_analyzer")

    state['vulnerabilities'].extend(vulns)
    
    return state

def filesystem_security(state):
    
    formatted_prompt = filesystem_security_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"filesystem_security")

    state['vulnerabilities'].extend(vulns)
    
    return state

def concurrency_analyzer(state):
    
    formatted_prompt = concurrency_analyzer_prompt.format(context=state['context'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)
    vulns = parse_security_tool_response(response.content.strip(),"concurrency_analyzer")

    state['vulnerabilities'].extend(vulns)
    
    return state

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

def context_node(state):
    pass

def planner_node(state):
    
    formatted_prompt = planner_prompt.format(context=state['context'], reason=state['reflection_reason'], tool_trace=state['tool_trace'], reflection=state['reflection'], file_content=state['file_content'])
    response = llm.invoke(formatted_prompt)

    output = parse_planner_response(response.content.strip())
    state['selected_tools'] = output['selected_tools']
    state['plan'] = output['plan']

    return state


def execute_node(state):
    
        tool_functions = {
        "static_vulnerability_scanner": static_vulnerability_scanner,
        "secrets_detector": secrets_detector,
        "dependency_vulnerability_checker": dependency_vulnerability_checker,
        "auth_analyzer": auth_analyzer,
        "input_validation_analyzer": input_validation_analyzer,
        "crypto_analyzer": crypto_analyzer,
        "data_security_analyzer": data_security_analyzer,
        "config_security_checker": config_security_checker,
        "business_logic_analyzer": business_logic_analyzer,
        "error_handling_analyzer": error_handling_analyzer,
        "code_quality_security": code_quality_security,
        "infrastructure_security": infrastructure_security,
        "api_security_analyzer": api_security_analyzer,
        "filesystem_security": filesystem_security,
        "concurrency_analyzer": concurrency_analyzer
    }
    
    
    for tool_name in state['selected_tools']:
        if tool_name in tool_functions:
        
            state = tool_functions[tool_name](state)
            state['tool_trace'].append(tool_name)
        else:
            print(f"Warning: Unknown tool '{tool_name}'")
    
    return state
    
def reflection_node(state):
    pass

def summation_node(state):
    pass

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#