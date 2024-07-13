import requests
import re
import json
import time

def reflected_xss(url, payload, context):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in JSON/JS variable:")
    print(f"\033[93mURL: \033[34m{url}\033[0m")
    print(f"Context: {context}")
    print(f"Payload: {payload}")

def scan(url, payload, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)
        
        json_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(json_pattern, response.text, re.DOTALL)
        
        for script in scripts:
            if payload.lower() in script.lower():
                print(f"\033[93m[WARNING]\033[0m Potential XSS in JSON/JS variable: {script[:100]}...")
                reflected_xss(url, payload, "Script content")
            
            try:
                json_objects = re.findall(r'\{[^{}]*\}', script)
                for json_obj in json_objects:
                    parsed = json.loads(json_obj)
                    if any(payload.lower() in str(v).lower() for v in parsed.values()):
                        print(f"\033[93m[WARNING]\033[0m Potential XSS in JSON object: {json_obj[:100]}...")
                        reflected_xss(url, payload, "JSON object")
            except json.JSONDecodeError:
                pass
        
        print(f"\033[96m\033[92m[SCAN]\033[0m JSON/JS variables scan completed for {url}")
    except Exception as e:
        print(f"\033[91m[FATAL]\033[0m Error scanning JSON/JS variables: {str(e)}")