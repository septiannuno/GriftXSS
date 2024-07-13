import requests
from bs4 import BeautifulSoup
import time

def scan(url, payload, full_scan=True, verify_ssl=True):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m Scanning form input fields for XSS vulnerabilities")

    try:
        response = requests.get(url, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            if not action.startswith('http'):
                action = url + action if action.startswith('/') else url + '/' + action
            
            inputs = form.find_all('input')
            payload_data = {}
            
            for input_field in inputs:
                input_name = input_field.get('name')
                if input_name:
                    payload_data[input_name] = payload
            
            if method == 'post':
                test_response = requests.post(action, data=payload_data, verify=verify_ssl)
            else:
                test_response = requests.get(action, params=payload_data, verify=verify_ssl)
            
            if payload in test_response.text:
                print(f"\033[91m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m XSS vulnerability found in form: {action}")
                reflected_xss(action, payload, "form input")
            elif any(dangerous_keyword in test_response.text for dangerous_keyword in ['<script>', 'onerror', 'onload']):
                print(f"\033[93m[{time.strftime('%H:%M:%S')}] \033[93m[WARNING]\033[0m Potential XSS vulnerability found in form: {action}")
            else:
                print(f"\033[92m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m No XSS vulnerability found in form: {action}")

    except Exception as e:
        print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m Error scanning form input fields: {str(e)}")

def reflected_xss(url, payload, location):
    print(f"\033[91m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in form:")
    print(f"URL: {url}")
    print(f"Location: {location}")
    print(f"Payload: {payload}")
