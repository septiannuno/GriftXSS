import requests
from urllib.parse import urlparse, parse_qs, urlencode
import time

def scan(url, payload, full_scan=False, verify_ssl=True):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m \033[0mScanning GET parameters for XSS vulnerabilities\033[0m")

    try:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m \033[37mNo GET parameters found in the URL\033[0m")
            return

        for param, value in params.items():
            modified_params = params.copy()
            modified_params[param] = [payload]
            
            new_query = urlencode(modified_params, doseq=True)
            test_url = parsed_url._replace(query=new_query).geturl()
            
            response = requests.get(test_url, verify=verify_ssl)
            
            if payload in response.text:
                print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m XSS vulnerability found in GET parameter: {param}")
                reflected_xss(test_url, payload, param)
            elif any(dangerous_keyword in response.text for dangerous_keyword in ['<script>', 'onerror', 'onload']):
                print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[93m[WARNING]\033[0m Potential XSS vulnerability found in GET parameter: {param}")
            else:
                print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m No XSS vulnerability found in GET parameter: {param}")

    except Exception as e:
        print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m Error scanning GET parameters: {str(e)}")

def reflected_xss(url, payload, param):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found:")
    print(f"URL: {url}")
    print(f"Parameter: {param}")
    print(f"Payload: {payload}")
