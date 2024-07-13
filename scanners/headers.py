import requests
import time
import colorama

colorama.init()

def scan(url, payload, full_scan=False, verify_ssl=True):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m Scanning headers for XSS vulnerabilities")

    try:
        headers_to_test = {
            'User-Agent': payload,
            'Referer': payload,
            'X-Forwarded-For': payload
        }

        for header, value in headers_to_test.items():
            custom_headers = {header: value}
            response = requests.get(url, headers=custom_headers, verify=verify_ssl)
            
            if payload in response.text:
                print(f"\033[91m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m XSS vulnerability found in header: {header}")
                reflected_xss(url, payload, header)
            elif any(dangerous_keyword in response.text for dangerous_keyword in ['<script>', 'onerror', 'onload']):
                print(f"\033[93m[{time.strftime('%H:%M:%S')}] \033[93m[WARNING]\033[0m Potential XSS vulnerability found in header: {header}")

    except Exception as e:
        print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m Error scanning headers: {str(e)}")

def reflected_xss(url, payload, header):
    print(f"\033[91m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in header:")
    print(f"URL: {url}")
    print(f"Header: {header}")
    print(f"Payload: {payload}")
