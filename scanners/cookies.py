import requests
from urllib.parse import urlparse, parse_qs, urlencode
import time
import math

def scan(url, payload, full_scan=True, verify_ssl=True):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m Scanning cookies for XSS vulnerabilities")

    try:
        session = requests.Session()
        response = session.get(url, verify=verify_ssl)
        cookies = session.cookies.get_dict()

        xss_payloads = [payload]  # Assuming payload is a list or can be iterated over

        for cookie_name, cookie_value in cookies.items():
            for payload in xss_payloads:
                modified_cookies = cookies.copy()
                modified_cookies[cookie_name] = payload
                
                test_response = session.get(url, cookies=modified_cookies, verify=verify_ssl)
                
                if payload in test_response.text:
                    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m XSS vulnerability found in cookie: {cookie_name}")
                    reflected_xss(url, payload, cookie_name)
                elif any(dangerous_keyword in test_response.text for dangerous_keyword in ['<script>', 'onerror', 'onload']):
                    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[93m[WARNING]\033[0m Potential XSS vulnerability found in cookie: {cookie_name}")

        # Check for Session Fixation
        session_cookies = [name for name in cookies if 'session' in name.lower()]
        for session_cookie in session_cookies:
            fixed_session = 'fixed_session_value_' + time.strftime('%Y%m%d%H%M%S')
            modified_cookies = cookies.copy()
            modified_cookies[session_cookie] = fixed_session
            
            test_response = session.get(url, cookies=modified_cookies, verify=verify_ssl)
            
            if fixed_session in session.cookies.get(session_cookie, ''):
                print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Session Fixation vulnerability found in cookie: {session_cookie}")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [SCAN] Checked for Session Fixation in cookie: {session_cookie}")

        # Check for Insecure Cookie Flags
        response = session.get(url)
        for cookie in response.cookies:
            flags = []
            if not cookie.secure:
                flags.append("missing Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                flags.append("missing HttpOnly flag")
            if flags:
                print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Insecure Cookie: {cookie.name}")
                print(f"    Issues: {', '.join(flags)}")
                print(f"    Domain: {cookie.domain}")
                print(f"    Path: {cookie.path}")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [SCAN] Cookie flags checked for: {cookie.name}")
                print(f"    Secure: {cookie.secure}")
                print(f"    HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")
                print(f"    Domain: {cookie.domain}")
                print(f"    Path: {cookie.path}")

        # Additional check for cookie value entropy
        for cookie_name, cookie_value in cookies.items():
            entropy = calculate_entropy(cookie_value)
            if entropy < 3.0:
                print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[93m[WARNING]\033[0m Low entropy in cookie: {cookie_name}")
                print(f"    Entropy: {entropy}")
                print(f"    Value: {cookie_value[:20]}...")  # Show first 20 characters
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [SCAN] Entropy checked for cookie: {cookie_name}")
                print(f"    Entropy: {entropy}")

    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] [SCAN] Error scanning cookies: {str(e)}")

def reflected_xss(url, payload, cookie_name):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in cookie:")
    print(f"\033[93mURL: \033[34m{url}\033[0m")
    print(f"Cookie: {cookie_name}")
    print(f"Payload: {payload}")

def calculate_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob if p != 0])
    return entropy
