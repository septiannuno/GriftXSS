import requests
from bs4 import BeautifulSoup
import time

def scan(url, payload, full_scan=True, verify_ssl=True):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m Scanning for DOM-based XSS vulnerabilities")

    try:
        response = requests.get(url, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                if check_dom_xss(script.string, payload):
                    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m DOM-based XSS vulnerability found in script")
                    reflected_xss(url, payload, "DOM")
                elif check_potential_dom_xss(script.string):
                    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[93m[WARNING]\033[0m Potential DOM-based XSS vulnerability found in script")
                else:
                    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m No DOM-based XSS vulnerability found in script")

    except Exception as e:
        print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[92m[SCAN]\033[0m Error scanning for DOM-based XSS: {str(e)}")

def check_dom_xss(script_content, payload):
    dangerous_sinks = ['eval(', 'setTimeout(', 'setInterval(', 'Function(', 'document.write(', 'document.writeln(',
    'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'onevent',
    'document.cookie', 'document.domain', 'location.href', 'location.replace', 'location.assign',
    'window.open', 'postMessage', 'localStorage', 'sessionStorage']
    for sink in dangerous_sinks:
        if sink in script_content and payload in script_content:
            return True
    return False

def check_potential_dom_xss(script_content):
    potential_sources = ['location', 'location.hash', 'location.href', 'location.search', 'location.pathname',
    'document.URL', 'document.documentURI', 'document.referrer', 'window.name',
    'history.pushState', 'history.replaceState',
    'localStorage', 'sessionStorage']
    for source in potential_sources:
        if source in script_content:
            return True
    return False

def reflected_xss(url, payload, context):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found:")
    print(f"URL: {url}")
    print(f"Context: {context}")
    print(f"Payload: {payload}")
