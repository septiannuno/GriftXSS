import requests
from bs4 import BeautifulSoup
import time

def reflected_xss(url, payload, handler):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in event handler:")
    print(f"\033[93mURL: \033[34m{url}\033[0m")
    print(f"Event Handler: {handler}")
    print(f"Payload: {payload}")

def scan(url, payload, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        event_handlers = ['onclick', 'onload', 'onmouseover', 'onerror', 'onsubmit', 'onkeyup', 'onkeydown']
        for handler in event_handlers:
            elements = soup.find_all(attrs={handler: True})
            for element in elements:
                if payload.lower() in element[handler].lower():
                    print(f"\033[93m[WARNING]\033[0m Potential XSS in {handler} event: {element}")
                    reflected_xss(url, payload, handler)
        
        print(f"\033[96m\033[92m[SCAN]\033[0m Inline event handlers scan completed for {url}")
    except Exception as e:
        print(f"\033[91m[FATAL]\033[0m Error scanning inline event handlers: {str(e)}")