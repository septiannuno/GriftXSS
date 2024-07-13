import requests
from bs4 import BeautifulSoup
import time

def reflected_xss(url, payload, attribute):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in HTML attribute:")
    print(f"\033[93mURL: \033[34m{url}\033[0m")
    print(f"Attribute: {attribute}")
    print(f"Payload: {payload}")

def scan(url, payload, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        risky_attributes = ['href', 'src', 'data', 'action']
        for attr in risky_attributes:
            elements = soup.find_all(attrs={attr: True})
            for element in elements:
                if payload.lower() in element[attr].lower():
                    print(f"\033[93m[WARNING]\033[0m Potential XSS in {attr} attribute: {element}")
                    reflected_xss(url, payload, attr)
        
        print(f"\033[96m\033[92m[SCAN]\033[0m HTML attributes scan completed for {url}")
    except Exception as e:
        print(f"\033[91m[FATAL]\033[0m Error scanning HTML attributes: {str(e)}")