import requests
from bs4 import BeautifulSoup
import time

def reflected_xss(url, payload, form_action):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in POST data:")
    print(f"\033[93mURL: \033[34m{url}\033[0m")
    print(f"Form Action: {form_action}")
    print(f"Payload: {payload}")

def scan(url, payload, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form', method='post')
        for form in forms:
            action = form.get('action', '')
            full_url = requests.compat.urljoin(url, action)
            
            data = {input.get('name'): payload for input in form.find_all('input') if input.get('name')}
            post_response = requests.post(full_url, data=data, verify=verify_ssl)
            
            if payload in post_response.text:
                print(f"\033[93m[WARNING]\033[0m Potential XSS in POST response: {full_url}")
                reflected_xss(full_url, payload, action)
        
        print(f"\033[96m\033[92m[SCAN]\033[0m POST data scan completed for {url}")
    except Exception as e:
        print(f"\033[91m[FATAL]\033[0m Error scanning POST data: {str(e)}")