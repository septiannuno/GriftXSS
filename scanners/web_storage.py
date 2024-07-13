import requests
from bs4 import BeautifulSoup
import re
import time

def reflected_xss(url, payload, storage_type, key):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in web storage:")
    print(f"\033[93mURL: \033[34m{url}\033[0m")
    print(f"Storage Type: {storage_type}")
    print(f"Key: {key}")
    print(f"Payload: {payload}")

def scan(url, payload, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        scripts = soup.find_all('script')
        storage_pattern = r'(localStorage|sessionStorage)\.setItem\s*\(\s*(["\'])(.+?)\2\s*,\s*(["\'])(.+?)\4\s*\)'
        
        for script in scripts:
            matches = re.findall(storage_pattern, script.string or '')
            for match in matches:
                storage_type, _, key, _, value = match
                if payload.lower() in value.lower():
                    print(f"\033[93m[WARNING]\033[0m Potential XSS in {storage_type}: {key}={value}")
                    reflected_xss(url, payload, storage_type, key)
        
        print(f"\033[96m\033[92m[SCAN]\033[0m Web storage scan completed for {url}")
    except Exception as e:
        print(f"\033[91m[FATAL]\033[0m Error scanning web storage: {str(e)}")