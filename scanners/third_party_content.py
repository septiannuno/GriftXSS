import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time

def reflected_xss(url, payload, resource_url):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in third-party content:")
    print(f"\033[93mURL: \033[34m{url}\033[0m")
    print(f"Resource URL: {resource_url}")
    print(f"Payload: {payload}")

def scan(url, payload, verify_ssl=True):
    try:
        response = requests.get(url, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        base_domain = urlparse(url).netloc
        
        external_resources = soup.find_all(['script', 'link', 'iframe', 'img'], src=True)
        for resource in external_resources:
            src = resource.get('src', '')
            if src.startswith('http') and urlparse(src).netloc != base_domain:
                print(f"\033[93m[WARNING]\033[0m Third-party content detected: {src}")
                if payload.lower() in src.lower():
                    reflected_xss(url, payload, src)
        
        print(f"\033[96m\033[92m[SCAN]\033[0m Third-party content scan completed for {url}")
    except Exception as e:
        print(f"\033[91m[FATAL]\033[0m Error scanning third-party content: {str(e)}")