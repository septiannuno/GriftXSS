import requests
from urllib.parse import urlparse, parse_qs
import time

def reflected_xss(url, payload, location):
    print(f"\033[36m[{time.strftime('%H:%M:%S')}] \033[91m[FATAL]\033[0m Reflected XSS found in URL:")
    print(f"\033[93mURL: \033[34m{url}\033[0m")
    print(f"Location: {location}")
    print(f"Payload: {payload}")

def scan(url, payload, verify_ssl=True):
    try:
        parsed_url = urlparse(url)
        fragment = parsed_url.fragment
        
        if fragment:
            if payload.lower() in fragment.lower():
                print(f"\033[93m[WARNING]\033[0m Potential XSS in URL fragment: {fragment}")
                reflected_xss(url, payload, "URL fragment")
        
        query_params = parse_qs(parsed_url.query)
        for param, values in query_params.items():
            for value in values:
                if payload.lower() in value.lower():
                    print(f"\033[93m[WARNING]\033[0m Potential XSS in query parameter: {param}={value}")
                    reflected_xss(url, payload, f"Query parameter: {param}")
        
        print(f"\033[96m\033[92m[SCAN]\033[0m URL fragments scan completed for {url}")
    except Exception as e:
        print(f"\033[91m[FATAL]\033[0m Error scanning URL fragments: {str(e)}")