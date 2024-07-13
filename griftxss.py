import argparse
import sys
import time
import colorama
import urllib3
from bs4 import BeautifulSoup
import requests
from requests.exceptions import RequestException, SSLError, Timeout
from urllib.parse import urljoin, urlparse
import signal
from utils.waf_detection import WAFDetection

from scanners import (
    cookies, dom_based, form_input_fields, headers, get_params,
    html_attributes, inline_event_handlers, json_js_vars, post_data,
    third_party_content, url_fragments, web_storage
)

colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

waf_detector = WAFDetection()

def log(message, type="INFO"):
    timestamp = f"\033[36m[{time.strftime('%H:%M:%S')}]\033[0m"
    if type == "SCAN":
        print(f"{timestamp} \033[92m[SCAN]\033[0m {message}")
    elif type == "PAYLOAD":
        print(f"{timestamp} \033[35m[INFO]\033[0m {message}")
    elif type == "ERROR":
        print(f"{timestamp} \033[91m[ERROR]\033[0m {message}")
    elif type == "INFO":
        print(f"{timestamp} \033[35m[INFO]\033[0m {message}")
    elif type == "CRAWL":
        print(f"{timestamp} \033[94m[CRAWL]\033[0m {message}")
    elif type == "WARNING":
        print(f"{timestamp} \033[93m[WARNING]\033[0m {message}")
    elif type == "FATAL":
        print(f"{timestamp} \033[91m[FATAL]\033[0m {message}")

def signal_handler(sig, frame):
    print('\nProgram dihentikan oleh pengguna.')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def crawl(url, verify_ssl):
    visited = set()
    to_visit = [url]
    domain = urlparse(url).netloc
    crawled_data = []

    while to_visit:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue

        try:
            log(f"Crawling: {current_url}", "CRAWL")
            response = requests.get(current_url, verify=verify_ssl, timeout=10)
            visited.add(current_url)
        except Exception as e:
            log(f"Error crawling {current_url}: {str(e)}", "ERROR")
            continue

        soup = BeautifulSoup(response.text, 'html.parser')
        
        page_data = {
            'url': current_url,
            'content': response.text,
            'links': [urljoin(current_url, a.get('href')) for a in soup.find_all('a', href=True)]
        }
        crawled_data.append(page_data)

        for link in page_data['links']:
            if urlparse(link).netloc == domain and link not in visited:
                to_visit.append(link)

    return crawled_data

def perform_scan(url, payload, verify_ssl, scanner_func, scanner_name):
    try:
        log(f"Performing {scanner_name} scan on {url}", "SCAN")
        log(f"Using payload: {payload}", "PAYLOAD")
        scanner_func(url, payload, verify_ssl=verify_ssl)
    except Exception as e:
        log(f"Error during {scanner_name} scan: {str(e)}", "ERROR")

def perform_targeted_scan(url, payload, verify_ssl):
    log(f"Performing targeted scan on {url}", "SCAN")
    perform_scan(url, payload, verify_ssl, cookies.scan, "cookies")
    perform_scan(url, payload, verify_ssl, dom_based.scan, "DOM-based")
    perform_scan(url, payload, verify_ssl, form_input_fields.scan, "form input fields")
    perform_scan(url, payload, verify_ssl, headers.scan, "headers")
    perform_scan(url, payload, verify_ssl, get_params.scan, "GET parameters")
    perform_scan(url, payload, verify_ssl, html_attributes.scan, "HTML attributes")
    perform_scan(url, payload, verify_ssl, inline_event_handlers.scan, "inline event handlers")
    perform_scan(url, payload, verify_ssl, json_js_vars.scan, "JSON/JS variables")
    perform_scan(url, payload, verify_ssl, post_data.scan, "POST data")
    perform_scan(url, payload, verify_ssl, third_party_content.scan, "third-party content")
    perform_scan(url, payload, verify_ssl, url_fragments.scan, "URL fragments")
    perform_scan(url, payload, verify_ssl, web_storage.scan, "web storage")

def perform_brute_force_scan(url, payloads, verify_ssl):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = [param.split('=')[0] for param in parsed_url.query.split('&') if param]
    
    if not params:
        params = ['xss']  

    for param in params:
        for payload in payloads:
            test_url = f"{base_url}?{param}={payload}"
            try:
                log(f"Scanning: {test_url}", "SCAN")
                response = requests.get(test_url, verify=verify_ssl, timeout=10)
                waf_status = waf_detector.get_waf_status(test_url)
                
                if payload in response.text:
                    log(f"Reflected XSS found:", "FATAL")
                    print(f"URL: {test_url}")
                    print(f"Parameter: {param}")
                    print(f"Payload: {payload}")
                    print(f"WAF Status: {waf_status}")
                    print(f"HTTP Status: {response.status_code}")
                else:
                    print(f"URL: {test_url}")
                    print(f"Parameter: {param}")
                    print(f"Payload: {payload}")
                    print(f"WAF Status: {waf_status}")
                    print(f"HTTP Status: {response.status_code}")
            except Exception as e:
                log(f"Error scanning {test_url}: {str(e)}", "ERROR")

def read_payloads(file_path):
    if not file_path.endswith('.txt'):
        log("Wordlist must be a .txt file", "FATAL")
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log(f"Payload file not found: {file_path}", "ERROR")
        return []
    except Exception as e:
        log(f"Error reading payload file: {str(e)}", "ERROR")
        return []

def display_ascii_art():
    art = """
      .    *  .     *____________
      |\_|/__/|    /             \\
     / / \/ \  \  /   GriftSXX    \\
    /__|O||O|__ \ \    V.1.0      /
   |/_ \_/\_/ *\ | \  *__________/
   | | (____) | ||  |/
   \/\___/\__/  // _/
   (_/         ||  
    |          ||\\\  \033[93mGriftXSS is a powerful and comprehensive XSS scanner designed to identify \033[0m
    \          //_/ \033[0m\033[93mpotential cross-site scripting vulnerabilities in web applications.\033[0m
     \________//    \033[0m\033[93mFeatures include targeted scanning, brute-force payload testing, and crawling.\033[0m
      |*| __||         
     (____(____)        \033[0m\033[92mhttps://github.com/septiannuno | https://www.nunozildjian.my.id\033[0m
    """
    print(art)

def main():
    parser = argparse.ArgumentParser(description="GriftXSS - XSS Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan", required=True)
    parser.add_argument("--crawl", action="store_true", help="Crawl the entire website and perform a comprehensive scan")
    parser.add_argument("--payload", help="Custom payload for testing", default="<script>alert('GriftXSS')</script>")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    parser.add_argument("--brute-force", help="Path to file containing additional payloads for XSS attempts", type=str)
    
    args = parser.parse_args()
    url = args.url
    crawl_enabled = args.crawl
    payload = args.payload
    verify_ssl = args.verify_ssl

    display_ascii_art()

    log(f"GriftXSS Starting scan on {url}", "WARNING")

    # Initial WAF check
    initial_waf_status = waf_detector.get_waf_status(url)
    log(f"Initial WAF detection: {initial_waf_status}", "INFO")
    
    if args.brute_force:
        payloads = read_payloads(args.brute_force)
        if not payloads:
            payloads = [payload]
            log("No payloads loaded from file, using default payload", "WARNING")
        else:
            log(f"Loaded {len(payloads)} payloads from {args.brute_force}", "INFO")
        
        if crawl_enabled:
            crawled_data = crawl(url, verify_ssl)
            for page in crawled_data:
                perform_brute_force_scan(page['url'], payloads, verify_ssl)
        else:
            perform_brute_force_scan(url, payloads, verify_ssl)
    else:
        log(f"Using payload: {payload}", "PAYLOAD")
        try:
            if crawl_enabled:
                crawled_data = crawl(url, verify_ssl)
                for page in crawled_data:
                    perform_targeted_scan(page['url'], payload, verify_ssl)
            else:
                perform_targeted_scan(url, payload, verify_ssl)
        except KeyboardInterrupt:
            log("Program interrupted by user.", "INFO")
        except Exception as e:
            log(f"An unexpected error occurred: {str(e)}", "FATAL")
        finally:
            log("Scan completed.", "INFO")

if __name__ == "__main__":
    main()
