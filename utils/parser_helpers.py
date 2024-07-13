import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import html

def extract_urls(html_content: str, base_url: str) -> List[str]:
    """
    Extract all URLs from the given HTML content.
    
    Args:
        html_content (str): The HTML content to parse.
        base_url (str): The base URL to resolve relative URLs.
    
    Returns:
        List[str]: A list of absolute URLs found in the HTML content.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    urls = []

    for tag in soup.find_all(['a', 'script', 'link', 'img']):
        url = tag.get('href') or tag.get('src')
        if url:
            absolute_url = urljoin(base_url, url)
            urls.append(absolute_url)

    return list(set(urls))  # Remove duplicates

def sanitize_input(input_string: str) -> str:
    """
    Sanitize user input to prevent XSS attacks.
    
    Args:
        input_string (str): The input string to sanitize.
    
    Returns:
        str: The sanitized input string.
    """
    # HTML entity encode
    sanitized = html.escape(input_string)
    
    # Remove potentially dangerous attributes
    sanitized = re.sub(r'(on\w+)=', '', sanitized, flags=re.IGNORECASE)
    
    # Remove javascript: URLs
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    
    return sanitized

def find_injection_points(html_content: str) -> List[Dict[str, Any]]:
    """
    Find potential XSS injection points in the HTML content.
    
    Args:
        html_content (str): The HTML content to analyze.
    
    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing information about potential injection points.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    injection_points = []

    # Check input fields
    for input_tag in soup.find_all('input'):
        injection_points.append({
            'type': 'input',
            'name': input_tag.get('name'),
            'id': input_tag.get('id'),
            'value': input_tag.get('value')
        })

    # Check script tags
    for script_tag in soup.find_all('script'):
        injection_points.append({
            'type': 'script',
            'content': script_tag.string
        })

    # Check on* event handlers
    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.startswith('on'):
                injection_points.append({
                    'type': 'event_handler',
                    'tag': tag.name,
                    'attribute': attr,
                    'value': tag[attr]
                })

    return injection_points
