import requests
from requests.exceptions import RequestException
import logging
from urllib.parse import urlparse
from typing import Dict, Any, Optional

def make_request(url: str, method: str = 'GET', headers: Optional[Dict[str, str]] = None, 
                 data: Optional[Dict[str, Any]] = None, timeout: int = 10, 
                 verify_ssl: bool = True, allow_redirects: bool = True) -> requests.Response:
    """
    Make an HTTP request to the specified URL.
    
    Args:
        url (str): The URL to send the request to.
        method (str): HTTP method (GET, POST, etc.). Defaults to 'GET'.
        headers (dict): Optional headers to include in the request.
        data (dict): Optional data to send in the request body.
        timeout (int): Request timeout in seconds. Defaults to 10.
        verify_ssl (bool): Whether to verify SSL certificates. Defaults to True.
        allow_redirects (bool): Whether to follow redirects. Defaults to True.
    
    Returns:
        requests.Response: The response object from the request.
    
    Raises:
        RequestException: If there's an error making the request.
    """
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=allow_redirects
        )
        response.raise_for_status()
        return response
    except RequestException as e:
        logging.error(f"Error making request to {url}: {str(e)}")
        raise

def parse_response(response: requests.Response) -> Dict[str, Any]:
    """
    Parse the response from an HTTP request.
    
    Args:
        response (requests.Response): The response object to parse.
    
    Returns:
        dict: A dictionary containing parsed information from the response.
    """
    parsed_url = urlparse(response.url)
    
    return {
        'status_code': response.status_code,
        'headers': dict(response.headers),
        'content': response.text,
        'url': response.url,
        'scheme': parsed_url.scheme,
        'netloc': parsed_url.netloc,
        'path': parsed_url.path,
        'params': parsed_url.params,
        'query': parsed_url.query,
        'fragment': parsed_url.fragment,
        'cookies': dict(response.cookies)
    }
