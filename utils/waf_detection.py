import re
import requests
from requests.exceptions import RequestException

class WAFDetection:
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': [
                'Cloudflare Ray ID:',
                'CF-RAY',
                'cloudflare-nginx'
            ],
            'ModSecurity': [
                'Mod_Security',
                'NOYB'
            ],
            'Incapsula': [
                'X-Iinfo',
                'incap_ses',
                'visid_incap'
            ],
            'Akamai': [
                'AkamaiGHost',
                'X-Akamai-Transformed'
            ],
            'Sucuri': [
                'Sucuri/Cloudproxy',
                'X-Sucuri-ID'
            ],
            'F5 BIG-IP ASM': [
                'TS',
                'BigIP',
                'F5'
            ],
            'Imperva': [
                'X-Iinfo',
                '_imp_apg_r_'
            ],
            'Barracuda': [
                'barra_counter_session',
                'BNI__BARRACUDA_LB_COOKIE'
            ],
            'Citrix NetScaler': [
                'ns_af=',
                'citrix_ns_id',
                'NSC_'
            ],
            'AWS WAF': [
                'AWS_WAF',
                'X-AMZ-CF-ID'
            ]
        }

    def detect(self, response):
        detected_wafs = []
        headers = response.headers
        content = response.text

        for waf, signatures in self.waf_signatures.items():
            for signature in signatures:
                if signature in str(headers) or signature in content:
                    detected_wafs.append(waf)
                    break

        return list(set(detected_wafs))

    def test_waf_presence(self, url):
        try:
            malicious_payloads = [
                "' OR '1'='1",
                "<script>alert('XSS')</script>",
                "../../../../../etc/passwd",
                "1 UNION SELECT null, null, null--",
                "' HAVING 1=1--",
                "<?php echo 'vulnerable'; ?>",
                "; DROP TABLE users--",
                "{{7*7}}",
                "${7*7}",
                "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'--"
            ]

            detected_wafs = set()

            for payload in malicious_payloads:
                test_url = f"{url}?test={payload}"
                response = requests.get(test_url, allow_redirects=False, timeout=10, verify=False)
                
                if response.status_code in [403, 406, 429, 501]:
                    waf_results = self.detect(response)
                    detected_wafs.update(waf_results)

                if len(detected_wafs) > 0:
                    break

            return list(detected_wafs)

        except RequestException as e:
            print(f"Error testing WAF presence: {str(e)}")
            return []

    def get_waf_status(self, url):
        detected_wafs = self.test_waf_presence(url)
        if detected_wafs:
            return f"WAF detected: {', '.join(detected_wafs)}"
        return "No WAF detected"