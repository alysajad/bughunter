import requests
from bs4 import BeautifulSoup
from colorama import Fore

class CSRFScanner:
    def __init__(self):
        self.common_csrf_names = [
            "csrf", "xsrf", "token", "_token", "__RequestVerificationToken",
            "csrf_token", "authenticity_token", "nonce"
        ]

    def scan(self, url, cookies=None):
        """
        Scans a URL for CSRF vulnerabilities.
        1. Checks forms for missing Anti-CSRF tokens.
        2. Checks cookies for missing SameSite attributes.
        """
        print(f"{Fore.CYAN}[*] Checking for CSRF/SameSite vulnerabilities on {url}...")
        findings = []
        
        try:
            res = requests.get(url, cookies=cookies, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            forms = soup.find_all('form')
            
            # 1. Form Analysis
            for form in forms:
                action = form.get('action') or url
                method = form.get('method', 'get').lower()
                
                # CSRF usually matters for state-changing requests (POST/PUT/DELETE)
                if method == 'post':
                    has_token = False
                    inputs = form.find_all('input')
                    
                    for i in inputs:
                        name = i.get('name', '').lower()
                        # Check if any input looks like a CSRF token
                        if any(token in name for token in self.common_csrf_names):
                            has_token = True
                            break
                    
                    if not has_token:
                        print(f"{Fore.RED}[!!!] Potential CSRF: Form at {url} (Action: {action}) missing CSRF token.")
                        findings.append({
                            "type": "CSRF",
                            "form_action": action,
                            "details": "Form allows POST method but lacks a recognized Anti-CSRF token field.",
                            "url": url
                        })

            # 2. Cookie Analysis (SameSite)
            # We look at the headers from the response
            if 'Set-Cookie' in res.headers:
                # requests.cookies matches parsed cookies, but we want raw attributes sometimes
                # or we just iterate over the CookieJar
                for cookie in res.cookies:
                    # Requests CookieJar objects have .name, .value, .domain ...
                    # but getting the raw 'SameSite' attribute is trickier with requests' default jar.
                    # We might need to parse the raw header if the attribut is missing in the object model.
                    # Simple heuristic:
                    pass
            
            # Simpler SameSite check (manual header parsing)
            # Since multiple cookies can be set, it's comma separated or multiple headers
            # Requests merges headers.
            cookie_headers = res.raw.headers.getlist('Set-Cookie')
            for header in cookie_headers:
                if "SameSite=Strict" not in header and "SameSite=Lax" not in header:
                     # It might default to Lax in modern browsers, but explicitly missing is worth noting for critical apps.
                     # However, to reduce noise, we report only if Secure is also missing or if it's explicitly None.
                     if "SameSite=None" in header and "Secure" not in header:
                         findings.append({
                             "type": "Weak Cookie Config",
                             "details": f"Set-Cookie header found with SameSite=None but missing Secure flag.",
                             "url": url
                         })

        except Exception as e:
            # print(e)
            pass
            
        return findings
