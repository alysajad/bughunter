import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore

class XSSTester:
    def __init__(self):
        self.payloads = [
            "<script>alert(1)</script>",
            "\"<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            "javascript:alert(1)"
        ]

    def test_reflected(self, url):
        """
        Tests URL parameters for reflected XSS.
        """
        print(f"{Fore.CYAN}[*] Starting Reflected XSS Check on {url}")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print(f"{Fore.YELLOW}[-] No parameters found to test in URL.")
            return []

        found_vulns = []

        for param_name in params:
            for payload in self.payloads:
                # Construct URL with payload
                # Note: This overrides other params for simplicity. Ideally we should preserve them.
                # A robust scanner would iterate through each param while keeping others constant.
                
                # New query details
                test_query = params.copy()
                test_query[param_name] = [payload]
                
                new_query_string = urlencode(test_query, doseq=True)
                new_parts = list(parsed)
                new_parts[4] = new_query_string
                target_url = urlunparse(new_parts)
                
                try:
                    response = requests.get(target_url, timeout=10)
                    
                    if payload in response.text:
                        print(f"{Fore.RED}[!!!] Reflected XSS FOUND in param '{param_name}'")
                        found_vulns.append({
                            "param": param_name,
                            "payload": payload,
                            "url": target_url
                        })
                        # Break after finding one working payload for this param to avoid noise
                        break 
                        
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Request failed: {e}")

        if not found_vulns:
            print(f"{Fore.GREEN}[-] No Reflected XSS found in URL parameters.")
            
        return found_vulns
