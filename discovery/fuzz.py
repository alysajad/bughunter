import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore

class Fuzzer:
    def __init__(self):
        self.payloads = [
            "'", "\"", "<!--", "%00", 
            "{{7*7}}", 
            "../../../../etc/passwd",
            "A" * 1000, # Buffer overflow attempt
            "NaN", "Infinity",
            "-1", "0", "99999999999"
        ]
        
        self.error_signatures = [
            "Internal Server Error",
            "SQLSyntaxErrorException",
            "Warning: mysql_",
            "Fatal error",
            "Uncaught exception",
            "IndexOutOfBoundsException",
            "django.db.utils",
            "Traceback (most recent call last)"
        ]

    def fuzz_params(self, url):
        """
        Fuzzes URL parameters to trigger errors.
        """
        print(f"{Fore.CYAN}[*] Starting Fuzzing on {url}")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print(f"{Fore.YELLOW}[-] No parameters found to fuzz in URL.")
            return []

        found_issues = []

        for param_name in params:
            for payload in self.payloads:
                # Construct URL
                test_query = params.copy()
                test_query[param_name] = [payload]
                
                new_query_string = urlencode(test_query, doseq=True)
                new_parts = list(parsed)
                new_parts[4] = new_query_string
                target_url = urlunparse(new_parts)
                
                try:
                    response = requests.get(target_url, timeout=10)
                    
                    # Check for 500s or Specific Error Messages
                    if response.status_code >= 500:
                         print(f"{Fore.RED}[!!!] Server Error ({response.status_code}) triggered by payload: {payload} in param: {param_name}")
                         found_issues.append({
                             "param": param_name,
                             "payload": payload,
                             "type": f"Server Error ({response.status_code})",
                             "url": target_url
                         })
                         break # Stop after breaking it once per param

                    for sig in self.error_signatures:
                        if sig in response.text:
                             print(f"{Fore.RED}[!!!] Error Leak detected ('{sig}') with payload: {payload}")
                             found_issues.append({
                                 "param": param_name,
                                 "payload": payload,
                                 "type": f"Information Leak ({sig})",
                                 "url": target_url
                             })
                             break

                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Request failed: {e}")

        if not found_issues:
            print(f"{Fore.GREEN}[-] No obvious errors triggered by fuzzing.")
            
        return found_issues
