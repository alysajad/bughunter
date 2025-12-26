import requests
from colorama import Fore

class AccessControlScanner:
    def __init__(self):
        self.sensitive_paths = [
            "/admin", "/admin/dashboard", "/dashboard", 
            "/settings", "/config", "/users", "/backup", 
            "/private", "/db", "/server-status"
        ]
        self.traversal_payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]

    def scan_bypass(self, base_url):
        """
        Checks if sensitive paths are accessible without authentication.
        """
        print(f"{Fore.CYAN}[*] Checking for Unauthenticated Access (A01:2025) on {base_url}...")
        findings = []
        
        # Normalize URL
        if base_url.endswith("/"): base_url = base_url[:-1]

        for path in self.sensitive_paths:
            full_url = base_url + path
            try:
                # Request WITHOUT cookies
                res = requests.get(full_url, timeout=5, allow_redirects=False)
                
                # Heuristic: 200 OK and NO redirect to login
                if res.status_code == 200:
                    # Filter out False Positives (e.g. "Login Page", "Access Denied" text)
                    if not self.is_login_or_error(res.text):
                         print(f"{Fore.RED}[!!!] Unauthenticated Access: {full_url}")
                         findings.append({
                            "type": "Unauthenticated Access",
                            "details": f"Accessible without credentials (HTTP 200).",
                            "url": full_url
                        })
            except:
                pass
        return findings

    def scan_traversal(self, target_url):
        """
        Checks for Path Traversal on URL parameters.
        """
        if "=" not in target_url: return []
        
        print(f"{Fore.CYAN}[*] Checking for Path Traversal (A01:2025) on {target_url}...")
        findings = []
        
        # Simple parameter replacement
        try:
            base, params = target_url.split('?', 1)
            pairs = params.split('&')
            
            for i, pair in enumerate(pairs):
                if '=' in pair:
                    key, val = pair.split('=', 1)
                    for payload in self.traversal_payloads:
                        # Construct test URL
                        # Replace THIS parameter with payload
                        new_pairs = pairs[:]
                        new_pairs[i] = f"{key}={payload}"
                        test_url = f"{base}?{'&'.join(new_pairs)}"
                        
                        try:
                            res = requests.get(test_url, timeout=5)
                            if self.is_traversal_success(res.text):
                                print(f"{Fore.RED}[!!!] Path Traversal Found: {test_url}")
                                findings.append({
                                    "type": "Path Traversal",
                                    "details": f"Payload '{payload}' revealed system file content.",
                                    "url": test_url
                                })
                                break # Stop fuzzing this param if found
                        except:
                            pass
        except:
            pass
            
        return findings

    def is_login_or_error(self, content):
        content = content.lower()
        checks = ["login", "sign in", "password", "unauthorized", "access denied", "forbidden", "404", "not found"]
        # If it's very short, likely an error
        if len(content) < 50: return True
        return any(c in content for c in checks)

    def is_traversal_success(self, content):
        # Check for *nix /etc/passwd signatures
        if "root:x:0:0:" in content: return True
        # Check for Windows INI signatures
        if "[extensions]" in content or "[fonts]" in content or "for 16-bit app support" in content: return True
        return False
