import requests
from colorama import Fore
from urllib.parse import urljoin

class MisconfigScanner:
    def __init__(self):
        self.sensitive_files = [
            ".env",
            ".git/HEAD",
            "robots.txt",
            "sitemap.xml",
            "backup.zip",
            ".vscode/settings.json",
            "config.php.bak",
            "DS_Store"
        ]
        self.security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Starting Security Misconfiguration Scan (A02:2025) on {target_url}...")
        findings = []

        # 1. Check Security Headers
        try:
            res = requests.get(target_url, timeout=10)
            headers = res.headers
            
            missing_headers = []
            for h in self.security_headers:
                if h not in headers:
                    missing_headers.append(h)
            
            if missing_headers:
                print(f"{Fore.YELLOW}[!] Missing Security Headers: {', '.join(missing_headers)}")
                findings.append({
                    "type": "Missing Headers",
                    "details": f"Missing: {', '.join(missing_headers)}",
                    "url": target_url
                })
                
            # Check for excessive information
            if "Server" in headers:
                print(f"{Fore.YELLOW}[!] Server Header Exposed: {headers['Server']}")
                findings.append({
                    "type": "Information Disclosure",
                    "details": f"Server header leaked: {headers['Server']}",
                    "url": target_url
                })

        except Exception as e:
            print(f"{Fore.RED}[!] Header check failed: {e}")

        # 2. Check for Sensitive Files
        for file in self.sensitive_files:
            file_url = urljoin(target_url, file)
            try:
                res = requests.get(file_url, timeout=5)
                if res.status_code == 200:
                    # Verify it's not a custom 404 page returning 200
                    if len(res.text) > 0 and "html" not in res.headers.get('content-type', '').lower():
                        # Simple heuristic: sensitive files usually aren't HTML (except maybe sitemap/robots reports)
                        # We also check if it looks like a soft 404
                        print(f"{Fore.RED}[!!!] Sensitive File Found: {file_url}")
                        findings.append({
                            "type": "Sensitive File Exposed",
                            "details": f"Accessible file: {file}",
                            "url": file_url
                        })
                    elif file in ["robots.txt", "sitemap.xml"] and res.status_code == 200:
                         print(f"{Fore.GREEN}[+] Found {file}")
                         findings.append({
                            "type": "Information Disclosure",
                            "details": f"Found {file}",
                            "url": file_url
                        })

            except Exception:
                pass

        return findings
