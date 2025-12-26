import requests
import re
from colorama import Fore

class GeneralScanner:
    def __init__(self):
        self.sensitive_files = [
            "robots.txt", "security.txt", ".well-known/security.txt", 
            "sitemap.xml", "clientaccesspolicy.xml", "crossdomain.xml"
        ]
        
        # Regex for PII / Sensitive Data
        self.regex_email = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        # Basic Credit Card (Luhn not checked here for speed, just pattern)
        self.regex_cc = r'\b(?:\d[ -]*?){13,16}\b'
        
    def scan(self, url):
        """
        Performs general compliance/best-practice checks.
        """
        print(f"{Fore.CYAN}[*] Running General Compliance Scan on {url}...")
        findings = []
        
        try:
            # 1. HTTP Methods Check (OPTIONS)
            try:
                res_opt = requests.options(url, timeout=5)
                if 'Allow' in res_opt.headers:
                    methods = res_opt.headers['Allow']
                    findings.append({
                        "type": "HTTP Attributes",
                        "details": f"Enabled HTTP Methods: {methods}",
                        "severity": "Info"
                    })
                    if "TRACE" in methods or "TRACK" in methods:
                        findings.append({
                            "type": "Unsafe HTTP Method",
                            "details": "Debug method TRACE/TRACK is enabled (Cross-Site Tracing risk).",
                            "severity": "Low"
                        })
            except:
                pass

            # 2. Main Page Analysis (Headers & Content)
            res = requests.get(url, timeout=10)
            
            # Rate Limit Header
            if "X-RateLimit-Limit" not in res.headers and "Retry-After" not in res.headers:
                 findings.append({
                     "type": "Missing Header",
                     "details": "Missing Rate-Limiting headers (X-RateLimit-Limit / Retry-After).",
                     "severity": "Low"
                 })
                 
            # Tech Stack (Server Header/Powered-By)
            tech = []
            if "Server" in res.headers: tech.append(res.headers["Server"])
            if "X-Powered-By" in res.headers: tech.append(res.headers["X-Powered-By"])
            if tech:
                findings.append({
                    "type": "Fingerprinting",
                    "details": f"Technology identified: {', '.join(tech)}",
                    "severity": "Info"
                })

            # PII / Sensitive Data in Response
            if re.search(self.regex_email, res.text):
                findings.append({
                    "type": "Sensitive Data",
                    "details": "Email addresses found in response body.",
                    "severity": "Info"
                })
            
            # Comments
            if "<!--" in res.text:
                 # Check for suspicious comments
                 if "TODO" in res.text or "FIXME" in res.text or "admin" in res.text.lower():
                     findings.append({
                         "type": "Information Leakage",
                         "details": "Suspicious HTML comments found (TODO/FIXME/admin).",
                         "severity": "Low"
                     })
            
            # Password field in plain HTTP (Mixed Content risk) -- checking URL scheme
            if url.startswith("http://"):
                if "password" in res.text.lower() and "<form" in res.text.lower():
                     findings.append({
                         "type": "Cleartext Submission",
                         "details": "Password field detected on unencrypted HTTP page.",
                         "severity": "High"
                     })

            # 3. File Checks
            # We look for files at the root relative to the given URL (or domain root)
            from urllib.parse import urlparse, urljoin
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}/"
            
            for f in self.sensitive_files:
                target_f = urljoin(base_url, f)
                try:
                    res_f = requests.get(target_f, timeout=3)
                    if res_f.status_code == 200:
                        findings.append({
                            "type": "Discovered File",
                            "details": f"Found accessible file: {f}",
                            "severity": "Info"
                        })
                        
                        # Specific Check: Robots.txt
                        if f == "robots.txt" and "Disallow: /admin" in res_f.text:
                             findings.append({
                                 "type": "Information Leakage",
                                 "details": "robots.txt reveals sensitive '/admin' path.",
                                 "severity": "Low"
                             })
                             
                except:
                    pass

        except Exception as e:
            # print(e)
            pass
            
        return findings
