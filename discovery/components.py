import requests
from bs4 import BeautifulSoup
from colorama import Fore
import re

class ComponentScanner:
    def __init__(self):
        self.signatures = {
            "jquery": r"jquery[/-]([\d\.]+)\.min\.js",
            "bootstrap": r"bootstrap[/-]([\d\.]+)\.min\.css",
            "angular": r"angular[/-]([\d\.]+)\.min\.js",
            "react": r"react[/-]([\d\.]+)\.min\.js",
            "vue": r"vue[/-]([\d\.]+)\.min\.js"
        }

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Starting Component Analysis (A03:2025) on {target_url}...")
        findings = []

        try:
            res = requests.get(target_url, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # 1. Analyze Script/Link tags for versions
            scripts = [s.get('src') for s in soup.find_all('script') if s.get('src')]
            links = [l.get('href') for l in soup.find_all('link') if l.get('href')]
            
            all_resources = scripts + links
            
            for resource in all_resources:
                for lib, pattern in self.signatures.items():
                    match = re.search(pattern, resource, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        print(f"{Fore.YELLOW}[!] Found {lib} version {version}")
                        findings.append({
                            "type": "Outdated Component",
                            "details": f"Detected {lib} version {version} in {resource}",
                            "url": target_url
                        })

            # 2. Check Headers for Server versions
            server = res.headers.get('Server')
            powered_by = res.headers.get('X-Powered-By')
            
            if server:
                # Look for numbers in Server header
                if re.search(r"\d", server):
                    print(f"{Fore.YELLOW}[!] Server Version Disclosed: {server}")
                    findings.append({
                        "type": "Version Disclosure",
                        "details": f"Server header: {server}",
                        "url": target_url
                    })
            
            if powered_by:
                 print(f"{Fore.YELLOW}[!] X-Powered-By Disclosed: {powered_by}")
                 findings.append({
                    "type": "Version Disclosure",
                    "details": f"X-Powered-By header: {powered_by}",
                    "url": target_url
                })

        except Exception as e:
            print(f"{Fore.RED}[!] Component scan error: {e}")

        return findings
