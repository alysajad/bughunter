import requests
import socket
from colorama import Fore
import json

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.found_subdomains = set()

    def scan(self):
        print(f"{Fore.CYAN}[*] Starting Subdomain Enumeration on {self.domain} (via crt.sh)...")
        
        try:
            # query crt.sh
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            res = requests.get(url, timeout=25)
            
            if res.status_code == 200:
                data = res.json()
                for entry in data:
                    name_value = entry['name_value']
                    # crt.sh can return multi-line strings or wildcards
                    subdomains = name_value.split('\n')
                    for sub in subdomains:
                        if "*" not in sub and self.domain in sub:
                            self.found_subdomains.add(sub.strip())
            
            print(f"{Fore.GREEN}[+] Found {len(self.found_subdomains)} unique entries in CT logs.")
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] crt.sh query failed: {e}")

        # Validation Step (DNS Resolution)
        alive_subdomains = []
        print(f"{Fore.CYAN}[*] Verifying active subdomains...")
        
        for sub in self.found_subdomains:
            try:
                # Basic A record check
                host = socket.gethostbyname(sub)
                alive_subdomains.append(sub)
                print(f"    {Fore.GREEN}-> {sub} ({host})")
            except socket.gaierror:
                pass
                
        return alive_subdomains
