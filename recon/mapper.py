import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore

class EndpointMapper:
    def __init__(self, target_url, scope_domain):
        self.target_url = target_url
        self.scope_domain = scope_domain
        self.endpoints = set()
        self.forms = []

    def crawl(self):
        """
        Basic crawler to identify endpoints and forms.
        """
        print(f"{Fore.CYAN}[*] Starting crawl on {self.target_url}")
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(self.target_url, timeout=30, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find links
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(self.target_url, href)
                    if self.is_in_scope(full_url):
                        self.endpoints.add(full_url)
                        print(f"{Fore.GREEN}[+] Found endpoint: {full_url}")

            # Find forms
            for form in soup.find_all('form'):
                action = form.get('action')
                method = form.get('method', 'get').upper()
                full_action = urljoin(self.target_url, action)
                
                inputs = []
                for inp in form.find_all('input'):
                    input_name = inp.get('name')
                    input_type = inp.get('type', 'text')
                    if input_name:
                        inputs.append({'name': input_name, 'type': input_type})
                
                self.forms.append({
                    'action': full_action, 
                    'method': method,
                    'inputs': inputs
                })
                print(f"{Fore.GREEN}[+] Found form: {method} {full_action} with inputs: {[i['name'] for i in inputs]}")

        except Exception as e:
            print(f"{Fore.RED}[!] Crawl error: {e}")

    def is_in_scope(self, url):
        parsed = urlparse(url)
        return self.scope_domain in parsed.netloc
