import requests
from colorama import Fore

class DefaultCredScanner:
    def __init__(self):
        self.creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "toor"),
            ("user", "user"),
            ("guest", "guest"),
            ("test", "test")
        ]

    def scan(self, login_form_url, username_field="username", password_field="password"):
        """
        Tries default credentials on a specific login form.
        """
        print(f"{Fore.CYAN}[*] Checking Default Credentials (A07:2025) on {login_form_url}...")
        findings = []

        for user, pwd in self.creds:
            data = {
                username_field: user,
                password_field: pwd
            }
            try:
                # Assuming Form Data for defaults
                res = requests.post(login_form_url, data=data, timeout=5)
                
                # Use same heuristic as SQLi for success
                if self.is_successful_login(res):
                     print(f"{Fore.RED}[!!!] Default Credentials Found: {user}/{pwd}")
                     findings.append({
                        "type": "Default Credentials",
                        "details": f"Login successful with {user}:{pwd}",
                        "url": login_form_url
                    })
                     break # Stop after one success per form to avoid noise
            except Exception:
                pass
        
        return findings

    def is_successful_login(self, response):
        """
        Reuse simple heuristic.
        """
        if response.status_code != 200: return False
        
        content = response.text.lower()
        fail_terms = ["invalid", "failed", "incorrect", "denied", "try again"]
        
        for term in fail_terms:
            if term in content:
                return False
                
        # Positive indicators
        success_terms = ["welcome", "dashboard", "logout", "my account", "token"]
        if any(term in content for term in success_terms):
            return True
            
        return False
