import requests
from colorama import Fore

class IDORTester:
    def __init__(self, headers_a, headers_b):
        """
        headers_a: Headers for Victim (User A)
        headers_b: Headers for Attacker (User B)
        """
        self.headers_a = headers_a
        self.headers_b = headers_b

    def test_access(self, url, target_id):
        """
        Tests if User B (Attacker) can access a resource belonging to User A (Victim).
        Assumption: 'url' contains the target_id which belongs to User A.
        """
        print(f"{Fore.CYAN}[*] Starting IDOR Check on {url}")
        
        # 1. Verify User A (Victim) can access their own resource
        try:
            resp_a = requests.get(url, headers=self.headers_a, timeout=10)
            if resp_a.status_code != 200:
                print(f"{Fore.YELLOW}[-] Victim (User A) cannot access the resource. Status: {resp_a.status_code}")
                return None
        except Exception as e:
            print(f"{Fore.RED}[!] Victim request failed: {e}")
            return None

        # 2. Attempt access as User B (Attacker)
        try:
            resp_b = requests.get(url, headers=self.headers_b, timeout=10)
            
            # Simple Heuristic: If Status is 200 and Content Length is similar to Victim's
            if resp_b.status_code == 200:
                # Check for "Access Denied" or soft 403s
                if "denied" in resp_b.text.lower() or "unauthorized" in resp_b.text.lower():
                     print(f"{Fore.GREEN}[-] Access Denied for Attacker (Safe).")
                     return []
                
                # Check similarity (simplified)
                # If content is exactly the same, it might be a public page. 
                # If it's different but 200, it might be an IDOR or just B's own profile.
                # Ideally we check if B sees A's data. 
                
                print(f"{Fore.RED}[!!!] IDOR Suspicion! Attacker accessed URL with Status 200.")
                return [{
                    "url": url,
                    "target_id": target_id,
                    "status": resp_b.status_code
                }]
            else:
                print(f"{Fore.GREEN}[-] Attacker blocked. Status: {resp_b.status_code}")
                return []
                
        except Exception as e:
             print(f"{Fore.YELLOW}[!] Attacker request failed: {e}")
             return []
