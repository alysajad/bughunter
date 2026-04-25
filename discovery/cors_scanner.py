import requests
from colorama import Fore


class CORSScanner:
    """CORS Misconfiguration Scanner (A01:2025 - Broken Access Control)."""
    
    def __init__(self):
        self.test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://evil.target.com",  # subdomain trust
        ]

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Checking for CORS misconfigurations on {target_url}...")
        findings = []

        try:
            # Test 1: Wildcard origin with credentials
            res = requests.get(target_url, timeout=10)
            acao = res.headers.get('Access-Control-Allow-Origin', '')
            acac = res.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                finding = {
                    "type": "CORS Wildcard Origin",
                    "details": f"Access-Control-Allow-Origin: * (any domain can read responses)",
                    "url": target_url, "payload": "Origin: *"
                }
                if acac.lower() == 'true':
                    finding["type"] = "CORS Wildcard with Credentials (Critical)"
                    finding["details"] += " + Access-Control-Allow-Credentials: true"
                    print(f"{Fore.RED}[!!!] Critical CORS: Wildcard + Credentials!")
                else:
                    print(f"{Fore.YELLOW}[!] CORS Wildcard origin detected.")
                findings.append(finding)

            # Test 2: Origin reflection
            for origin in self.test_origins:
                headers = {"Origin": origin}
                res = requests.get(target_url, headers=headers, timeout=5)
                reflected_origin = res.headers.get('Access-Control-Allow-Origin', '')
                allow_creds = res.headers.get('Access-Control-Allow-Credentials', '').lower()

                if reflected_origin == origin:
                    severity = "Critical" if allow_creds == 'true' else "Medium"
                    print(f"{Fore.RED}[!!!] CORS Origin Reflection: {origin} → reflected back!")
                    findings.append({
                        "type": f"CORS Origin Reflection ({severity})",
                        "details": f"Origin '{origin}' reflected in ACAO header. Credentials: {allow_creds}",
                        "url": target_url, "payload": f"Origin: {origin}"
                    })
                    break  # One reflection proof is enough

            # Test 3: Null origin
            res_null = requests.get(target_url, headers={"Origin": "null"}, timeout=5)
            if res_null.headers.get('Access-Control-Allow-Origin', '') == 'null':
                print(f"{Fore.RED}[!!!] CORS Null Origin Accepted!")
                findings.append({
                    "type": "CORS Null Origin Accepted",
                    "details": "Server accepts Origin: null (exploitable via sandboxed iframes)",
                    "url": target_url, "payload": "Origin: null"
                })

            # Test 4: Pre-flight bypass (OPTIONS)
            try:
                preflight_headers = {
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Header"
                }
                res_pre = requests.options(target_url, headers=preflight_headers, timeout=5)
                allowed_methods = res_pre.headers.get('Access-Control-Allow-Methods', '')
                if 'PUT' in allowed_methods or 'DELETE' in allowed_methods:
                    print(f"{Fore.YELLOW}[!] CORS allows dangerous methods: {allowed_methods}")
                    findings.append({
                        "type": "CORS Dangerous Methods Allowed",
                        "details": f"Pre-flight allows: {allowed_methods}",
                        "url": target_url, "payload": "OPTIONS pre-flight"
                    })
            except Exception:
                pass

        except Exception as e:
            print(f"{Fore.YELLOW}[!] CORS scan error: {e}")

        if not findings:
            print(f"{Fore.GREEN}[-] No CORS misconfigurations found.")
        return findings
