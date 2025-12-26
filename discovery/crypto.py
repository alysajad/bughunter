import requests
import ssl
import socket
from urllib.parse import urlparse
from colorama import Fore
import datetime

class CryptoScanner:
    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Starting Cryptographic Failure Scan (A04:2025) on {target_url}...")
        findings = []
        
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0]
        
        # 1. Check HTTPS (Basic)
        if parsed.scheme == "http":
             print(f"{Fore.YELLOW}[!] Use of HTTP detected (Unencrypted)")
             findings.append({
                "type": "Cleartext HTTP",
                "details": "Target is using unencrypted HTTP protocol.",
                "url": target_url
            })
        
        # 2. Check Certificate (if HTTPS or available)
        try:
            # Connect to 443 regardless of target URL scheme to check if SSL is available
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    # Check Expiry
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.datetime.now():
                         print(f"{Fore.RED}[!] SSL Certificate Expired: {not_after}")
                         findings.append({
                            "type": "Expired SSL Certificate",
                            "details": f"Certificate expired on {not_after}",
                            "url": f"https://{domain}"
                        })
                    else:
                         print(f"{Fore.GREEN}[+] SSL Certificate Valid until {not_after}")
                         
        except Exception as e:
            if parsed.scheme == "https":
                print(f"{Fore.RED}[!] SSL Connection Failed: {e}")
                findings.append({
                    "type": "SSL Handshake Failed",
                    "details": str(e),
                    "url": f"https://{domain}"
                })
        
        # 3. Check Cookie Flags
        try:
            res = requests.get(target_url, timeout=10)
            for cookie in res.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Missing Secure Flag")
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.get_nonstandard_attr('HttpOnly', None):
                    # Requests cookie parsing for httponly matches strictly, usually simplistic check is better
                    # Actually Requests stores it in ._rest but standard dict might not show it easily.
                    # We'll use a safer heuristic or rely on header parsing if needed. 
                    # For now, check if we can infer. Requests 'Cookie' object has boolean methods? No.
                    pass 

                # Parsing Set-Cookie header manually is more reliable
            
            set_cookie = res.headers.get('Set-Cookie')
            if set_cookie:
                if "Secure" not in set_cookie and parsed.scheme == "https":
                     print(f"{Fore.YELLOW}[!] Cookie missing Secure flag")
                     findings.append({
                        "type": "Insecure Cookie Configuration",
                        "details": "Cookie missing 'Secure' flag over HTTPS",
                        "url": target_url
                    })
                if "HttpOnly" not in set_cookie:
                     print(f"{Fore.YELLOW}[!] Cookie missing HttpOnly flag")
                     findings.append({
                        "type": "Insecure Cookie Configuration",
                        "details": "Cookie missing 'HttpOnly' flag",
                        "url": target_url
                    })

        except Exception:
            pass
            
        return findings
