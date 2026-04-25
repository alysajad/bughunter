import requests
from colorama import Fore


class HeaderInjectionScanner:
    """HTTP Header Injection / Host Header Attack Scanner (A02:2025 - Security Misconfiguration)."""

    def __init__(self):
        self.host_payloads = [
            "evil.com",
            "evil.com:80",
            "attacker.com",
            "localhost",
            "127.0.0.1",
        ]
        self.crlf_payloads = [
            "%0d%0aSet-Cookie:crlf_injection=true",
            "%0d%0a%0d%0a<script>alert('CRLF')</script>",
            "\r\nSet-Cookie:crlf_injection=true",
        ]

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Checking for HTTP Header Injection on {target_url}...")
        findings = []

        # Test 1: Host Header Injection (Password Reset Poisoning / Cache Poisoning)
        host_findings = self._test_host_injection(target_url)
        findings.extend(host_findings)

        # Test 2: X-Forwarded-For Bypass (IP spoofing)
        xff_findings = self._test_xff_bypass(target_url)
        findings.extend(xff_findings)

        # Test 3: CRLF Injection in parameters (if present)
        if "?" in target_url:
            crlf_findings = self._test_crlf_injection(target_url)
            findings.extend(crlf_findings)

        if not findings:
            print(f"{Fore.GREEN}[-] No Header Injection vulnerabilities found.")
        return findings

    def _test_host_injection(self, url):
        findings = []
        for payload in self.host_payloads:
            try:
                # 1. Modify Host header directly
                headers = {"Host": payload}
                res = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
                
                # Check if payload is reflected in location (redirect poisoning)
                location = res.headers.get('Location', '')
                if payload in location:
                    print(f"{Fore.RED}[!!!] Host Header Injection (Redirect) Found!")
                    findings.append({
                        "type": "Host Header Poisoning (Redirect)",
                        "cwe": "CWE-113",
                        "details": f"Injected Host '{payload}' reflected in Location header.",
                        "url": url,
                        "payload": f"Host: {payload}"
                    })
                    break

                # Check if payload is reflected in links within body (cache poisoning / password reset)
                if res.status_code == 200 and payload in res.text:
                    body = res.text.lower()
                    if f"href=\"http://{payload}" in body or f"href=\"https://{payload}" in body:
                        print(f"{Fore.RED}[!!!] Host Header Injection (Body Reflection) Found!")
                        findings.append({
                            "type": "Host Header Poisoning (Body Reflection)",
                            "cwe": "CWE-113",
                            "details": f"Injected Host '{payload}' reflected in absolute URLs within response body.",
                            "url": url,
                            "payload": f"Host: {payload}"
                        })
                        break

            except Exception:
                pass
        return findings

    def _test_xff_bypass(self, url):
        findings = []
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
        ]
        
        # We need a baseline to compare against
        try:
            baseline = requests.get(url, timeout=5)
        except Exception:
            return findings

        for headers in bypass_headers:
            try:
                res = requests.get(url, headers=headers, timeout=5)
                # If status code changes (e.g. 403 -> 200) or length changes significantly, might be a bypass
                if res.status_code != baseline.status_code:
                    if res.status_code == 200 and baseline.status_code in [401, 403]:
                        header_name = list(headers.keys())[0]
                        print(f"{Fore.RED}[!!!] Access Control Bypass via {header_name}!")
                        findings.append({
                            "type": f"Access Control Bypass ({header_name})",
                            "cwe": "CWE-290",
                            "details": f"Bypassed {baseline.status_code} restriction using {header_name}: {headers[header_name]}",
                            "url": url,
                            "payload": str(headers)
                        })
            except Exception:
                pass
        return findings

    def _test_crlf_injection(self, target_url):
        findings = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        for param_name in params:
            for payload in self.crlf_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                new_parts = list(parsed)
                new_parts[4] = new_query
                test_url = urlunparse(new_parts)
                
                try:
                    res = requests.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Check if our injected header was parsed as a real header by the server/proxy
                    if 'crlf_injection' in res.cookies or 'crlf_injection' in res.headers.get('Set-Cookie', ''):
                        print(f"{Fore.RED}[!!!] CRLF Injection Found in param '{param_name}'!")
                        findings.append({
                            "type": "CRLF Injection (HTTP Response Splitting)",
                            "cwe": "CWE-113",
                            "details": f"Parameter '{param_name}' vulnerable to CRLF. Injected Set-Cookie header was processed.",
                            "url": test_url,
                            "payload": payload
                        })
                        break
                except Exception:
                    pass
        return findings
