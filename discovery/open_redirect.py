import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore


class OpenRedirectScanner:
    """Open Redirect Scanner (A01:2025 - Broken Access Control)."""
    
    def __init__(self):
        self.redirect_params = [
            "url", "redirect", "next", "return", "goto", "dest",
            "destination", "continue", "redir", "target", "out",
            "return_to", "returnUrl", "redirect_uri", "callback",
            "forward", "link", "to", "ref", "site", "view",
        ]
        self.payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "\\/\\/evil.com",
            "https:evil.com",
            "/\\evil.com",
            "////evil.com",
            "%2F%2Fevil.com",
            "%2f%2fevil.com",
            "https://evil.com%00.target.com",
            "https://evil.com%23.target.com",
            "javascript:alert(1)",
            "data:text/html,<h1>redirect</h1>",
            "https://evil.com?target.com",
            "https://evil.com#target.com",
            "https://target.com@evil.com",
        ]
        self.canary_domain = "evil.com"

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Checking for Open Redirects on {target_url}...")
        findings = []

        parsed = urlparse(target_url)
        existing_params = parse_qs(parsed.query)

        # Strategy 1: Test existing redirect-like parameters
        for param_name in existing_params:
            if any(rp in param_name.lower() for rp in self.redirect_params):
                results = self._test_param(target_url, param_name, parsed)
                findings.extend(results)

        # Strategy 2: Inject common redirect params even if not present
        for param_name in self.redirect_params[:10]:  # Top 10 most common
            if param_name not in existing_params:
                results = self._test_injected_param(target_url, param_name)
                findings.extend(results)
                if findings:
                    break  # Found enough evidence

        if not findings:
            print(f"{Fore.GREEN}[-] No Open Redirect found.")
        return findings

    def _test_param(self, target_url, param_name, parsed):
        """Test an existing parameter for open redirect."""
        findings = []
        params = parse_qs(parsed.query)

        for payload in self.payloads:
            test_params = params.copy()
            test_params[param_name] = [payload]
            new_query = urlencode(test_params, doseq=True)
            new_parts = list(parsed)
            new_parts[4] = new_query
            test_url = urlunparse(new_parts)

            if self._check_redirect(test_url, payload):
                print(f"{Fore.RED}[!!!] Open Redirect in param '{param_name}'!")
                findings.append({
                    "type": "Open Redirect",
                    "details": f"Parameter '{param_name}' redirects to external domain",
                    "url": test_url,
                    "payload": payload
                })
                break  # One proof per param
        return findings

    def _test_injected_param(self, target_url, param_name):
        """Test by injecting a redirect parameter."""
        findings = []
        separator = "&" if "?" in target_url else "?"

        for payload in self.payloads[:5]:  # Fewer payloads for injection
            test_url = f"{target_url}{separator}{param_name}={payload}"
            if self._check_redirect(test_url, payload):
                print(f"{Fore.RED}[!!!] Open Redirect via injected param '{param_name}'!")
                findings.append({
                    "type": "Open Redirect (Injected Parameter)",
                    "details": f"Injected '{param_name}' parameter causes redirect to external domain",
                    "url": test_url,
                    "payload": payload
                })
                break
        return findings

    def _check_redirect(self, url, payload):
        """Check if URL causes a redirect to our canary domain."""
        try:
            res = requests.get(url, timeout=5, allow_redirects=False)

            # Check 3xx redirect
            if res.status_code in [301, 302, 303, 307, 308]:
                location = res.headers.get('Location', '')
                if self.canary_domain in location:
                    return True
                # Check for protocol-relative redirect
                if location.startswith('//') and self.canary_domain in location:
                    return True

            # Check meta refresh redirect in body
            if res.status_code == 200 and self.canary_domain in res.text:
                body = res.text.lower()
                if 'meta' in body and 'refresh' in body and self.canary_domain in body:
                    return True

            # Check JavaScript-based redirect
            if f"window.location" in res.text and self.canary_domain in res.text:
                return True

        except Exception:
            pass
        return False
