import requests
import base64
import urllib.parse
from colorama import Fore


class DeserializationScanner:
    """Insecure Deserialization Scanner (A08:2025 - Integrity Failures)."""

    def __init__(self):
        # Known signatures for serialized objects in various languages
        self.signatures = {
            "Java": {
                "hex": "ac ed 00 05",
                "base64": "rO0AB",
                "cwe": "CWE-502"
            },
            "PHP": {
                "regex": r'O:\d+:"[^"]+":\d+:',
                "string": "O:", # Simplistic check
                "cwe": "CWE-502"
            },
            "Python_Pickle": {
                "base64": "gASV", # Common start for pickle protocol 4/5
                "cwe": "CWE-502"
            },
            ".NET_ViewState": {
                "base64": "/wEP", # Common start for MAC-less ViewState
                "cwe": "CWE-502"
            },
            "Node_Serialize": {
                "string": "_$$ND_FUNC$$_:", # Used by popular node-serialize npm package
                "cwe": "CWE-502"
            }
        }

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Checking for Insecure Deserialization patterns on {target_url}...")
        findings = []

        try:
            res = requests.get(target_url, timeout=10)
            
            # Check 1: Cookies
            cookie_findings = self._analyze_dict_for_serialization(res.cookies.get_dict(), "Cookie")
            findings.extend(cookie_findings)

            # Check 2: URL Parameters
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)
            # Flatten lists to strings for analysis
            flat_params = {k: v[0] for k, v in params.items()}
            param_findings = self._analyze_dict_for_serialization(flat_params, "URL Parameter")
            findings.extend(param_findings)

            # Check 3: Response Headers (sometimes contain state)
            header_findings = self._analyze_dict_for_serialization(res.headers, "Response Header")
            findings.extend(header_findings)

            # Check 4: Response Body (Hidden inputs, JS vars)
            body_findings = self._analyze_body_for_serialization(res.text)
            findings.extend(body_findings)

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Deserialization scan error: {e}")

        if not findings:
            print(f"{Fore.GREEN}[-] No serialized objects detected.")
        else:
            print(f"{Fore.YELLOW}[!] Found serialized data. This requires manual verification to confirm exploitability.")

        return findings

    def _analyze_dict_for_serialization(self, data_dict, source_type):
        findings = []
        for key, value in data_dict.items():
            if not isinstance(value, str):
                continue

            # Check raw string first
            finding = self._check_signatures(value, source_type, key)
            if finding:
                findings.append(finding)
                continue

            # Check URL decoded
            unquoted = urllib.parse.unquote(value)
            if unquoted != value:
                finding = self._check_signatures(unquoted, source_type, key)
                if finding:
                    findings.append(finding)
                    continue

            # Check Base64 decoded (very common for serialization)
            try:
                # Add padding if needed
                padded = value + '=' * (4 - len(value) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                finding = self._check_signatures(decoded, source_type, key, is_base64=True)
                if finding:
                    findings.append(finding)
            except Exception:
                pass

        return findings

    def _analyze_body_for_serialization(self, body):
        findings = []
        # Specifically look for hidden inputs
        import re
        hidden_inputs = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']', body, re.IGNORECASE)
        
        for i, val in enumerate(hidden_inputs):
            # Check raw
            finding = self._check_signatures(val, "Hidden HTML Input", f"input_{i}")
            if finding:
                findings.append(finding)
                continue
                
            # Check Base64
            try:
                padded = val + '=' * (4 - len(val) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                finding = self._check_signatures(decoded, "Hidden HTML Input (Base64)", f"input_{i}", is_base64=True)
                if finding:
                    findings.append(finding)
            except Exception:
                pass
                
        return findings

    def _check_signatures(self, data, source_type, key_name, is_base64=False):
        for lang, sigs in self.signatures.items():
            
            # String signature check
            if "string" in sigs and data.startswith(sigs["string"]):
                return self._create_finding(lang, source_type, key_name, data, sigs["cwe"], is_base64)
                
            # Base64 specific signature check (if the original data was base64)
            if is_base64 and "base64" in sigs:
                # We need to check the ORIGINAL base64 string, not the decoded data for this signature
                # Since we pass 'data' which is decoded, we can't do this easily here.
                # However, if it decoded successfully, we can check if the base64 prefix matches
                # This requires restructuring slightly, but we'll do a simple check on the decoded data
                pass 
            
            # Java Magic Bytes check
            if lang == "Java" and len(data) >= 4:
                # \xac\xed\x00\x05
                if data[0:4] == "\xac\xed\x00\x05":
                    return self._create_finding(lang, source_type, key_name, data, sigs["cwe"], is_base64)
                    
            # PHP Regex check
            if lang == "PHP" and "regex" in sigs:
                import re
                if re.search(sigs["regex"], data):
                    return self._create_finding(lang, source_type, key_name, data, sigs["cwe"], is_base64)
                    
            # Node specific
            if lang == "Node_Serialize" and "_$$ND_FUNC$$" in data:
                return self._create_finding(lang, source_type, key_name, data, sigs["cwe"], is_base64)

        return None

    def _create_finding(self, lang, source, key, data, cwe, is_b64):
        print(f"{Fore.RED}[!!!] Potentially Insecure {lang} Serialization Detected in {source} '{key}'!")
        b64_note = " (Base64 Encoded)" if is_b64 else ""
        return {
            "type": f"Insecure Deserialization ({lang})",
            "cwe": cwe,
            "details": f"Detected {lang} serialized object in {source} '{key}'{b64_note}. This endpoint may be vulnerable to RCE if it deserializes untrusted data.",
            "url": f"Source: {source} [{key}]",
            "payload": data[:100] + ("..." if len(data) > 100 else "")
        }
