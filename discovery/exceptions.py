import requests
from colorama import Fore
import time

class ExceptionScanner:
    def __init__(self):
        self.error_signatures = [
            "Fatal error",
            "Uncaught exception",
            "java.lang.NullPointerException",
            "Traceback (most recent call last)",
            "SyntaxError",
            "Connection timed out" # If we cause a hang
        ]
        
        # Payloads designed to break logic, not just syntax
        self.logic_payloads = [
            "%00",              # Null Byte
            "A" * 5000,         # Buffer Overflow / Length
            "[]",               # Array Flooding (PHP/Rails)
            "{{7*7}}",          # SSTI (often causes crash if not handled)
            "true",             # Type Juggling (Boolean)
            "NaN"               # Type Juggling (Number)
        ]

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Starting Logic Exception Scan (A10:2025) on {target_url}...")
        findings = []

        # We need to find parameters to inject into. 
        # For this simple agent, we will append payloads to the URL query string 
        # or replace values if params exist.
        
        # Simple Logic: If URL has params (e.g. ?id=1), fuzz them.
        if "?" in target_url:
            base_url, query_string = target_url.split("?", 1)
            params = query_string.split("&")
            
            for i, param in enumerate(params):
                if "=" not in param: continue
                key, value = param.split("=", 1)
                
                for payload in self.logic_payloads:
                    # Construct crafted URL
                    # 1. Replace value
                    new_query = params.copy()
                    new_query[i] = f"{key}={payload}"
                    fuzzed_url = f"{base_url}?{'&'.join(new_query)}"
                    
                    try:
                        start_time = time.time()
                        res = requests.get(fuzzed_url, timeout=5)
                        duration = time.time() - start_time
                        
                        # Check 1: Server Error
                        if res.status_code >= 500:
                            print(f"{Fore.RED}[!!!] Server Error (500) triggered by {payload}")
                            findings.append({
                                "type": "Unhandled Exception (500)",
                                "details": f"Payload {payload} caused HTTP 500",
                                "url": fuzzed_url
                            })
                            continue
                            
                        # Check 2: Error Signatures in Body
                        for sig in self.error_signatures:
                            if sig.lower() in res.text.lower():
                                print(f"{Fore.RED}[!!!] Exception Trace Leaked by {payload}")
                                findings.append({
                                    "type": "Exception Trace Leak",
                                    "details": f"Found signature: {sig}",
                                    "url": fuzzed_url
                                })
                                break
                        
                        # Check 3: Timeout/Lag (DoS indicator)
                        # We use a short timeout above, so this is mostly catching slow logic
                        if duration > 4: 
                             print(f"{Fore.YELLOW}[!] Potential DoS/Lag triggered by {payload}")
                             findings.append({
                                "type": "Potential DoS (Latency)",
                                "details": f"Response took {duration:.2f}s",
                                "url": fuzzed_url
                            })

                    except requests.exceptions.Timeout:
                        print(f"{Fore.RED}[!!!] Timeout triggered by {payload} (Possible DoS)")
                        findings.append({
                            "type": "DoS / Timeout",
                            "details": f"Request timed out with payload {payload}",
                            "url": fuzzed_url
                        })
                    except Exception as e:
                        pass
        else:
             print(f"{Fore.YELLOW}[-] No parameters found in URL to fuzz for logic errors.")

        return findings
