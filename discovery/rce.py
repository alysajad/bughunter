import requests
import time
from colorama import Fore

class RCEAgent:
    def __init__(self):
        # Command Injection Payloads
        # We use a mix of echo-based (content check) and time-based (blind)
        self.cmd_payloads = [
            # Check for valid command execution signatures
            {"payload": "; echo RCE_TEST_SUCCESS", "check": "RCE_TEST_SUCCESS", "type": "Command Injection (Echo)"},
            {"payload": "| echo RCE_TEST_SUCCESS", "check": "RCE_TEST_SUCCESS", "type": "Command Injection (Echo)"},
            {"payload": "&& echo RCE_TEST_SUCCESS", "check": "RCE_TEST_SUCCESS", "type": "Command Injection (Echo)"},
            # Linux specific
            {"payload": "; id", "check": "uid=", "type": "Command Injection (id)"},
            {"payload": "| id", "check": "uid=", "type": "Command Injection (id)"},
            # Windows specific
            {"payload": "& whoami", "check": "\\", "type": "Command Injection (whoami)"}, # simplistic check for domain\user
        ]
        
        self.ssti_payloads = [
            {"payload": "{{7*7}}", "check": "49", "type": "SSTI (Code Injection)"},
            {"payload": "${7*7}", "check": "49", "type": "SSTI (Code Injection)"},
            {"payload": "<%= 7*7 %>", "check": "49", "type": "SSTI (Code Injection)"},
            {"payload": "#{7*7}", "check": "49", "type": "SSTI (Code Injection)"},
        ]
        
        self.code_payloads = [
            # PHP Code Injection
            {"payload": "; phpinfo();", "check": "PHP Version", "type": "Code Injection (PHP)"},
            {"payload": "'; phpinfo(); //", "check": "PHP Version", "type": "Code Injection (PHP)"},
            {"payload": "\"; phpinfo(); //", "check": "PHP Version", "type": "Code Injection (PHP)"},
            # Python Code Injection (context dependent, tricky to blind check without OOB)
            # We look for simple math eval which is similar to SSTI but might work in exec()
            {"payload": "__import__('os').popen('echo CODE_INJ_TEST').read()", "check": "CODE_INJ_TEST", "type": "Code Injection (Python)"}
        ]

    def scan(self, target_url):
        """
        Scans URL parameters for RCE.
        Args:
            target_url: The URL to scan (must have parameters).
        Returns:
            List of findings.
        """
        if "=" not in target_url: return []
        
        print(f"{Fore.CYAN}[*] Checking for RCE (Cmd Injection / SSTI) on {target_url}...")
        findings = []
        
        try:
            base, params = target_url.split('?', 1)
            pairs = params.split('&')
            
            # Combine all payloads
            all_tests = self.cmd_payloads + self.ssti_payloads + self.code_payloads
            
            for i, pair in enumerate(pairs):
                if '=' in pair:
                    key, val = pair.split('=', 1)
                    
                    for test in all_tests:
                        # Construct test URL
                        new_pairs = pairs[:]
                        # Injection often needs to be appended or replace.
                        # We try appending first as it's common (e.g. id=1;ls)
                        
                        # Strategy 1: Append
                        injected_val = f"{val}{test['payload']}"
                        new_pairs[i] = f"{key}={injected_val}"
                        test_url = f"{base}?{'&'.join(new_pairs)}"
                        
                        if self._run_check(test_url, test):
                            findings.append(self._create_finding(test_url, key, test))
                            continue # Found one for this payload, move to next

                        # Strategy 2: Replace (if append failed)
                        injected_val = test['payload']
                        new_pairs[i] = f"{key}={injected_val}"
                        test_url = f"{base}?{'&'.join(new_pairs)}"
                        
                        if self._run_check(test_url, test):
                            findings.append(self._create_finding(test_url, key, test))

        except Exception as e:
            # print(e)
            pass
            
        return findings

    def _run_check(self, url, test):
        try:
            res = requests.get(url, timeout=5)
            if test['check'] in res.text:
                # Double check for false positives (simple reflection)
                # If the payload itself is reflected verbatim, it's XSS not RCE usually.
                # E.g. input "{{7*7}}" -> output "{{7*7}}" (Not RCE)
                # input "{{7*7}}" -> output "49" (RCE)
                
                if test['type'].startswith("SSTI"):
                    if test['payload'] in res.text:
                        return False # payload reflected, not executed
                
                return True
        except:
            pass
        return False

    def _create_finding(self, url, param, test):
        print(f"{Fore.RED}[!!!] {test['type']} Found: {url}")
        return {
            "type": test['type'],
            "cwe": "CWE-77" if "Command" in test['type'] else "CWE-94", # CWE-94 for Code Injection (SSTI)
            "details": f"Payload executed successfully in parameter '{param}'.",
            "url": url,
            "payload": test['payload']
        }
