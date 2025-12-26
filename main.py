import sys
import argparse
import requests
from colorama import init, Fore
from recon.mapper import EndpointMapper
from recon.auth import AuthDetector
from recon.subdomains import SubdomainFinder
from llm.client import GeminiClient
from discovery.logic import LogicAnalyzer
from reporting.builder import ReportBuilder
from reporting.pdf_generator import PDFGenerator
from reporting.poc_generator import PoCGenerator
from reporting.pdf_generator import PDFGenerator
from discovery.sqli import SQLInjector
from discovery.xss import XSSTester
from discovery.idor import IDORTester
from discovery.fuzz import Fuzzer
from discovery.misconfig import MisconfigScanner
from discovery.components import ComponentScanner
from discovery.exceptions import ExceptionScanner
from discovery.crypto import CryptoScanner
from discovery.crypto import CryptoScanner
from discovery.defaults import DefaultCredScanner
from discovery.access_control import AccessControlScanner
from discovery.rce import RCEAgent
from discovery.cve import CVEAgent
from discovery.nosqli import NoSQLInjector
from discovery.csrf import CSRFScanner
from discovery.ssrf import SSRFScanner
from discovery.general import GeneralScanner
from discovery.bruteforce import BruteForcer
from dotenv import load_dotenv
import os

# Initialize colorama
init(autoreset=True)
load_dotenv()

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Hunter Agent")
    parser.add_argument("--target", help="Target URL", required=True)
    parser.add_argument("--scope", help="Scope definition (domain/wildcard)", required=True)
    parser.add_argument("--gemini-key", help="Gemini API Key (optional, can use env var)", required=False)
    parser.add_argument("--check-sqli", help="Force SQLi check on target", action="store_true")
    parser.add_argument("--check-xss", help="Force Reflected XSS check on target params", action="store_true")
    parser.add_argument("--check-idor", help="Force IDOR check", action="store_true")
    parser.add_argument("--session-a", help="Cookie/Session for User A (Victim)", required=False)
    parser.add_argument("--session-b", help="Cookie/Session for User B (Attacker)", required=False)
    parser.add_argument("--fuzz", help="Run input fuzzing on target params", action="store_true")
    parser.add_argument("--brute-force", help="Run password brute-force on login forms", action="store_true")
    parser.add_argument("--scan-all", help="Run ALL available scans (SQLi, XSS, Fuzz, Auth)", action="store_true")
    
    args = parser.parse_args()

    if args.scan_all:
        args.check_sqli = True
        args.check_xss = True
        args.fuzz = True
        # IDOR requires sessions, so we only run it if sessions are explicitly provided even in scan-all
        if args.session_a and args.session_b:
            args.check_idor = True
    
    print(f"{Fore.GREEN}[*] Starting Bug Bounty Hunter Agent on target: {args.target}")
    print(f"{Fore.CYAN}[*] Scope: {args.scope}")
    
    # Initialize modules
    try:
        report_builder = ReportBuilder()
        
        api_key = args.gemini_key or os.getenv("GEMINI_API_KEY")
        if api_key:
            gemini = GeminiClient(api_key=api_key)
            print(f"{Fore.GREEN}[+] Gemini Client initialized.")
        else:
            print(f"{Fore.YELLOW}[!] No Gemini Key provided. LLM features will be disabled.")
            gemini = None

        # 0. Subdomain Recon (Optional but recommended for full scope)
        # We run this check if --scan-all is enabled or explicit.
        # It expands knowledge but for this MVP we just report it.
        if args.scan_all:
             # Basic domain extraction
             from urllib.parse import urlparse
             ds = args.scope if args.scope else urlparse(args.target).netloc
             
             sub_finder = SubdomainFinder(ds)
             subdomains = sub_finder.scan()
             
             if subdomains:
                report_builder.add_vulnerability({
                    "Title": "Informational - Discovered Subdomains",
                    "Summary": f"Reconnaissance identified {len(subdomains)} active subdomains related to {ds}.",
                    "Type": "Asset Discovery",
                    "Component": "Recon Module",
                    "Details": f"**Active Subdomains:**\n" + "\n".join([f"- {s}" for s in subdomains]),
                    "PoC": "DNS Lookup: `nslookup <subdomain>`",
                    "Impact": "Expanded attack surface.",
                    "CVSS": "None",
                    "Remediation": "Ensure all exposed subdomains are intended and secured."
                })

        mapper = EndpointMapper(args.target, args.scope)
        mapper.crawl()

        # Add crawl results to report
        if mapper.endpoints:
            endpoints_list = "\n".join([f"- {ep}" for ep in mapper.endpoints])
            report_builder.add_vulnerability({
                "Title": "Reconnaissance - Discovered Endpoints",
                "Summary": f"The agent successfully crawled the target and identified {len(mapper.endpoints)} in-scope endpoints.",
                "Type": "Informational",
                "Component": "Recon Module",
                "Details": f"**Discovered Endpoints:**\n{endpoints_list}",
                "PoC": "Manual Verification: Navigate to the discovered URLs to verify accessibility.",
                "Impact": "Helps identify the attack surface.",
                "CVSS": "None",
                "Remediation": "Ensure no sensitive endpoints are exposed without authentication."
            })

        if gemini:
            analyzer = LogicAnalyzer(gemini)
            print(f"{Fore.GREEN}[+] Logic Analyzer ready.")

        # Auth Flow Identification
        auth_detector = AuthDetector()
        login_forms = auth_detector.find_login_forms(mapper.forms)
        
        if login_forms:
            form_list = "\n".join([f"- {f['action']} (Inputs: {[i['name'] for i in f['inputs']]})" for f in login_forms])
            report_builder.add_vulnerability({
                "Title": "Reconnaissance - Discovered Login Forms",
                "Summary": f"Identified {len(login_forms)} potential login forms.",
                "Type": "Informational",
                "Component": "Auth Module",
                "Details": f"**Login Forms:**\n{form_list}",
                "PoC": "Manual Verification: Attempt to access the form and identify if it allows unauthenticated interaction.",
                "Impact": "Useful for targeting Auth Bypass and Password Spraying attacks.",
                "CVSS": "None",
                "Remediation": "Ensure these forms are protected against brute-force (Rate Limiting)."
            })

        # SQL Injection Check (Targeted)
        # If we found login forms, we can Auto-Target them!
        if args.check_sqli:
             targets_to_check = []
             # If target is a known login form, use its inputs
             # We need to map inputs to targets. 
             # Refactor: targets_to_check should store dicts: {'url': ..., 'inputs': ...}
             
             # 1. Add manual target (default inputs)
             targets_to_check.append({'url': args.target, 'inputs': []})
             
             # 2. Add discovered login forms
             for form in login_forms:
                 # Avoid duplicates (basic check)
                 if form['action'] != args.target:
                     targets_to_check.append({'url': form['action'], 'inputs': form['inputs']})
             
             for item in targets_to_check:
                 target_url = item['url']
                 inputs = item['inputs']
                 
                 # Determine field names
                 user_field = "username"
                 pass_field = "password"
                 
                 # Simple heuristic to find user/pass fields from discovered inputs
                 if inputs:
                     for inp in inputs:
                         name = inp['name'].lower()
                         if "user" in name or "name" in name or "login" in name or "email" in name or "uname" in name:
                             user_field = inp['name']
                         if "pass" in name or "key" in name or "pwd" in name:
                             pass_field = inp['name']
                 
                 sqli_tester = SQLInjector(target_url)
                 # Update SQLInjector to accept these params if not already
                 sqli_vulns = sqli_tester.test_login(username_field=user_field, password_field=pass_field)
                 
                 if sqli_vulns:
                     human_sqli_poc = f"""
**Step-by-Step Reproduction:**
1. Navigate to the login page: `{target_url}`
2. In the **{user_field}** input field, copy and paste the following payload *exactly* (including any quotes):
   ```text
   {sqli_vulns[0]['payload']}
   ```
3. In the **{pass_field}** field, enter any random text (e.g., `12345`).
4. Click the **Login** / **Submit** button.
5. **Observation**: 
   - You should be logged in immediately (bypassing the password check).
   - Or, you might see a database error, or a "Welcome Administrator" message.
"""
                     report_builder.add_vulnerability({
                        "Title": "Critical - SQL Injection (Auth Bypass)",
                        "Summary": f"SQL Injection found in login form at {target_url}.",
                        "Type": "Injection (SQLi)",
                        "Component": "Login Module",
                        "Details": f"The following payloads successfully bypassed authentication (User Field: {user_field}):\n{sqli_vulns}",
                        "PoC": human_sqli_poc,
                        "Impact": "Full account takeover, potentially admin access.",
                        "CVSS": "Critical",
                        "Remediation": "Use parameterized queries (Prepared Statements)."
                     })
                 
                     # Generate Standalone Exploit
                     poc_gen = PoCGenerator()
                     # Pass the correctly identified params to the generator
                     # The generator needs to know the field names to build valid python code
                     # We passed 'method' in sqli_vulns, let's pass params too or just handle in generator
                     exploit_path = poc_gen.generate_sqli_poc(target_url, sqli_vulns[0]['payload'], method=sqli_vulns[0]['method'], params={user_field: "PAYLOAD", pass_field: "password"})
                     print(f"{Fore.RED}[+] Generated SQLi Exploit: {exploit_path}")

        # NoSQL Injection Check
        if args.scan_all or args.check_sqli:
             # Re-use targets from SQLi or re-derive
             nosqli_targets = targets_to_check if 'targets_to_check' in locals() else [{'url': args.target, 'inputs': []}]
             
             for item in nosqli_targets:
                 # Guess fields if variables not in scope (re-logic or reuse)
                 # Simplified: Just grab from item if available, else default
                 t_url = item['url']
                 u_field = "username" 
                 p_field = "password"
                 if item['inputs']:
                     for i in item['inputs']:
                         if "user" in i['name']: u_field = i['name']
                         if "pass" in i['name']: p_field = i['name']

                 nosqli_tester = NoSQLInjector(t_url)
                 nosqli_vulns = nosqli_tester.test_login(username_field=u_field, password_field=p_field)
                 
                 if nosqli_vulns:
                     human_nosqli_poc = f"""
**Step-by-Step Reproduction (using tools):**
*Note: This exploit requires modifying hidden request data, which cannot be done easily in a standard browser address bar.*
1. Open a tool like **Burp Suite** or **Postman**.
2. Set the Request Method to `POST` and URL to `{t_url}`.
3. Set the Header `Content-Type: application/json`.
4. In the Body, paste this JSON Payload:
   ```json
   {nosqli_vulns[0]['payload']}
   ```
5. Send the request.
6. **Observation**: The server response should indicate a successful login (e.g., HTTP 200 OK, a Session Token, or a Redirect to Dashboard).
"""
                     report_builder.add_vulnerability({
                        "Title": "Critical - NoSQL Injection (Auth Bypass)",
                        "Summary": f"NoSQL Injection found in login form at {t_url}.",
                        "Type": "Injection (NoSQL)",
                        "Component": "Login Module (MongoDB/CouchDB)",
                        "Details": f"The following payloads bypassed authentication:\n{nosqli_vulns}",
                        "PoC": human_nosqli_poc,
                        "Impact": "Full account takeover, potentially admin access.",
                        "CVSS": "Critical",
                        "Remediation": "Sanitize input, check types (prevent objects where strings expected)."
                     })

        # Collect all targets to scan (Base Target + Crawled Endpoints)
        targets_to_scan = [args.target]
        if args.scan_all and mapper.endpoints:
            targets_to_scan.extend(mapper.endpoints)
            
        # Also add discovered login form actions (so XSS/RCE scan them too)
        if login_forms:
             for f in login_forms:
                 targets_to_scan.append(f['action'])
        
        # Remove duplicates
        targets_to_scan = list(set(targets_to_scan))
        
        print(f"{Fore.CYAN}[*] Running Vulnerability Scans on {len(targets_to_scan)} targets...")

        # XSS Check
        if args.check_xss:
            for url in targets_to_scan:
                xss_tester = XSSTester()
                xss_vulns = xss_tester.test_reflected(url)
                
                if xss_vulns:
                    human_poc = f"""
**Step-by-Step Reproduction:**
1. Open a standard web browser (Chrome/Firefox).
2. Copy the following URL exactly:
   `{xss_vulns[0]['url']}`
3. Paste it into the address bar and press Enter.
4. **Observation**: You should see a browser pop-up alert box displaying the number '1' or the text from the payload.
   - *Note*: If the browser blocks the popup, check the Developer Tools (F12) -> Console for the executed error/log.
"""
                    report_builder.add_vulnerability({
                        "Title": "High - Reflected Cross-Site Scripting (XSS)",
                        "Summary": f"Reflected XSS found in URL parameter '{xss_vulns[0]['param']}'.",
                        "Type": "Injection (XSS)",
                        "Component": "URL Parameter",
                        "Details": f"Payload reflected in response:\n{xss_vulns}",
                        "PoC": human_poc,
                        "Impact": "Attacker can execute arbitrary scripts in user's browser (Session Hijacking).",
                        "CVSS": "High",
                        "Remediation": "Input validation and Output Encoding (e.g., HTML Entity Encoding)."
                    })
                    
                    # Generate Standalone Exploit
                    poc_gen = PoCGenerator()
                    exploit_path = poc_gen.generate_xss_poc(url, xss_vulns[0]['param'], xss_vulns[0]['payload'])
                    print(f"{Fore.MAGENTA}[+] Generated XSS Exploit: {exploit_path}")

        # IDOR Check (Only works if we have specific resource IDs, usually manual)
        if args.check_idor and args.session_a and args.session_b:
            # Parse headers (assuming "Cookie: ...")
            headers_a = {"Cookie": args.session_a}
            headers_b = {"Cookie": args.session_b}
            
            # For IDOR, target is the specific resource URL (e.g., /user/123)
            # We assume --target IS the resource belonging to User A
            idor_tester = IDORTester(headers_a, headers_b)
            idor_vulns = idor_tester.test_access(args.target, "TARGET_RESOURCE")
            
            if idor_vulns:
                 poc_idor = f"""
1. Log in as **User A** (Victim) and identify a private resource URL:
   `{args.target}`
2. Log in as **User B** (Attacker) and capture your session cookie:
   `{args.session_b}`
3. Send a GET request to the Victim's URL using Attacker's cookie:
   ```bash
   curl "{args.target}" -H "Cookie: {args.session_b}"
   ```
4. **Result**: The server returns HTTP 200 and displays User A's private data.
"""
                 report_builder.add_vulnerability({
                    "Title": "High - Insecure Direct Object Reference (IDOR)",
                    "Summary": "User B (Attacker) successfully accessed a resource belonging to User A (Victim).",
                    "Type": "Broken Access Control (IDOR)",
                    "Component": "Authorization Logic",
                    "Details": f"Access confirmed for:\n{idor_vulns}",
                    "PoC": poc_idor,
                    "Impact": "Unauthorized access to sensitive data or functionality.",
                    "CVSS": "High",
                    "Remediation": "Implement proper ownership checks on the server side."
                 })

        # Fuzzing Check
        if args.fuzz:
            for url in targets_to_scan:
                fuzzer = Fuzzer()
                fuzz_issues = fuzzer.fuzz_params(url)
                
                if fuzz_issues:
                     poc_fuzz = f"""
1. Visit the following URL to trigger the error:
   ```text
   {fuzz_issues[0]['url']}
   ```
2. **Result**: The server responds with `{fuzz_issues[0]['type']}`, potentially revealing stack traces or internal paths.
"""
                     report_builder.add_vulnerability({
                        "Title": "Medium - Unhandled Exception / Information Leak",
                        "Summary": f"Fuzzing triggering application errors in parameter '{fuzz_issues[0]['param']}'.",
                        "Type": "Improper Error Handling",
                        "Component": "Input Validation",
                        "Details": f"The following payloads triggered errors:\n{fuzz_issues}",
                        "PoC": poc_fuzz,
                        "Impact": "Information leakage (stack traces, paths) can aid further attacks.",
                        "CVSS": "Medium",
                        "Remediation": "Implement generic error pages and ensure robust input validation."
                     })

        # Security Misconfiguration Check (A02:2025)
        if args.scan_all: # Or add specific flag if needed
            misconfig_scanner = MisconfigScanner()
            misconfigs = misconfig_scanner.scan(args.target)
            
            if misconfigs:
                details = "\n".join([f"- {m['type']}: {m['details']} ({m['url']})" for m in misconfigs])
                report_builder.add_vulnerability({
                    "Title": "Medium - Security Misconfiguration (OWASP A02:2025)",
                    "Summary": f"Identified {len(misconfigs)} security misconfigurations.",
                    "Type": "Security Misconfiguration",
                    "Component": "Server Config",
                    "Details": f"**Findings:**\n{details}",
                    "PoC": "Verify headers or access the sensitive files listed.",
                    "Impact": "Can lead to compromise or easier exploitation of other flaws.",
                    "CVSS": "Low-Medium",
                    "Remediation": "Harden server configuration, disable directory listing, hide version info."
                })

        # Component Check (A03:2025)
        if args.scan_all:
            comp_scanner = ComponentScanner()
            components = comp_scanner.scan(args.target)
            
            if components:
                details = "\n".join([f"- {c['type']}: {c['details']}" for c in components])
                report_builder.add_vulnerability({
                    "Title": "Low - Vulnerable/Outdated Components (OWASP A03:2025)",
                    "Summary": f"Identified {len(components)} potentially outdated components.",
                    "Type": "Vulnerable Components",
                    "Component": "Supply Chain",
                    "Details": f"**Findings:**\n{details}",
                    "PoC": "Check the version numbers against CVE databases.",
                    "Impact": "Known vulnerabilities in libraries can be exploited.",
                    "CVSS": "Low",
                    "Remediation": "Update libraries to the latest stable versions."
                })

        # Exception Handling Check (A10:2025)
        if args.scan_all:
             all_exceptions = []
             for url in targets_to_scan:
                exc_scanner = ExceptionScanner()
                exceptions = exc_scanner.scan(url)
                if exceptions:
                    for e in exceptions:
                        e['url'] = url # Ensure URL is tracked
                        all_exceptions.append(e)
             
             if all_exceptions:
                # De-duplicate by type or detail
                unique_exc = []
                seen_exc = set()
                for e in all_exceptions:
                    sig = f"{e['type']}:{e['details']}"
                    if sig not in seen_exc:
                        seen_exc.add(sig)
                        unique_exc.append(e)

                details = "\n".join([f"- {e['type']}: {e['details']} in {e['url']}" for e in unique_exc[:10]]) # Limit to 10
                if len(unique_exc) > 10: details += f"\n... (and {len(unique_exc)-10} more)"
                
                report_builder.add_vulnerability({
                    "Title": "Medium - Mishandling of Exceptional Conditions (OWASP A10:2025)",
                    "Summary": f"Triggered {len(unique_exc)} unique unhandled error states.",
                    "Type": "Improper Exception Handling",
                    "Component": "Logic / Input Handling",
                    "Details": f"**Findings:**\n{details}",
                    "PoC": "Replay the specific payloads in the URL to observe the failure state.",
                    "Impact": "Can lead to Information Disclosure, Logic Bypasses, or Denial of Service.",
                    "CVSS": "Medium",
                    "Remediation": "Implement global exception handlers and ensure 'Fail Safe' defaults."
                })

        # Crypto Check (A04:2025)
        if args.scan_all:
             crypto_scanner = CryptoScanner()
             # Just scan base target + potentially domain root
             crypto_findings = crypto_scanner.scan(args.target)
             
             if crypto_findings:
                details = "\n".join([f"- {f['type']}: {f['details']}" for f in crypto_findings])
                report_builder.add_vulnerability({
                    "Title": "Medium - Cryptographic Failures (OWASP A04:2025)",
                    "Summary": f"Identified {len(crypto_findings)} cryptographic issues.",
                    "Type": "Cryptographic Failure",
                    "Component": "Encryption / SSL",
                    "Details": f"**Findings:**\n{details}",
                    "PoC": "Inspect SSL certificate or HTTP headers (cookies).",
                    "Impact": "Data interception (MITM) or session hijacking.",
                    "CVSS": "Medium",
                    "Remediation": "Enforce HTTPS, use strong ciphers, set Secure/HttpOnly flags."
                })

        # Default Credentials (A07:2025)
        if args.scan_all:
             # Run on discovered login forms
             # Reuse targets_to_check logic if check_sqli ran, or re-derive
             # For simplicity, let's just re-iterate known forms or use targets_to_check if available,
             # but targets_to_check is local to that scope. 
             # Let's rebuild a quick list of login forms to test.
             
             targets_defaults = []
             targets_defaults.append({'url': args.target, 'inputs': []})
             for form in login_forms:
                 if form['action'] != args.target:
                     targets_defaults.append({'url': form['action'], 'inputs': form['inputs']})
            
             # Brute Force Check (Optional / Flag-based)
             if args.brute_force:
                 brute_forcer = BruteForcer()
                 for item in targets_defaults:
                     # Guess username (admin by default) and fields
                     user_f = "username"
                     if item['inputs']:
                         for i in item['inputs']:
                             if "user" in i['name'] or "name" in i['name']: user_f = i['name']
                     
                     # Using 'admin' as target user for now
                     found_pass = brute_forcer.run(item['url'], "admin", threads=10)
                     
                     if found_pass:
                         report_builder.add_vulnerability({
                            "Title": "Critical - Weak Password (Brute Force)",
                            "Summary": f"Password cracked for user 'admin' at {item['url']}.",
                            "Type": "Weak Authentication",
                            "Component": "Authentication",
                            "Details": f"**Credentials Found:**\nUser: admin\nPass: {found_pass}",
                            "PoC": f"Login with admin:{found_pass}",
                            "Impact": "Unauthorized access.",
                            "CVSS": "Critical",
                            "Remediation": "Enforce strong password policies and rate limiting."
                         })

             def_scanner = DefaultCredScanner()
             
             for item in targets_defaults:
                 # Guess fields
                 user_f = "username"
                 pass_f = "password"
                 if item['inputs']:
                     for i in item['inputs']:
                         if "user" in i['name'] or "name" in i['name']: user_f = i['name']
                         if "pass" in i['name'] or "pwd" in i['name']: pass_f = i['name']
                 
                 def_findings = def_scanner.scan(item['url'], username_field=user_f, password_field=pass_f)
                 
                 if def_findings:
                    details = "\n".join([f"- {f['details']} at {f['url']}" for f in def_findings])
                    report_builder.add_vulnerability({
                        "Title": "High - Default Credentials (OWASP A07:2025)",
                        "Summary": f"Successful login using default credentials.",
                        "Type": "Authentication Failure",
                        "Component": "Authentication",
                        "Details": f"**Findings:**\n{details}",
                        "PoC": "Try logging in with the listed credentials.",
                        "Impact": "Unauthoried access to the system.",
                        "CVSS": "High",
                        "Remediation": "Change all default passwords and enforce strong password policies."
                    })

        # Access Control Check (A01:2025)
        if args.scan_all:
             ac_scanner = AccessControlScanner()
             
             # 1. Unauthenticated Bypass (check admin paths)
             # Basic heuristic: try against base URL
             bypass_findings = ac_scanner.scan_bypass(args.target)
             
             if bypass_findings:
                 details = "\n".join([f"- {f['type']}: {f['details']} ({f['url']})" for f in bypass_findings])
                 report_builder.add_vulnerability({
                    "Title": "High - Broken Access Control (OWASP A01:2025)",
                    "Summary": f"Detected {len(bypass_findings)} endpoints accessible without authentication.",
                    "Type": "Broken Access Control",
                    "Component": "Authorization",
                    "Details": f"**Findings:**\n{details}",
                    "PoC": "Browse to the URL in an Incognito window (no session).",
                    "Impact": "Unauthorized access to sensitive functionality.",
                    "CVSS": "High",
                    "Remediation": "Enforce authentication checks on these endpoints."
                 })

             # 2. Path Traversal (check targets with params)
             all_trav_findings = []
             for url in targets_to_scan:
                 trav_findings = ac_scanner.scan_traversal(url)
                 if trav_findings:
                     all_trav_findings.extend(trav_findings)
             
             if all_trav_findings:
                  details = "\n".join([f"- {f['url']} ({f['details']})" for f in all_trav_findings])
                  report_builder.add_vulnerability({
                     "Title": "High - Path Traversal (OWASP A01:2025)",
                     "Summary": f"Successful Directory Traversal identified on {len(all_trav_findings)} endpoints.",
                     "Type": "Path Traversal",
                     "Component": "File System",
                     "Details": f"**Findings:**\n{details}",
                     "PoC": "Visit the URL to view system files.",
                     "Impact": "Disclosure of sensitive system files (/etc/passwd, win.ini).",
                     "CVSS": "High",
                     "Remediation": "Validate inputs and prevent file path manipulation."
                  })

        # RCE Check (Command Injection / SSTI) (A03:2025/General)
        if args.scan_all:
             rce_agent = RCEAgent()
             all_rce_findings = []
             for url in targets_to_scan:
                 rce_findings = rce_agent.scan(url)
                 if rce_findings:
                     all_rce_findings.extend(rce_findings)
            
             if all_rce_findings:
                 details = "\n".join([f"- {f['type']} at {f['url']} (Payload: `{f['payload']}`)" for f in all_rce_findings])
                 # Determine Title based on primary finding (CWE-77 vs CWE-94)
                 cwe_id = all_rce_findings[0].get('cwe', 'CWE-77')
                 title = f"Critical - Command Injection ({cwe_id})" if cwe_id == 'CWE-77' else "Critical - Remote Code Execution (SSTI)"
                 
                 human_rce_poc = f"""
**Step-by-Step Reproduction:**
1. Open your web browser or a tool like Postman.
2. Navigate to the following Vulnerable URL:
   `{all_rce_findings[0]['url']}`
   *(Note: The payload `{all_rce_findings[0]['payload']}` is already embedded in this link)*
3. **Observation**: Look at the page content. You should see system-level output.
   - For Command Injection: Look for user details like `uid=0(root)` or `www-data`.
   - For Code Injection: Look for a computation result (e.g., `49` from `7*7`) or PHP version info.
"""
                 report_builder.add_vulnerability({
                    "Title": title,
                    "Summary": f"Identified {len(all_rce_findings)} RCE vulnerabilities ({cwe_id}).",
                    "Type": f"Remote Code Execution ({cwe_id})",
                    "Component": "OS Command / Template Engine",
                    "Details": f"**Findings:**\n{details}",
                    "PoC": human_rce_poc,
                    "Impact": "Full system compromise.",
                    "CVSS": "Critical",
                    "Remediation": "Sanitize input, avoid system calls, use safe APIs."
                 })
                 
                 # Generate PoC if possible
                 poc_gen = PoCGenerator()
                 exploit_path = poc_gen.generate_xss_poc(all_rce_findings[0]['url'], "RCE_PARAM", all_rce_findings[0]['payload']) # Reusing generic generator for now
                 print(f"{Fore.MAGENTA}[+] Generated RCE Exploit Script: {exploit_path}")

        # Targeted CVE Check (CVE-2023-21839)
        if args.scan_all:
             cve_agent = CVEAgent()
             # We need just the hostname/ip, not the full URL scheme for T3 check primarily
             # But our scan() handles resolution.
             from urllib.parse import urlparse
             host = urlparse(args.target).hostname
             if not host: host = args.target # Fallback if just IP provided or no scheme
             
             cve_findings = cve_agent.scan(host)
             
             if cve_findings:
                 details = "\n".join([f"- {f['title']} at {f['url']}" for f in cve_findings])
                 report_builder.add_vulnerability({
                    "Title": "Critical - Oracle WebLogic RCE (CVE-2023-21839)",
                    "Summary": f"Detected vulnerable WebLogic T3 service.",
                    "Type": "Remote Code Execution (CVE)",
                    "Component": "Oracle WebLogic",
                    "Details": f"**Findings:**\n{details}\n\nExposed T3 protocol allows unauthenticated remote attackers to execute arbitrary code via JNDI injection.",
                    "PoC": "Use a T3 client to bind a malicious object: `java -jar JNDIExploit.jar -i <IP>`",
                    "Impact": "Full system compromise (Unauthenticated RCE).",
                    "CVSS": "Critical (9.8)",
                    "Remediation": "Apply Oracle Critical Patch Update (CPU) or block T3/IIOP ports."
                 })

        # CSRF Check (A01/A07)
        if args.scan_all:
             csrf_scanner = CSRFScanner()
             all_csrf_findings = []
             # Run on all endpoints that might have forms
             for url in targets_to_scan:
                 csrf_findings = csrf_scanner.scan(url)
                 if csrf_findings:
                     all_csrf_findings.extend(csrf_findings)
            
             if all_csrf_findings:
                 # Deduplicate based on form action
                 unique_csrf = []
                 seen_actions = set()
                 for f in all_csrf_findings:
                     action = f.get('form_action', 'N/A')
                     if action not in seen_actions and action != 'N/A':
                         seen_actions.add(action)
                         unique_csrf.append(f)
                     elif action == 'N/A':
                         unique_csrf.append(f) # Keep if unknown action

                 details = "\n".join([f"- {f['type']}: {f['details']} (Form Action: {f.get('form_action', 'N/A')})" for f in unique_csrf])
                 
                 # Use first finding for PoC
                 first_finding = unique_csrf[0] if unique_csrf else all_csrf_findings[0]
                 
                 human_csrf_poc = f"""
**Step-by-Step Reproduction:**
1. Create a new file on your desktop named `exploit.html`.
2. Open it with a text editor (Notepad) and paste the following code:
   ```html
   <html>
     <body>
       <h1>CSRF PoC</h1>
       <form action="{first_finding.get('form_action', 'TARGET_URL')}" method="POST">
         <input type="submit" value="Click to exploit">
       </form>
       <script>document.forms[0].submit();</script>
     </body>
   </html>
   ```
3. Save the file.
4. **Log in** to the target application in your browser.
5. While logged in, open `exploit.html` with the same browser.
6. **Observation**: The action should be performed immediately without your consent (e.g., password change, data delete), proving the site accepts requests from external sources.
"""
                 report_builder.add_vulnerability({
                    "Title": "Medium - Cross-Site Request Forgery (CSRF)",
                    "Summary": f"Identified {len(unique_csrf)} unique CSRF vulnerabilities.",
                    "Type": "CSRF",
                    "Component": "Session Management",
                    "Details": f"**Findings (Unique Actions):**\n{details}",
                    "PoC": human_csrf_poc,
                    "Impact": "Attacker can force authenticated users to perform unwanted actions.",
                    "CVSS": "Medium",
                    "Remediation": "Implement Anti-CSRF tokens (Synchronizer Token Pattern) and set SameSite=Strict cookies."
                 })

        # SSRF Check
        if args.scan_all:
             ssrf_scanner = SSRFScanner()
             all_ssrf_findings = []
             for url in targets_to_scan:
                 ssrf_findings = ssrf_scanner.scan(url)
                 if ssrf_findings:
                    all_ssrf_findings.extend(ssrf_findings)

             if all_ssrf_findings:
                 details = "\n".join([f"- {f['type']} at {f['url']} (Payload: `{f['payload']}`)" for f in all_ssrf_findings])
                 human_ssrf_poc = f"""
**Step-by-Step Reproduction:**
1. Open your web browser.
2. Visit the Vulnerable URL:
   `{all_ssrf_findings[0]['url']}`
3. **Observation**:
   - **Localhost**: If you see a generic login page or server default page that is normally only accessible locally, the attack succeeded.
   - **Cloud Metadata**: If you see JSON data with keys like `ami-id`, `instance-id`, or `security-credentials`, the server is exposing critical cloud infrastructure data.
   - **File Read**: If you see the contents of a system file (like users: `root:x:0:0`), the server has Local File Inclusion.
"""
                 report_builder.add_vulnerability({
                    "Title": "Critical - Server-Side Request Forgery (SSRF)",
                    "Summary": f"Identified {len(all_ssrf_findings)} SSRF vulnerabilities.",
                    "Type": "SSRF",
                    "Component": "Input Validation",
                    "Details": f"**Findings:**\n{details}",
                    "PoC": human_ssrf_poc,
                    "Impact": "Access to internal metadata service (Cloud Credential Theft) or local files.",
                    "CVSS": "Critical",
                     "Remediation": "Whitelist permitted domains/IPs, disable HTTP redirects, block internal IP ranges."
                 })

        # General Compliance Check (Best Practices)
        if args.scan_all:
            gen_scanner = GeneralScanner()
            # Run on base target only (usually sufficient for headers/files)
            gen_findings = gen_scanner.scan(args.target)
            
            if gen_findings:
                details = "\n".join([f"- [{f['severity']}] {f['type']}: {f['details']}" for f in gen_findings])
                report_builder.add_vulnerability({
                    "Title": "Low - General Compliance & Best Practices",
                    "Summary": f"Identified {len(gen_findings)} compliance or best-practice items.",
                    "Type": "Security Misconfiguration / Info",
                    "Component": "General",
                    "Details": f"**Findings:**\n{details}",
                    "PoC": "Manual Verification: Check headers, visit discovered files, or inspect source code comments.",
                        "Impact": "Varies (Information Leakage to Misconfiguration).",
                        "CVSS": "Low",
                        "Remediation": "Address reported items (e.g., disable TRACE, remove comments, secure cookies)."
                })

        # Logic Analysis (LLM)
        if args.scan_all and gemini:
            print(f"{Fore.CYAN}[*] Sending generic target content to Gemini for Logic Analysis...")
            try:
                # Fetch main page content
                r = requests.get(args.target, timeout=10)
                flow_data = {
                    'request': f"GET {args.target}",
                    'response': r.text[:2000] # Limit to avoid token limits
                }
                
                logic_findings = analyzer.analyze_flow(flow_data)
                if logic_findings:
                     report_builder.add_vulnerability({
                       "Title": "Informational - AI Logic Analysis",
                       "Summary": f"Gemini A.I. analyzed the application response.",
                       "Type": "AI Analysis",
                       "Component": "Logic Layer",
                       "Details": f"**AI Analysis Findings:**\n{logic_findings}",
                       "PoC": "N/A (AI Generated Observation)",
                       "Impact": "Potential logic flaws or interesting verification points.",
                       "CVSS": "Info",
                       "Remediation": "Manual review recommended."
                    })
            except Exception as e:
                print(f"{Fore.YELLOW}[!] LLM Logic Analysis failed: {e}")

        # Save Report
        report_builder.save_report(filename="scan_report.md")
        
        # Generate PDF
        try:
            with open("scan_report.md", "r", encoding="utf-8") as f:
                md_content = f.read()
            
            pdf_gen = PDFGenerator()
            pdf_gen.generate_from_markdown(md_content, filename="scan_report.pdf")
            print(f"{Fore.GREEN}[+] PDF Report saved to scan_report.pdf")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to generate PDF: {e}")

    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
if __name__ == "__main__":
    main()
