import sys
import argparse
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
                     poc_steps = f"""
1. Navigate to the login page: `{target_url}`
2. In the **{user_field}** field, enter the following payload:
   ```text
   {sqli_vulns[0]['payload']}
   ```
3. Enter anything in the **{pass_field}** field (e.g., `test`).
4. Click the **Login** button.
5. **Result**: You will be successfully logged in as the administrator, bypassing authentication.
"""
                     report_builder.add_vulnerability({
                        "Title": "Critical - SQL Injection (Auth Bypass)",
                        "Summary": f"SQL Injection found in login form at {target_url}.",
                        "Type": "Injection (SQLi)",
                        "Component": "Login Module",
                        "Details": f"The following payloads successfully bypassed authentication (User Field: {user_field}):\n{sqli_vulns}",
                        "PoC": poc_steps,
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

                 # NEW: NoSQL Injection Check
                 nosqli_tester = NoSQLInjector(target_url)
                 nosqli_vulns = nosqli_tester.test_login(username_field=user_field, password_field=pass_field)
                 
                 if nosqli_vulns:
                     poc_step = f"""
1. Send a POST request to `{target_url}` with the header `Content-Type: application/json`.
2. Body:
   ```json
   {nosqli_vulns[0]['payload']}
   ```
3. **Result**: Authentication bypassed.
"""
                     report_builder.add_vulnerability({
                        "Title": "Critical - NoSQL Injection (Auth Bypass)",
                        "Summary": f"NoSQL Injection found in login form at {target_url}.",
                        "Type": "Injection (NoSQL)",
                        "Component": "Login Module (MongoDB/CouchDB)",
                        "Details": f"The following payloads bypassed authentication:\n{nosqli_vulns}",
                        "PoC": poc_step,
                        "Impact": "Full account takeover, potentially admin access.",
                        "CVSS": "Critical",
                        "Remediation": "Sanitize input, check types (prevent objects where strings expected)."
                     })

        # Collect all targets to scan (Base Target + Crawled Endpoints)
        targets_to_scan = [args.target]
        if args.scan_all and mapper.endpoints:
            targets_to_scan.extend(mapper.endpoints)
        
        # Remove duplicates
        targets_to_scan = list(set(targets_to_scan))
        
        print(f"{Fore.CYAN}[*] Running Vulnerability Scans on {len(targets_to_scan)} targets...")

        # XSS Check
        if args.check_xss:
            for url in targets_to_scan:
                xss_tester = XSSTester()
                xss_vulns = xss_tester.test_reflected(url)
                
                if xss_vulns:
                    poc_xss = f"""
1. Visit the following URL:
   ```text
   {xss_vulns[0]['url']}
   ```
2. **Result**: An alert box with '1' should appear, confirming the XSS execution.
"""
                    report_builder.add_vulnerability({
                        "Title": "High - Reflected Cross-Site Scripting (XSS)",
                        "Summary": f"Reflected XSS found in URL parameter '{xss_vulns[0]['param']}'.",
                        "Type": "Injection (XSS)",
                        "Component": "URL Parameter",
                        "Details": f"Payload reflected in response:\n{xss_vulns}",
                        "PoC": poc_xss,
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
             # Loop through targets specifically for exception testing as it's input-heavy
             for url in targets_to_scan:
                exc_scanner = ExceptionScanner()
                exceptions = exc_scanner.scan(url)
                
                if exceptions:
                    details = "\n".join([f"- {e['type']}: {e['details']} in {e['url']}" for e in exceptions])
                    report_builder.add_vulnerability({
                        "Title": "Medium - Mishandling of Exceptional Conditions (OWASP A10:2025)",
                        "Summary": f"Triggered {len(exceptions)} unhandled error states or latency spikes.",
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
             for url in targets_to_scan:
                 if "=" in url:
                     trav_findings = ac_scanner.scan_traversal(url)
                     if trav_findings:
                         details = "\n".join([f"- {f['url']} ({f['details']})" for f in trav_findings])
                         report_builder.add_vulnerability({
                            "Title": "High - Path Traversal (OWASP A01:2025)",
                            "Summary": "Successful Directory Traversal identified.",
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
             for url in targets_to_scan:
                 if "=" in url:
                     rce_findings = rce_agent.scan(url)
                     if rce_findings:
                         details = "\n".join([f"- {f['type']} at {f['url']} (Payload: `{f['payload']}`)" for f in rce_findings])
                         report_builder.add_vulnerability({
                            "Title": "Critical - Remote Code Execution (RCE)",
                            "Summary": f"Identified {len(rce_findings)} RCE vulnerabilities.",
                            "Type": "Remote Code Execution",
                            "Component": "OS Command / Template Engine",
                            "Details": f"**Findings:**\n{details}",
                            "PoC": f"Visit the URL with the payload: `{rce_findings[0]['payload']}`",
                            "Impact": "Full system compromise.",
                            "CVSS": "Critical",
                            "Remediation": "Sanitize input, avoid system calls, use safe APIs."
                         })
                         
                         # Generate PoC if possible
                         poc_gen = PoCGenerator()
                         exploit_path = poc_gen.generate_xss_poc(rce_findings[0]['url'], "RCE_PARAM", rce_findings[0]['payload']) # Reusing generic generator for now
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
