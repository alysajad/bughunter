# Bug Bounty Hunter Agent System

## 🌟 Overview
The **Bug Bounty Hunter Agent** is an advanced, automated security assessment tool designed to emulate the workflow of a professional penetration tester. It goes beyond simple scanning by actively identifying, validating, and establishing Proof-of-Concepts (PoCs) for critical vulnerabilities in web applications.

The system features a **Task-Oriented Architecture** where specialized "Agents" (modules) handle specific vulnerability classes, from Reconnaissance to Exploitation and Reporting. It includes a modern Web UI for real-time monitoring and interaction.

## 🕵️‍♂️ Vulnerability Coverage & Agents

The system covers the **OWASP Top 10 (2025)** and checks for specific high-impact CVEs.

### 1. Injection Attacks (`discovery/`)

| Agent | Vulnerability | Exploitation Logic | Payload Examples |
| :--- | :--- | :--- | :--- |
| **SQLInjector** | SQL Injection (Auth Bypass) | Fuzzes login forms with boolean-based payloads to bypass authentication. Checks for successful redirects or "Welcome" messages. | `' OR 1=1--`, `admin' #` |
| **NoSQLInjector** | NoSQL Injection (Auth Bypass) | Targets MongoDB/CouchDB by injecting JSON objects (`$ne`) or array parameters to manipulate query logic. | `{"user": {"$ne": null}}`, `user[$ne]=null` |
| **XSSTester** | Reflected XSS | Injects unique canaries and JavaScript payloads into URL parameters. Verifies if the payload is reflected verbatim in the response body. | `<script>alert(1)</script>`, `javascript:alert(1)` |
| **RCEAgent** | Command Injection / SSTI | **Cmd Injection**: Injects OS separators (`;`, `\|`) and checks for command output (e.g., `uid=`). <br> **SSTI**: Injects template math expressions and checks for evaluation. | `; id`, `{{7*7}}` (evaluates to `49`) |

### 2. Broken Access Control (`discovery/`)

| Agent | Vulnerability | Exploitation Logic |
| :--- | :--- | :--- |
| **AccessControlScanner** | Unauthenticated Access | **Forced Browsing**: Attempts to access sensitive paths (`/admin`, `/backup`) without cookies. <br> **Path Traversal**: Fuzzes parameters with `../../etc/passwd` to read system files. |
| **IDORTester** | Insecure Direct Object Ref (IDOR) | **Cookie Swapping**: Replays requests with a different user's session cookies to access their resources. <br> **Ownership Check**: Verifies if User A can access User B's objects. |

### 3. Authentication Failures (`discovery/`)

| Agent | Vulnerability | Exploitation Logic |
| :--- | :--- | :--- |
| **DefaultCredScanner** | Default Credentials | Tests discovered login forms against a list of common vendor defaults (e.g., `admin:admin`, `root:toor`). |
| **BruteForcer** | Weak Passwords | Performs a multi-threaded dictionary attack using auto-downloaded wordlists (e.g., `rockyou.txt`) against identifying login forms. |

### 4. Security Misconfigurations (`discovery/`)

| Agent | Module | Checks |
| :--- | :--- | :--- |
| **MisconfigScanner** | `misconfig.py` | Missing Security Headers (`CSP`, `HSTS`), Verbose Headers (`Server`, `X-Powered-By`), Exposed Sensitive Files (`robots.txt`, `.env`). |
| **CryptoScanner** | `crypto.py` | **Cleartext HTTP**: Checks for lack of HTTPS. <br> **Weak SSL**: Checks certificate validity. <br> **Cookie Flags**: Checks for missing `Secure` / `HttpOnly`. |
| **ComponentScanner** | `components.py` | Identifies outdated software versions via headers. |
| **ExceptionScanner** | `exceptions.py` | Fuzzes inputs to trigger unhandled stack traces (Information Leakage). |

### 5. Targeted Exploits (CVEs)

| Agent | CVE | Description | Detection Logic |
| :--- | :--- | :--- | :--- |
| **CVEAgent** | **CVE-2023-21839** | Oracle WebLogic RCE | Connects to T3/IIOP port (7001) and sends a handshake packet. A successful T3 handshake indicates exposure to unauthenticated JNDI injection. |

---

## 🚀 Usage

### Quick Start
1.  **Install Dependencies**: `pip install -r requirements.txt`
2.  **Environment**: Create `.env` with `GEMINI_API_KEY=...` (Optional for AI logic).
3.  **Run UI**: `python app.py` -> Open `http://localhost:5000`.

### CLI Mode
```bash
python main.py --target http://example.com --scan-all
```
*   `--scan-all`: Enables ALL scanners (SQLi, XSS, RCE, IDOR, NoSQLi, CVE, etc.).
*   `--fuzz`: Enables Fuzzing/Misconfig scanners.

---

## 📝 Reporting

The system generates professional reports in two formats:
1.  **Markdown (`scan_report.md`)**: Detailed technical findings.
2.  **PDF (`scan_report.pdf`)**: Client-ready document with Executive Summary and PoCs.

### Proof of Concept (PoC) Generation
The tool automatically generates standalone Python exploit scripts for verified vulnerabilities (SQLi, XSS, RCE), allowing for easy validation by triagers.

---

## 📚 References & Standards

*   **OWASP Top 10 (2021/2025)**: The framework for vulnerability categorization.
*   **CWE (Common Weakness Enumeration)**: Used for vulnerability classification.
*   **CVSS v3.1**: Used for severity scoring.
*   **Payloads**: Adapted from *PayloadAllTheThings*, *Seclists*, and *PortSwigger Web Security Academy*.

---

**Disclaimer**: This tool is for educational purposes and authorized testing only. Usage against targets without prior mutual consent is illegal.
