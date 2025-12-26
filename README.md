# Bug Bounty Hunter Agent System

## Objective
To identify REAL, REPORTABLE security vulnerabilities suitable for professional disclosure.

## Authorization
**IMPORTANT:** All activities are conducted strictly within the authorized scope of a legitimate Bug Bounty / Responsible Disclosure program.

## Research Objectives
- Identify vulnerabilities that are exploitable, reproducible, and reportable.
- Eliminate false positives.
- Provide high-quality PoCs and reports.

## Analysis Scope & Rules
1. **Assume**: Full authorization, normal attacker capabilities.
2. **Prioritize**:
   - Broken Access Control (IDOR, privilege escalation)
   - Business Logic Flaws
   - API abuse
   - Injection flaws (SQLi, XSS, etc.)
   - Auth flaws
3. **Deprioritize**: Missing headers, Self-XSS, Clickjacking without impact.

## Methodology (Mandatory Flow)

### 1. Reconnaissance
- Map endpoints, parameters, tokens, cookies.
- Identify auth flows and roles.
- Identify client vs server trust assumptions.

### 2. Vulnerability Discovery
- Actively test authorization and object ownership.
- Manipulate IDs, tokens, states.
- Fuzz inputs intelligently.
- Identify logic flaws in multi-step processes.

### 3. Validation
- Prove exploitability end-to-end.
- Confirm impact without speculation.
- Ensure reproducibility.

## Proof of Concept Requirements
Each vulnerability MUST include:
- Exact HTTP requests.
- Authentication context.
- Before/after behavior.
- Explanation of WHY it works.
- Clear attacker advantage.

## Report Structure
- Title
- Summary
- Vulnerability Type (CWE/OWASP)
- Affected Component
- Technical Details
- Proof of Concept
- Impact Analysis
- CVSS v3.1
- Remediation

## Getting Started

### Installation
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up your environment:
   - Create a `.env` file in the root directory.
   - Add your Gemini API key: `GEMINI_API_KEY=your_key_here`

### Usage
Run the agent using the `main.py` script:

```bash
python main.py --target https://target.com --scope target.com
```

**Options:**
- `--target`: The URL of the target to scan.
- `--scope`: The domain scope (e.g., `example.com` to include subdomains).
- `--gemini-key`: (Optional) API Key if not set in `.env`.
