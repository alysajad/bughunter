class ReportBuilder:
    def __init__(self):
        self.vulnerabilities = []

    def add_vulnerability(self, vuln_data):
        """
        vuln_data should be a dict matching strict fields:
        Title, Summary, VunType, Component, Details, PoC, Impact, CVSS, Remediation
        """
        self.vulnerabilities.append(vuln_data)

    def generate_markdown(self):
        report = "# Vulnerability Report\n\n"
        for vuln in self.vulnerabilities:
            report += f"## {vuln.get('Title')}\n\n"
            report += f"**Summary:**\n{vuln.get('Summary')}\n\n"
            report += f"**Vulnerability Type:** {vuln.get('Type')}\n"
            report += f"**Affected Component:** {vuln.get('Component')}\n\n"
            report += f"### Technical Details\n{vuln.get('Details')}\n\n"
            report += f"### Proof of Concept\n{vuln.get('PoC')}\n\n"
            report += f"### Impact Analysis\n{vuln.get('Impact')}\n\n"
            report += f"### CVSS v3.1\n{vuln.get('CVSS')}\n\n"
            report += f"### Remediation\n{vuln.get('Remediation')}\n\n"
            report += "---\n\n"
        return report

    def save_report(self, filename="report.md"):
        with open(filename, "w") as f:
            f.write(self.generate_markdown())
        print(f"Report saved to {filename}")
