import json
from colorama import Fore
from llm.client import ClaudeClient
from llm.prompts_templates import (
    PLANNING_PROMPT, RECON_ANALYSIS_PROMPT, 
    ENUMERATION_PROMPT, EXPLOITATION_PROMPT
)

class Orchestrator:
    """AI Orchestrator Agent (Claude-Powered) managing the BugHunter lifecycle."""

    def __init__(self, claude_client: ClaudeClient):
        self.client = claude_client

    def phase_1_planning(self, target_url, scope, endpoints, forms):
        """Creates an attack strategy based on initial recon."""
        print(f"\n{Fore.MAGENTA}[=] ORCHESTRATOR: Phase 1 - Planning Strategy for {target_url} [=]")
        
        target_info = f"URL: {target_url}\nScope: {scope}\n"
        target_info += f"Discovered Endpoints ({len(endpoints)}):\n" + "\n".join(list(endpoints)[:10]) + "\n"
        target_info += f"Discovered Forms ({len(forms)}):\n"
        for f in forms:
             target_info += f"- {f['method']} {f['action']} (Inputs: {[i['name'] for i in f.get('inputs', [])]})\n"

        response = self.client.analyze(target_info, PLANNING_PROMPT)
        
        if response:
            try:
                # Try to extract JSON if Claude wrapped it in markdown blocks
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                    plan = json.loads(json_str)
                else:
                    plan = json.loads(response)
                
                print(f"{Fore.GREEN}[+] AI Attack Plan Generated:")
                print(f"{Fore.WHITE}Analysis: {plan.get('target_analysis', 'N/A')}")
                print(f"{Fore.WHITE}Priority Agents: {', '.join(plan.get('priority_agents', []))}")
                print(f"{Fore.WHITE}Fuzz Targets: {', '.join(plan.get('custom_parameters_to_fuzz', []))}")
                return plan
            except json.JSONDecodeError:
                print(f"{Fore.YELLOW}[!] Failed to parse AI JSON. Raw response:\n{response}")
                return None
        return None

    def phase_2_recon_analysis(self, subdomains, endpoints, login_forms):
        """Analyzes recon data for specific high-value targets."""
        print(f"\n{Fore.MAGENTA}[=] ORCHESTRATOR: Phase 2 - Recon Analysis [=]")
        
        recon_data = f"Subdomains:\n{subdomains}\n\n"
        recon_data += f"Endpoints:\n{endpoints}\n\n"
        recon_data += f"Login Forms:\n{login_forms}\n"

        analysis = self.client.analyze(recon_data, RECON_ANALYSIS_PROMPT)
        if analysis:
            print(f"{Fore.WHITE}{analysis}\n")
        return analysis

    def phase_3_enumeration(self, findings_summary):
        """Reviews findings to suggest chains or manual follow-ups."""
        print(f"\n{Fore.MAGENTA}[=] ORCHESTRATOR: Phase 3 - Enumeration Review [=]")
        
        if not findings_summary:
            print(f"{Fore.YELLOW}[-] No findings to review.")
            return None

        analysis = self.client.analyze(str(findings_summary), ENUMERATION_PROMPT)
        if analysis:
            print(f"{Fore.WHITE}{analysis}\n")
        return analysis

    def phase_4_exploitation_report(self, verified_findings):
        """Generates the final vulnerability impact summary."""
        print(f"\n{Fore.MAGENTA}[=] ORCHESTRATOR: Phase 4 - Final Reporting & Validation [=]")
        
        if not verified_findings:
            return "No verified findings to report."

        summary = self.client.analyze(str(verified_findings), EXPLOITATION_PROMPT)
        if summary:
            print(f"{Fore.WHITE}{summary}\n")
            return summary
        return None
