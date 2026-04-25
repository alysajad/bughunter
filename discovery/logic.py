from colorama import Fore
from llm.client import ClaudeClient
from llm.prompts_templates import VULN_ANALYSIS_PROMPT

class LogicAnalyzer:
    def __init__(self, claude_client: ClaudeClient):
        self.client = claude_client

    def analyze_flow(self, request_response_pair):
        """
        Sends a request/response pair (or a sequence) to Claude for analysis.
        """
        print(f"{Fore.CYAN}[*] Sending flow to Claude for logic analysis...")
        
        # Prepare the content for the LLM
        content = f"""
        REQUEST:
        {request_response_pair.get('request')}
        
        RESPONSE:
        {request_response_pair.get('response')}
        """
        
        analysis = self.client.analyze(content, VULN_ANALYSIS_PROMPT)
        
        if analysis:
            print(f"{Fore.GREEN}[+] Claude Analysis Received:")
            print(f"{Fore.WHITE}{analysis}\n")
            return analysis
        else:
            print(f"{Fore.RED}[!] Claude analysis failed to return a result.")
            return None
