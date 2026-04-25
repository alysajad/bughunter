import anthropic
import os
from colorama import Fore

class ClaudeClient:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Anthropic API Key is required. Set ANTHROPIC_API_KEY env var or pass it explicitly.")
        
        # Initialize the Anthropic Client
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model_id = 'claude-sonnet-4-20250514'

    def analyze(self, content, prompt_template):
        """
        Analyzes the given content using Claude with the specified prompt template.
        Uses the Anthropic Python SDK.
        """
        try:
            full_prompt = f"{prompt_template}\n\nINPUT DATA:\n{content}"
            
            # Use the Anthropic Messages API
            message = self.client.messages.create(
                model=self.model_id,
                max_tokens=4096,
                messages=[
                    {"role": "user", "content": full_prompt}
                ]
            )
            
            return message.content[0].text
        except Exception as e:
            print(f"{Fore.RED}[!] Claude Error: {e}")
            return None
