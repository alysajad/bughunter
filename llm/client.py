import google.generativeai as genai
import os
from colorama import Fore

class GeminiClient:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API Key is required. Set GEMINI_API_KEY env var or pass it explicitly.")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-pro')

    def analyze(self, content, prompt_template):
        """
        Analyzes the given content using Gemini with the specified prompt template.
        """
        try:
            full_prompt = f"{prompt_template}\n\nINPUT DATA:\n{content}"
            response = self.model.generate_content(full_prompt)
            return response.text
        except Exception as e:
            print(f"{Fore.RED}[!] Gemini Error: {e}")
            return None
