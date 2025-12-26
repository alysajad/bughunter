from colorama import Fore

class AuthDetector:
    def __init__(self):
        self.login_signatures = [
            "login", "signin", "sign_in", "log_in", "authenticate"
        ]
        self.password_signatures = [
            "password", "pass", "pwd", "key"
        ]

    def find_login_forms(self, forms):
        """
        Analyzes a list of forms to identify login forms.
        """
        print(f"{Fore.CYAN}[*] Analyzing {len(forms)} forms for Auth Flows...")
        
        login_forms = []

        for form in forms:
            score = 0
            action = form.get('action', '').lower()
            inputs = form.get('inputs', [])
            
            # Heuristic 1: URL/Action contains login keywords
            if any(sig in action for sig in self.login_signatures):
                score += 3
            
            # Heuristic 2: Has a password field
            has_password = False
            for inp in inputs:
                if inp['type'] == 'password':
                    score += 5
                    has_password = True
                elif any(sig in inp['name'].lower() for sig in self.password_signatures):
                    score += 2
            
            # Heuristic 3: Small number of fields (usually just user/pass/remember/csrf)
            if 1 <= len(inputs) <= 5 and has_password:
                score += 1

            if score >= 5:
                print(f"{Fore.RED}[!] Login Form Triggered: {form['action']} (Score: {score})")
                login_forms.append(form)

        if not login_forms:
            print(f"{Fore.GREEN}[-] No obvious login forms found.")
            
        return login_forms
