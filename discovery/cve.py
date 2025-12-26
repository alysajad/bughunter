import socket
from colorama import Fore
import time

class CVEAgent:
    def __init__(self):
        pass

    def scan(self, target_host):
        """
        Scans for specific CVEs.
        Args:
           target_host: The host (IP/Domain) to scan.
        """
        findings = []
        
        # CVE-2023-21839: Oracle WebLogic T3 RCE
        # We check for exposed T3/IIOP ports (default 7001) and attempt a handshake.
        print(f"{Fore.CYAN}[*] Checking for CVE-2023-21839 (WebLogic RCE) on {target_host}...")
        
        # 1. Resolve host
        try:
            ip = socket.gethostbyname(target_host)
        except:
            return findings

        # 2. Check Port 7001 (Default WebLogic)
        # Note: In a real scenario, we'd scan all ports, but for this specific Agent we check default.
        if self._check_t3_handshake(ip, 7001):
             print(f"{Fore.RED}[!!!] WebLogic T3 Service Detected at {ip}:7001")
             findings.append({
                 "cve": "CVE-2023-21839",
                 "title": "Oracle WebLogic T3 RCE",
                 "url": f"t3://{target_host}:7001",
                 "details": "Exposed T3 protocol allowing JNDI lookup.",
                 "severity": "Critical"
             })
        
        return findings

    def _check_t3_handshake(self, ip, port):
        """
        Sends a T3 handshake packet to verify the service.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, port))
            
            # T3 Handshake Header
            # "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n"
            handshake = b"t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n"
            sock.sendall(handshake)
            
            data = sock.recv(1024)
            sock.close()
            
            # Check response for "HELO" or "L: " signature from WebLogic
            if b"HELO" in data or b"12.2.1" in data or b"10.3.6" in data:
                return True
                
        except Exception:
            return False
            
        return False
