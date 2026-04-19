import subprocess

class FirewallBlocker:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def block_ip(self, ip):
        # Executes iptables to block malicious IP
        if not self.enabled:
            print(f"[*] Simulation: IP {ip} would be blocked.")
            return False

        try:
            command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[+++] FIREWALL: IP {ip} has been blocked successfully.")
                return True
            else:
                print(f"[!] FIREWALL ERROR: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Exception during firewall block: {e}")
            return False