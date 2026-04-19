import os
import json
import time
from datetime import datetime
from dotenv import load_dotenv # To read env

from core.parser import LogParser
from core.engine import DetectionEngine
from core.intel import ThreatIntel      
from core.notifier import DiscordNotifier 
from core.blocker import FirewallBlocker 

load_dotenv()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
DISCORD_URL = os.getenv("DISCORD_WEBHOOK_URL")

def save_report(detections, filename="alerts/report.json"):
    # Keeps track of the detections in a JSON
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, "w") as f:
            json.dump(detections, f, indent=4)
        print(f"\n[+] Final report generated: {filename}")
    except Exception as e:
        print(f"[!] Error saving report: {e}")

def main():
    # Initializing Modules
    parser = LogParser()
    engine = DetectionEngine("rules/")
    intel = ThreatIntel(ABUSE_KEY)
    notifier = DiscordNotifier(DISCORD_URL)
    blocker = FirewallBlocker(enabled=True)

    LOG_FILE = "logs/sample_auth.log"
    threat_counter = {}
    detected_ips = set()
    all_detections = []
    BRUTE_FORCE_THRESHOLD = 3

    print("\n" + "="*50)
    print("VIGILANTE CORE - SENTINEL MODE ACTIVE")
    print("="*50)
    print(f"[*] Target: {LOG_FILE}")
    print(f"[*] Intel: {'ENABLED' if ABUSE_KEY else 'DISABLED'}")
    print(f"[*] Discord: {'ENABLED' if DISCORD_URL else 'DISABLED'}")
    print("[*] Press Ctrl+C to stop and save report.\n")

    try:
        with open(LOG_FILE, "r") as f:
            # f.seek(0, os.SEEK_END) to ignorar old logs
            while True:
                line = f.readline()

                # If no new line, wait a bit
                if not line:
                    time.sleep(0.1)
                    continue

                structured_log = parser.parse_line(line)
                if not structured_log:
                    continue
                
                ip = structured_log.get('src_ip')
                event = structured_log.get('event_type')
                service = structured_log.get('service', 'unknown')

                # A. Atomic Detection Logic
                if ip not in detected_ips:
                    alerts = engine.check_rules(structured_log)
                    for alert in alerts:
                        detection = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "rule": alert['name'],
                            "severity": alert['severity'],
                            "attacker_ip": ip,
                            "service": service,
                            "details": structured_log.get('message', 'N/A')
                        }
                        all_detections.append(detection)
                        print(f"[!] ALERT: {alert['name']} | IP: {ip}")

                # B. Stateful Detection Logic (Correlation)
                if event in ['failed_login', 'web_not_found'] and ip:
                    threat_counter[ip] = threat_counter.get(ip, 0) + 1

                    if threat_counter[ip] == BRUTE_FORCE_THRESHOLD and ip not in detected_ips:
                        # Enriquecimiento con Intel
                        print(f"\n[*] Investigating IP: {ip}...")
                        reputation = intel.get_ip_reputation(ip)
                        
                        # Notificación SOAR
                        notifier.send_critical(
                            ip=ip, 
                            score=reputation, 
                            service=service, 
                            attempts=threat_counter[ip]
                        )

                        print(f"[*] Activating Firewall block for {ip}...")
                        block_success = blocker.block_ip(ip)

                        # Registro de alerta crítica
                        critical_alert = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "rule": "CRITICAL_THRESHOLD_REACHED",
                            "severity": "CRITICAL",
                            "attacker_ip": ip,
                            "reputation": reputation,
                            "total_events": threat_counter[ip],
                            "firewall_blocked": block_success,
                            "action_recommended": "BLOCK_IP_IMMEDIATELY"
                        }
                        all_detections.append(critical_alert)
                        detected_ips.add(ip)
                        print(f"[!!!] CRITICAL ALERT: Threshold reached for {ip}. Reputation: {reputation}")

    except KeyboardInterrupt:
        print("\n\n[!] Sentinel stopped by user.")
        if all_detections:
            save_report(all_detections)
        print("[*] Shutdown complete. Stay vigilant.")

    except FileNotFoundError:
        print(f"[!] Error: The log file '{LOG_FILE}' was not found.")
        
    except Exception as e:
        print(f"[!] Unexpected Error: {e}")

if __name__ == "__main__":
    main()