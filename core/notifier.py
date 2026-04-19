import requests

class DiscordNotifier:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send_critical(self, ip, score, service, attempts):
        # Sends an Embed message to Discord
        if not self.webhook_url:
            print("[!] Error: There's no URL of Webhook configurated.")
            return

        # Creates the "Embed" message
        payload = {
            "username": "VigilanteCore Sentinel",
            "embeds": [{
                "title": "🚨 CRITICAL ALERT: SUSPICIOUS ACTIVITY",
                "color": 15158332,  # RED
                "fields": [
                    {"name": "🌍 Attacker's IP", "value": f"`{ip}`", "inline": True},
                    {"name": "📊 Reputation (Intel)", "value": score, "inline": True},
                    {"name": "🛠️ Service", "value": service.upper(), "inline": True},
                    {"name": "📉 Tries", "value": str(attempts), "inline": True}
                ],
                "footer": {"text": "SOAR Module - VigilanteCore v1.0"}
            }]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            if response.status_code == 204:
                print("[+] Notification send to Discord succesfully.")
            else:
                print(f"[!] Discord answered with error: {response.status_code}")
        except Exception as e:
            print(f"[!] Failed to connect to Discord: {e}")