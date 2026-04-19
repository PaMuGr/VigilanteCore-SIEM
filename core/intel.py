import requests

class ThreatIntel:
    def __init__(self, api_key):
        # Initializes module with API Key of AbuseIPDB
        self.api_key = api_key
        self.url = 'https://api.abuseipdb.com/api/v2/check'

    def get_ip_reputation(self, ip):
        # Checks IP reputations and returns string with abuse score and country
        if not self.api_key or self.api_key == "None":
            return "Intel: No API Key configurada"

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90' # Buscamos reportes de los últimos 3 meses
        }

        try:
            # API petition
            response = requests.get(self.url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                score = data['data']['abuseConfidenceScore']
                country = data['data']['countryCode']
                
                return f"{score}% Abuse Confidence Score (Country: {country})"
            
            elif response.status_code == 401:
                return "Intel: Invalid API Key"
            else:
                return f"Intel: Error {response.status_code}"
                
        except Exception:
            return "Intel: API connection error"