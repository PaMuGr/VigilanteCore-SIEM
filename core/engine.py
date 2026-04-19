import json
import os

class DetectionEngine:
    def __init__(self, rules_path):
        self.rules_path = rules_path
        self.rules = self.load_rules()

    def load_rules(self):
        # Loads all JSON rules from /rules
        loaded_rules = []
        if not os.path.exists(self.rules_path):
            print(f"[!] Error: The folder {self.rules_path} was not found.")
            return loaded_rules
        
        #Transverses all files checking and loading them
        for filename in os.listdir(self.rules_path):
            if filename.endswith(".json"):
                path = os.path.join(self.rules_path, filename)
                with open(path, 'r') as f:
                    try:
                        rule_data = json.load(f)
                        loaded_rules.append(rule_data)
                    except json.JSONDecodeError:
                        print(f"[!] Error: Couldn't read file {filename}")
        print(f"[*] Engine ready: {len(loaded_rules)} rules loaded.")
        return loaded_rules
    
    def check_rules(self, log_entry):
        # Check log_entry with each of the rules conditions

        matched_rules = []

        for rule in self.rules:
            conditions = rule.get('conditions', {})
            is_match = True

            for key, expected_value in conditions.items():
                # If the key not on log or value doesn't match -> false
                if log_entry.get(key) != expected_value:
                    is_match = False
                    break

            if is_match:
                matched_rules.append(rule)

        return matched_rules

