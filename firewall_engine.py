from datetime import datetime

class FirewallSimulator:
    def __init__(self):
        self.rules = []
        self.logs = []

    def add_rule(self, name, action, port, protocol="tcp", color="green"):
        rule = {
            "name": name,
            "action": action,
            "port": port,
            "protocol": protocol,
            "color": color,
            "timestamp": datetime.now().isoformat()
        }
        self.rules.append(rule)
        return rule

    def delete_rule(self, name):
        before = len(self.rules)
        self.rules = [r for r in self.rules if r["name"] != name]
        after = len(self.rules)
        return before != after

    def list_rules(self):
        return self.rules

    def simulate_packet(self, port, protocol="tcp"):
        # First match wins
        for rule in self.rules:
            if (rule["port"] == port or rule["port"] == "any") and \
                rule["protocol"] == protocol:

                decision = rule["action"]
                break
        else:
            decision = "deny"  # Default deny

        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "port": port,
            "protocol": protocol,
            "decision": decision
        }
        self.logs.append(entry)
        return decision

    def get_logs(self):
        return self.logs