# firewall_engine.py
from datetime import datetime


class FirewallSimulator:
    """
    Simple firewall simulator with:
      - Ordered rule list (First Match Wins)
      - Rule add/delete
      - Rule reordering (move up/down)
      - Logging of packet decisions
    """

    def __init__(self):
        self.rules = []  # list of dicts: name, action, port, protocol
        self.logs = []   # list of dicts: time, port, protocol, decision

    # -----------------------
    # Rule Management
    # -----------------------
    def add_rule(self, name, action, port, protocol="tcp"):
        rule = {
            "name": name,
            "action": action.lower(),   # "allow" or "deny"
            "port": str(port).strip(),
            "protocol": protocol.lower().strip()
        }
        self.rules.append(rule)
        return rule

    def delete_rule(self, name):
        """
        Deletes the first rule with the given name.
        Returns True if a rule was deleted, False otherwise.
        """
        for i, r in enumerate(self.rules):
            if r["name"] == name:
                del self.rules[i]
                return True
        return False

    def move_rule_up(self, name):
        """
        Moves the first rule with this name one position up in the list.
        Returns True if moved, False if not found or already at top.
        """
        idx = None
        for i, r in enumerate(self.rules):
            if r["name"] == name:
                idx = i
                break

        if idx is None or idx == 0:
            return False  # not found or already at top

        self.rules[idx - 1], self.rules[idx] = self.rules[idx], self.rules[idx - 1]
        return True

    def move_rule_down(self, name):
        """
        Moves the first rule with this name one position down in the list.
        Returns True if moved, False if not found or already at bottom.
        """
        idx = None
        for i, r in enumerate(self.rules):
            if r["name"] == name:
                idx = i
                break

        if idx is None or idx == len(self.rules) - 1:
            return False  # not found or already at bottom

        self.rules[idx + 1], self.rules[idx] = self.rules[idx], self.rules[idx + 1]
        return True

    def list_rules(self):
        """
        Returns the current rule list in order.
        """
        return self.rules

    # -----------------------
    # Packet Simulation
    # -----------------------
    def simulate_packet(self, port, protocol):
        """
        First Match Wins (FMFW):
          - Iterate rules in order
          - First rule whose port+protocol match decides the action
          - If no rule matches, DEFAULT = deny
        """
        port = str(port).strip()
        protocol = protocol.lower().strip()

        decision = "deny"  # default policy: deny (best practice)

        # First Match Wins
        for rule in self.rules:
            if rule["port"] == port and rule["protocol"] == protocol:
                decision = rule["action"]
                break

        log_entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "port": port,
            "protocol": protocol,
            "decision": decision
        }
        self.logs.append(log_entry)
        return decision

    # -----------------------
    # Logging
    # -----------------------
    def show_logs(self):
        return self.logs

    def clear_logs(self):
        self.logs.clear()