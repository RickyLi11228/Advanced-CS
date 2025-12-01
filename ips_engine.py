# ips_engine.py (advanced IPS with signatures, behavior, threat scoring, auto-block)
from datetime import datetime
from collections import defaultdict


class IntrusionPreventionSystem:
    """
    Simulated IPS with:
      - Signature-based detection
      - Behavior-based rate limiting per source IP
      - Threat scoring per source IP
      - Auto-block when threat score exceeds a threshold
    """

    def __init__(self):
        self.signatures = []            # list of dicts: pattern, action, severity, description
        self.behavior_rules = {}        # e.g., {"max_requests_per_src": {"threshold": 5, "action": "block"}}
        self.src_counters = defaultdict(int)   # counts per source IP
        self.threat_scores = defaultdict(int)  # threat score per source
        self.auto_block_enabled = True
        self.auto_block_threshold = 10   # default threshold
        self.logs = []                  # list of log dicts

    # -----------------------
    # Signature Management
    # -----------------------
    def add_signature(self, pattern, action="block", severity="high", description=""):
        sig = {
            "pattern": pattern,
            "action": action.lower(),        # "block", "alert", "allow"
            "severity": severity.lower(),    # "low", "medium", "high"
            "description": description
        }
        self.signatures.append(sig)
        return sig

    def list_signatures(self):
        return self.signatures

    def remove_signature(self, pattern):
        before = len(self.signatures)
        self.signatures = [s for s in self.signatures if s["pattern"] != pattern]
        return len(self.signatures) < before

    # -----------------------
    # Behavior Rules
    # -----------------------
    def set_max_requests_per_src(self, threshold, action="block"):
        self.behavior_rules["max_requests_per_src"] = {
            "threshold": threshold,
            "action": action.lower()
        }

    def reset_behavior_state(self):
        self.src_counters.clear()

    # -----------------------
    # Auto-block & Threat Scoring
    # -----------------------
    def set_auto_block(self, enabled: bool, threshold: int = None):
        self.auto_block_enabled = enabled
        if threshold is not None and threshold > 0:
            self.auto_block_threshold = threshold

    def _severity_points(self, severity: str) -> int:
        sev = severity.lower()
        if sev == "high":
            return 5
        if sev == "medium":
            return 3
        if sev == "low":
            return 1
        return 1

    # -----------------------
    # Packet Inspection
    # -----------------------
    def inspect_packet(self, src_ip, dst_ip, port, protocol, payload):
        """
        Returns (decision, reason, current_threat_score_for_src)
        Order:
          0. Check auto-block based on existing threat score
          1. Check signature-based detection
          2. Check behavior-based detection
          3. Re-check auto-block after scoring
          4. Log everything
        """
        src_ip = src_ip.strip()
        dst_ip = dst_ip.strip()
        port = str(port).strip()
        protocol = protocol.lower().strip()
        payload_str = str(payload)

        # 0. Auto-block check first
        if self.auto_block_enabled and self.threat_scores[src_ip] >= self.auto_block_threshold:
            decision = "block"
            reason = f"auto-block: threat score {self.threat_scores[src_ip]} >= threshold {self.auto_block_threshold}"
        else:
            decision = "allow"
            reason = "no rule matched"

            # 1. Signature-Based Matching
            payload_lower = payload_str.lower()
            for sig in self.signatures:
                if sig["pattern"].lower() in payload_lower:
                    decision = sig["action"]
                    reason = f"signature match: '{sig['pattern']}' (severity={sig['severity']})"
                    # increase threat score based on severity
                    self.threat_scores[src_ip] += self._severity_points(sig["severity"])
                    break  # first match wins

            # 2. Behavior-Based Detection
            if decision == "allow":
                self.src_counters[src_ip] += 1
                rule = self.behavior_rules.get("max_requests_per_src")
                if rule:
                    threshold = rule["threshold"]
                    if self.src_counters[src_ip] > threshold:
                        decision = rule["action"]
                        reason = f"behavior: source {src_ip} exceeded {threshold} requests"
                        # bump score for noisy behavior
                        self.threat_scores[src_ip] += 2

            # 3. Auto-block after scoring
            if self.auto_block_enabled and self.threat_scores[src_ip] >= self.auto_block_threshold:
                decision = "block"
                reason = f"auto-block: threat score {self.threat_scores[src_ip]} >= threshold {self.auto_block_threshold}"

        # 4. Logging
        log_entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": src_ip,
            "dst": dst_ip,
            "port": port,
            "protocol": protocol,
            "payload": (payload_str[:50] + "...") if len(payload_str) > 50 else payload_str,
            "decision": decision,
            "reason": reason,
            "threat_score": self.threat_scores[src_ip]
        }
        self.logs.append(log_entry)
        return decision, reason, self.threat_scores[src_ip]

    # -----------------------
    # Logging
    # -----------------------
    def get_logs(self):
        return self.logs

    def clear_logs(self):
        self.logs.clear()
        self.src_counters.clear()
        # threat_scores intentionally NOT cleared to simulate long-lived reputation