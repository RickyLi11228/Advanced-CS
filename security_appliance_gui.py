# security_appliance_gui.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv

from firewall_engine import FirewallSimulator
from ips_engine import IntrusionPreventionSystem


# =========================
# FIREWALL TAB
# =========================

def build_firewall_tab(parent):
    fw = FirewallSimulator()

    # ---------- Rule Controls ----------
    frame_rules = tk.LabelFrame(parent, text="Firewall Rules (First Match Wins)")
    frame_rules.pack(fill="x", padx=10, pady=5)

    tk.Label(frame_rules, text="Name:").grid(row=0, column=0, sticky="e")
    rule_name = tk.StringVar()
    rule_name_entry = tk.Entry(frame_rules, textvariable=rule_name, width=20)
    rule_name_entry.grid(row=0, column=1, padx=5, pady=2)

    tk.Label(frame_rules, text="Action:").grid(row=1, column=0, sticky="e")
    rule_action = tk.StringVar(value="allow")
    ttk.Combobox(frame_rules, textvariable=rule_action, values=["allow", "deny"], width=10) \
        .grid(row=1, column=1, sticky="w", pady=2)

    tk.Label(frame_rules, text="Port:").grid(row=2, column=0, sticky="e")
    rule_port = tk.StringVar(value="80")
    tk.Entry(frame_rules, textvariable=rule_port, width=10).grid(row=2, column=1, padx=5, pady=2)

    tk.Label(frame_rules, text="Protocol:").grid(row=3, column=0, sticky="e")
    rule_protocol = tk.StringVar(value="tcp")
    ttk.Combobox(frame_rules, textvariable=rule_protocol, values=["tcp", "udp"], width=10) \
        .grid(row=3, column=1, sticky="w", pady=2)

    # ---------- Rule Table ----------
    frame_rule_list = tk.LabelFrame(parent, text="Current Firewall Rules (Top = First Match)")
    frame_rule_list.pack(fill="both", expand=True, padx=10, pady=5)

    rules_table = ttk.Treeview(
        frame_rule_list,
        columns=("Name", "Action", "Port", "Protocol"),
        show="headings",
        height=5
    )
    for col in ("Name", "Action", "Port", "Protocol"):
        rules_table.heading(col, text=col)
        rules_table.column(col, width=120)

    rules_table.pack(fill="both", expand=True, side="left")
    scrollbar = ttk.Scrollbar(frame_rule_list, orient="vertical", command=rules_table.yview)
    rules_table.configure(yscroll=scrollbar.set)
    scrollbar.pack(side="right", fill="y")

    # ---------- Callbacks ----------
    def refresh_rules():
        rules_table.delete(*rules_table.get_children())
        for r in fw.list_rules():
            rules_table.insert("", "end", values=(r["name"], r["action"], r["port"], r["protocol"]))

    def add_rule():
        name = rule_name.get().strip()
        action = rule_action.get()
        port = rule_port.get().strip()
        protocol = rule_protocol.get()

        if not name:
            messagebox.showerror("Error", "Rule name is required.")
            return

        if not port.isdigit():
            messagebox.showerror("Error", "Port must be a number.")
            return

        fw.add_rule(name, action, port, protocol)
        refresh_rules()
        rule_name_entry.delete(0, tk.END)

    def delete_rule():
        # Prefer selected row; fallback to name text box
        selected = rules_table.selection()
        if selected:
            values = rules_table.item(selected[0], "values")
            name = values[0]
        else:
            name = rule_name.get().strip()

        if not name:
            messagebox.showerror("Error", "Select a rule or enter a rule name to delete.")
            return

        if fw.delete_rule(name):
            refresh_rules()
            messagebox.showinfo("Deleted", f"Rule '{name}' removed.")
        else:
            messagebox.showerror("Not Found", f"No rule named '{name}' found.")

    def move_rule_up():
        selected = rules_table.selection()
        if not selected:
            messagebox.showerror("Error", "Select a rule to move up.")
            return
        values = rules_table.item(selected[0], "values")
        name = values[0]

        if fw.move_rule_up(name):
            refresh_rules()
        else:
            messagebox.showinfo("Info", "Rule is already at the top or not found.")

    def move_rule_down():
        selected = rules_table.selection()
        if not selected:
            messagebox.showerror("Error", "Select a rule to move down.")
            return
        values = rules_table.item(selected[0], "values")
        name = values[0]

        if fw.move_rule_down(name):
            refresh_rules()
        else:
            messagebox.showinfo("Info", "Rule is already at the bottom or not found.")

    # Buttons
    tk.Button(frame_rules, text="Add Rule", command=add_rule).grid(row=4, column=0, pady=5)
    tk.Button(frame_rules, text="Delete Rule", command=delete_rule).grid(row=4, column=1, pady=5, sticky="w")
    tk.Button(frame_rules, text="Move Up", command=move_rule_up).grid(row=5, column=0, pady=5)
    tk.Button(frame_rules, text="Move Down", command=move_rule_down).grid(row=5, column=1, pady=5, sticky="w")

    # ---------- Packet Simulation ----------
    frame_sim = tk.LabelFrame(parent, text="Simulate Packet (Firewall)")
    frame_sim.pack(fill="x", padx=10, pady=5)

    tk.Label(frame_sim, text="Port:").grid(row=0, column=0, sticky="e")
    sim_port = tk.StringVar(value="80")
    tk.Entry(frame_sim, textvariable=sim_port, width=10).grid(row=0, column=1, padx=5)

    tk.Label(frame_sim, text="Protocol:").grid(row=1, column=0, sticky="e")
    sim_protocol = tk.StringVar(value="tcp")
    ttk.Combobox(frame_sim, textvariable=sim_protocol, values=["tcp", "udp"], width=10) \
        .grid(row=1, column=1, padx=5)

    # ---------- Firewall Logs ----------
    frame_logs = tk.LabelFrame(parent, text="Firewall Logs")
    frame_logs.pack(fill="both", expand=True, padx=10, pady=5)

    fw_log_table = ttk.Treeview(
        frame_logs,
        columns=("Time", "Port", "Protocol", "Decision"),
        show="headings",
        height=6
    )
    for col in ("Time", "Port", "Protocol", "Decision"):
        fw_log_table.heading(col, text=col)
        fw_log_table.column(col, width=120)
    fw_log_table.pack(fill="both", expand=True)

    def refresh_logs():
        fw_log_table.delete(*fw_log_table.get_children())
        for log in fw.show_logs():
            fw_log_table.insert("", "end", values=(
                log["time"], log["port"], log["protocol"], log["decision"]
            ))

    def simulate_packet():
        port = sim_port.get().strip()
        protocol = sim_protocol.get()
        if not port.isdigit():
            messagebox.showerror("Error", "Port must be a number.")
            return
        decision = fw.simulate_packet(port, protocol)
        messagebox.showinfo("Firewall Result", f"Decision: {decision.upper()}")
        refresh_logs()

    def export_fw_logs():
        logs = fw.show_logs()
        if not logs:
            messagebox.showinfo("No Logs", "There are no firewall logs to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save Firewall Logs As"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["time", "port", "protocol", "decision"])
                for log in logs:
                    writer.writerow([log["time"], log["port"], log["protocol"], log["decision"]])
            messagebox.showinfo("Success", f"Firewall logs exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save CSV:\n{e}")

    tk.Button(frame_sim, text="Simulate Packet", command=simulate_packet) \
        .grid(row=2, column=0, columnspan=2, pady=5)

    tk.Button(frame_logs, text="Export Firewall Logs to CSV", command=export_fw_logs) \
        .pack(pady=5)


# =========================
# IPS TAB
# =========================

def build_ips_tab(parent):
    ips = IntrusionPreventionSystem()

    # ---------- Signatures ----------
    frame_sig = tk.LabelFrame(parent, text="Signature-Based Detection")
    frame_sig.pack(fill="x", padx=10, pady=5)

    tk.Label(frame_sig, text="Pattern:").grid(row=0, column=0, sticky="e")
    sig_pattern = tk.StringVar()
    sig_pattern_entry = tk.Entry(frame_sig, textvariable=sig_pattern, width=30)
    sig_pattern_entry.grid(row=0, column=1, padx=5)

    tk.Label(frame_sig, text="Action:").grid(row=1, column=0, sticky="e")
    sig_action = tk.StringVar(value="block")
    ttk.Combobox(frame_sig, textvariable=sig_action, values=["block", "alert", "allow"], width=10) \
        .grid(row=1, column=1, sticky="w")

    tk.Label(frame_sig, text="Severity:").grid(row=2, column=0, sticky="e")
    sig_severity = tk.StringVar(value="high")
    ttk.Combobox(frame_sig, textvariable=sig_severity, values=["low", "medium", "high"], width=10) \
        .grid(row=2, column=1, sticky="w")

    tk.Label(frame_sig, text="Description:").grid(row=3, column=0, sticky="e")
    sig_description = tk.StringVar()
    sig_description_entry = tk.Entry(frame_sig, textvariable=sig_description, width=40)
    sig_description_entry.grid(row=3, column=1, padx=5)

    # Signature table
    sig_table_frame = tk.LabelFrame(parent, text="Current IPS Signatures")
    sig_table_frame.pack(fill="both", expand=True, padx=10, pady=5)

    sig_table = ttk.Treeview(
        sig_table_frame,
        columns=("Pattern", "Action", "Severity", "Description"),
        show="headings",
        height=5
    )
    for col in ("Pattern", "Action", "Severity", "Description"):
        sig_table.heading(col, text=col)
        sig_table.column(col, width=140)
    sig_table.pack(fill="both", expand=True)

    def refresh_signatures():
        sig_table.delete(*sig_table.get_children())
        for s in ips.list_signatures():
            sig_table.insert("", "end", values=(s["pattern"], s["action"], s["severity"], s["description"]))

    def add_signature():
        pattern = sig_pattern.get().strip()
        action = sig_action.get()
        severity = sig_severity.get()
        desc = sig_description.get().strip()

        if not pattern:
            messagebox.showerror("Error", "Signature pattern is required.")
            return

        sig = ips.add_signature(pattern, action, severity, desc)
        refresh_signatures()
        messagebox.showinfo("Signature Added", f"Added signature '{sig['pattern']}'")
        sig_pattern_entry.delete(0, tk.END)
        sig_description_entry.delete(0, tk.END)

    def remove_signature():
        # Prefer selected row; fallback to pattern text box
        selected = sig_table.selection()
        if selected:
            values = sig_table.item(selected[0], "values")
            pattern = values[0]
        else:
            pattern = sig_pattern.get().strip()

        if not pattern:
            messagebox.showerror("Error", "Select a signature or enter a pattern to remove.")
            return

        if ips.remove_signature(pattern):
            refresh_signatures()
            messagebox.showinfo("Removed", f"Removed signature '{pattern}'")
        else:
            messagebox.showerror("Not Found", f"No signature '{pattern}' found.")

    tk.Button(frame_sig, text="Add Signature", command=add_signature) \
        .grid(row=4, column=0, pady=5)
    tk.Button(frame_sig, text="Remove Signature", command=remove_signature) \
        .grid(row=4, column=1, pady=5)

    # ---------- Behavior ----------
    frame_behavior = tk.LabelFrame(parent, text="Behavior-Based Detection")
    frame_behavior.pack(fill="x", padx=10, pady=5)

    tk.Label(frame_behavior, text="Max requests per source:").grid(row=0, column=0, sticky="e")
    behavior_threshold = tk.StringVar(value="5")
    tk.Entry(frame_behavior, textvariable=behavior_threshold, width=10) \
        .grid(row=0, column=1, sticky="w", padx=5)

    tk.Label(frame_behavior, text="Action:").grid(row=1, column=0, sticky="e")
    behavior_action = tk.StringVar(value="block")
    ttk.Combobox(frame_behavior, textvariable=behavior_action, values=["block", "alert"], width=10) \
        .grid(row=1, column=1, sticky="w", padx=5)

    tk.Label(frame_behavior, text="Auto-block threshold (threat score):").grid(row=2, column=0, sticky="e")
    auto_threshold = tk.StringVar(value="10")
    tk.Entry(frame_behavior, textvariable=auto_threshold, width=10) \
        .grid(row=2, column=1, sticky="w", padx=5)

    auto_block_var = tk.BooleanVar(value=True)
    tk.Checkbutton(frame_behavior, text="Enable Auto-Block", variable=auto_block_var) \
        .grid(row=3, column=0, columnspan=2, sticky="w", padx=5)

    def apply_behavior():
        try:
            threshold = int(behavior_threshold.get())
            if threshold <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Max requests per source must be a positive integer.")
            return

        action = behavior_action.get()
        ips.set_max_requests_per_src(threshold, action)

        try:
            auto_th_val = int(auto_threshold.get())
            if auto_th_val <= 0:
                raise ValueError
        except ValueError:
            auto_th_val = 10

        ips.set_auto_block(auto_block_var.get(), auto_th_val)
        ips.reset_behavior_state()
        messagebox.showinfo(
            "Behavior Rules Applied",
            f"Max req/src={threshold}, action={action}, "
            f"auto-block={auto_block_var.get()}, threshold={auto_th_val}"
        )

    tk.Button(frame_behavior, text="Apply Behavior Rules", command=apply_behavior) \
        .grid(row=0, column=2, rowspan=2, padx=10)

    # ---------- Packet Simulation ----------
    frame_packet = tk.LabelFrame(parent, text="Simulate Packet (IPS)")
    frame_packet.pack(fill="x", padx=10, pady=5)

    tk.Label(frame_packet, text="Source IP:").grid(row=0, column=0, sticky="e")
    packet_src = tk.StringVar(value="10.0.0.1")
    tk.Entry(frame_packet, textvariable=packet_src, width=15).grid(row=0, column=1, padx=5)

    tk.Label(frame_packet, text="Destination IP:").grid(row=0, column=2, sticky="e")
    packet_dst = tk.StringVar(value="10.0.0.2")
    tk.Entry(frame_packet, textvariable=packet_dst, width=15).grid(row=0, column=3, padx=5)

    tk.Label(frame_packet, text="Port:").grid(row=1, column=0, sticky="e")
    packet_port = tk.StringVar(value="80")
    tk.Entry(frame_packet, textvariable=packet_port, width=10).grid(row=1, column=1, padx=5)

    tk.Label(frame_packet, text="Protocol:").grid(row=1, column=2, sticky="e")
    packet_protocol = tk.StringVar(value="tcp")
    ttk.Combobox(frame_packet, textvariable=packet_protocol, values=["tcp", "udp"], width=10) \
        .grid(row=1, column=3, padx=5)

    tk.Label(frame_packet, text="Payload:").grid(row=2, column=0, sticky="ne")
    packet_payload = tk.Text(frame_packet, width=60, height=4)
    packet_payload.grid(row=2, column=1, columnspan=3, padx=5, pady=5)

    # ---------- IPS Logs ----------
    frame_logs = tk.LabelFrame(parent, text="IPS Logs")
    frame_logs.pack(fill="both", expand=True, padx=10, pady=5)

    log_table = ttk.Treeview(
        frame_logs,
        columns=("Time", "Src", "Dst", "Port", "Proto", "Decision", "Reason", "Score"),
        show="headings",
        height=8
    )
    for col in ("Time", "Src", "Dst", "Port", "Proto", "Decision", "Reason", "Score"):
        log_table.heading(col, text=col)
        log_table.column(col, width=90 if col not in ("Reason",) else 260)
    log_table.pack(fill="both", expand=True)

    def refresh_logs():
        log_table.delete(*log_table.get_children())
        for log in ips.get_logs():
            log_table.insert("", "end", values=(
                log["time"], log["src"], log["dst"], log["port"],
                log["protocol"], log["decision"], log["reason"], log["threat_score"]
            ))

    def simulate_packet():
        src = packet_src.get().strip() or "10.0.0.1"
        dst = packet_dst.get().strip() or "10.0.0.2"
        port = packet_port.get().strip() or "80"
        proto = packet_protocol.get()
        payload = packet_payload.get("1.0", tk.END).strip()

        if not port.isdigit():
            messagebox.showerror("Error", "Port must be a number.")
            return
        if not payload:
            messagebox.showerror("Error", "Payload is required.")
            return

        decision, reason, score = ips.inspect_packet(src, dst, port, proto, payload)
        messagebox.showinfo(
            "IPS Result",
            f"Decision: {decision.upper()}\nReason: {reason}\nThreat score: {score}"
        )
        refresh_logs()

    def clear_logs():
        ips.clear_logs()
        refresh_logs()

    def export_ips_logs():
        logs = ips.get_logs()
        if not logs:
            messagebox.showinfo("No Logs", "There are no IPS logs to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save IPS Logs As"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "time", "src", "dst", "port", "protocol",
                    "decision", "reason", "threat_score"
                ])

            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "time", "src", "dst", "port", "protocol",
                    "decision", "reason", "threat_score"
                ])
                for log in logs:
                    writer.writerow([
                        log["time"], log["src"], log["dst"], log["port"],
                        log["protocol"], log["decision"], log["reason"], log["threat_score"]
                    ])
            messagebox.showinfo("Success", f"IPS logs exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save CSV:\n{e}")

    tk.Button(frame_packet, text="Inspect Packet", command=simulate_packet) \
        .grid(row=3, column=0, columnspan=2, pady=5)

    tk.Button(frame_packet, text="Clear Logs", command=clear_logs) \
        .grid(row=3, column=2, columnspan=2, pady=5)

    tk.Button(frame_logs, text="Export IPS Logs to CSV", command=export_ips_logs) \
        .pack(pady=5)


# =========================
# MAIN APP
# =========================

def main():
    root = tk.Tk()
    root.title("CSC223 Security Appliance Simulator – Firewall + IPS")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    fw_frame = ttk.Frame(notebook)
    ips_frame = ttk.Frame(notebook)

    notebook.add(fw_frame, text="Firewall")
    notebook.add(ips_frame, text="IPS")

    build_firewall_tab(fw_frame)
    build_ips_tab(ips_frame)

    root.mainloop()


if __name__ == "__main__":
    main()