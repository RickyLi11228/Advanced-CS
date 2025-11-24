import tkinter as tk
from tkinter import messagebox, ttk
from firewall_engine import FirewallSimulator

fw = FirewallSimulator()

def add_rule():
    name = rule_name.get()
    action = rule_action.get()
    port = rule_port.get()
    protocol = rule_protocol.get()

    if not name:
        messagebox.showerror("Error", "Rule name required")
        return

    fw.add_rule(name, action, port, protocol)
    refresh_rules()
    rule_name_entry.delete(0, tk.END)

def delete_rule():
    name = rule_name.get()
    if fw.delete_rule(name):
        refresh_rules()
        messagebox.showinfo("Deleted", f"Rule '{name}' removed")
    else:
        messagebox.showerror("Error", "Rule not found")

def reset_firewall():
    fw.rules.clear()
    fw.logs.clear()
    refresh_rules()
    refresh_logs()
    messagebox.showinfo("Reset", "All rules and logs have been cleared.")

def refresh_rules():
    rules_list.delete(*rules_list.get_children())
    for r in fw.list_rules():
        color_tag = "green" if r["action"] == "allow" else "red"
        rules_list.insert(
            "", "end",
            values=(r["name"], r["action"], r["port"], r["protocol"]),
            tags=(color_tag,)
        )

def simulate():
    port = sim_port.get()
    protocol = sim_protocol.get()
    result = fw.simulate_packet(port, protocol)
    messagebox.showinfo("Result", f"Packet decision: {result.upper()}")
    refresh_logs()

def refresh_logs():
    logs_list.delete(*logs_list.get_children())
    for log in fw.get_logs():
        color_tag = "green" if log["decision"] == "allow" else "red"
        logs_list.insert(
            "", "end",
            values=(log["time"], log["port"], log["protocol"], log["decision"]),
            tags=(color_tag,)
        )

root = tk.Tk()
root.title("Ricky's Firewall Simulation")
root.geometry("850x600")

# ===== RULE CREATION FRAME =====
frame_rules = tk.LabelFrame(root, text="Add / Remove Rules")
frame_rules.pack(fill="x", padx=10, pady=5)

tk.Label(frame_rules, text="Name:").grid(row=0, column=0)
rule_name = tk.StringVar()
rule_name_entry = tk.Entry(frame_rules, textvariable=rule_name)
rule_name_entry.grid(row=0, column=1)

tk.Label(frame_rules, text="Action:").grid(row=1, column=0)
rule_action = tk.StringVar(value="allow")
ttk.Combobox(frame_rules, textvariable=rule_action, values=["allow", "deny"], width=10).grid(row=1, column=1)

tk.Label(frame_rules, text="Port:").grid(row=2, column=0)
rule_port = tk.StringVar(value="80")
tk.Entry(frame_rules, textvariable=rule_port).grid(row=2, column=1)

tk.Label(frame_rules, text="Protocol:").grid(row=3, column=0)
rule_protocol = tk.StringVar(value="tcp")
ttk.Combobox(frame_rules, textvariable=rule_protocol, values=["tcp", "udp"], width=10).grid(row=3, column=1)

tk.Button(frame_rules, text="Add Rule", command=add_rule).grid(row=4, column=0, pady=5)
tk.Button(frame_rules, text="Delete Rule", command=delete_rule).grid(row=4, column=1)
tk.Button(frame_rules, text="Reset Firewall", command=reset_firewall, bg="#FF7777").grid(row=4, column=2, padx=10)

# ===== RULE LIST TABLE =====
frame_rule_list = tk.LabelFrame(root, text="Current Rules")
frame_rule_list.pack(fill="both", expand=True, padx=10, pady=5)

rules_list = ttk.Treeview(frame_rule_list, columns=("Name", "Action", "Port", "Protocol"), show="headings")
for col in ("Name", "Action", "Port", "Protocol"):
    rules_list.heading(col, text=col)
rules_list.pack(fill="both", expand=True)

rules_list.tag_configure("green", background="#CCFFCC")
rules_list.tag_configure("red", background="#FFCCCC")

# ===== PACKET SIMULATION =====
frame_sim = tk.LabelFrame(root, text="Simulate Packet")
frame_sim.pack(fill="x", padx=10, pady=5)

tk.Label(frame_sim, text="Port:").grid(row=0, column=0)
sim_port = tk.StringVar(value="80")
tk.Entry(frame_sim, textvariable=sim_port).grid(row=0, column=1)

tk.Label(frame_sim, text="Protocol:").grid(row=1, column=0)
sim_protocol = tk.StringVar(value="tcp")
ttk.Combobox(frame_sim, textvariable=sim_protocol, values=["tcp", "udp"], width=10).grid(row=1, column=1)

tk.Button(frame_sim, text="Simulate Packet", command=simulate).grid(row=2, column=0, columnspan=2, pady=5)

# ===== LOG TABLE =====
frame_logs = tk.LabelFrame(root, text="Firewall Logs")
frame_logs.pack(fill="both", expand=True, padx=10, pady=5)

logs_list = ttk.Treeview(frame_logs, columns=("Time", "Port", "Protocol", "Decision"), show="headings")
for col in ("Time", "Port", "Protocol", "Decision"):
    logs_list.heading(col, text=col)
logs_list.pack(fill="both", expand=True)

logs_list.tag_configure("green", background="#CCFFCC")
logs_list.tag_configure("red", background="#FFCCCC")

root.mainloop()
