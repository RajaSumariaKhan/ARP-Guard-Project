"""
ARP Spoofing / MITM Detector: Desktop GUI
=============================================
A Tkinter front-end for arp_mitm_detector.py. Runs the exact same
detection engine (ArpWatcher) as the command-line tool; this file
only adds a visual layer on top of it:

    - Simulation Demo   (safe, scripted, no network needed)
    - Scale Test        (N simulated devices + resource stats)
    - Live Monitoring   (real ARP sniffing via scapy, start/stop)
    - Live dashboard    (event counters: HIGH / LOW / OK / Watching)
    - Trusted device manager (whitelist IP/MAC pairs at runtime)
    - Colour-coded, auto-scrolling alert log
    - One-click "open alerts log file" / "clear log" / "save log as..."

REQUIREMENTS
------------
- arp_mitm_detector.py must be in the SAME FOLDER as this file.
- Tkinter ships with standard Python (no extra install needed).
- Scale Test button needs:      pip install psutil
- Live Monitoring button needs: pip install scapy   (+ run as admin/root)

USAGE
-----
    python gui.py
"""

import csv
import os
import platform
import queue
import re
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

import arp_mitm_detector as detector

# Colour palette (dark, security-tool look)
BG = "#12181f"
PANEL = "#1a232d"
PANEL_BORDER = "#26323e"
TEXT = "#d7e0e8"
MUTED = "#7f8fa0"
ACCENT = "#2fa8ff"
GOOD = "#3ecf8e"
WARN = "#e8a13a"
MED = "#ff9f4a"
BAD = "#ff5c5c"


class ArpGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Guard: ARP Spoofing / MITM Detector")
        self.root.geometry("980x680")
        self.root.minsize(760, 520)
        self.root.configure(bg=BG)

        self.log_queue = queue.Queue()
        self.worker_thread = None
        self.live_stop_event = threading.Event()
        self.live_running = False

        # Running counters for the dashboard, updated by scanning
        # printed log lines (works across all three modes uniformly).
        self.counts = {"high": 0, "medium": 0, "low": 0, "ok": 0, "watch": 0, "trusted": 0}

        self._build_style()
        self._build_widgets()
        self._poll_log_queue()

        # Redirect the detector module's print() calls into the GUI log
        # instead of the terminal, without changing detector.py's logic.
        detector.print = self._threadsafe_print

    # Styling
   
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 16, "bold"))
        style.configure("Stat.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 20, "bold"))

        style.configure("Accent.TButton", background=ACCENT, foreground="#062033",
                         font=("Segoe UI", 10, "bold"), padding=8, borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#57bdff"), ("disabled", "#31424f")])

        style.configure("Ghost.TButton", background=PANEL_BORDER, foreground=TEXT,
                         font=("Segoe UI", 9), padding=6, borderwidth=0)
        style.map("Ghost.TButton", background=[("active", "#33424f")])

        style.configure("Danger.TButton", background="#3a1f22", foreground=BAD,
                         font=("Segoe UI", 10, "bold"), padding=8, borderwidth=0)
        style.map("Danger.TButton", background=[("active", "#552428")])

        style.configure("TEntry", fieldbackground="#0e1419", foreground=TEXT,
                         insertcolor=TEXT, borderwidth=0, padding=6)
        style.configure("TSpinbox", fieldbackground="#0e1419", foreground=TEXT,
                         arrowsize=12, padding=4)

    
    # Layout
    
    def _build_widgets(self):
        header = ttk.Frame(self.root, padding=(18, 16, 18, 8))
        header.pack(fill="x")
        ttk.Label(header, text="🛡  ARP Guard", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Lightweight ARP spoofing / MITM detector with confirmation "
                 "thresholds, VM-aware scoring, a trusted whitelist, and alert cooldowns.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        body = ttk.Frame(self.root, padding=(18, 0, 18, 18))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Left control panel 
        left = ttk.Frame(body, style="Panel.TFrame", padding=14)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 14))

        ttk.Label(left, text="RUN MODE", style="PanelMuted.TLabel").pack(anchor="w", pady=(0, 6))

        self.simulate_btn = ttk.Button(left, text="▶  Simulation Demo", style="Accent.TButton",
                                        command=self.run_simulate)
        self.simulate_btn.pack(fill="x", pady=3)

        scale_row = ttk.Frame(left, style="Panel.TFrame")
        scale_row.pack(fill="x", pady=(10, 3))
        ttk.Label(scale_row, text="Devices:", style="Panel.TLabel").pack(side="left")
        self.device_count = tk.StringVar(value="100")
        ttk.Spinbox(scale_row, from_=10, to=2000, increment=10, width=6,
                    textvariable=self.device_count).pack(side="left", padx=(6, 0))

        self.scale_btn = ttk.Button(left, text="⚙  Run Scale Test", style="Accent.TButton",
                                     command=self.run_scale_test)
        self.scale_btn.pack(fill="x", pady=3)

        iface_row = ttk.Frame(left, style="Panel.TFrame")
        iface_row.pack(fill="x", pady=(10, 3))
        ttk.Label(iface_row, text="Interface (optional):", style="PanelMuted.TLabel").pack(anchor="w")
        self.iface_var = tk.StringVar()
        ttk.Entry(iface_row, textvariable=self.iface_var).pack(fill="x", pady=(2, 0))

        self.live_btn = ttk.Button(left, text="⬤  Start Live Monitoring", style="Danger.TButton",
                                    command=self.toggle_live)
        self.live_btn.pack(fill="x", pady=(6, 3))

        ttk.Separator(left).pack(fill="x", pady=12)

        ttk.Label(left, text="TRUSTED WHITELIST", style="PanelMuted.TLabel").pack(anchor="w", pady=(0, 6))
        self.trust_ip = tk.StringVar()
        self.trust_mac = tk.StringVar()
        ttk.Entry(left, textvariable=self.trust_ip).pack(fill="x", pady=2)
        self._placeholder(left, self.trust_ip, "e.g. 192.168.1.1")
        ttk.Entry(left, textvariable=self.trust_mac).pack(fill="x", pady=2)
        self._placeholder(left, self.trust_mac, "e.g. AA:BB:CC:00:00:01")
        ttk.Button(left, text="＋  Add Trusted Pair", style="Ghost.TButton",
                   command=self.add_trusted).pack(fill="x", pady=(4, 0))

        ttk.Separator(left).pack(fill="x", pady=12)

        ttk.Button(left, text="🗎  Open alerts log file", style="Ghost.TButton",
                   command=self.open_log_file).pack(fill="x", pady=2)
        ttk.Button(left, text="⬇  Export alerts as CSV", style="Ghost.TButton",
                   command=self.export_csv).pack(fill="x", pady=2)
        ttk.Button(left, text="🗑  Clear console", style="Ghost.TButton",
                   command=self.clear_log).pack(fill="x", pady=2)

        self.status_var = tk.StringVar(value="Idle.")
        ttk.Label(left, textvariable=self.status_var, style="PanelMuted.TLabel",
                  wraplength=190).pack(anchor="w", pady=(14, 0))

        # Right side: dashboard + log 
        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        dash = ttk.Frame(right)
        dash.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        for i in range(5):
            dash.columnconfigure(i, weight=1)

        self.stat_labels = {}
        stats = [("high", "HIGH alerts", BAD), ("medium", "Traffic anomalies", MED),
                 ("low", "LOW alerts", WARN), ("watch", "Watching", ACCENT),
                 ("ok", "Confirmed OK", GOOD)]
        for i, (key, label, color) in enumerate(stats):
            card = ttk.Frame(dash, style="Panel.TFrame", padding=(14, 10))
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0))
            val = ttk.Label(card, text="0", style="Stat.TLabel")
            val.configure(foreground=color)
            val.pack(anchor="w")
            ttk.Label(card, text=label, style="PanelMuted.TLabel").pack(anchor="w")
            self.stat_labels[key] = val

        log_frame = ttk.Frame(right, style="Panel.TFrame", padding=2)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_box = scrolledtext.ScrolledText(
            log_frame, wrap="word", font=("Consolas", 10), state="disabled",
            bg="#0e1419", fg=TEXT, insertbackground=TEXT, borderwidth=0,
            highlightthickness=0, padx=12, pady=10,
        )
        self.log_box.grid(row=0, column=0, sticky="nsew")

        self.log_box.tag_config("high", foreground=BAD)
        self.log_box.tag_config("medium", foreground=MED)
        self.log_box.tag_config("low", foreground=WARN)
        self.log_box.tag_config("ok", foreground=GOOD)
        self.log_box.tag_config("trusted", foreground=ACCENT)
        self.log_box.tag_config("normal", foreground=TEXT)
        self.log_box.tag_config("meta", foreground=MUTED)

        self._append_log("Ready. Choose a mode on the left to begin.", force_tag="meta")

    def _placeholder(self, parent, var, hint):
        # lightweight placeholder text shown via a small caption under the field
        ttk.Label(parent, text=hint, style="PanelMuted.TLabel", font=("Segoe UI", 8)).pack(anchor="w")

    
    # Logging helpers (thread-safe: worker threads push to a queue,
    # the Tk main loop drains it)
   
    def _threadsafe_print(self, *args, **kwargs):
        text = " ".join(str(a) for a in args)
        self.log_queue.put(text)

    def _poll_log_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self._append_log(line)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_log_queue)

    def _append_log(self, line: str, force_tag: str = None):
        if not line.strip():
            return
        tag = force_tag or "normal"
        if force_tag is None:
            if "HIGH confidence" in line or "🚨" in line:
                tag = "high"
                self.counts["high"] += 1
            elif "MEDIUM confidence" in line or "🟠" in line:
                tag = "medium"
                self.counts["medium"] += 1
            elif "LOW confidence" in line or "⚠️" in line:
                tag = "low"
                self.counts["low"] += 1
            elif "[ok]" in line:
                tag = "ok"
                self.counts["ok"] += 1
            elif "[watch]" in line:
                tag = "meta"
                self.counts["watch"] += 1
            elif "[trusted]" in line:
                tag = "trusted"
                self.counts["trusted"] += 1
            elif line.startswith("====") or line.startswith("----"):
                tag = "meta"
            elif line.strip() in ("Scale test summary",):
                tag = "meta"

        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n", tag)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
        self._refresh_dashboard()

    def _refresh_dashboard(self):
        self.stat_labels["high"].configure(text=str(self.counts["high"]))
        self.stat_labels["medium"].configure(text=str(self.counts["medium"]))
        self.stat_labels["low"].configure(text=str(self.counts["low"]))
        self.stat_labels["watch"].configure(text=str(self.counts["watch"]))
        self.stat_labels["ok"].configure(text=str(self.counts["ok"]))

    def clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        self.counts = {"high": 0, "medium": 0, "low": 0, "ok": 0, "watch": 0, "trusted": 0}
        self._refresh_dashboard()

    def open_log_file(self):
        path = os.path.abspath(detector.LOG_FILE)
        if not os.path.exists(path):
            messagebox.showinfo("No log yet", "No alerts have been written to "
                                 f"{detector.LOG_FILE} yet. Run a mode first.")
            return
        try:
            system = platform.system()
            if system == "Windows":
                os.startfile(path)  # noqa
            elif system == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Couldn't open file", f"{e}\n\nFile is at:\n{path}")

    def export_csv(self):
        log_path = os.path.abspath(detector.LOG_FILE)
        if not os.path.exists(log_path):
            messagebox.showinfo("No log yet", "No alerts have been recorded yet. "
                                 "Run a mode first.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Save alerts as CSV",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
            initialfile="arp_mitm_alerts.csv",
        )
        if not save_path:
            return

        pattern = re.compile(r"^\[(?P<ts>[^\]]+)\]\s\((?P<conf>\w+) confidence\)\s(?P<msg>.*)$")
        rows = []
        with open(log_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                m = pattern.match(line)
                if m:
                    rows.append([m.group("ts"), m.group("conf"), m.group("msg")])

        try:
            with open(save_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "confidence", "message"])
                writer.writerows(rows)
            messagebox.showinfo("Exported", f"Saved {len(rows)} alerts to:\n{save_path}")
        except OSError as e:
            messagebox.showerror("Export failed", str(e))

    
    # Trusted whitelist
    
    def add_trusted(self):
        ip = self.trust_ip.get().strip()
        mac = self.trust_mac.get().strip()
        if not ip or not mac:
            messagebox.showwarning("Missing info", "Enter both an IP address and a MAC address.")
            return
        detector.add_trusted_pair(ip, mac)
        self._append_log(f"  [config] Added trusted pair: {ip} -> {mac.upper()}", force_tag="trusted")
        self.trust_ip.set("")
        self.trust_mac.set("")

    
    # Button actions, each runs the real detector code in a
    # background thread so the GUI never freezes.
    
    def _set_run_buttons_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.simulate_btn.configure(state=state)
        self.scale_btn.configure(state=state)

    def run_simulate(self):
        self._set_run_buttons_enabled(False)
        self.status_var.set("Running simulation demo...")
        self._append_log("\n[Simulation] Started", force_tag="meta")

        def task():
            try:
                detector.run_simulation()
            except Exception as e:
                self._threadsafe_print(f"Error: {e}")
            finally:
                self.root.after(0, lambda: self._set_run_buttons_enabled(True))
                self.root.after(0, lambda: self.status_var.set("Idle."))

        threading.Thread(target=task, daemon=True).start()

    def run_scale_test(self):
        try:
            n = int(self.device_count.get())
            if n <= 0:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Invalid number", "Enter a positive number of devices.")
            return

        self._set_run_buttons_enabled(False)
        self.status_var.set(f"Running scale test ({n} simulated devices)...")
        self._append_log(f"\n[Scale Test] Started, {n} devices", force_tag="meta")

        def task():
            try:
                detector.run_scale_test(num_devices=n)
            except Exception as e:
                self._threadsafe_print(f"Error: {e}")
            finally:
                self.root.after(0, lambda: self._set_run_buttons_enabled(True))
                self.root.after(0, lambda: self.status_var.set("Idle."))

        threading.Thread(target=task, daemon=True).start()

    def toggle_live(self):
        if self.live_running:
            # Ask the sniff loop to stop after its next packet.
            self.live_stop_event.set()
            self.live_btn.configure(text="⬤  Stopping...", state="disabled")
            self.status_var.set("Stopping live monitoring...")
            return

        self.live_stop_event.clear()
        self.live_running = True
        self.status_var.set("Starting live monitoring (needs admin/root + scapy)...")
        self._append_log("\n[Live Monitoring] Started", force_tag="meta")
        self.live_btn.configure(text="■  Stop Live Monitoring")
        self._set_run_buttons_enabled(False)

        iface = self.iface_var.get().strip() or None

        def task():
            try:
                detector.run_live(interface=iface, stop_event=self.live_stop_event)
                self._threadsafe_print("[Live Monitoring] Stopped")
            except Exception as e:
                self._threadsafe_print(f"Error: {e}")
                self._threadsafe_print("Live mode needs: pip install scapy, and admin/root privileges.")
            finally:
                self.live_running = False
                self.root.after(0, lambda: self.live_btn.configure(
                    text="⬤  Start Live Monitoring", state="normal"))
                self.root.after(0, lambda: self._set_run_buttons_enabled(True))
                self.root.after(0, lambda: self.status_var.set("Idle."))

        self.worker_thread = threading.Thread(target=task, daemon=True)
        self.worker_thread.start()


if __name__ == "__main__":
    root = tk.Tk()
    app = ArpGuardGUI(root)
    root.mainloop()
