"""
ARP Spoofing / MITM Detector

A defensive network security tool that detects ARP spoofing (a common
technique used in Man-in-the-Middle attacks) by monitoring ARP traffic
on your network.

HOW IT WORKS

On a normal network, each IP address maps to exactly ONE MAC address.
When an attacker performs ARP spoofing, they send fake ARP replies
claiming their MAC address belongs to another device's IP (usually the
router's IP), this makes traffic route through the attacker's machine.

This tool watches ARP traffic and flags the moment an IP address
suddenly appears to "belong" to a second, different MAC address --
which is the signature of ARP spoofing.

TWO MODES

1. Live mode (default): sniffs real ARP packets on your network using
   scapy. Requires admin/root privileges and Npcap (Windows) or libpcap
   (Linux/Mac) to be installed.

2. Simulation mode (--simulate): generates a safe, fake sequence of ARP
   events so you can demo the detection logic (and see an alert fire)
   WITHOUT touching a real network or needing special drivers. Useful
   for presentations/demos.

FALSE-POSITIVE HANDLING (what makes this more than a bare MAC-conflict check)

Plain "IP now has two MACs" logic is noisy in real networks because of
legitimate reasons an IP's MAC can change:
  - A device gets a new IP via DHCP and an old lease briefly overlaps.
  - Virtual machines (VMware/VirtualBox/Hyper-V) have their own MAC
    prefixes and can appear as "new" devices on the same IP a host used.
  - A single stray/duplicate packet flips the mapping for an instant.

To reduce false alarms, this tool:
  1. Requires a conflicting MAC to be seen CONFIRM_THRESHOLD times
     before raising an alert (ignores one-off blips).
  2. Recognizes common virtualization MAC prefixes (OUIs) and labels
     conflicts involving them as lower-confidence "possible VM" alerts
     instead of high-confidence spoofing alerts.
  3. Supports a TRUSTED_PAIRS whitelist (e.g. your router's real
     IP/MAC) so known-good devices never trigger alerts.
  4. Applies a cooldown so the same conflicting pair doesn't spam
     repeated alerts every second.

USAGE

    python arp_mitm_detector.py                # live monitoring (needs admin/root)
    python arp_mitm_detector.py --simulate      # safe demo mode, no network needed
    python arp_mitm_detector.py --scale-test               # 100 simulated devices
    python arp_mitm_detector.py --scale-test --devices 500 # bigger scale test
    (scale-test needs: pip install psutil)

LEGAL / ETHICAL NOTE

Only run live mode on a network you own or have explicit permission to
monitor. This tool only DETECTS spoofing, it does not perform any
attack and does not require special permissions beyond packet capture.
"""

import argparse
import json
import os
import random
import time
from collections import deque
from datetime import datetime

LOG_FILE = "arp_mitm_alerts.log"

# File used to persist the trusted whitelist across runs (so pairs added
# from the GUI are still there next time you open it).
TRUSTED_PAIRS_FILE = "trusted_pairs.json"

# How many times a conflicting MAC must be seen before we raise an alert.
# Filters out single stray/duplicate packets.
CONFIRM_THRESHOLD = 2

# Don't re-alert on the exact same (ip, old_mac, new_mac) conflict more
# often than this, in seconds, avoids spamming the same alert.
ALERT_COOLDOWN_SECONDS = 30

# Known-good (ip, mac) pairs that should NEVER trigger an alert, e.g.
# your router. Fill this in with your own network's trusted devices.
TRUSTED_PAIRS = {
    # "192.168.1.1": "AA:BB:CC:00:00:01",
}

# Common OUI (MAC address) prefixes used by virtual machine software.
# A conflict where the NEW mac starts with one of these is more likely
# to be a VM/hypervisor adapter than an actual attacker.
VM_MAC_PREFIXES = (
    "00:05:69",  # VMware
    "00:0C:29",  # VMware
    "00:50:56",  # VMware
    "08:00:27",  # VirtualBox
    "0A:00:27",  # VirtualBox (host-only adapter)
    "00:15:5D",  # Hyper-V
    "00:1C:42",  # Parallels
)


def is_vm_mac(mac: str) -> bool:
    return mac.upper().startswith(VM_MAC_PREFIXES)


def add_trusted_pair(ip: str, mac: str) -> None:
    """Register a known-good (ip, mac) pair at runtime (e.g. from a GUI)
    so it never triggers an alert, without having to hand-edit the
    TRUSTED_PAIRS dict in source code. Persists to TRUSTED_PAIRS_FILE."""
    TRUSTED_PAIRS[ip.strip()] = mac.strip().upper()
    save_trusted_pairs()


def save_trusted_pairs(path: str = None) -> None:
    path = path or TRUSTED_PAIRS_FILE
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(TRUSTED_PAIRS, f, indent=2)
    except OSError:
        pass  # non-fatal, whitelist just won't persist this run


def load_trusted_pairs(path: str = None) -> None:
    path = path or TRUSTED_PAIRS_FILE
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            TRUSTED_PAIRS.update({str(k): str(v).upper() for k, v in data.items()})
    except (OSError, json.JSONDecodeError):
        pass  # corrupt/missing file, start with an empty whitelist


load_trusted_pairs()


def log_alert(message: str, confidence: str = "HIGH") -> None:
    """Print an alert to the console and append it to the log file.
    confidence: "CRITICAL"/"ELEVATED" (fused risk-score alerts, see
    ArpWatcher._update_risk), "HIGH" (confirmed IP/MAC conflict, likely
    a real attack), "MEDIUM" (suspicious ARP traffic pattern, e.g.
    gratuitous-ARP flood or reply/request ratio anomaly, worth a
    look), or "LOW" (conflict that matches a known virtualization MAC
    prefix, likely benign)."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] ({confidence} confidence) {message}"
    icon = {
        "CRITICAL": "🔥",
        "ELEVATED": "🟡",
        "HIGH": "🚨",
        "MEDIUM": "🟠",
        "LOW": "⚠️ ",
    }.get(confidence, "⚠️ ")
    print(f"\n{icon} ALERT: {line}\n")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


class ArpWatcher:
    """
    Keeps track of IP -> MAC mappings and flags conflicts, with
    false-positive reduction (confirmation threshold, VM-awareness,
    a trusted whitelist, and an alert cooldown).

    Also tracks raw ARP traffic *shape* per source MAC (gratuitous
    announcements, request/reply ratio) as a second, independent
    detection signal, this catches spoofing tools that flood
    unsolicited replies, even in the instant before any IP/MAC
    conflict has been confirmed. This signal needs real packet
    opcodes/timing, so it's only fed data in Live mode.
    """

    #, traffic-shape anomaly tuning --
    TRAFFIC_WINDOW_SECONDS = 60      # sliding window for rate tracking
    GRATUITOUS_ALERT_THRESHOLD = 3   # unsolicited announcements in window -> alert
    RATIO_MIN_SAMPLES = 10           # need at least this many packets before judging ratio
    RATIO_ALERT_MULTIPLE = 3         # replies >= 3x requests -> alert
    RATIO_MIN_REPLIES = 10           # absolute floor: routers occasionally send a
                                      # few unsolicited replies with zero matching
                                      # requests seen; only flag once volume is high
                                      # enough to look like actual flooding, not a
                                      # normal router announcement
    TRAFFIC_ALERT_COOLDOWN_SECONDS = 60

    #, fused risk scoring --
    # Each independent signal contributes points toward a single 0-100
    # risk score per MAC address, instead of being reported only in
    # isolation. This answers a question separate detectors can't:
    # "overall, how suspicious is this MAC right now, across everything
    # we've observed about it?"
    RISK_WEIGHTS = {
        "conflict_high": 70,   # confirmed IP/MAC conflict, not VM-flagged
        "conflict_watch": 25,  # conflict seen but not yet confirmed
        "conflict_vm": 20,     # conflict matches a known VM adapter prefix
        "gratuitous": 20,      # gratuitous ARP flood signature
        "ratio": 20,           # reply/request ratio anomaly
    }
    RISK_LEVEL_THRESHOLDS = (("CRITICAL", 70), ("ELEVATED", 30))

    def __init__(self):
        # ip_to_mac[ip] = mac  (the MAC we currently trust for this IP)
        self.ip_to_mac = {}
        # pending[(ip, new_mac)] = how many times we've seen this
        # specific conflicting claim, before it's confirmed.
        self.pending_conflicts = {}
        # last_alert_time[(ip, old_mac, new_mac)] = timestamp of last alert
        self.last_alert_time = {}

        #, traffic-shape tracking (live mode) --
        self.request_times = {}      # mac -> deque[timestamps] (ARP requests seen from it)
        self.reply_times = {}        # mac -> deque[timestamps] (ARP replies seen from it)
        self.gratuitous_times = {}   # mac -> deque[timestamps] (gratuitous ARPs seen from it)
        self.last_traffic_alert = {}  # (kind, mac) -> timestamp

        #, fused risk scoring --
        self.risk_components = {}     # mac -> {signal_name: points}
        self.risk_alerted_level = {}  # mac -> last level we already alerted on

    def _is_trusted(self, ip: str, mac: str) -> bool:
        return TRUSTED_PAIRS.get(ip) == mac

    def _prune(self, dq: deque, now: float) -> None:
        while dq and now - dq[0] > self.TRAFFIC_WINDOW_SECONDS:
            dq.popleft()

    def _traffic_cooldown_ok(self, kind: str, mac: str, now: float) -> bool:
        last = self.last_traffic_alert.get((kind, mac), 0)
        if now - last < self.TRAFFIC_ALERT_COOLDOWN_SECONDS:
            return False
        self.last_traffic_alert[(kind, mac)] = now
        return True

    def _risk_level_for(self, score: int):
        for level, cutoff in self.RISK_LEVEL_THRESHOLDS:
            if score >= cutoff:
                return level
        return None

    def get_risk_score(self, mac: str) -> int:
        """Current fused risk score (0-100) for a MAC, from all signals seen so far."""
        return min(100, sum(self.risk_components.get(mac, {}).values()))

    def _update_risk(self, mac: str, signal: str, source_desc: str = "") -> int:
        """
        Record that `signal` fired for `mac` (using RISK_WEIGHTS to score
        it), recompute the fused total, and raise a single combined alert
        the first time the total crosses a new severity threshold. Avoids
        re-alerting every time the score is merely re-confirmed.
        """
        comps = self.risk_components.setdefault(mac, {})
        comps[signal] = self.RISK_WEIGHTS[signal]
        total = min(100, sum(comps.values()))
        level = self._risk_level_for(total)
        previous_level = self.risk_alerted_level.get(mac)

        if level and level != previous_level:
            active_signals = ", ".join(sorted(comps.keys()))
            log_alert(
                f"Fused risk score for MAC {mac}: {total}/100 ({level}). "
                f"Combines every signal seen for this MAC so far ({active_signals}) "
                f"into one overall confidence estimate. {source_desc}",
                confidence=level,
            )
        self.risk_alerted_level[mac] = level
        return total

    def note_arp_packet(self, op: int, src_ip: str, dst_ip: str, mac: str,
                         source_desc: str = "") -> None:
        """
        Feed in a raw ARP packet's opcode (1=request, 2=reply), the IPs
        involved, and the sender's MAC. Tracks traffic shape and raises
        MEDIUM-confidence alerts on two attack-tool signatures:

          - Gratuitous ARP flood: repeated unsolicited announcements
            (sender IP == target IP) from the same MAC, attacker tools
            like arpspoof/ettercap continuously broadcast "I am this IP"
            to keep victims poisoned.
          - Reply/request ratio anomaly: a host sending far more ARP
            replies than requests, normal hosts mostly answer requests
            they triggered themselves; a flood of unsolicited replies
            with few matching requests is a spoofing signature.

        Independent of observe()'s IP/MAC-conflict check, can fire even
        before a conflict is confirmed, or even if MACs never conflict
        (e.g. attacker impersonating an IP nothing else is using). Both
        signals also feed the fused risk score alongside the conflict
        signal from observe().
        """
        if self._is_trusted(dst_ip, mac) or self._is_trusted(src_ip, mac):
            return

        now = time.time()

        if op == 1:
            dq = self.request_times.setdefault(mac, deque())
            dq.append(now)
            self._prune(dq, now)
        elif op == 2:
            dq = self.reply_times.setdefault(mac, deque())
            dq.append(now)
            self._prune(dq, now)

        # Gratuitous ARP: the sender is announcing itself (src == dst).
        if src_ip == dst_ip:
            gq = self.gratuitous_times.setdefault(mac, deque())
            gq.append(now)
            self._prune(gq, now)
            if len(gq) >= self.GRATUITOUS_ALERT_THRESHOLD and self._traffic_cooldown_ok("grat", mac, now):
                log_alert(
                    f"MAC {mac} sent {len(gq)} gratuitous (unsolicited) ARP "
                    f"announcements for IP {src_ip} in the last "
                    f"{self.TRAFFIC_WINDOW_SECONDS}s. Repeated self-announcements "
                    f"are a common ARP-spoofing signature (attacker tools "
                    f"re-poison targets on a timer). {source_desc}",
                    confidence="MEDIUM",
                )
                self._update_risk(mac, "gratuitous", source_desc)

        # Reply/request ratio anomaly.
        req_count = len(self.request_times.get(mac, ()))
        rep_count = len(self.reply_times.get(mac, ()))
        total = req_count + rep_count
        if (total >= self.RATIO_MIN_SAMPLES
                and rep_count >= max(self.RATIO_ALERT_MULTIPLE * req_count, self.RATIO_MIN_REPLIES)
                and self._traffic_cooldown_ok("ratio", mac, now)):
            log_alert(
                f"MAC {mac} sent an unusually high ratio of ARP replies to "
                f"requests ({rep_count}:{req_count}) in the last "
                f"{self.TRAFFIC_WINDOW_SECONDS}s. Real hosts mostly reply to "
                f"requests they triggered; a flood of unsolicited replies "
                f"with few matching requests is typical of spoofing tools. "
                f"{source_desc}",
                confidence="MEDIUM",
            )
            self._update_risk(mac, "ratio", source_desc)

    def observe(self, ip: str, mac: str, source_desc: str = "", quiet: bool = False) -> str:
        """
        Record a new (IP, MAC) pairing seen on the network.
        If this IP was already mapped to a DIFFERENT MAC, run it through
        the false-positive filters before raising an alert.

        Returns a short status string: "trusted", "seen", "ok", "watch",
        "alert_high", or "alert_low", useful for tallying stats in bulk
        tests without needing to parse printed output.
        """
        def out(msg):
            if not quiet:
                print(msg)

        if self._is_trusted(ip, mac):
            self.ip_to_mac[ip] = mac
            out(f"  [trusted] {ip} -> {mac}  {source_desc}")
            return "trusted"

        known_mac = self.ip_to_mac.get(ip)

        if known_mac is None:
            # First time we've seen this IP, just remember it.
            self.ip_to_mac[ip] = mac
            out(f"  [seen]  {ip} -> {mac}  {source_desc}")
            return "seen"

        if known_mac == mac:
            out(f"  [ok]    {ip} -> {mac}  (matches known mapping)")
            # A confirmed-good sighting clears any pending conflict count.
            self.pending_conflicts.pop((ip, mac), None)
            return "ok"

        # --- We have a conflict: known_mac != mac. Apply filters. ---
        key = (ip, mac)
        self.pending_conflicts[key] = self.pending_conflicts.get(key, 0) + 1
        seen_count = self.pending_conflicts[key]

        if seen_count < CONFIRM_THRESHOLD:
            out(
                f"  [watch] {ip} -> {mac} conflicts with known {known_mac} "
                f"(seen {seen_count}/{CONFIRM_THRESHOLD}, waiting for confirmation)"
            )
            self._update_risk(mac, "conflict_watch", source_desc)
            return "watch"

        # Confirmed conflict, decide confidence level.
        alert_key = (ip, known_mac, mac)
        now = time.time()
        last_time = self.last_alert_time.get(alert_key, 0)
        if now - last_time < ALERT_COOLDOWN_SECONDS:
            # Same conflict alerted recently, stay quiet to avoid spam.
            self.ip_to_mac[ip] = mac
            return "cooldown"

        if is_vm_mac(mac):
            log_alert(
                f"IP {ip} changed from MAC {known_mac} to {mac}, which matches "
                f"a known virtual-machine adapter prefix. Likely a VM/hypervisor "
                f"on this host rather than an attacker, but worth checking. "
                f"{source_desc}",
                confidence="LOW",
            )
            self._update_risk(mac, "conflict_vm", source_desc)
            result = "alert_low"
        else:
            log_alert(
                f"Possible ARP spoofing detected! IP {ip} was mapped to MAC "
                f"{known_mac}, now confirmed claimed by a different MAC {mac} "
                f"({seen_count} consistent sightings). {source_desc}",
                confidence="HIGH",
            )
            self._update_risk(mac, "conflict_high", source_desc)
            result = "alert_high"

        self.last_alert_time[alert_key] = now
        self.ip_to_mac[ip] = mac
        self.pending_conflicts.pop(key, None)
        return result



# LIVE MODE (real packet sniffing, requires scapy + admin/root)

def run_live(interface: str | None = None, stop_event=None) -> None:
    """
    stop_event: optional threading.Event. When set, sniffing stops at the
    next captured packet. Lets a GUI offer a real "Stop" button; plain CLI
    use (Ctrl+C) still works fine without passing this.
    """
    try:
        from scapy.all import sniff, ARP
    except ImportError:
        print("scapy is not installed. Run: pip install scapy")
        return

    watcher = ArpWatcher()
    print("Starting live ARP monitoring... (Ctrl+C to stop)")
    print("Only run this on a network you own or have permission to monitor.\n")

    def handle_packet(pkt):
        if not pkt.haslayer(ARP):
            return
        op = pkt[ARP].op          # 1 = request, 2 = reply ("is-at")
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        mac = pkt[ARP].hwsrc

        # Traffic-shape signal (gratuitous ARP + reply/request ratio) --
        # independent of the conflict check, works on every ARP packet.
        watcher.note_arp_packet(op, src_ip, dst_ip, mac, source_desc="(from live ARP traffic)")

        # Conflict-based signal, only meaningful on replies, which are
        # the packets that actually assert "this IP is at this MAC".
        if op == 2:
            watcher.observe(src_ip, mac, source_desc="(from live ARP reply)")

    def should_stop(pkt):
        return bool(stop_event and stop_event.is_set())

    sniff(filter="arp", prn=handle_packet, store=False, iface=interface, stop_filter=should_stop)



# SIMULATION MODE (safe demo, no real network needed)

def run_simulation() -> None:
    watcher = ArpWatcher()
    print("Running SIMULATION mode, no real network traffic is used.\n")

    # A fake, realistic sequence covering THREE cases:
    #   1) normal traffic (no alert)
    #   2) a real spoofing attempt, confirmed over repeated sightings
    #      (HIGH confidence alert)
    #   3) a VM adapter briefly reusing an IP (LOW confidence / likely
    #      benign, shows the false-positive filtering working)
    fake_events = [
        ("192.168.1.1", "AA:BB:CC:00:00:01", "(router, normal)"),
        ("192.168.1.5", "AA:BB:CC:00:00:05", "(laptop, normal)"),
        ("192.168.1.6", "AA:BB:CC:00:00:06", "(phone, normal)"),
        ("192.168.1.1", "AA:BB:CC:00:00:01", "(router, normal again)"),

        # --- Case 2: real attacker repeatedly claims to be the router ---
        ("192.168.1.1", "DE:AD:BE:EF:13:37", "(!) suspicious ARP reply #1"),
        ("192.168.1.1", "DE:AD:BE:EF:13:37", "(!) suspicious ARP reply #2 (confirms it)"),

        ("192.168.1.6", "AA:BB:CC:00:00:06", "(phone, normal)"),

        # --- Case 3: a VM adapter shows up once on the laptop's IP ---
        # Only ONE sighting, below CONFIRM_THRESHOLD, so with a real
        # confirmation requirement this would just sit in "watch" state
        # rather than firing an alert. We send it twice here so you can
        # SEE the low-confidence VM alert path fire during the demo.
        ("192.168.1.5", "00:0C:29:AB:CD:EF", "(VMware adapter) sighting #1"),
        ("192.168.1.5", "00:0C:29:AB:CD:EF", "(VMware adapter) sighting #2"),
    ]

    for ip, mac, desc in fake_events:
        watcher.observe(ip, mac, source_desc=desc)
        time.sleep(0.6)

    print("\nSimulation complete. Check arp_mitm_alerts.log for the recorded alert(s).")
    print("Notice: the router conflict fired a HIGH confidence alert,")
    print("while the VMware-prefixed MAC fired a LOW confidence alert --")
    print("that's the false-positive handling distinguishing the two.")



# SCALE TEST MODE (many simulated devices + resource usage measurement)

def _generate_scale_events(num_devices: int, seed: int = 42):
    """
    Build a synthetic event stream for `num_devices` simulated devices:
    mostly normal traffic, a handful of confirmed real spoofing attempts,
    and a handful of VM-adapter false-positive-style conflicts.
    Returns (events, ground_truth) where ground_truth tags each event's
    ip as "attack" or "benign_conflict" if it's part of one of those
    injected scenarios (for scoring accuracy afterward).
    """
    rng = random.Random(seed)
    events = []
    ground_truth = {"attack_ips": set(), "vm_conflict_ips": set()}

    device_ips = [f"192.168.1.{i}" for i in range(2, num_devices + 2)]
    device_macs = {ip: f"AA:BB:CC:{i:02X}:{i:02X}:{i:02X}" for i, ip in enumerate(device_ips)}

    # Normal baseline traffic first: every device's real mapping gets
    # established before any attack happens (realistic ordering, a
    # device is on the network normally before an attacker targets it).
    baseline_events = []
    for _ in range(3):
        shuffled_ips = device_ips[:]
        rng.shuffle(shuffled_ips)
        for ip in shuffled_ips:
            baseline_events.append((ip, device_macs[ip], "(normal)"))
    events.extend(baseline_events)

    # Inject a handful of real spoofing attempts (~5% of devices),
    # each confirmed with 2 repeated conflicting sightings. These come
    # AFTER the baseline so they represent a genuine takeover attempt,
    # not just re-ordering of normal traffic.
    injected = []
    num_attacks = max(1, num_devices // 20)
    attacker_targets = rng.sample(device_ips, num_attacks)
    for ip in attacker_targets:
        ground_truth["attack_ips"].add(ip)
        fake_mac = "DE:AD:BE:EF:%02X:%02X" % (rng.randint(0, 255), rng.randint(0, 255))
        injected.append((ip, fake_mac, "(!) spoofed reply #1"))
        injected.append((ip, fake_mac, "(!) spoofed reply #2"))

    # Inject a handful of VM-adapter conflicts (~5% of devices).
    num_vm = max(1, num_devices // 20)
    remaining = [ip for ip in device_ips if ip not in attacker_targets]
    vm_targets = rng.sample(remaining, min(num_vm, len(remaining)))
    for ip in vm_targets:
        ground_truth["vm_conflict_ips"].add(ip)
        vm_mac = rng.choice(VM_MAC_PREFIXES) + ":AB:CD:EF"[:9]
        injected.append((ip, vm_mac, "(VM adapter) sighting #1"))
        injected.append((ip, vm_mac, "(VM adapter) sighting #2"))

    # Shuffle the injected events among themselves only (not mixed back
    # into the baseline) so each device's two confirming sightings for
    # the SAME conflict still land consecutively per-IP in effect (the
    # watcher tracks state per-IP regardless of interleaving with other
    # IPs' events, so this interleaving is realistic and safe).
    rng.shuffle(injected)
    events.extend(injected)
    return events, ground_truth


def run_scale_test(num_devices: int = 100) -> None:
    try:
        import psutil
    except ImportError:
        print("psutil is not installed. Run: pip install psutil")
        return

    print(f"Running SCALE TEST with {num_devices} simulated devices...")
    print("(No real network traffic, this measures detection accuracy")
    print(" and resource usage to gauge feasibility on lightweight devices,")
    print(" e.g. an IoT gateway or Raspberry Pi-class device.)\n")

    events, ground_truth = _generate_scale_events(num_devices)
    watcher = ArpWatcher()

    process = psutil.Process()
    process.cpu_percent(interval=None)  # prime the CPU measurement
    mem_before_mb = process.memory_info().rss / (1024 * 1024)
    start_time = time.time()

    results = {"alert_high": 0, "alert_low": 0, "watch": 0, "ok": 0, "seen": 0, "cooldown": 0}
    detected_attack_ips = set()
    detected_vm_ips = set()

    for ip, mac, desc in events:
        status = watcher.observe(ip, mac, source_desc=desc, quiet=True)
        results[status] = results.get(status, 0) + 1
        if status == "alert_high":
            detected_attack_ips.add(ip)
        elif status == "alert_low":
            detected_vm_ips.add(ip)

    elapsed = time.time() - start_time
    cpu_percent = process.cpu_percent(interval=None)
    mem_after_mb = process.memory_info().rss / (1024 * 1024)

    true_attacks = ground_truth["attack_ips"]
    true_vm = ground_truth["vm_conflict_ips"]
    attacks_caught = len(detected_attack_ips & true_attacks)
    vm_correctly_low = len(detected_vm_ips & true_vm)
    # A "false positive" here means a VM/benign conflict that was wrongly
    # raised as HIGH confidence instead of LOW.
    false_positives = len(detected_attack_ips & true_vm)

    print()
    print("Scale test summary")
    print(f"  Simulated devices:            {num_devices}")
    print(f"  Total ARP events processed:   {len(events)}")
    print(f"  Processing time:              {elapsed:.3f} sec")
    print(f"  CPU usage during run:         {cpu_percent:.1f}%")
    print(f"  Memory (RSS) before/after:    {mem_before_mb:.1f} MB -> {mem_after_mb:.1f} MB")
    print()
    print(f"  Real attacks injected:                        {len(true_attacks)}")
    print(f"  Real attacks correctly caught (HIGH alert):   {attacks_caught}/{len(true_attacks)}")
    print(f"  VM/benign conflicts injected:                 {len(true_vm)}")
    print(f"  VM conflicts correctly kept LOW confidence:   {vm_correctly_low}/{len(true_vm)}")
    print(f"  False positives (VM conflict wrongly flagged HIGH): {false_positives}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing / MITM Detector")
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run a safe simulated demo instead of live network sniffing.",
    )
    parser.add_argument(
        "--scale-test",
        action="store_true",
        help="Run a large simulated network (many devices) and report "
        "detection accuracy plus CPU/memory usage, for testing "
        "feasibility on resource-constrained (e.g. IoT-class) devices.",
    )
    parser.add_argument(
        "--devices",
        type=int,
        default=100,
        help="Number of simulated devices for --scale-test (default: 100).",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to sniff on (live mode only, e.g. eth0, Wi-Fi).",
    )
    args = parser.parse_args()

    if args.simulate:
        run_simulation()
    elif args.scale_test:
        run_scale_test(num_devices=args.devices)
    else:
        run_live(interface=args.interface)
