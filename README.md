# ARP Guard: ARP Spoofing / MITM Detector

A lightweight, false-positive-aware ARP spoofing / Man-in-the-Middle
detector, with a desktop GUI on top of the detection engine.

## Files

| File                     | Purpose                                                      |
|---------------------------|---------------------------------------------------------------|
| `arp_mitm_detector.py`    | Core detection engine (`ArpWatcher`) + CLI (simulate / scale-test / live) |
| `gui.py`                  | Desktop GUI (Tkinter), run this for the visual app          |
| `requirements.txt`        | Optional dependencies                                         |
| `arp_mitm_alerts.log`     | Alert history written by previous runs                        |

## Detection signals

Two independent signals feed the alert log:

1. **IP/MAC conflict detection** (all modes), the original approach:
   an IP suddenly claimed by a different MAC, confirmed over repeated
   sightings, scored HIGH (real conflict) or LOW (matches a known VM
   MAC prefix).
2. **ARP traffic-shape anomalies** (Live mode only, needs real packet
   opcodes/timing that simulation doesn't model), scored MEDIUM:
   - *Gratuitous ARP flood*, a MAC repeatedly announcing itself
     unsolicited (sender IP == target IP), the mechanism spoofing tools
     use to keep re-poisoning a target.
   - *Reply/request ratio anomaly*, a MAC sending far more ARP
     replies than requests, typical of a flooding attack tool rather
     than a normal host.

## Fused risk score

Each of the signals above is reported individually, but they also all
feed a single **0-100 risk score per MAC address**. Instead of three
separate, disconnected alerts, the score answers one question:
"overall, how suspicious is this device right now?"

- 70+ -> **CRITICAL**
- 30-69 -> **ELEVATED**
- below 30 -> no fused alert (individual signals may still log)

A confirmed real conflict alone already reaches CRITICAL. A VM-adapter
conflict alone stays in the low ELEVATED range and never reaches
CRITICAL on its own, the fused score keeps the same
false-positive-aware behaviour as the individual signals, just
summarised into one number.

This means the tool can flag suspicious traffic even before an IP/MAC
conflict is confirmed, or in cases where MACs never technically
conflict.

## Trusted whitelist persistence

Pairs added via the GUI's "Add Trusted Pair" are saved to
`trusted_pairs.json` in the project folder and reloaded automatically
next time you run the app or the CLI, no need to re-enter your
router's IP/MAC every session.

## Setup

```bash
# Optional but recommended, gives you the Scale Test and Live modes
pip install -r requirements.txt
```

`gui.py` and `arp_mitm_detector.py` must stay in the **same folder**.
Tkinter itself ships with standard Python, so no extra install is
needed just to open the window.

## Running the GUI

```bash
python gui.py
```

Three run modes, all in one window:

- **Simulation Demo**, safe, scripted ARP events. No network access,
  no privileges needed. Good for a first look / a demo in front of
  someone.
- **Scale Test**, generates a synthetic network of N devices (set the
  count in the sidebar), injects spoofing attempts and benign
  VM-adapter conflicts, and reports detection accuracy plus CPU/memory
  use. Requires `pip install psutil`.
- **Live Monitoring**, sniffs real ARP traffic on your machine's
  network interface and flags spoofing as it happens. Requires
  `pip install scapy`, and admin/root privileges (plus Npcap on
  Windows). Only run this on a network you own or have permission to
  monitor. Click it again to stop.

The dashboard at the top counts HIGH alerts, LOW (VM-likely) alerts,
conflicts still being confirmed ("Watching"), and confirmed-normal
traffic, live as events come in.

### Trusted whitelist

Add known-good IP/MAC pairs (e.g. your router) in the sidebar so they
never trigger an alert, useful before running Live Monitoring on
your real network.

### Alerts log

Every HIGH/MEDIUM/LOW alert, in every mode, is appended to
`arp_mitm_alerts.log` in this folder (with a timestamp). Use "Open
alerts log file" in the sidebar to view the full history in your
default text editor, or "Export alerts as CSV" to save it as a
spreadsheet-friendly file.

## Building a standalone .exe (no Python needed to run it)

If you want a single double-click-able app instead of running
`python gui.py` every time:

**Windows:**
```
build_exe.bat
```
(or just double-click `build_exe.bat` in File Explorer)

**Mac / Linux:**
```bash
chmod +x build_exe.sh
./build_exe.sh
```

Either way, this installs `pyinstaller` and packages everything into
one file at `dist/ARPGuard.exe` (Windows) or `dist/ARPGuard` (Mac/Linux).
Copy just that one file anywhere, it runs standalone, no Python
install needed on the machine you copy it to. You only need to run the
build script once, on the same type of OS you'll run the final app on
(a Windows build must be built on Windows, etc.).

Note: Live Monitoring inside the built .exe still needs scapy's
packet-capture driver installed on that machine (Npcap on Windows,
already-present libpcap on Mac/Linux), and still needs to be run as
administrator/root.

## Running from the command line (no GUI)

```bash
python arp_mitm_detector.py --simulate
python arp_mitm_detector.py --scale-test --devices 200
python arp_mitm_detector.py --interface eth0      # live mode
```

## Notes

- This tool **detects** ARP spoofing; it does not block or mitigate an
  ongoing attack.
- False-positive handling: a conflicting MAC must be seen twice before
  alerting, virtualization MAC prefixes are scored as low-confidence,
  whitelisted pairs never alert, and repeat alerts for the same
  conflict are cooled down for 30 seconds.
