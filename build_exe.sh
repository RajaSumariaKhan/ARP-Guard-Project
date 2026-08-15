#!/bin/bash
#  ARP Guard -- build a standalone Mac/Linux executable
#  Run this once on your machine:
#      chmod +x build_exe.sh
#      ./build_exe.sh
set -e

echo "Installing build tools and dependencies..."
pip3 install pyinstaller psutil scapy

echo
echo "Building ARPGuard executable..."
# arp_mitm_detector.py is auto-bundled since gui.py imports it directly.
pyinstaller --onefile --windowed --name ARPGuard gui.py

echo
echo "Done! Your app is at:  dist/ARPGuard"
echo "Copy that one file anywhere and double-click (or run it) --"
echo "no Python install needed on the machine you copy it to."