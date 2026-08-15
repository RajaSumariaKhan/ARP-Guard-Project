@echo off
REM  ARP Guard -- build a standalone Windows .exe
REM  Run this once on your Windows laptop (double-click it, or
REM  open a terminal in this folder and run: build_exe.bat)

echo Installing build tools and dependencies...
pip install pyinstaller psutil scapy

echo.
echo Building ARPGuard.exe ...
REM arp_mitm_detector.py is auto-bundled since gui.py imports it directly.
pyinstaller --onefile --windowed --name ARPGuard gui.py

echo.
echo Done! Your app is at:  dist\ARPGuard.exe
echo Copy that one file anywhere and double-click it to run --
echo no Python install needed on the machine you copy it to.
pause
