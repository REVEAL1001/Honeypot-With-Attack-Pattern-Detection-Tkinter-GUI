# Honeypot With Attack Pattern Detection (Tkinter GUI)

This project is a Python-based honeypot web server featuring real-time attack pattern detection and a modern Tkinter graphical interface. It helps monitor suspicious activities, log potential attacks, and analyze visitor details in a desktop application.

## Features

- **Web Server Honeypot:** Simulates an internal developer portal to attract and log unauthorized or malicious activity.
- **Attack Detection:** Identifies common attack patterns:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Dirsearch brute-force attacks
  - Reverse shell script uploads
- **Visitor Tracking:** Logs visitor info (IP, OS, browser, device, user agent).
- **Live Log Viewer:** See server activity and alerts in real time.
- **Export Logs:** Save logs for analysis.
- **Evidence Collection:** Stores suspicious file uploads in an `evidence/` folder.
- **Tkinter GUI:** Intuitive interface for server management and monitoring.

## Requirements

- Python 3.7+
- [user-agents](https://pypi.org/project/user-agents/) (`pip install user-agents`)
- Tkinter (included with most Python installations)

## Installation

```bash
git clone https://github.com/REVEAL1001/Honeypot-With-Attack-Pattern-Detection-Tkinter-GUI.git
cd Honeypot-With-Attack-Pattern-Detection-Tkinter-GUI
pip install user-agents
