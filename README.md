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

# Honeypot

## Usage

### Start the Application
- Launch `honeypot.py` to open the GUI.

### Select Port
- Enter the port number (default: **8080**) and click **Start Server**.

### Monitor Activity
- Visitor details and attack alerts show in real time.

### Export Logs
- Click **Export Logs** to save logs.

### Stop Server
- Click **Stop Server** when finished.

---

## GUI Overview

- **Port Selection**: Set the honeypot server port.
- **Start/Stop Buttons**: Manage the server.
- **Visitor Table**: View all visitors.
- **Log Viewer**: See activity, requests, and detected attacks.
- **Export Logs**: Save logs as `.log` files.

---

## Security Patterns Detected

The honeypot is capable of detecting several suspicious behaviors and attack patterns:

### SQL Injection
Examples: `OR 1=1`, `UNION SELECT`, `SLEEP(n)`

### Cross-Site Scripting (XSS)
Examples: `<script>` tags, JavaScript event handlers like `onload`, `onclick`

### Path Traversal
Examples: `../`, `/etc/passwd`, `.env`

### Dirsearch Scans
High-frequency automated directory or file requests from the same IP.

### Reverse Shell Upload Attempts
Indicators include uploaded bash scripts, use of `nc`, `exec`, and other command injection attempts.

---

## Evidence Storage

- All suspicious uploaded files are stored in the `evidence/` folder for further analysis.

---

## Disclaimer

> ⚠️ **This project is intended for educational and research purposes only.**  
> Do **not** deploy this honeypot in production environments.  
> Always obtain proper **authorization** before deploying or testing in any real-world network.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
