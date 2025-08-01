import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import threading
import http.server
import socketserver
import logging
from datetime import datetime
import os
import re
from urllib.parse import unquote
import cgi
from user_agents import parse

# Configure logging
logging.basicConfig(filename='honeypot.log', level=logging.INFO, 
                   format='%(asctime)s - %(message)s')

class HoneypotServer(http.server.SimpleHTTPRequestHandler):
    # Track requests per IP for dirsearch detection
    request_counts = {}
    REQUEST_THRESHOLD = 10  # Number of requests in time window to flag dirsearch
    TIME_WINDOW = 60  # Seconds

    # Detection patterns
    SQL_INJECTION_PATTERNS = [
        r"['\"][\s]*OR[\s]*['\"]?1['\"]?=1",
        r"UNION[\s]+SELECT",
        r"SLEEP\(\d+\)",
        r"SELECT[\s]+.*FROM[\s]+",
    ]
    XSS_PATTERNS = [
        r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
        r"on\w+\s*=",
        r"javascript:",
        r"alert\(",
    ]
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"/etc/passwd",
        r"\.env",
        r"/config\.",
    ]

    def detect_attacks(self, data):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        client_ip = self.client_address[0]
        alerts = []

        # Check SQL Injection
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                alerts.append(f"Possible SQL Injection attempt from {client_ip}: {data}")
                break

        # Check XSS
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                alerts.append(f"Possible XSS attempt from {client_ip}: {data}")
                break

        # Check Path Traversal
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                alerts.append(f"Possible Path Traversal attempt from {client_ip}: {data}")
                break

        # Log and update GUI for detected attacks
        for alert in alerts:
            logging.info(alert)
            app.update_log(f"{timestamp} - {alert}\n")
        
        return alerts

    def do_GET(self):
        client_ip = self.client_address[0]
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user_agent = self.headers.get('User-Agent', 'Unknown')
        ua = parse(user_agent)
        
        # Collect visitor details
        visitor_info = {
            'ip': client_ip,
            'os': f"{ua.os.family} {ua.os.version_string}",
            'browser': f"{ua.browser.family} {ua.browser.version_string}",
            'device': ua.device.family,
            'user_agent': user_agent,
            'requests': []
        }
        
        # Update request tracking for dirsearch detection
        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = []
        self.request_counts[client_ip].append(datetime.now())
        self.request_counts[client_ip] = [
            t for t in self.request_counts[client_ip]
            if (datetime.now() - t).total_seconds() <= self.TIME_WINDOW
        ]
        if len(self.request_counts[client_ip]) > self.REQUEST_THRESHOLD:
            log_message = f"Possible dirsearch attack from {client_ip}: {len(self.request_counts[client_ip])} requests in {self.TIME_WINDOW}s"
            logging.info(log_message)
            app.update_log(f"{timestamp} - {log_message}\n")
        
        # Check for attack patterns in request path
        request_path = unquote(self.path)
        self.detect_attacks(request_path)
        
        # Log request
        log_message = f"Request from {client_ip}: GET {request_path} | OS: {visitor_info['os']} | Browser: {visitor_info['browser']}"
        logging.info(log_message)
        app.update_visitor(client_ip, visitor_info, f"{timestamp} - GET {request_path}")
        
        # Serve deceptive HTML
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(self.get_html().encode())

    def do_POST(self):
        client_ip = self.client_address[0]
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Handle search form submission
        if self.path == '/search':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            if 'query' in form:
                query = form['query'].value
                self.detect_attacks(query)
                log_message = f"Search query from {client_ip}: {query}"
                logging.info(log_message)
                app.update_log(f"{timestamp} - {log_message}\n")
        
        # Handle file uploads
        elif self.path == '/uploads':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            if 'file' in form:
                file_item = form['file']
                if file_item.filename:
                    content = file_item.file.read().decode('utf-8', errors='ignore')
                    self.detect_attacks(content)
                    is_bash = any([
                        content.startswith('#!/bin/bash'),
                        'exec' in content,
                        'nc ' in content,
                        'bash -i' in content
                    ])
                    log_message = f"File upload from {client_ip}: {file_item.filename}"
                    if is_bash:
                        log_message += " - Possible reverse shell detected!"
                    logging.info(log_message)
                    app.update_log(f"{timestamp} - {log_message}\n")
                    
                    # Save file to evidence folder
                    evidence_dir = 'evidence'
                    os.makedirs(evidence_dir, exist_ok=True)
                    with open(os.path.join(evidence_dir, file_item.filename), 'wb') as f:
                        f.write(content.encode())
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(self.get_html().encode())

    def get_html(self):
        return """
        <html>
        <head>
            <title>Internal Developer Portal</title>
            <style>
                body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
                .container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 5px; }
                h1 { color: #333; }
                .warning { color: red; font-weight: bold; }
                .form-section { margin-top: 20px; }
                .search-form input[type=text] { width: 70%; padding: 8px; }
                .upload-form input[type=file] { margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Developer Portal - Internal Use Only</h1>
                <p class="warning">Unauthorized access is strictly prohibited. All actions are logged.</p>
                <p>Welcome to the internal development server. This system is for authorized developers only.</p>
                <h3>Search Documentation</h3>
                <form class="form-section search-form" method="post" action="/search">
                    <input type="text" name="query" placeholder="Search internal docs...">
                    <input type="submit" value="Search">
                </form>
                <h3>Upload Development Scripts</h3>
                <form class="form-section upload-form" enctype="multipart/form-data" method="post" action="/uploads">
                    <input type="file" name="file" accept=".sh,.bash">
                    <input type="submit" value="Upload Script">
                </form>
                <p>Contact the admin team at devops@internal.local for access credentials.</p>
            </div>
        </body>
        </html>
        """

class HoneypotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Honeypot Web Server")
        self.root.geometry("800x600")
        
        self.server = None
        self.server_thread = None
        self.is_running = False
        self.visitors = {}  # Track visitors by IP
        
        # GUI Elements
        self.create_widgets()
        
    def create_widgets(self):
        # Port selection
        ttk.Label(self.root, text="Port:").grid(row=0, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(self.root)
        self.port_entry.insert(0, "8080")
        self.port_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Start/Stop buttons
        self.start_button = ttk.Button(self.root, text="Start Server", command=self.start_server)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)
        
        self.stop_button = ttk.Button(self.root, text="Stop Server", command=self.stop_server, state="disabled")
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)
        
        # Export logs button
        self.export_button = ttk.Button(self.root, text="Export Logs", command=self.export_logs)
        self.export_button.grid(row=0, column=4, padx=5, pady=5)
        
        # Visitor treeview
        self.tree = ttk.Treeview(self.root, columns=('IP', 'OS', 'Browser', 'Device'), show='headings')
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('OS', text='Operating System')
        self.tree.heading('Browser', text='Browser')
        self.tree.heading('Device', text='Device')
        self.tree.grid(row=1, column=0, columnspan=5, padx=5, pady=5, sticky='nsew')
        
        # Log display
        self.log_text = scrolledtext.ScrolledText(self.root, height=15, width=90)
        self.log_text.grid(row=2, column=0, columnspan=5, padx=5, pady=5)
        
        # Configure grid weights
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
    def start_server(self):
        try:
            port = int(self.port_entry.get())
            if port < 1024 or port > 65535:
                self.update_log("Error: Port must be between 1024 and 65535\n")
                return
                
            self.server = socketserver.TCPServer(("", port), HoneypotServer)
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.is_running = True
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.port_entry.config(state="disabled")
            self.update_log(f"Server started on port {port}\n")
            
        except ValueError:
            self.update_log("Error: Invalid port number\n")
        except OSError as e:
            self.update_log(f"Error starting server: {str(e)}\n")
            
    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.server_thread = None
            self.is_running = False
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.port_entry.config(state="normal")
            self.update_log("Server stopped\n")
            
    def update_log(self, message):
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        
    def update_visitor(self, ip, visitor_info, request):
        if ip not in self.visitors:
            self.visitors[ip] = visitor_info
            self.tree.insert('', 'end', iid=ip, values=(
                ip, visitor_info['os'], visitor_info['browser'], visitor_info['device']
            ))
        self.visitors[ip]['requests'].append(request)
        self.update_log(f"{request}\n")
        
    def export_logs(self):
        log_content = self.log_text.get("1.0", tk.END).strip()
        if not log_content:
            self.update_log("No logs to export\n")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"honeypot_export_{timestamp}.log"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            initialfile=default_filename,
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(log_content)
                self.update_log(f"Logs exported to {file_path}\n")
            except Exception as e:
                self.update_log(f"Error exporting logs: {str(e)}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = HoneypotGUI(root)
    root.mainloop()
