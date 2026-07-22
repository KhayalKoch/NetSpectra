#!/usr/bin/env python3
# netspectra_c2_listener.py
# NetSpectra Lab - Harmless C2 Listener Simulation
# Purpose: Receive and log beacon check-ins (does NOT execute real commands)

from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

LOG_FILE = "c2_checkins.log"

class C2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        timestamp = datetime.now().isoformat()
        client_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "unknown")
        entry = f"[{timestamp}] Check-in from {client_ip} -> {self.path} (UA: {user_agent})\n"

        print(entry.strip())
        with open(LOG_FILE, "a") as f:
            f.write(entry)

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ack")

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    port = 8080
    server = HTTPServer(("0.0.0.0", port), C2Handler)
    print(f"[*] NetSpectra C2 Listener started on port {port}")
    print(f"[*] Log file: {LOG_FILE}")
    server.serve_forever()
    
    
    
    
    
    
    