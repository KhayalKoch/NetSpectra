#!/usr/bin/env python3
# netspectra_c2_beacon.py
# NetSpectra Lab - Harmless C2 Beacon Simulation
# Purpose: Generate periodic, jittered HTTP requests so Zeek/Sigma
# can detect this as "C2 beaconing behavior" (MITRE T1071)
# THIS SCRIPT EXECUTES NO REAL COMMANDS - only sends HTTP GET requests.

import requests
import time
import random
from datetime import datetime

C2_SERVER = "http://127.0.0.1:8080/beacon"
BASE_INTERVAL = 30
JITTER = 10
LOG_FILE = "beacon_sent.log"  # ground truth log of every sent check-in

def log_sent(status):
    timestamp = datetime.now().isoformat()
    entry = f"[{timestamp}] Sent check-in -> status: {status}\n"
    with open(LOG_FILE, "a") as f:
        f.write(entry)

def beacon_loop():
    print(f"[*] NetSpectra Beacon started. Target: {C2_SERVER}")
    while True:
        try:
            response = requests.get(C2_SERVER, timeout=5)
            print(f"[+] Check-in sent. Status: {response.status_code}")
            log_sent(response.status_code)
        except requests.exceptions.RequestException as e:
            print(f"[-] Listener not reachable: {e}")
            log_sent("failed")

        sleep_time = BASE_INTERVAL + random.uniform(-JITTER, JITTER)
        print(f"[*] Next check-in in {sleep_time:.1f} seconds...")
        time.sleep(sleep_time)

if __name__ == "__main__":
    beacon_loop()
    
    
    
    
    