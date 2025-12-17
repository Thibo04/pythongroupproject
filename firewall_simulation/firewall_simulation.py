import random
import time
import os

# =================================================
# Paths
# =================================================

BASE_DIR = os.path.dirname(__file__)
CONFIG_DIR = os.path.join(BASE_DIR, "config")


# =================================================
# Helpers to read config files
# =================================================

def load_lines(filename):
    """
    Read non-empty, non-comment lines from a config file.
    Returns a list of strings.
    """
    path = os.path.join(CONFIG_DIR, filename)
    lines = []

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
    except FileNotFoundError:
        print(f"[WARN] Missing config file: {filename}")

    return lines


def load_int(filename, default_value):
    """
    Read an integer value from a config file.
    Returns default_value if file is missing or invalid.
    """
    path = os.path.join(CONFIG_DIR, filename)

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    return int(line)
    except Exception:
        print(f"[WARN] Invalid or missing {filename}, using {default_value}")

    return default_value


# =================================================
# Firewall / DoS Simulation
# =================================================

def start_firewall_simulation():
    """
    Simulated firewall:
    - Random traffic
    - Blacklist filtering
    - Nimda malware detection
    - DoS detection by packet counting
    """

    # Load configuration
    blacklist = set(load_lines("blacklist.txt"))
    dos_limit = load_int("dos_config.txt", 20)

    nimda_signature = "NIMDA"
    nimda_lines = load_lines("nimda_signature.txt")
    if nimda_lines:
        nimda_signature = nimda_lines[0]

    # Runtime state
    packet_count = {}   # packets per IP
    blocked_ips = {}    # blocked IPs with reason

    print("\n=== Firewall / DoS Simulation ===")
    print(f"Blacklist IPs   : {len(blacklist)}")
    print(f"DoS threshold   : {dos_limit} packets per IP")
    print(f"Nimda signature : {nimda_signature}")
    print("Press CTRL+C to stop\n")

    try:
        while True:
            # Generate random source IP
            ip = f"192.168.1.{random.randint(1, 254)}"

            # Generate packet payload
            payload = "NORMAL"
            if random.random() < 0.01:
                payload = f"...{nimda_signature}..."

            # Already blocked
            if ip in blocked_ips:
                print(f"[BLOCKED] {ip} | reason: {blocked_ips[ip]}")
                time.sleep(0.1)
                continue

            # Rule 1: Blacklist
            if ip in blacklist:
                blocked_ips[ip] = "Blacklist"
                print(f"[BLOCKED] {ip} | reason: Blacklist")
                time.sleep(0.1)
                continue

            # Rule 2: Malware detection
            if nimda_signature in payload:
                blocked_ips[ip] = "Nimda malware"
                print(f"[BLOCKED] {ip} | reason: Nimda malware")
                time.sleep(0.1)
                continue

            # Rule 3: DoS detection
            packet_count[ip] = packet_count.get(ip, 0) + 1
            if packet_count[ip] > dos_limit:
                blocked_ips[ip] = "DoS attack"
                pri

