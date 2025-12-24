import random   # for random IP addresses and random traffic
import time     # to add small pauses so output is readable
import os       # to find files (config folder)

# =================================================
# I) File paths
# =================================================

# Get the folder where this Python file is located (keeps only the folder path)
BASE_DIR = os.path.dirname(__file__)

# Build the path to the config folder (blacklist, DoS config, etc.)
CONFIG_DIR = os.path.join(BASE_DIR, "config")

# =================================================
# II) Functions to read configuration files
# =================================================

# This function reads a config file
# - ignores empty lines
# - ignores lines starting with '#'
# - returns only useful lines (IPs, signatures, etc.)
def load_lines(filename):
    # Build the full path to the config file
    path = os.path.join(CONFIG_DIR, filename)

    # Create an empty list to store valid lines
    lines = []

    try:
        # Open the file in read mode
        with open(path, "r", encoding="utf-8") as file:

            # Read the file line by line
            for line in file:

                # Remove spaces and newline characters
                line = line.strip()

                # Check that the line is not empty and not a comment
                if line and not line.startswith("#"):

                    # Add the valid line to the list
                    lines.append(line)

    except FileNotFoundError:
        # Print a warning if the file does not exist
        print(f"[WARN] Missing config file: {filename}")

    # Return the list of valid lines
    return lines


# This function reads a number from a config file (example: DoS threshold)
# If the file is missing or invalid, we use a default value
def load_int(filename, default_value):
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
# III) Firewall / DoS Simulation
# =================================================

# This function simulates a simple firewall:
# - generates random network traffic
# - blocks IPs based on blacklist
# - blocks packets containing a malware signature (Nimda)
# - blocks IPs if they send too many packets (DoS)

# This function is called from the main menu (option 3)
def start_firewall_simulation():
    # Load blacklist IPs from config
    blacklist = set(load_lines("blacklist.txt"))

    # Load DoS threshold (max packets per IP)
    dos_limit = load_int("dos_config.txt", 20)

    # Default malware signature
    nimda_signature = "NIMDA"

    # Load malware signature from file if available (use first line)
    nimda_lines = load_lines("nimda_signature.txt")
    if nimda_lines:
        nimda_signature = nimda_lines[0]

    # Count how many packets each IP has sent (for DoS detection)
    packet_count = {}

    # Store blocked IPs and the reason why they were blocked
    blocked_ips = {}

    # Show firewall configuration to the user
    print("\n=== Firewall / DoS Simulation ===")
    print(f"Blacklist IPs   : {len(blacklist)}")
    print(f"DoS threshold   : {dos_limit} packets per IP")
    print(f"Nimda signature : {nimda_signature}")
    print("Press CTRL+C to stop\n")

    try:
        while True:
            # Generate a random source IP address
            ip = f"192.168.1.{random.randint(1, 254)}"

            # Fake packet content (payload)
            payload = "NORMAL"

            # Small chance to simulate malware traffic
            if random.random() < 0.01:
                payload = f"...{nimda_signature}..."

            # If the IP is already blocked, print it and skip
            if ip in blocked_ips:
                print(f"[BLOCKED] {ip} | reason: {blocked_ips[ip]}")
                time.sleep(0.1)
                continue

            # Rule 1: block if IP is in blacklist
            if ip in blacklist:
                blocked_ips[ip] = "Blacklist"
                print(f"[BLOCKED] {ip} | reason: Blacklist")
                time.sleep(0.1)
                continue

            # Rule 2: block if malware signature is found
            if nimda_signature in payload:
                blocked_ips[ip] = "Nimda malware"
                print(f"[BLOCKED] {ip} | reason: Nimda malware")
                time.sleep(0.1)
                continue

            # Rule 3: DoS detection (too many packets from same IP)
            packet_count[ip] = packet_count.get(ip, 0) + 1
            if packet_count[ip] > dos_limit:
                blocked_ips[ip] = "DoS attack"
                print(f"[BLOCKED] {ip} | reason: DoS attack")
                time.sleep(0.1)
                continue

            # If no rule blocked the IP, allow the traffic
            print(f"[ALLOW ] {ip}")
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nSimulation stopped.")
        print("Blocked IP summary:")

        if not blocked_ips:
            print("No IPs were blocked.")
        else:
            for ip, reason in blocked_ips.items():
                print(f"- {ip}: {reason}")



