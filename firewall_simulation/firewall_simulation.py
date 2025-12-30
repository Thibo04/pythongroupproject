###############################
# File: firewall_simulation.py
# Purpose:
#   Simulates a simple firewall and DoS detection mechanism by generating random
#   network traffic and applying three rule types:
#     1) Block IPs on a blacklist (config/blacklist.txt)
#     2) Block packets containing a malware signature (config/nimda_signature.txt)
#     3) Block IPs exceeding a request threshold (DoS simulation; config/dos_config.txt)
#
#   - Robust configuration loading (ignores comments/empty lines, uses defaults on errors)
#   - Safe failure behavior (missing/invalid config does not crash the simulation)
#   - Clear separation between config parsing and simulation logic
#   - Logging of important events for reporting (allowed vs blocked + reasons)
###############################

import random
import time
import os
import sys

# Add project root to PYTHONPATH so imports work when this script is run from subfolders.
sys.path.append(os.path.dirname(os.path.dirname(__file__)))


from logging_setup import get_logger
logger = get_logger(__name__, "firewall_simulation.log")



# Get the folder where this Python file is located (only keeps the name of the file)
BASE_DIR = os.path.dirname(__file__)
# Build the path to the config folder (blacklist, DoS config, etc.)
CONFIG_DIR = os.path.join(BASE_DIR, "config")


# This function reads a config file and returns a list of meaningful lines.
def load_lines(filename):
    path = os.path.join(CONFIG_DIR, filename)
    lines = []

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                # Only keep lines that contain actual configuration values.
                if line and not line.startswith("#"):
                    lines.append(line)

    except FileNotFoundError:
        # Missing config should not crash the program.
        print(f"[WARN] Missing config file: {filename}")
        logger.warning(f"Missing config file: {filename}")

    return lines


# This function reads a single integer from a config file (e.g., DoS threshold).
# If the file is missing or contains invalid content, it falls back to a default value.
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
        logger.warning(f"Invalid or missing {filename}, using default {default_value}")

    return default_value


# This function simulates firewall behavior by generating random traffic and applying rules.
# It is designed as a continuous loop that can be stopped by the user with CTRL+C.
def start_firewall_simulation():
    # Load blacklist IPs from config
    blacklist = set(load_lines("blacklist.txt"))

    # Load DoS threshold (max packets per IP)
    dos_limit = load_int("dos_config.txt", 20)

    # Default malware signature
    nimda_signature = "NIMDA"

    # Load malware signature from file if available.
    nimda_lines = load_lines("nimda_signature.txt")
    if nimda_lines:
        nimda_signature = nimda_lines[0]

    packet_count = {}
    blocked_ips = {}

    print("\n=== Firewall / DoS Simulation ===")
    print(f"Blacklist IPs   : {len(blacklist)}")
    print(f"DoS threshold   : {dos_limit} packets per IP")
    print(f"Nimda signature : {nimda_signature}")
    print("Press CTRL+C to stop\n")

    # Log configuration at start
    logger.info("Firewall simulation started")
    logger.info(f"Blacklist IPs: {len(blacklist)} | DoS limit: {dos_limit} | Nimda signature: {nimda_signature}")

    try:
        while True:
            # Generate a pseudo-random internal IP (simulation only).
            ip = f"192.168.1.{random.randint(1, 254)}"

            # Default payload is normal traffic.
            payload = "NORMAL"

            # Small probability to simulate malicious payload traffic.
            if random.random() < 0.01:
                payload = f"...{nimda_signature}..."

            # If already blocked, skip rule evaluation and report.
            if ip in blocked_ips:
                print(f"[BLOCKED] {ip} | reason: {blocked_ips[ip]}")
                logger.warning(f"BLOCKED {ip} | reason: {blocked_ips[ip]}")
                time.sleep(0.1)
                continue

            # Rule 1: Block based on blacklist membership.
            if ip in blacklist:
                blocked_ips[ip] = "Blacklist"
                print(f"[BLOCKED] {ip} | reason: Blacklist")
                logger.warning(f"BLOCKED {ip} | reason: Blacklist")
                time.sleep(0.1)
                continue

            # Rule 2: Block if malware signature appears in payload.
            if nimda_signature in payload:
                blocked_ips[ip] = "Nimda malware"
                print(f"[BLOCKED] {ip} | reason: Nimda malware")
                logger.warning(f"BLOCKED {ip} | reason: Nimda malware")
                time.sleep(0.1)
                continue

            # Rule 3: DoS detection by counting packets per IP.
            packet_count[ip] = packet_count.get(ip, 0) + 1
            if packet_count[ip] > dos_limit:
                blocked_ips[ip] = "DoS attack"
                print(f"[BLOCKED] {ip} | reason: DoS attack")
                logger.warning(f"BLOCKED {ip} | reason: DoS attack | packets={packet_count[ip]}")
                time.sleep(0.1)
                continue

            # If the traffic passes all rules, it is allowed.
            print(f"[ALLOW ] {ip}")
            logger.info(f"ALLOWED {ip}")
            time.sleep(0.1)

    except KeyboardInterrupt:
        # CTRL+C is treated as a normal exit condition; report a summary.
        print("\nSimulation stopped.")
        print("Blocked IP summary:")

        logger.info("Firewall simulation stopped by user (CTRL+C)")
        logger.info(f"Total blocked IPs: {len(blocked_ips)}")

        if not blocked_ips:
            print("No IPs were blocked.")
            logger.info("No IPs were blocked.")
        else:
            # Print a readable summary of all blocked IPs and reasons.
            for ip, reason in blocked_ips.items():
                print(f"- {ip}: {reason}")
                logger.warning(f"Blocked summary: {ip} | reason: {reason}")

if __name__ == "__main__":
    start_firewall_simulation()
