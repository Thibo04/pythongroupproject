import random   # for random IP addresses and random traffic
import time     # to add small pauses so output is readable
import os       # to find files (config folder)

# I) File paths

# Get the folder where this Python file is located and onnly keeps the name fo the file/ This allows the program to work on any computer
BASE_DIR = os.path.dirname(__file__)

# Path to the config folder
CONFIG_DIR = os.path.join(BASE_DIR, "config")



# II) Functions to read configuration files

    # This function reads a config file
    # It ignores empty lines and lines starting with '#'
    # It returns only the useful lines (for example IPs or signatures)

def load_lines(filename):
 
    path = os.path.join(CONFIG_DIR, filename)
    lines = []

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()  # remove spaces and \n
                if line and not line.startswith("#"):
                    lines.append(line)
    except FileNotFoundError:
        print(f"[WARN] Missing config file: {filename}")

    return lines


    # This function reads a number from a config file
    # It is used for values like the DoS threshold
    # If the file is missing or incorrect, a default value is used

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



# III) Firewall / DoS Simulation
    # This function simulates a simple firewall.
    # It generates random network traffic.
    # Incoming IPs are checked against different security rules:
        # - blacklist filtering
        # - malware (Nimda) detection
        # - DoS detection based on packet count

def start_firewall_simulation():

    # Load blacklist IPs from file in config
    blacklist = set(load_lines("blacklist.txt"))

    # Load DoS threshold (max packets per IP)
    dos_limit = load_int("dos_config.txt", 20)

    # Default malware signature
    nimda_signature = "NIMDA"

    # Try to load malware signature from config file 
    # If the file exists and not empty, use the first value from the file as signature
    nimda_lines = load_lines("nimda_signature.txt")
    if nimda_lines:
        nimda_signature = nimda_lines[0]

    # Dictionary that stores how many packets each IP has sent (for Dos function)
    packet_count = {}

    # Dictionary that stores blocked IPs and the reason why they were blocked
    blocked_ips = {}
    
    # Display firewall configuration and basic information
    print("\n=== Firewall / DoS Simulation ===")
    print(f"Blacklist IPs   : {len(blacklist)}")
    print(f"DoS threshold   : {dos_limit} packets per IP")
    print(f"Nimda signature : {nimda_signature}")
    print("Press CTRL+C to stop\n")

    try:
        while True:
            # Create a random source IP address
            ip = f"192.168.1.{random.randint(1, 254)}"

            # Create a fake packet content
            payload = "NORMAL"

            # Random chance to simulate malware traffic
            if random.random() < 0.01:
                payload = f"...{nimda_signature}..."

            # If IP is already blocked, ignore it
            if ip in blocked_ips:
                print(f"[BLOCKED] {ip} | reason: {blocked_ips[ip]}")
                time.sleep(0.1)
                continue

            # Rule 1: Block if IP is in blacklist
            if ip in blacklist:
                
                    # Save the IP as blocked and store the reason
                blocked_ips[ip] = "Blacklist"                
                    # Display that the IP has been blocked because of the blacklist
                print(f"[BLOCKED] {ip} | reason: Blacklist")
                    # Small pause to slow down the output
                time.sleep(0.1)
                    # Stop processing this IP and move to the next one
                continue

            # Rule 2: Block if malware signature is found
            if nimda_signature in payload:
                blocked_ips[ip] = "Nimda malware"
                print(f"[BLOCKED] {ip} | reason: Nimda malware")
                time.sleep(0.1)
                continue

            # Rule 3: DoS detection (too many packets)
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
        # Stop simulation when CTRL+C is pressed
        print("\nSimulation stopped.")
        print("Blocked IP summary:")

        if not blocked_ips:
            print("No IPs were blocked.")
        else:
            for ip, reason in blocked_ips.items():
                print(f"- {ip}: {reason}")


