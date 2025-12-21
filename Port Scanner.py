####################
# Author: Marc Nekes
# Description: This program is a port scanner that scans whether a pre-defined range of ports on a network is open or not.
####################

# Import socket library to create network connections
# Import re library to be able to check if a string (in this case IP-adress and port number) matches a certain pattern.
import socket
import re

# Ask user to insert the ip-adress he wants to scan.
# Check if ip-adress is valid through comparing it to ip-adress pattern.
while True:
    # ip_format defines the ip pattern
    ip_format = re.compile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")
    # ip_adress reads the ip adress the user wants to scan
    ip_adress = input("\nPlease insert an ip-adress you want to scan:")
    # if ip_format matches with ip_adress, then the  entered ip adress is valid
    if ip_format.search(ip_adress):
        print("The entered IP adress is valid")
        break

# Ask user to insert the port range he wants to scan
while True:
    # port_format defines the port pattern
    port_format = re.compile("([0-9]+)-([0-9]+)")
    # port_range reads the port range the user wants to scan
    port_range = input(
        "\nPlease enter the range of ports you want to scan in format min-max (e.g. 10-120)")
    # Scan if there is a match between port_format and port_range
    match = port_format.search(port_range)
    # If there is a match, proceed to storing first number into port_min and second number into port_max (e.g. 10-20 -> 10 in port_min and 20 in port_max)
    if match:
        port_min = int(match.group(1))
        port_max = int(match.group(2))
        break

# Create empty list, in which later all open ports are stored
ports_open = []

# Repeat the port scan for every defined port from port_min to port_max
for port in range(port_min, port_max + 1):
    try:
        # Create a temporary socket object that enables to connect to a network
        # AF_INET defines to use IPv4 as internet adress family
        # SOCK_STREAM defines the TCP protocol as socket type
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Socket tries to connect to ip_adress and port for 0.5 secs
            s.settimeout(0.5)
            s.connect((ip_adress, port))
            # If connection to ip and port succeeded, then the port is open and is appended to the list
            ports_open.append(port)
    # If connection to port fails it prints that the port is closed
    except:
        print("No danger, port %d is closed" % (port))
# Open ports stored in the list are printed out
for port in ports_open:
    print("Watch out, port %d is open on %s" % (port, ip_adress))
