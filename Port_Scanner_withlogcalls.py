####################
# Author: Marc Nekes
# Description: This program is a port scanner that scans whether a pre-defined range of ports on a network is open or not.
####################

import socket
import re

from logging_setup import get_logger
#Change by Thibo: I added the function and indented this script in order to add it to the main-function.
def port_scanner_withlogcalls():
    logger = get_logger(__name__, "port_scanner.log")


    # Ask user to insert the ip-adress he wants to scan.
    # Check if ip-adress is valid through comparing it to ip-adress pattern.
    while True:
        ip_format = re.compile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")
        ip_adress = input("\nPlease insert an ip-adress you want to scan:")
        if ip_format.search(ip_adress):
            print("The entered IP adress is valid")
            logger.info(f"Target IP entered: {ip_adress}")
            break


    # Ask user to insert the port range he wants to scan
    while True:
        port_format = re.compile("([0-9]+)-([0-9]+)")
        port_range = input(
            "\nPlease enter the range of ports you want to scan in format min-max (e.g. 10-120)")
        match = port_format.search(port_range)
        if match:
            port_min = int(match.group(1))
            port_max = int(match.group(2))
            logger.info(f"Port scan range selected: {port_min}-{port_max}")
            break


    # Create empty list, in which later all open ports are stored
    ports_open = []

    logger.info("Port scan started")

    # Repeat the port scan for every defined port from port_min to port_max
    for port in range(port_min, port_max + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((ip_adress, port))
                ports_open.append(port)
                print("Watch out, port %d is open on %s" % (port, ip_adress))
                logger.warning(f"OPEN port detected: {ip_adress}:{port}")
        except:
            print("No danger, port %d is closed" % (port))
            logger.info(f"Port closed: {ip_adress}:{port}")


    # Summary
    logger.info(f"Port scan finished. Open ports found: {ports_open}")

    for port in ports_open:
        print("Watch out, port %d is open on %s" % (port, ip_adress))
