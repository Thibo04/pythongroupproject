#Python group project, Cybersecurity
import os
import sys


# 1. option: Service & OS-Fingerprinting
from fingerprinting import fingerprint_host


def service_os_menu() -> None:
    print("PyNetGuard – Service & OS Fingerprinting\n")

    ip = input("Target IP (e.g. 127.0.0.1): ").strip()
    ports_str = input("Ports (comma separated, e.g. 22,80,443): ").strip()

    # basic validation so the program doesn’t crash on bad input
    try:
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
    except ValueError:
        print("Invalid port list. Please enter only numbers separated by commas.")
        return

    if not ports:
        print("No ports given – aborting scan.")
        return

    results = fingerprint_host(ip, ports)

    if not results:
        print("\nNo results – host may be down or nmap could not detect any services.")
        return

    print("\nScan results:")
    for r in results:
        print("-" * 40)
        print(f"IP: {r['ip']}")
        print(f"OS: {r['os']}")
        print(f"Port: {r['port']} ({r['name']})")
        print(f"Product/Version: {r['product']} {r['version']}")
        banner = r["banner"] or "No banner received"
        print(f"Banner: {banner}")
        print(f"Risk level: {r['risk']}")

# 2. option: Port Scanner
from Port_Scanner_withlogcalls import port_scanner_withlogcalls


# 3. option: Firewall-/DoS-Simulation
from firewall_simulation.firewall_simulation import start_firewall_simulation

def firewall_menu() -> None:
    print("\n=== Firewall / DoS Simulation ===")
    print("Press CTRL+C to stop\n")
    start_firewall_simulation()

# 4. option: Stealth Mode
from stealth_engine import set_stealth_mode
import stealth_engine

# 5. option: Reporting & Logging
from logging_setup import get_logger
import logs

#main function
def main() -> None:
    # This is the main()-function, where the user interface is. The user can choose between the 4 available services.      
    # As this program needs access to system-critical information, the user must enter his password, in order for the program to access the information.
    # On windows: Administrator privileges.
    if os.geteuid() != 0:
        print("\nBefore using this program, be aware that it requires root privileges (administrator privileges) in order to run.")
        print("If you consent, please enter the password of your device below, in order to restart with sudo.\nIt will not be displayed on the screen.\n")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    print("\nWelcome to our Cybersecurity-Multifunction-Program!\nWe offer several functions in Cybersecurity, to make your internet usage safer.")
    print("In the logs folder (in the subfiles) a full log is available of past actions of these functions.\nFurther information on the services offered in this program and its requirements are available in the README script.\n\n")
    print("To get started, select one of the following functions:")
    #To be able to create a second loop for the continuing options, we define a boolean. This is to differentiate between inner and outer loop.
    running = True
    
    while running:   
        service_choice = input("\n1. OS-Fingerprinting\n2. Port Scanner\n3. Firewall/DoS-Application\n4. Network Stealth Mode\n\nEnter the number of the service you desire: ")
        #If the user enters a wrong number, the program will jump back to the input. If a valid integer has been entered, the program jumps to the selected function.
        try:
            service_choice = int(service_choice)
            if 1 < service_choice > 4:
                raise ValueError
            if service_choice == 1:
                service_os_menu()
            elif service_choice == 2:
                port_scanner_withlogcalls()
            elif service_choice == 3:
                firewall_menu()
            elif service_choice == 4:
                set_stealth_mode()
        
        except ValueError:
            print("\nError. Please enter an integer between 1 and 4, according to the program you desire:")
        
        while True:
            # We use the strip-function, to get remove the following and leading whitepaces. This makes the function more error-proof.
            continuing_options = input("\n-----------\nIf you wish to return to the services-menu, press ENTER. If you wish to end the program, enter QUIT: ").strip()
            if continuing_options == '':
                # We now use the boolean we defined before, to tell the code, to stay continue the outher loop               
                running = True 
                break
            # With the uppercase-converter, it doesn't matter how the user entered quit. This avoids unnecessary perfectionism for the required input.              
            elif continuing_options.upper() == "QUIT":
                print("Thank you for using this tool. Have a nice day!")
                running = False
                break
            else:
                print("Invalid input. Please press the ENTER-key or write QUIT, all uppercase.")
                continue



if __name__ == "__main__":
    main()