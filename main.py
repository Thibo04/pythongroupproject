###############################
# Project: Cybersecurity Multifunction Program
# File: main.py
# Purpose:
#   Provides a simple command-line menu that lets the user run the project’s
#   independent modules (OS/service fingerprinting, port scanning, firewall/DoS
#   simulation and stealth mode) from a single entry point.
#
#   - This file focuses on user interaction and routing (calling the right module).
#   - Input parsing is protected with try/except to avoid crashes on invalid input.
#   - Root/admin privileges are requested because some network/security operations
#     may require elevated permissions.
###############################

import os
import sys


# 1) Option: Service & OS Fingerprinting
from fingerprinting import fingerprint_host


def service_os_menu() -> None:
    # Menu handler for OS and service fingerprinting.
    # Collects user input (target IP, ports, options), validates it, then calls
    # fingerprint_host(). Results are printed and saved to a CSV file.
    print("PyNetGuard – Service & OS Fingerprinting\n")

    ip = input("Target IP (e.g. 127.0.0.1): ").strip()
    ports_str = input("Ports (comma separated, e.g. 22,80,443): ").strip()

    # Public IP scanning is potentially sensitive; this flag acts as an explicit consent switch.
    allow_public_in = input("Allow scanning public IPs? (y/N): ").strip().lower()
    allow_public = allow_public_in in ("y", "yes")

    # CSV history can either be appended or overwritten.
    append_in = input("Append results to CSV (keep history)? (Y/n): ").strip().lower()
    append_csv = append_in not in ("n", "no")

    output_file = "fingerprint_results.csv"

    # Port list parsing is validated so non-numeric input does not crash the program.
    try:
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
    except ValueError:
        print("Invalid port list. Please enter only numbers separated by commas.")
        return

    # Running a scan without ports is not meaningful.
    if not ports:
        print("No ports given – aborting scan.")
        return

    # fingerprint_host is treated as a "service" that may fail due to invalid input,
    # missing tools (e.g., nmap), connectivity issues, or other runtime constraints.
    try:
        results = fingerprint_host(
            ip,
            ports,
            output_file=output_file,
            allow_public=allow_public,
            append_csv=append_csv,
        )
    except ValueError as e:
        print(f"Input error: {e}")
        return
    except RuntimeError as e:
        print(f"Runtime error: {e}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

    if not results:
        print("\nNo results – host may be down, filtered, or nmap couldn’t detect services.")
        return

    print("\nScan results:")
    for r in results:
        print("-" * 40)
        print(f"IP: {r.get('ip', '')}")
        print(f"OS: {r.get('os', 'Unknown')}")
        print(f"Port: {r.get('port')} ({r.get('name', '')})  State: {r.get('state', '')}")
        print(f"Product/Version: {(r.get('product', '') + ' ' + r.get('version', '')).strip()}")
        banner = r.get("banner") or "No banner received"
        print(f"Banner: {banner}")
        print(f"Risk level: {r.get('risk', '')}")

    print(f"\nSaved to: {output_file}")

# 2) Option: Port Scanner
from port_scanner import port_scanner_withlogcalls


# 3) Option: Firewall / DoS Simulation
from firewall_simulation.firewall_simulation import start_firewall_simulation

def firewall_menu() -> None:
    # Menu handler for the firewall and DoS simulation module.
    #The simulation runs until the user stops it (CTRL+C).
    print("\n=== Firewall / DoS Simulation ===")
    print("Press CTRL+C to stop\n")
    start_firewall_simulation()

# 4) Option: Stealth Mode
from stealth_engine import set_stealth_mode
import stealth_engine as stealth_engine
from smoke_test import main_smoke_test

# 5) Option: Reporting & Logging


# Function, to ensure sufficient root/administrator-privileges. This function can also determine the operation system
import platform
import ctypes

def is_admin() -> bool:
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        return os.geteuid() == 0


if not is_admin():
    print("\nBefore using this program, be aware that it requires administrator/root privileges.\n")

    if platform.system() == "Windows":
        # Restart script with admin rights on Windows
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join(sys.argv),
            None,
            1
        )
    else:
        # Restart with sudo on Linux/macOS
        print("If you consent, please enter the password of your device below, in order to restart with sudo.\nIt will not be displayed on the screen.\n")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

    sys.exit()

def main() -> None:
    # Entry point for the CLI application.
    # Responsibilities:
    # - Ensure the program runs with sufficient privileges (root/admin).
    # - Present a menu and route the user to the chosen module.
    # - Prevent common input errors (non-integer choices, out-of-range values).
    # - Provide a simple loop to return to the menu or quit cleanly.

    # Some networking/security features may require root/admin privileges.
    # On Linux/macOS, os.geteuid() checks effective user ID; if not root, re-run with sudo.
    # On Windows, the is_admin-function checks if the system is run as administrator.
    
    is_admin()
    #If this was successful, the program jumps to the next step  
    print("\nWelcome to our Cybersecurity-Multifunction-Program!\nWe offer several functions in Cybersecurity, to make your internet usage safer.")
    print("In the logs folder (in the subfiles) a full log is available of past actions of these functions.\nFurther information on the services offered in this program and its requirements are available in the README script.\n\n")
    print("To get started, select one of the following functions:")
    #To be able to create a second loop for the continuing options, we define a boolean. This is to differentiate between inner and outer loop.
    running = True
    
    while running:   
        service_choice = input("\n1. OS-Fingerprinting\n2. Port Scanner\n3. Firewall/DoS-Application\n4. Network Stealth Mode\n5. Quit programn\n\nEnter the number of the service you desire: ")
        #If the user enters a wrong number, the program will jump back to the input. If a valid integer has been entered, the program jumps to the selected function.
        try:
            service_choice = int(service_choice)
            # Range check prevents invalid choices from being executed.
            # If out of range, raise ValueError to reuse the existing error handling path.
            if 1 < service_choice > 5:
                raise ValueError
            # Route to the selected functionality.
            if service_choice == 1:
                service_os_menu()
            elif service_choice == 2:
                port_scanner_withlogcalls()
            elif service_choice == 3:
                firewall_menu()
            elif service_choice == 4:
                while True:
                    print("If you want to start the stealth mode directly (only for Windows): 1\nIf you want to test the program: 2")
                    choice = input("Your choice (1 or 2): ")
                    try:
                        choice = int(choice)
                        if choice == 1:
                            set_stealth_mode(enable=True)        
                            print("The results of this execution are now available in the logs-folder.\nTo see more detailed log-details follow path: C:\Windows\System32\LogFiles\Firewall\pfirewall.log")
                            break
                        elif choice == 2:
                            main_smoke_test()
                            break
                        else:
                            print("Enter one of the following options as integer:")
                            continue

                    except ValueError:
                        print("Error. Please enter the integer 1 or 2")
                        continue
            elif service_choice == 5:
                print("Thank you for using this tool. Have a nice day!")
                break
                       
        except ValueError:
            print("\nError. Please enter an integer between 1 and 4, according to the program you desire: ")
        
        # Inner loop controls whether we return to the main menu or exit the program.
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
