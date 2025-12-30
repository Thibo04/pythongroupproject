# Python group project: Cybersecurity Multifunction Program

## Overview

Project members: Alan, Garret, Luca, Marc, Samuel, Thibo

Group ID: 4480

This is a group project in the course Skills: Programming by Mario Silic. The project written in Python is a Cybersecurity Multifunction Program, which offers the user a mini-program with an interface, from which it can choose several services.

It demonstrates basic security concepts such as port scanning, firewall and DoS simulation, OS and service fingerprinting,
stealth techniques and logging/reporting. Each service is explained in a comment section at the top of each code.

All these concepts are available in the services, except for the logging: The script logging_setup.py is programmed to monitor all the actions of the other services, which can be tracked in the logs-folder.


## Project Structure

## Project Structure

```text
project-root/
├── main.py
├── fingerprinting.py
├── port_scanner.py
├── firewall_simulation.py
├── stealth_engine.py
├── smoke_test.py
├── logging_setup.py
├── logs/
│   ├── fingerprinting.log
│   ├── port_scanner.log
│   ├── firewall_simulation.log
│   └── stealth_engine.log
├── config/
│   ├── blacklist.txt
│   ├── dos_config.txt
│   └── nimda_signature.txt
└── README.md
```

## Requirements / Dependencies

Python:
- Python 3.10 or newer (recommended)

Python standard libraries (no installation required):
- socket
- re
- os
- time
- csv
- logging
- random
- (python-)nmap
- ctypes
- platform

External tool:
- Nmap (required for OS fingerprinting, the program will crash if not installed)

Nmap installation:
- Windows: https://nmap.org/download.html
- Linux: sudo apt install nmap
- macOS: brew install nmap or download from website (same URL as Windows)


## How to Start the Program
In short: Download the file from github as a zip-file, enter "python3 main.py" in the terminal/cmd
In more detail:
1. Make sure, that you have Python 3.10 or newer installed
2. Make sure, you have Nmap installed
3. Set the directory of the file (most likely "pythongroupproject-main")
4. In the terminal/cmd, set the path for Nmap (e.g. on Windows: C:\Program Files (x86)\Nmap\)
      You can check whether the program has access to it, by the command "nmap --version")
5. If not, set the PATH for Nmap on Windows (via Run). On Mac, this is normally not necessary.
6. If there is ModuleNotFoundError "nmap", enter the following command: py -m pip install python-nmap
   After that, try again
8. Execute "python3 main.py"

All the 5 services are accessed through the interface in main.py. The interface is intuitively designed to access all features from it. The user must just follow the instructions in the terminal. After every execution, the user can either turn back to the menu to execute another service or quit the program.

Each module can also be started individually. For this, just enter the python3 and the corresponding file,
e.g. python3 fingerprinting.py (This file requires nmap and root/administrator privileges).


## Logging Design (Reporting & Documentation)

Purpose:
Logging records important security-related events during program execution and allows later analysis.

Implementation:
- Central logging is implemented in logging_setup.py
- Each main module creates its own logger
- Log files are written automatically into the logs/ folder
- Console output and program behavior remain unchanged

Log Files:
- logs/firewall_simulation.log
  Firewall decisions, blocked IPs, DoS detection

- logs/port_scanner.log
  Open and closed ports

- logs/fingerprinting.log
  Detected services and assigned risk levels

- logs/stealth_engine.log
  Records reactions to pings from ip-adresses

Log Format:
YYYY-MM-DD HH:MM:SS - LEVEL - message

Example:
2025-01-10 14:32:05 - WARNING - BLOCKED 192.168.1.44 | reason: DoS attack

Console vs Logging:
- print() is used for user interaction
- logger.info() and logger.warning() are used for persistent logs
- Logging does not change program functionality


## Notes

- Some features may require administrator/root privileges depending on the operating system
- The system-level stealth engine only works on Windows. There is a simulation (smoke_test.py) available though, which can  be chosen in the services-menu, when option 4 is chosen.


## Course Information

- University group project
- Programming language: Python
- Deadline: 31st of December 2025
