# pythongroupproject

## Overview

This project is a python cybersecurity project.
It demonstrates basic security concepts such as port scanning, firewall and DoS simulation, OS and service fingerprinting,
stealth techniques, and logging/reporting.

Each module can be executed independently.


## Project Structure

project-root/
├── firewall_simulation.py
├── Port Scanner.py
├── fingerprinting.py
├── os_fingerprint.py
├── service_fingerprint.py
├── stealth_engine.py
├── logging_setup.py
├── logs/
│   ├── firewall_simulation.log
│   ├── port_scanner.log
│   └── fingerprinting.log
├── config/
│   ├── blacklist.txt
│   ├── dos_config.txt
│   └── nimda_signature.txt
└── README.md


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

External tool:
- Nmap (required only for OS fingerprinting)

Nmap installation:
- Windows: https://nmap.org/download.html
- Linux: sudo apt install nmap
- macOS: brew install nmap


## Installation

1. Clone or download the repository
   git clone <repository-url>
   cd project-root

2. Check Python installation
   python --version

3. (Optional) Install Nmap if OS fingerprinting is required


## How to Start the Program

Each module is started individually.

Firewall & DoS Simulation:
python firewall_simulation.py

Port Scanner:
python "Port Scanner.py"

OS & Service Fingerprinting:
python fingerprinting.py


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

Log Format:
YYYY-MM-DD HH:MM:SS - LEVEL - message

Example:
2025-01-10 14:32:05 - WARNING - BLOCKED 192.168.1.44 | reason: DoS attack

Console vs Logging:
- print() is used for user interaction
- logger.info() and logger.warning() are used for persistent logs
- Logging does not change program functionality


## Notes

- Some features may require administrator privileges depending on the operating system


## Course Information

- University group project
- Programming language: Python
