#Python group project, Cybersecurity

#Ihr könnt euren code gleich unter dem jeweiligen Kommentar einfügen. Für das separate erstellen/bearbeiten würde ich zuerst
#in einem offline-fenster arbeiten

# 1. option: network scanner






# 2. option: Service & OS-Fingerprinting
# main.py
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


def main() -> None:
    # Later your full main menu will go here.
    # For now we only run the Service/OS fingerprinting to test this part.
    service_os_menu()


if __name__ == "__main__":
    main()






# 3. option: Firewall-/DoS-Simulation





# 4. option: Reporting & Logging





# eventually a 5. option: Stealth Mode (only if needed and enough time)

