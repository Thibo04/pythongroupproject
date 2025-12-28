#Python group project, Cybersecurity

#Ihr könnt euren code gleich unter dem jeweiligen Kommentar einfügen. Für das separate erstellen/bearbeiten würde ich zuerst
#in einem offline-fenster arbeiten

from firewall_simulation.firewall_simulation import start_firewall_simulation

# 1. option: network scanner






# 2. option: Service & OS-Fingerprinting
# main.py
from __future__ import annotations

from fingerprinting import fingerprint_host


def service_os_menu() -> None:
    print("PyNetGuard – Service & OS Fingerprinting\n")

    ip = input("Target IP (e.g. 127.0.0.1): ").strip()
    ports_str = input("Ports (comma separated, e.g. 22,80,443): ").strip()

    allow_public_in = input("Allow scanning public IPs? (y/N): ").strip().lower()
    allow_public = allow_public_in in ("y", "yes")

    append_in = input("Append results to CSV (keep history)? (Y/n): ").strip().lower()
    append_csv = append_in not in ("n", "no")

    output_file = "fingerprint_results.csv"

    try:
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
    except ValueError:
        print("Invalid port list. Please enter only numbers separated by commas.")
        return

    if not ports:
        print("No ports given – aborting scan.")
        return

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


def main() -> None:
    service_os_menu()


if __name__ == "__main__":
    main()






# 3. option: Firewall-/DoS-Simulation

def firewall_menu() -> None:
    print("\n=== Firewall / DoS Simulation ===")
    print("Press CTRL+C to stop\n")
    start_firewall_simulation()





# 4. option: Reporting & Logging





# eventually a 5. option: Stealth Mode (only if needed and enough time)

