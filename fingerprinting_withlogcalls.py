import os
import csv

from os_fingerprint import scan_host
from service_fingerprint import get_service_banner

from logging_setup import get_logger
logger = get_logger(__name__, "fingerprinting.log")


def assess_risk(port: int, service_name: str, banner: str | None) -> str:
    """
    Very simple risk heuristic:
    - HIGH: Telnet or other well-known “critical” ports
    - MEDIUM: other common services on lower ports
    - LOW: everything else
    """
    name = (service_name or "").lower()
    b = (banner or "").lower()

    # Example: Telnet detected in service name or banner
    if "telnet" in name or "telnet" in b:
        return "HIGH"

    # Typical “critical” ports: FTP, RDP, SMB, etc.
    high_risk_ports = {21, 23, 445, 3389}
    if port in high_risk_ports:
        return "HIGH"

    # Medium risk: other “classic” services on known ports
    medium_risk_ports = {20, 22, 25, 110, 143, 3306}
    if port in medium_risk_ports:
        return "MEDIUM"

    # Default case
    return "LOW"


def write_fingerprint_csv(output_file: str, rows: list[dict]) -> None:
    """
    Writes the extended scan results to a CSV file.

    Expects dicts with the keys:
    ip, os, port, name, product, version, banner, risk
    """
    if not rows:
        return

    fieldnames = ["ip", "os", "port", "name", "product", "version", "banner", "risk"]
    file_exists = os.path.isfile(output_file)

    with open(output_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)


def fingerprint_host(
    ip: str,
    ports: list[int],
    output_file: str = "fingerprint_results.csv",
) -> list[dict]:
    """
    Combines OS fingerprinting (nmap) with service banner collection.

    ports: List of ports (e.g. [22, 80, 443]).
    - Calls scan_host() to obtain OS and service information.
    - Retrieves a banner for each port.
    - Computes a risk level.
    - Writes all results to a CSV file.
    - Returns the results as a list of dictionaries.
    """
    port_str = ",".join(str(p) for p in ports)

    # Log start
    logger.info(f"Fingerprint scan started for {ip} ports={port_str}")

    # 1. Retrieve OS and service info using nmap
    host_infos = scan_host(ip, port_str)

    # If nothing is found, log it and return empty
    if not host_infos:
        logger.warning(f"No scan results for {ip} (host down or no open ports?)")
        return []

    results: list[dict] = []
    for info in host_infos:
        port = int(info["port"])

        # 2. Retrieve the service banner
        banner = get_service_banner(ip, port)

        # 3. Determine the risk level
        risk = assess_risk(port, info["name"], banner or info["product"])

        # Log risk (HIGH/MEDIUM = warning)
        if risk in ("HIGH", "MEDIUM"):
            logger.warning(f"{ip}:{port} service={info['name']} risk={risk}")
        else:
            logger.info(f"{ip}:{port} service={info['name']} risk={risk}")

        # 4. Construct enriched result entry
        enriched = {
            "ip": info["ip"],
            "os": info["os"],
            "port": port,
            "name": info["name"],
            "product": info["product"],
            "version": info["version"],
            "banner": banner,
            "risk": risk,
        }
        results.append(enriched)

    # 5. Write results to CSV
    write_fingerprint_csv(output_file, results)

    # Log CSV write
    logger.info(f"Fingerprint results written to {output_file} (rows={len(results)})")

    return results


if __name__ == "__main__":
    # Small test run, for example:
    target_ip = "192.168.1.10"
    ports_to_scan = [22, 80, 443]

    print(f"Fingerprinting {target_ip} on ports {ports_to_scan} ...")
    logger.info(f"Manual test run: fingerprinting {target_ip} ports={ports_to_scan}")

    infos = fingerprint_host(target_ip, ports_to_scan)

    for info in infos:
        print("-" * 40)
        for k, v in info.items():
            print(f"{k}: {v}")

