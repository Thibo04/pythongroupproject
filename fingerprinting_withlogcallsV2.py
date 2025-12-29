from __future__ import annotations

import csv
import ipaddress
import os
import shutil
import socket
import ssl
from typing import Optional

import nmap

from logging_setup import get_logger

# Create module-level logger (writes to logs/fingerprinting.log)
logger = get_logger(__name__, "fingerprinting.log")


# -------------------------
# Safety / validation helpers
# -------------------------
def validate_target_ip(ip: str, *, allow_public: bool = False) -> str:
    """
    Validate an IP address.

    By default (allow_public=False), only allows private/loopback/link-local/reserved
    ranges to reduce accidental scanning of public hosts.

    Set allow_public=True only if you have explicit authorization to scan public IPs.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        logger.error(f"Invalid IP address provided: {ip}")
        raise ValueError(f"Invalid IP address: {ip}") from e

    if not allow_public:
        if not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
        ):
            logger.warning(f"Refusing public IP scan by default: {ip}")
            raise ValueError(
                "Refusing to scan public IPs by default. "
                "Set allow_public=True only if you have explicit authorization."
            )

    logger.info(f"Target IP validated: {ip} (allow_public={allow_public})")
    return ip


def validate_ports(ports: list[int]) -> list[int]:
    """
    Validate and normalize ports:
    - remove duplicates
    - ensure 1..65535
    """
    clean: list[int] = []
    seen = set()

    for p in ports:
        if not isinstance(p, int):
            logger.error(f"Port must be int, got {type(p)}")
            raise ValueError(f"Port must be int, got {type(p)}")
        if p < 1 or p > 65535:
            logger.error(f"Port out of range: {p}")
            raise ValueError(f"Port out of range: {p}")
        if p not in seen:
            seen.add(p)
            clean.append(p)

    logger.info(f"Ports validated: {clean}")
    return clean


def ensure_nmap_available() -> None:
    """
    python-nmap requires the system 'nmap' binary. Fail fast with a helpful message.
    """
    if shutil.which("nmap") is None:
        logger.error("The 'nmap' binary was not found in PATH.")
        raise RuntimeError(
            "The 'nmap' binary was not found in PATH. Install nmap and try again."
        )


# -------------------------
# Banner / Service Fingerprinting
# -------------------------
def _recv_some(sock: socket.socket, max_bytes: int = 2048, timeout: float = 2.0) -> bytes:
    try:
        sock.settimeout(timeout)
        return sock.recv(max_bytes)
    except (socket.timeout, OSError):
        return b""


def _send_http_probe(sock: socket.socket, host: str) -> None:
    req = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + host.encode("utf-8") + b"\r\n"
        b"User-Agent: PyNetGuard\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n\r\n"
    )
    sock.sendall(req)


def _should_try_tls(port: int, service_hint: str | None) -> bool:
    """
    Decide whether to attempt TLS wrapping.

    We keep this conservative: only obvious TLS ports or obvious service hints.
    """
    if port in (443, 8443, 9443):
        return True

    hint = (service_hint or "").lower()
    if "https" in hint or "ssl" in hint or "tls" in hint:
        return True

    return False


def get_service_banner(
    ip: str,
    port: int,
    *,
    service_hint: str | None = None,
    timeout: float = 3.0,
) -> Optional[str]:
    """
    Attempts to retrieve a banner from ip:port.

    Defensive approach:
    - Connect with timeout
    - Read first (many services speak first)
    - Only try HTTP probe for HTTP-like services
    - Only try TLS for clear TLS ports/hints
    """
    try:
        raw = socket.create_connection((ip, int(port)), timeout=timeout)
        sock: socket.socket

        if _should_try_tls(port, service_hint):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw

        with sock:
            initial = _recv_some(sock, timeout=min(2.0, timeout))

            # If nothing spoke first, try a minimal protocol nudge for HTTP-like ports/hints
            if not initial:
                hint = (service_hint or "").lower()
                is_httpish = port in (80, 8080, 8000, 8888, 5000) or ("http" in hint)
                if is_httpish:
                    _send_http_probe(sock, ip)
                    initial = _recv_some(sock, timeout=min(3.0, timeout))
                else:
                    # minimal poke (avoids aggressive protocol guessing)
                    sock.sendall(b"\r\n")
                    initial = _recv_some(sock, timeout=min(2.0, timeout))

            banner = initial.decode("utf-8", errors="ignore").strip()
            return banner if banner else None

    except (ssl.SSLError, OSError):
        logger.info(f"Banner grab failed or no banner: {ip}:{port}")
        return None


# -------------------------
# OS + Service/Version Fingerprinting (nmap)
# -------------------------
def scan_host(ip: str, ports: str) -> list[dict]:
    """
    Uses python-nmap to scan services on a host.

    Returns dicts with:
      ip, os, port, name, product, version, state
    """
    ensure_nmap_available()

    nm = nmap.PortScanner()
    host_infos: list[dict] = []

    # -sV: service/version detection
    # -O : OS detection (may require admin/root)
    base_args = "-sV -O"

    logger.info(f"Nmap scan started: target={ip} ports={ports} args='{base_args}'")

    try:
        nm.scan(ip, ports, arguments=base_args)
    except nmap.PortScannerError:
        logger.warning("Nmap -O failed (privileges?). Falling back to -sV only.")
        try:
            nm.scan(ip, ports, arguments="-sV")
        except Exception as e:
            logger.error(f"Nmap scan failed even with -sV only: {e}")
            return host_infos
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return host_infos

    if ip not in nm.all_hosts():
        logger.warning(f"Nmap returned no host results for: {ip}")
        return host_infos

    # Extract OS family if available
    os_family = "Unknown"
    try:
        os_matches = nm[ip].get("osmatch", [])
        if os_matches:
            os_classes = os_matches[0].get("osclass", [])
            if os_classes:
                os_family = os_classes[0].get("osfamily", "Unknown") or "Unknown"
    except Exception:
        os_family = "Unknown"

    logger.info(f"OS detection result: {ip} -> {os_family}")

    for proto in nm[ip].all_protocols():
        for port in sorted(nm[ip][proto].keys()):
            port_data = nm[ip][proto][port]
            state = (port_data.get("state") or "").lower()

            host_infos.append(
                {
                    "ip": ip,
                    "os": os_family,
                    "port": int(port),
                    "state": state,
                    "name": port_data.get("name", "") or "",
                    "product": port_data.get("product", "") or "",
                    "version": port_data.get("version", "") or "",
                }
            )

    logger.info(f"Nmap scan finished: {ip} -> services_found={len(host_infos)}")
    return host_infos


# -------------------------
# Risk Scoring + CSV Export
# -------------------------
def assess_risk(port: int, service_name: str, evidence: Optional[str]) -> str:
    """
    Very simple heuristic risk scoring (placeholder).
    Adjust to your threat model.

    evidence is typically a concatenation of banner/product/name strings.
    """
    name = (service_name or "").lower()
    ev = (evidence or "").lower()

    if "telnet" in name or "telnet" in ev:
        return "HIGH"

    high_risk_ports = {21, 23, 445, 3389}
    if port in high_risk_ports:
        return "HIGH"

    medium_risk_ports = {20, 22, 25, 110, 143, 3306}
    if port in medium_risk_ports:
        return "MEDIUM"

    return "LOW"


def write_fingerprint_csv(
    output_file: str,
    rows: list[dict],
    *,
    append: bool = True,
) -> None:
    """
    Write scan results to a CSV file.
    """
    if not rows:
        logger.info("No fingerprinting results to write (empty rows).")
        return

    fieldnames = ["ip", "os", "port", "state", "name", "product", "version", "banner", "risk"]

    mode = "a" if append else "w"
    file_exists = os.path.isfile(output_file)

    try:
        with open(output_file, mode, newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")

            if (append and not file_exists) or (not append):
                writer.writeheader()

            for row in rows:
                safe_row = {k: row.get(k, "") for k in fieldnames}
                writer.writerow(safe_row)

        logger.info(f"Fingerprint CSV written: {output_file} rows={len(rows)} append={append}")
    except Exception as e:
        logger.error(f"Failed to write fingerprint CSV '{output_file}': {e}")


# -------------------------
# Public function used by main.py
# -------------------------
def fingerprint_host(
    ip: str,
    ports: list[int],
    output_file: str = "fingerprint_results.csv",
    *,
    allow_public: bool = False,
    append_csv: bool = True,
) -> list[dict]:
    """
    Combines OS + service/version fingerprinting (nmap) with banner collection.
    Writes results to CSV and returns list of dicts.
    """
    logger.info(f"Fingerprinting started: ip={ip} ports={ports} output_file={output_file}")

    ip = validate_target_ip(ip, allow_public=allow_public)
    ports = validate_ports(ports)

    port_str = ",".join(str(p) for p in ports)
    host_infos = scan_host(ip, port_str)

    results: list[dict] = []
    for info in host_infos:
        port = int(info["port"])
        state = (info.get("state") or "").lower()

        banner = None
        if state == "open":
            banner = get_service_banner(
                ip,
                port,
                service_hint=info.get("name"),
                timeout=3.0,
            )

        evidence = " ".join(
            s for s in [banner, info.get("product", ""), info.get("name", "")] if s
        )

        # Only score risk for open ports
        if state != "open":
            risk = "N/A"
        else:
            risk = assess_risk(port, info.get("name", ""), evidence)

        results.append(
            {
                "ip": info.get("ip", ip),
                "os": info.get("os", "Unknown"),
                "port": port,
                "state": state,
                "name": info.get("name", ""),
                "product": info.get("product", ""),
                "version": info.get("version", ""),
                "banner": banner,
                "risk": risk,
            }
        )

        if state == "open":
            logger.warning(
                f"OPEN service: {ip}:{port} name={info.get('name','')} product={info.get('product','')} version={info.get('version','')} risk={risk}"
            )
        else:
            logger.info(f"Non-open port recorded: {ip}:{port} state={state}")

    write_fingerprint_csv(output_file, results, append=append_csv)

    logger.info(f"Fingerprinting finished: ip={ip} results={len(results)}")
    return results


# Entry point to execute the module and generate logs when run directly
if __name__ == "__main__":
    print("Starting fingerprinting test...")

    try:
        # localhost test (safe)
        results = fingerprint_host(
            "127.0.0.1",
            [22, 80, 443],
            output_file="fingerprint_results.csv",
            allow_public=False,
            append_csv=True,
        )
        print(f"Done. Results: {len(results)}")
    except Exception as e:
        print(f"Error: {e}")
