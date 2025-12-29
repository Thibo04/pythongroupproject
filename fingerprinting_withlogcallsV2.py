###############################
# File: fingerprinting.py
# Purpose:
#   Implements OS + service/version fingerprinting using Nmap, and complements it
#   with lightweight banner grabbing (socket/TLS/HTTP probe) for open ports.
#
#   - Safe-by-default target validation (prevents accidental public scanning unless explicitly allowed)
#   - Robust input validation (IP and ports), and fail-fast dependency checks (nmap availability)
#   - Defensive networking (timeouts, conservative probing, graceful failure)
#   - Clear logging + CSV export so results can be reviewed and reproduced
###############################
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

# Module-level logger:
# - Centralizes fingerprinting messages in logs/fingerprinting.log
# - Supports debugging and reporting without changing console behavior
logger = get_logger(__name__, "fingerprinting.log")


# Safety / validation helpers
def validate_target_ip(ip: str, *, allow_public: bool = False) -> str:
    # Validate an IP address.
    # Safety-by-default:
    # - If allow_public=False, only private/loopback/link-local ranges are accepted.
    #  This reduces the risk of accidentally scanning public hosts without authorization.
    # Raises ValueError if the IP is invalid or not allowed by policy.
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        # Invalid IP input should never crash the program.
        logger.error(f"Invalid IP address provided: {ip}")
        raise ValueError(f"Invalid IP address: {ip}") from e

    if not allow_public:
        # Scanning public IP space can be unethical/illegal without permission.
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
    # Validate and normalize port input:
    # - Ensures all items are integers
    # - Ensures valid port range (1..65535)
    # - Removes duplicates while keeping the original order
    # Raises ValueError if ports contain invalid types or values.
    clean: list[int] = []
    seen = set()

    for p in ports:
        # Type validation prevents subtle bugs if upstream code passes strings, floats, etc.
        if not isinstance(p, int):
            logger.error(f"Port must be int, got {type(p)}")
            raise ValueError(f"Port must be int, got {type(p)}")
        # Type validation prevents subtle bugs if upstream code passes strings, floats, etc.
        if p < 1 or p > 65535:
            logger.error(f"Port out of range: {p}")
            raise ValueError(f"Port out of range: {p}")
        if p not in seen:
            seen.add(p)
            clean.append(p)

    logger.info(f"Ports validated: {clean}")
    return clean


def ensure_nmap_available() -> None:
    # Verify that the system 'nmap' binary is available.
    # Python-nmap is only a wrapper; it still requires the actual nmap executable.
    if shutil.which("nmap") is None:
        logger.error("The 'nmap' binary was not found in PATH.")
        raise RuntimeError(
            "The 'nmap' binary was not found in PATH. Install nmap and try again."
        )


# Banner / Service Fingerprinting
def _recv_some(sock: socket.socket, max_bytes: int = 2048, timeout: float = 2.0) -> bytes:
    # Read up to max_bytes from a socket with a timeout.
    # Returns empty bytes on timeout/OS errors instead of throwing, so banner grabbing does not crash the overall scan.
    try:
        sock.settimeout(timeout)
        return sock.recv(max_bytes)
    except (socket.timeout, OSError):
        return b""


def _send_http_probe(sock: socket.socket, host: str) -> None:
    # Send a minimal HTTP GET request.
    # Used only as a gentle nudge for HTTP-like services when no banner is received on initial read.
    req = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + host.encode("utf-8") + b"\r\n"
        b"User-Agent: PyNetGuard\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n\r\n"
    )
    sock.sendall(req)


def _should_try_tls(port: int, service_hint: str | None) -> bool:
    # Decide whether to attempt TLS wrapping.
    # - TLS handshakes can fail on non-TLS services; we keep this conservative.
    # - Only obvious TLS ports or clear service hints trigger TLS probing.
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
    # Attempt to retrieve a banner from ip:port.
    # 1) Connect with a timeout
    # 2) Read first (some services send a greeting banner)
    # 3) If empty, try a minimal HTTP probe only for HTTP-like targets
    # 4) If not HTTP-like, send a very small poke and read again
    try:
        raw = socket.create_connection((ip, int(port)), timeout=timeout)
        sock: socket.socket

        # TLS probing is optional and decided conservatively to reduce false failures.
        if _should_try_tls(port, service_hint):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw

        with sock:
            initial = _recv_some(sock, timeout=min(2.0, timeout))

            # Only nudge protocols if nothing was received initially.
            if not initial:
                hint = (service_hint or "").lower()
                is_httpish = port in (80, 8080, 8000, 8888, 5000) or ("http" in hint)
                if is_httpish:
                    _send_http_probe(sock, ip)
                    initial = _recv_some(sock, timeout=min(3.0, timeout))
                else:
                    # Minimal poke avoids aggressive guessing and reduces side effects.
                    sock.sendall(b"\r\n")
                    initial = _recv_some(sock, timeout=min(2.0, timeout))

            banner = initial.decode("utf-8", errors="ignore").strip()
            return banner if banner else None

    except (ssl.SSLError, OSError):
        logger.info(f"Banner grab failed or no banner: {ip}:{port}")
        return None


# OS + Service/Version Fingerprinting (nmap)
def scan_host(ip: str, ports: str) -> list[dict]:
    # Run an Nmap scan for OS + service/version detection.

    # Args:
    # ip: target IP string
    # ports: Nmap port string (e.g., "22,80,443")

    # Returns:
    # A list of dictionaries containing: ip, os, port, name, product, version, state


    # - Attempts "-sV -O" first (requires privileges for OS detection)
    # - Falls back to "-sV" if OS detection fails
    # - Returns empty list if scanning fails or host is not found in results

    ensure_nmap_available()

    nm = nmap.PortScanner()
    host_infos: list[dict] = []

    # -sV: service/version detection
    # -O : OS detection (may require admin/root privileges)
    base_args = "-sV -O"

    logger.info(f"Nmap scan started: target={ip} ports={ports} args='{base_args}'")

    try:
        nm.scan(ip, ports, arguments=base_args)
    except nmap.PortScannerError:
        # Common issue: OS fingerprinting may fail when run without elevated privileges.
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

    # Collect per-port scan results into a uniform structure for downstream processing.
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


# Risk Scoring + CSV Export
def assess_risk(port: int, service_name: str, evidence: Optional[str]) -> str:
    # Simple heuristic risk scoring.
    name = (service_name or "").lower()
    ev = (evidence or "").lower()

    # Telnet is a classic insecure service (cleartext).
    if "telnet" in name or "telnet" in ev:
        return "HIGH"

    # High-risk ports are common attack surfaces in many environments.
    high_risk_ports = {21, 23, 445, 3389}
    if port in high_risk_ports:
        return "HIGH"

    # Medium risk ports: widely used services that may be secure if configured well.
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
    # Persist fingerprinting results in CSV format.
    # - If rows is empty, does nothing (prevents empty files and confusing output)
    # - Writes headers only when needed (new file or overwrite mode)
    # - Uses extrasaction="ignore" to avoid failures if upstream adds new fields
    if not rows:
        logger.info("No fingerprinting results to write (empty rows).")
        return

    fieldnames = ["ip", "os", "port", "state", "name", "product", "version", "banner", "risk"]

    mode = "a" if append else "w"
    file_exists = os.path.isfile(output_file)

    try:
        with open(output_file, mode, newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")

            # Ensure CSV has headers exactly once in append mode.
            if (append and not file_exists) or (not append):
                writer.writeheader()

            # Use a safe_row mapping to guarantee all expected columns exist.
            for row in rows:
                safe_row = {k: row.get(k, "") for k in fieldnames}
                writer.writerow(safe_row)

        logger.info(f"Fingerprint CSV written: {output_file} rows={len(rows)} append={append}")
    except Exception as e:
        logger.error(f"Failed to write fingerprint CSV '{output_file}': {e}")


# Public function used by main.py
def fingerprint_host(
    ip: str,
    ports: list[int],
    output_file: str = "fingerprint_results.csv",
    *,
    allow_public: bool = False,
    append_csv: bool = True,
) -> list[dict]:
    # Fingerprinting workflow used by the main CLI program.
    # 1) Validate IP and ports (safe defaults)
    # 2) Run Nmap scan to identify OS + services/versions
    # 3) For each open port, attempt best-effort banner grabbing
    # 4) Assign a simple risk level
    # 5) Write results to CSV and return them to the caller
    logger.info(f"Fingerprinting started: ip={ip} ports={ports} output_file={output_file}")

    ip = validate_target_ip(ip, allow_public=allow_public)
    ports = validate_ports(ports)

    port_str = ",".join(str(p) for p in ports)
    host_infos = scan_host(ip, port_str)

    results: list[dict] = []
    for info in host_infos:
        port = int(info["port"])
        state = (info.get("state") or "").lower()

        # Banner grabbing is attempted only for open ports.
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

        # Risk is only meaningful for open services; closed/filtered ports are marked as N/A.
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


if __name__ == "__main__":
    # Simple local test run (safe default: localhost and allow_public=False).
    print("Starting fingerprinting test...")

    try:
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
