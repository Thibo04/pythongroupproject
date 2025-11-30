import nmap


def scan_host(ip: str, ports: str) -> list[dict]:
    """
    Uses python-nmap to scan services on a host.

    Parameters
    ----------
    ip : str
        Target IP address.
    ports : str
        Port string in nmap format, e.g. "22,80,443" or "1-1024".

    Returns
    -------
    list[dict]
        A list of dictionaries with keys: ip, os, port, name, product, version.
    """
    nm = nmap.PortScanner()

    # Try to enable OS detection (-O). If it fails, we still get port info.
    nm.scan(ip, ports, arguments="-O")
    host_infos: list[dict] = []

    if ip not in nm.all_hosts():
        # nothing found (host down or filtered)
        return host_infos

    # Try to extract an OS family if available
    os_family = "Unknown"
    try:
        os_matches = nm[ip].get("osmatch", [])
        if os_matches:
            os_classes = os_matches[0].get("osclass", [])
            if os_classes:
                os_family = os_classes[0].get("osfamily", "Unknown")
    except Exception:
        os_family = "Unknown"

    for proto in nm[ip].all_protocols():
        for port in sorted(nm[ip][proto].keys()):
            port_data = nm[ip][proto][port]
            host_info = {
                "ip": ip,
                "os": os_family,
                "port": port,
                "name": port_data.get("name", ""),
                "product": port_data.get("product", ""),
                "version": port_data.get("version", ""),
            }
            host_infos.append(host_info)

    return host_infos
