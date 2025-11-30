import socket


def get_service_banner(ip: str, port: int, timeout: float = 3.0) -> str | None:
    """
    Attempts to retrieve a simple service banner from ip:port.

    Returns
    -------
    str | None
        The banner string, or None if no banner is received or an error occurs.
    """
    try:
        # create_connection handles DNS + connect and closes in the context manager
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            request = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
            sock.sendall(request)
            banner = sock.recv(1024)
            return banner.decode("utf-8", errors="ignore")
    except OSError:
        # Any network error → no banner
        return None


def scan_banners(ip: str, ports: list[int]) -> list[dict]:
    """
    Retrieves banners for all given ports on a host.

    Returns
    -------
    list[dict]
        List of dicts with keys: ip, port, banner.
    """
    results: list[dict] = []
    for port in ports:
        banner = get_service_banner(ip, port)
        results.append({"ip": ip, "port": port, "banner": banner})
    return results
