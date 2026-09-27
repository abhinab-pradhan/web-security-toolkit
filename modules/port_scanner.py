"""TCP connect scanner with conservative banner grabbing."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_BANNER_PORTS = {
    21: b"\r\n",
    22: b"\r\n",
    23: b"\r\n",
    25: b"EHLO security-toolkit\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n",
    110: b"\r\n",
    143: b"\r\n",
    3306: b"\x00",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n",
}


def _grab_banner(sock: socket.socket, port: int) -> str:
    try:
        sock.settimeout(1.0)
        payload = COMMON_BANNER_PORTS.get(port, b"\r\n")
        sock.sendall(payload)
        data = sock.recv(512)
        return data.decode("utf-8", errors="replace").strip()[:300] if data else ""
    except OSError:
        return ""


def _scan_one(host: str, port: int, timeout: float) -> dict:
    result = {"port": port, "status": "closed", "banner": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            result["status"] = "open"
            result["banner"] = _grab_banner(sock, port)
    except OSError:
        pass
    finally:
        sock.close()
    return result


def scan_ports(host: str, ports: list[int], timeout: float = 3.0) -> list[dict]:
    results = []
    workers = min(32, max(1, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_one, host, port, timeout): port for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item["port"])
