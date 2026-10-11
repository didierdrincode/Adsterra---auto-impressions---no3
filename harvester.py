from __future__ import annotations

import time
import socket
import ssl
import base64
import struct
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
PROXY_FILE = "free-proxy-list.txt"  # Saved where check_proxies.py expects it
TARGET_WORKING_COUNT = 150          # Stop testing early once we find this many
FETCH_INTERVAL = 300                # Time in seconds between fetch cycles
TEST_URL_HOST = "api.ipify.org"
TEST_URL_PATH = "/?format=json"
TEST_PORT = 443
TIMEOUT = 8.0
WORKERS = 64

# Raw text proxy list endpoints
PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
]

# ---------------------------------------------------------------------------
# DATA MODEL & PARSING
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProxyConfig:
    raw: str
    scheme: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

def parse_proxy(line: str) -> Optional[ProxyConfig]:
    raw = line.strip()
    if not raw:
        return None

    scheme = "http"
    remainder = raw
    if "://" in remainder:
        scheme, remainder = remainder.split("://", 1)
        scheme = scheme.lower()

    username = password = None
    if "@" in remainder:
        creds, remainder = remainder.rsplit("@", 1)
        if ":" in creds:
            username, password = creds.split(":", 1)
        else:
            username = creds

    parts = remainder.split(":")
    if len(parts) == 2:
        host, port_text = parts
    elif len(parts) == 4:
        host, port_text, username, password = parts
    else:
        return None

    try:
        port = int(port_text)
    except ValueError:
        return None
    if not host:
        return None

    return ProxyConfig(raw=raw, scheme=scheme, host=host, port=port,
                       username=username, password=password)

# ---------------------------------------------------------------------------
# ROBUST HTTPS / TLS SOCKET CHECKER LOGIC
# ---------------------------------------------------------------------------
def build_connect_request(proxy: ProxyConfig, host: str, port: int) -> bytes:
    headers = [
        f"CONNECT {host}:{port} HTTP/1.1",
        f"Host: {host}:{port}",
        "Connection: keep-alive",
        "User-Agent: ProxyHarvester/1.0",
    ]
    if proxy.username is not None:
        creds = f"{proxy.username}:{proxy.password or ''}".encode("utf-8")
        headers.append(f"Proxy-Authorization: Basic {base64.b64encode(creds).decode('ascii')}")
    headers += ["", ""]
    return "\r\n".join(headers).encode("ascii")

def build_https_get(host: str, path: str) -> bytes:
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Connection: close",
        "User-Agent: ProxyHarvester/1.0",
        "Accept: */*",
        "", "",
    ]
    return "\r\n".join(headers).encode("ascii")

def recv_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    data = bytearray()
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) != size:
        raise OSError("Unexpected end of proxy response")
    return bytes(data)

def read_http_status(sock: socket.socket) -> Optional[int]:
    data = recv_until(sock, b"\r\n\r\n")
    if not data:
        return None
    head = data.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="ignore")
    parts = head.split()
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    return int(parts[1])

def connect_socket(proxy: ProxyConfig, timeout: float) -> socket.socket:
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    sock.settimeout(timeout)
    if proxy.scheme == "https":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=proxy.host)
        sock.settimeout(timeout)
    return sock

def tls_wrap(sock: socket.socket, host: str, timeout: float) -> socket.socket:
    ctx = ssl.create_default_context()
    tls = ctx.wrap_socket(sock, server_hostname=host)
    tls.settimeout(timeout)
    return tls

def check_http_proxy(proxy: ProxyConfig, timeout: float) -> bool:
    sock = connect_socket(proxy, timeout)
    try:
        sock.sendall(build_connect_request(proxy, TEST_URL_HOST, TEST_PORT))
        status = read_http_status(sock)
        if status is None or not (200 <= status < 300):
            return False
        tls = tls_wrap(sock, TEST_URL_HOST, timeout)
        try:
            tls.sendall(build_https_get(TEST_URL_HOST, TEST_URL_PATH))
            st = read_http_status(tls)
            return st is not None and 200 <= st < 400
        finally:
            try: tls.close()
            except Exception: pass
    finally:
        try: sock.close()
        except Exception: pass

def socks5_connect(sock: socket.socket, proxy: ProxyConfig, host: str, port: int) -> None:
    methods = [0x00]
    if proxy.username is not None:
        methods.append(0x02)
    sock.sendall(bytes([0x05, len(methods), *methods]))
    response = recv_exact(sock, 2)
    if response[0] != 0x05: raise OSError("Invalid SOCKS5 handshake")
    method = response[1]
    if method == 0xFF: raise OSError("SOCKS5 no acceptable auth methods")
    if method == 0x02:
        u = (proxy.username or "").encode("utf-8")
        p = (proxy.password or "").encode("utf-8")
        sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        if recv_exact(sock, 2)[1] != 0x00: raise OSError("SOCKS5 auth failed")

    host_bytes = host.encode("idna")
    req = bytearray(b"\x05\x01\x00\x03")
    req.append(len(host_bytes))
    req.extend(host_bytes)
    req.extend(struct.pack(">H", port))
    sock.sendall(bytes(req))

    resp = recv_exact(sock, 4)
    if resp[1] != 0x00: raise OSError("SOCKS5 connect rejected")
    atyp = resp[3]
    if atyp == 0x01: recv_exact(sock, 4)
    elif atyp == 0x03: recv_exact(sock, recv_exact(sock, 1)[0])
    elif atyp == 0x04: recv_exact(sock, 16)
    recv_exact(sock, 2)

def check_socks_proxy(proxy: ProxyConfig, timeout: float) -> bool:
    sock = connect_socket(proxy, timeout)
    try:
        if proxy.scheme == "socks5":
            socks5_connect(sock, proxy, TEST_URL_HOST, TEST_PORT)
        else:
            return False
        tls = tls_wrap(sock, TEST_URL_HOST, timeout)
        try:
            tls.sendall(build_https_get(TEST_URL_HOST, TEST_URL_PATH))
            st = read_http_status(tls)
            return st is not None and 200 <= st < 400
        finally:
            try: tls.close()
            except Exception: pass
    finally:
        try: sock.close()
        except Exception: pass

def test_proxy_item(proxy: ProxyConfig) -> tuple[ProxyConfig, bool]:
    try:
        if proxy.scheme in {"http", "https"}:
            return proxy, check_http_proxy(proxy, TIMEOUT)
        elif proxy.scheme in {"socks4", "socks5"}:
            return proxy, check_socks_proxy(proxy, TIMEOUT)
    except Exception:
        pass
    return proxy, False

# ---------------------------------------------------------------------------
# HARVESTER LOOP
# ---------------------------------------------------------------------------
def load_existing_proxies() -> set[str]:
    existing = set()
    if os.path.exists(PROXY_FILE):
        for line in Path(PROXY_FILE).read_text(encoding="utf-8-sig", errors="ignore").splitlines():
            p = line.strip()
            if p and not p.startswith("#"):
                existing.add(p)
    return existing

def fetch_sources() -> list[str]:
    new_lines = []
    with httpx.Client(follow_redirects=True, timeout=15.0) as client:
        for url in PROXY_SOURCES:
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        clean = line.strip()
                        if clean and ":" in clean and not clean.startswith("#"):
                            new_lines.append(clean)
            except Exception as e:
                print(f"[-] Error fetching source {url}: {e}")
    return new_lines

def main():
    print("[*] Starting Autonomous Infinite Proxy Harvester & Robust HTTPS Checker...")
    
    while True:
        existing_proxies = load_existing_proxies()
        print(f"\n[*] Loaded {len(existing_proxies)} existing proxies from {PROXY_FILE}.")

        print("[*] Fetching raw proxies from target sources...")
        raw_candidates = fetch_sources()
        
        unique_candidates = [c for c in raw_candidates if c not in existing_proxies]
        print(f"[*] Discovered {len(unique_candidates)} new unique proxy candidates to test.")

        if unique_candidates:
            parsed_proxies = [parse_proxy(c) for c in unique_candidates]
            parsed_proxies = [p for p in parsed_proxies if p is not None]

            print(f"[*] Testing candidates concurrently (Target: {TARGET_WORKING_COUNT} working proxies)...")
            working_batch = []
            
            workers = max(1, min(WORKERS, len(parsed_proxies)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(test_proxy_item, p): p for p in parsed_proxies}
                for fut in as_completed(futures):
                    try:
                        proxy, ok = fut.result()
                        if ok:
                            print(f"[+] WORKING: {proxy.raw}")
                            working_batch.append(proxy.raw)
                            # Early stop once target count is reached
                            if len(working_batch) >= TARGET_WORKING_COUNT:
                                print(f"[*] Reached target of {TARGET_WORKING_COUNT} working proxies. Stopping checks early.")
                                for f in futures:
                                    f.cancel()
                                break
                    except Exception:
                        pass

            if working_batch:
                with open(PROXY_FILE, "w", encoding="utf-8") as f:
                    for p in working_batch:
                        f.write(p + "\n")
                print(f"[+] Saved {len(working_batch)} working proxies to {PROXY_FILE}")
            else:
                print("[-] Found 0 working fresh proxies in this cycle.")
        else:
            print("[*] No new unique proxies found to test.")

        print(f"[*] Sleeping for {FETCH_INTERVAL} seconds before next harvest cycle...")
        time.sleep(FETCH_INTERVAL)

if __name__ == "__main__":
    main()
