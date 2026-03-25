import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
open_ports = []
lock       = threading.Lock()
 
def scan_port(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports.append(port)
    except Exception:
        pass
 
def validate(start, end):
    if not (0 <= start <= 65535 and 0 <= end <= 65535):
        raise ValueError("Ports must be in range 0–65535.")
    if start > end:
        raise ValueError("Start port must be <= end port.")
 
def main():
    print("=" * 55)
    print("Port Scanner  v2.0 — Multi-Threaded")
    print("=" * 55)
 
    target = input("Enter target IP or hostname: ").strip()
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Cannot resolve: {target}")
        return
 
    start = int(input("Start port [default 1]   : ") or "1")
    end   = int(input("End port   [default 1024]: ") or "1024")
    threads = int(input("Threads    [default 100] : ") or "100")
 
    try:
        validate(start, end)
    except ValueError as e:
        print(f"[!] {e}")
        return
 
    total = end - start + 1
    print(f"\n[*] Scanning {ip} | Ports {start}–{end} | Threads: {threads}")
    t0 = datetime.now()
 
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, p) for p in range(start, end + 1)]
        done = 0
        for _ in as_completed(futures):
            done += 1
            print(f"\r[*] Progress: {done}/{total}", end="", flush=True)
 
    elapsed = (datetime.now() - t0).total_seconds()
    print(f"\n\n[+] Scan complete in {elapsed:.2f}s")
 
    if open_ports:
        print(f"[+] Open ports ({len(open_ports)} found):")
        for p in sorted(open_ports):
            print(f"    PORT {p} — OPEN")
    else:
        print("[!] No open ports found.")
 
if __name__ == "__main__":
    main()