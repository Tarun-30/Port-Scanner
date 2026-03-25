import socket
from datetime import datetime
 
def scan_port(ip, port, timeout=1.0):
    """Returns True if port is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0
 
def main():
    print("=" * 50)
    print("   AntiGravity Port Scanner  v1.0 — Basic")
    print("=" * 50)
 
    target = input("Enter target IP or hostname: ").strip()
 
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Cannot resolve host: {target}")
        return
 
    start_port = int(input("Start port: "))
    end_port   = int(input("End port  : "))
 
    print(f"\n[*] Scanning {target} ({ip}) from port {start_port} to {end_port}...")
    print(f"[*] Started at: {datetime.now().strftime('%H:%M:%S')}\n")
 
    open_ports = []
 
    for port in range(start_port, end_port + 1):
        if scan_port(ip, port):
            print(f"  [OPEN]  Port {port}")
            open_ports.append(port)
 
    print(f"\n[*] Scan complete. {len(open_ports)} open port(s) found.")
    print(f"[*] Finished at: {datetime.now().strftime('%H:%M:%S')}")
 
if __name__ == "__main__":
    main()
 