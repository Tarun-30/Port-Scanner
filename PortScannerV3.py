import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
# ── ANSI Colors ──────────────────────────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; B = "\033[1m"; D = "\033[2m"; X = "\033[0m"
 
# ── Service Map ───────────────────────────────────────────────────────────────
SERVICE_MAP = {
    21: "FTP",       22: "SSH",        23: "Telnet",    25: "SMTP",
    53: "DNS",       67: "DHCP",       69: "TFTP",      80: "HTTP",
    110: "POP3",     123: "NTP",       135: "RPC",      139: "NetBIOS",
    143: "IMAP",     161: "SNMP",      389: "LDAP",     443: "HTTPS",
    445: "SMB",      465: "SMTPS",     587: "SMTP-Sub", 636: "LDAPS",
    993: "IMAPS",    995: "POP3S",     1080: "SOCKS",   1433: "MSSQL",
    1521: "Oracle",  1723: "PPTP",     2049: "NFS",     3000: "Dev-HTTP",
    3306: "MySQL",   3389: "RDP",      4444: "MSF",     5432: "PostgreSQL",
    5900: "VNC",     6379: "Redis",    8080: "HTTP-Alt",8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "ES-HTTP",  27017: "MongoDB",
}
 
open_ports = []
lock       = threading.Lock()
 
def get_service(port):
    return SERVICE_MAP.get(port, "Unknown")
 
def grab_banner(ip, port, timeout=1.5):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            s.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            raw = s.recv(512).decode(errors="ignore").strip()
            return raw.split("\n")[0][:55] if raw else ""
        except Exception:
            return ""
        finally:
            s.close()
    except Exception:
        return ""
 
def scan_port(ip, port, timeout, do_banner):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                service = get_service(port)
                banner  = grab_banner(ip, port) if do_banner else ""
                with lock:
                    open_ports.append((port, service, banner))
    except Exception:
        pass
 
def main():
    print(f"{C}{B}")
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║  Port Scanner  v3.0             ║")
    print("  ║  Service Detection + Banner Grabbing        ║")
    print("  ╚══════════════════════════════════════════════╝")
    print(X)
 
    target = input(f"  {C}Target (IP/hostname){X}: ").strip()
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"  {D}Resolved → {ip}{X}")
    except socket.gaierror:
        print(f"  {R}[!] Cannot resolve: {target}{X}")
        return
 
    start      = int(input(f"  {C}Start port {X}[1]   : ") or "1")
    end        = int(input(f"  {C}End port   {X}[1024]: ") or "1024")
    threads    = int(input(f"  {C}Threads    {X}[150] : ") or "150")
    do_banner  = input(f"  {C}Banner grab?{X} [y/N] : ").lower() == "y"
 
    total = end - start + 1
    print(f"\n  {Y}[*] Scanning {target} ({ip}) | {total} ports | {threads} threads{X}\n")
    t0 = datetime.now()
 
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(scan_port, ip, p, 0.5, do_banner) for p in range(start, end + 1)]
        done = 0
        for _ in as_completed(futures):
            done += 1
            pct = done / total * 100
            print(f"\r  {Y}Progress: {done}/{total} ({pct:.1f}%){X}", end="", flush=True)
 
    elapsed = (datetime.now() - t0).total_seconds()
    print(f"\n\n  {'─'*55}")
    print(f"  {G}{B}Scan complete{X} in {Y}{elapsed:.2f}s{X} — "
          f"{G}{len(open_ports)} open{X} / {R}{total - len(open_ports)} closed{X}")
    print(f"  {'─'*55}\n")
 
    if open_ports:
        print(f"  {B}{W}{'PORT':<8} {'SERVICE':<16} {'BANNER'}{X}")
        print(f"  {D}{'─'*8} {'─'*16} {'─'*30}{X}")
        for port, svc, banner in sorted(open_ports):
            print(f"  {G}{B}{port:<8}{X} {Y}{svc:<16}{X} {D}{banner[:40]}{X}")
    else:
        print(f"  {R}No open ports found.{X}")
    print()
 
if __name__ == "__main__":
    main()