import socket
import threading
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; WHITE = "\033[97m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"
def cl(t, *codes): return "".join(codes) + t + C.RESET
 
# ── Risk Map ──────────────────────────────────────────────────────────────────
RISK = {
    21: "HIGH", 22: "LOW", 23: "HIGH", 25: "MEDIUM", 53: "MEDIUM",
    80: "LOW",  110: "MEDIUM", 135: "HIGH", 137: "HIGH", 139: "HIGH",
    143: "MEDIUM", 161: "HIGH", 389: "MEDIUM", 443: "LOW", 445: "HIGH",
    1433: "HIGH", 1521: "HIGH", 3306: "HIGH", 3389: "HIGH", 4444: "HIGH",
    5432: "HIGH", 5900: "HIGH", 6379: "HIGH", 8080: "LOW", 27017: "HIGH",
}
RISK_COLOR = {"HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.GREEN}
 
SERVICE_MAP = {
    21: "FTP",    22: "SSH",    23: "Telnet",   25: "SMTP",    53: "DNS",
    67: "DHCP",   69: "TFTP",   80: "HTTP",     110: "POP3",   123: "NTP",
    135: "RPC",   137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP",  443: "HTTPS", 445: "SMB",     465: "SMTPS",  587: "SMTP-Sub",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",   1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL",1521: "Oracle",1723: "PPTP",  2049: "NFS",   3000: "Dev-HTTP",
    3306: "MySQL",3389: "RDP",  4444: "MSF",    5432: "PostgreSQL",
    5900: "VNC",  6379: "Redis",8080: "HTTP-Alt",8443: "HTTPS-Alt",
    8888: "Jupyter",9200: "ES-HTTP",27017: "MongoDB",
}
 
TOP_PORTS = [21,22,23,25,53,80,110,111,135,137,138,139,143,161,389,
             443,445,465,587,636,993,995,1080,1433,1521,1723,2049,
             3000,3306,3389,4444,5432,5900,6379,8080,8443,8888,9200,27017]
 
open_ports = []; lock = threading.Lock()
 
# ── Host Check ────────────────────────────────────────────────────────────────
def host_up(ip):
    param = "-n" if os.name == "nt" else "-c"
    return os.system(f"ping {param} 1 -W 1 {ip} >{'nul' if os.name=='nt' else '/dev/null'} 2>&1") == 0
 
# ── Banner Grab ───────────────────────────────────────────────────────────────
def grab_banner(ip, port, timeout=1.2):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(256).decode(errors="ignore").split("\n")[0][:50]
        except: return ""
        finally: s.close()
    except: return ""
 
# ── TCP Scan ──────────────────────────────────────────────────────────────────
def scan_tcp(ip, port, timeout, do_banner):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                svc    = SERVICE_MAP.get(port, "Unknown")
                risk   = RISK.get(port, "LOW")
                banner = grab_banner(ip, port) if do_banner else ""
                with lock:
                    open_ports.append({"port": port, "proto": "TCP",
                                       "service": svc, "risk": risk, "banner": banner})
    except: pass
 
# ── UDP Scan (best-effort) ────────────────────────────────────────────────────
def scan_udp(ip, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (ip, port))
            try:
                s.recvfrom(1024)
                svc = SERVICE_MAP.get(port, "Unknown")
                with lock:
                    open_ports.append({"port": port, "proto": "UDP",
                                       "service": svc, "risk": RISK.get(port,"LOW"), "banner": ""})
            except socket.timeout:
                # No ICMP unreachable = possibly open (ambiguous for UDP)
                pass
    except: pass
 
# ── Progress Bar ──────────────────────────────────────────────────────────────
def draw_bar(done, total, t0):
    pct  = done / total
    bar  = int(pct * 28)
    eta  = (time.time() - t0) / done * (total - done) if done else 0
    fill = cl("█" * bar, C.GREEN) + cl("░" * (28 - bar), C.DIM)
    print(f"\r  [{fill}] {cl(f'{pct*100:5.1f}%', C.YELLOW)} "
          f"{done}/{total}  ETA:{cl(f'{eta:.0f}s',C.CYAN)}   ", end="", flush=True)
 
# ── Scan Mode Menu ────────────────────────────────────────────────────────────
def pick_mode():
    print(cl("\n  Scan Mode:", C.BOLD + C.CYAN))
    modes = ["Top Common Ports (~40)","Well-Known 1–1024",
             "Full 1–65535","Custom Range","Single Port"]
    for i, m in enumerate(modes, 1):
        print(f"  {cl(f'[{i}]', C.GREEN)}  {m}")
    ch = input(cl("\n  Choice [1-5]: ", C.YELLOW)).strip()
    if ch=="1": return list(TOP_PORTS), None, None
    if ch=="2": return None, 1, 1024
    if ch=="3":
        print(cl("  ⚠  Full scan may take minutes.", C.YELLOW))
        return None, 1, 65535
    if ch=="4":
        s = int(input("  Start: ")); e = int(input("  End  : "))
        return None, s, e
    if ch=="5":
        p = int(input("  Port : "))
        return None, p, p
    return list(TOP_PORTS), None, None
 
# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(cl("\n╔════════════════════════════════════════════╗", C.CYAN))
    print(cl("  ║   Port Scanner  v4.0                       ║", C.CYAN + C.BOLD))
    print(cl("  ║  Scan Modes + UDP + Progress Bar           ║", C.CYAN))
    print(cl("  ╚════════════════════════════════════════════╝\n", C.CYAN))
 
    target = input(cl("  Target: ", C.CYAN)).strip()
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(cl(f"  [!] Cannot resolve: {target}", C.RED)); return
 
    print(f"  {cl('Checking host...', C.DIM)} ", end="", flush=True)
    up = host_up(ip)
    print(cl("UP ✓", C.GREEN) if up else cl("no ping response (may still be up)", C.YELLOW))
 
    port_list, s, e = pick_mode()
    proto     = input(cl("  Protocol [TCP/UDP/both]: ", C.CYAN)).strip().upper() or "TCP"
    threads   = int(input(cl("  Threads  [200]: ", C.CYAN)).strip() or "200")
    timeout   = float(input(cl("  Timeout  [0.5]: ", C.CYAN)).strip() or "0.5")
    do_banner = input(cl("  Banners? [y/N] : ", C.CYAN)).strip().lower() == "y"
 
    ports = port_list if port_list else list(range(s, e + 1))
    total = len(ports)
    print(cl(f"\n  🛸 Scanning {target} | {total} ports | {proto}\n", C.MAGENTA + C.BOLD))
    t0 = time.time()
 
    tasks = []
    if "TCP" in proto or proto == "BOTH":
        tasks += [(scan_tcp, p, timeout, do_banner) for p in ports]
    if "UDP" in proto or proto == "BOTH":
        tasks += [(scan_udp, p, timeout) for p in ports]
 
    with ThreadPoolExecutor(max_workers=threads) as ex:
        ftrs = []
        for task in tasks:
            fn, *args = task
            ftrs.append(ex.submit(fn, ip, *args))
        done = 0
        for _ in as_completed(ftrs):
            done += 1
            if done % 30 == 0 or done == len(ftrs):
                draw_bar(done, len(ftrs), t0)
 
    elapsed = time.time() - t0
    print(f"\n\n  {'─'*58}")
    print(cl(f"  ✅ Scan done in {elapsed:.2f}s | {len(open_ports)} open port(s) found", C.BOLD))
    print(f"  {'─'*58}\n")
 
    if open_ports:
        print(cl(f"  {'PORT':<7}{'PROTO':<7}{'SERVICE':<16}{'RISK':<9}{'BANNER'}", C.BOLD + C.WHITE))
        print(cl(f"  {'─'*7}{'─'*7}{'─'*16}{'─'*9}{'─'*28}", C.DIM))
        for r in sorted(open_ports, key=lambda x: x["port"]):
            rc = RISK_COLOR.get(r["risk"], C.WHITE)
            print(f"  {cl(str(r['port'])+'  ', C.GREEN + C.BOLD)}"
                  f"{cl(r['proto']+'  ', C.CYAN)}"
                  f"{cl(r['service']+'  ', C.YELLOW):<25}"
                  f"{cl(r['risk'], rc):<18}"
                  f"{cl(r['banner'][:28], C.DIM)}")
    print()
 
if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(cl("\n\n  [!] Interrupted.\n", C.YELLOW))