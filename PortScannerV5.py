import socket
import threading
import time
import json
import argparse
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; M="\033[95m"
    CY="\033[96m"; W="\033[97m"; B="\033[1m"; D="\033[2m"; X="\033[0m"
 
def cl(t, *c): return ("".join(c) + t + C.X) if sys.stdout.isatty() else t
 
SERVICE_MAP = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",67:"DHCP",
    69:"TFTP",80:"HTTP",110:"POP3",123:"NTP",135:"RPC",137:"NetBIOS",
    139:"NetBIOS",143:"IMAP",161:"SNMP",389:"LDAP",443:"HTTPS",
    445:"SMB",465:"SMTPS",587:"SMTP-Sub",636:"LDAPS",993:"IMAPS",
    995:"POP3S",1080:"SOCKS",1194:"OpenVPN",1433:"MSSQL",1521:"Oracle",
    1723:"PPTP",2049:"NFS",3000:"Dev-HTTP",3306:"MySQL",3389:"RDP",
    4444:"MSF-Listener",5432:"PostgreSQL",5900:"VNC",6379:"Redis",
    8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",9200:"ES-HTTP",
    27017:"MongoDB",
}
 
RISK_MAP = {
    21:"HIGH",23:"HIGH",135:"HIGH",137:"HIGH",139:"HIGH",445:"HIGH",
    161:"HIGH",1433:"HIGH",1521:"HIGH",3306:"HIGH",3389:"HIGH",
    4444:"HIGH",5432:"HIGH",5900:"HIGH",6379:"HIGH",27017:"HIGH",
    25:"MEDIUM",53:"MEDIUM",110:"MEDIUM",143:"MEDIUM",389:"MEDIUM",
    22:"LOW",80:"LOW",443:"LOW",8080:"LOW",8443:"LOW",
}
 
TOP_PORTS = [21,22,23,25,53,80,110,111,135,137,138,139,143,161,
             389,443,445,465,587,993,995,1080,1433,1521,2049,3000,
             3306,3389,4444,5432,5900,6379,8080,8443,8888,9200,27017]
 
results  = []
lock     = threading.Lock()
 
# ── Core Functions ────────────────────────────────────────────────────────────
def grab_banner(ip, port, timeout=1.2):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            raw = s.recv(256).decode(errors="ignore").strip()
            return raw.split("\n")[0][:60]
        except: return ""
        finally: s.close()
    except: return ""
 
def scan_tcp(ip, port, timeout, do_banner):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    results.append({
                        "port": port, "protocol": "TCP",
                        "service": SERVICE_MAP.get(port, "Unknown"),
                        "risk": RISK_MAP.get(port, "LOW"),
                        "banner": grab_banner(ip, port) if do_banner else "",
                        "timestamp": datetime.now().isoformat(),
                    })
    except: pass
 
def build_ports(args):
    if args.mode == "top":
        return list(TOP_PORTS)
    if args.mode == "wellknown":
        return list(range(1, 1025))
    if args.mode == "full":
        return list(range(1, 65536))
    if args.ports:
        parts = args.ports.split("-")
        if len(parts) == 2:
            return list(range(int(parts[0]), int(parts[1]) + 1))
        return [int(p) for p in parts]
    return list(TOP_PORTS)
 
# ── Report Writers ────────────────────────────────────────────────────────────
def write_txt(meta, filename):
    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write(" Port Scanner — Scan Report\n")
        f.write("=" * 60 + "\n")
        for k, v in meta.items():
            if k != "open_ports":
                f.write(f"  {k:<16}: {v}\n")
        f.write("-" * 60 + "\n")
        f.write(f"  {'PORT':<8}{'PROTO':<8}{'SERVICE':<18}{'RISK':<10}{'BANNER'}\n")
        f.write("-" * 60 + "\n")
        for r in sorted(meta["open_ports"], key=lambda x: x["port"]):
            f.write(f"  {r['port']:<8}{r['protocol']:<8}{r['service']:<18}"
                    f"{r['risk']:<10}{r['banner'][:30]}\n")
        f.write("=" * 60 + "\n")
 
def write_json(meta, filename):
    with open(filename, "w") as f:
        json.dump(meta, f, indent=2)
 
# ── Argparse ──────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="Port-scanner",
        description="Port Scanner v5.0 — CLI Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1
  %(prog)s -t scanme.nmap.org --mode wellknown --threads 300
  %(prog)s -t 10.0.0.1 --ports 1-500 --output json
  %(prog)s -t localhost --mode top --banner --output both --quiet
        """
    )
    p.add_argument("-t", "--target",   required=True,   help="Target IP or hostname")
    p.add_argument("--mode",           default="top",
                   choices=["top","wellknown","full","custom"],
                   help="Scan mode (default: top)")
    p.add_argument("--ports",          default=None,
                   help="Custom port range e.g. 1-1000 (requires --mode custom)")
    p.add_argument("--threads",        type=int, default=200, help="Thread count (default: 200)")
    p.add_argument("--timeout",        type=float, default=0.5, help="Socket timeout seconds (default: 0.5)")
    p.add_argument("--banner",         action="store_true",  help="Enable banner grabbing")
    p.add_argument("--output",         default=None,
                   choices=["txt","json","both"], help="Save report to file")
    p.add_argument("--quiet",          action="store_true", help="Suppress banner, only show results")
    return p.parse_args()
 
# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
 
    if not args.quiet:
        print(cl("\n╔════════════════════════════════════════════╗", C.CY))
        print(cl("  ║  Port Scanner  v5.0  ⚡                   ║", C.CY + C.B))
        print(cl("  ║  CLI Args + JSON/TXT Report Export         ║", C.CY))
        print(cl("  ╚════════════════════════════════════════════╝\n", C.CY))
 
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(cl(f"[!] Cannot resolve: {args.target}", C.R)); sys.exit(1)
 
    ports   = build_ports(args)
    total   = len(ports)
    t_start = time.time()
 
    if not args.quiet:
        print(cl(f"  Target  : {args.target} ({ip})", C.W))
        print(cl(f"  Mode    : {args.mode}", C.W))
        print(cl(f"  Ports   : {total}", C.W))
        print(cl(f"  Threads : {args.threads}", C.W))
        print(cl(f"  Banners : {'yes' if args.banner else 'no'}\n", C.W))
 
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        fts = [ex.submit(scan_tcp, ip, p, args.timeout, args.banner) for p in ports]
        done = 0
        for _ in as_completed(fts):
            done += 1
            if not args.quiet and (done % 50 == 0 or done == total):
                pct = done / total * 100
                print(f"\r  {cl('Scanning...', C.Y)} {done}/{total} ({pct:.0f}%)  ", end="", flush=True)
 
    elapsed = time.time() - t_start
    sorted_r = sorted(results, key=lambda x: x["port"])
 
    # ── Print Results ──────────────────────────────────────────────────────────
    if not args.quiet:
        print(f"\n\n  {'─'*58}")
        print(cl(f"  ✅  {len(results)} open port(s) found in {elapsed:.2f}s", C.B + C.G))
        print(f"  {'─'*58}\n")
 
    if results:
        if not args.quiet:
            print(cl(f"  {'PORT':<8}{'SERVICE':<18}{'RISK':<10}{'BANNER'}", C.B + C.W))
            print(cl(f"  {'─'*8}{'─'*18}{'─'*10}{'─'*25}", C.D))
        for r in sorted_r:
            risk_c = {C.R:"HIGH", C.Y:"MEDIUM", C.G:"LOW"}.get
            rc = C.R if r["risk"]=="HIGH" else (C.Y if r["risk"]=="MEDIUM" else C.G)
            if args.quiet:
                print(f"{r['port']}/{r['protocol']}  {r['service']}  {r['risk']}")
            else:
                print(f"  {cl(str(r['port'])+'  ', C.G+C.B)}"
                      f"{cl(r['service']+'  ', C.Y):<25}"
                      f"{cl(r['risk'], rc):<18}"
                      f"{cl(r['banner'][:28], C.D)}")
    else:
        print(cl("  No open ports found.", C.R))
 
    # ── Save Report ────────────────────────────────────────────────────────────
    if args.output:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        meta  = {
            "target": args.target, "ip": ip, "mode": args.mode,
            "total_ports": total, "open_count": len(results),
            "scan_time_s": round(elapsed, 2),
            "scanned_at": datetime.now().isoformat(),
            "open_ports": sorted_r,
        }
        if args.output in ("txt", "both"):
            fn = f"scan_{ip}_{stamp}.txt"
            write_txt(meta, fn)
            if not args.quiet: print(cl(f"\n  💾  TXT saved → {fn}", C.G))
        if args.output in ("json", "both"):
            fn = f"scan_{ip}_{stamp}.json"
            write_json(meta, fn)
            if not args.quiet: print(cl(f"  💾  JSON saved → {fn}", C.G))
 
    if not args.quiet:
        print(cl("\n  restored. Scan complete.\n", C.CY))
 
if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt:
        print(cl("\n\n  [!] Interrupted.\n", C.Y)); sys.exit(0)
 