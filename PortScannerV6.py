"""
Port Scanner - v6.0 (Final Release)
-------------------------------------------------
Author : Tarun
GitHub : github.com/Tarun-30
Desc   : The complete, production-grade port scanner. Merges all
         previous versions with additional features: OS fingerprinting
         hints, CVE alerts for vulnerable open ports, subnet scanning,
         and a full interactive + CLI dual-mode interface.
 
What's New in v6.0:
  - Subnet scanning (e.g., 192.168.1.0/24)
  - OS fingerprinting hints (TTL-based guess)
  - CVE alerts for known-vulnerable service versions
  - Dual mode: interactive menu OR full CLI args
  - --stealth flag (slower, lower thread count, randomized port order)
  - Colorized risk summary table at end of scan
  - Auto ping sweep before subnet scan
"""
 
import socket
import threading
import time
import json
import argparse
import sys
import os
import random
import struct
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
# ══ COLORS ════════════════════════════════════════════════════════════════════
class C:
    R="\033[91m";G="\033[92m";Y="\033[93m";B="\033[94m";M="\033[95m"
    CY="\033[96m";W="\033[97m";BO="\033[1m";D="\033[2m";X="\033[0m"
 
USE_COLOR = sys.stdout.isatty()
def cl(t, *codes): return ("".join(codes)+t+C.X) if USE_COLOR else t
 
BANNER = r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║    Port Scanner v6.0 — Final Release by Tarun Gupta          ║
  ║    "We scan ports others won't even float near"              ║
  ╚══════════════════════════════════════════════════════════════╝
"""
 
# ══ DATA MAPS ════════════════════════════════════════════════════════════════
SERVICE_MAP = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP",69:"TFTP",80:"HTTP",110:"POP3",111:"RPCBind",123:"NTP",
    135:"RPC/DCOM",137:"NetBIOS-NS",138:"NetBIOS-DGM",139:"NetBIOS-SSN",
    143:"IMAP",161:"SNMP",194:"IRC",389:"LDAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",500:"IKE/ISAKMP",512:"rexec",513:"rlogin",514:"rsh/syslog",
    515:"LPD",587:"SMTP-Sub",631:"IPP",636:"LDAPS",993:"IMAPS",995:"POP3S",
    1080:"SOCKS",1194:"OpenVPN",1433:"MSSQL",1434:"MSSQL-UDP",1521:"Oracle-DB",
    1723:"PPTP",2049:"NFS",2121:"FTP-Alt",3000:"Dev-HTTP",3306:"MySQL",
    3389:"RDP",4444:"MSF-Listener",4445:"MSF-Alt",5432:"PostgreSQL",
    5900:"VNC",5985:"WinRM-HTTP",5986:"WinRM-HTTPS",6379:"Redis",
    6443:"K8s-APIServer",6881:"BitTorrent",7070:"RTSP",8080:"HTTP-Alt",
    8443:"HTTPS-Alt",8888:"Jupyter-NB",9090:"Cockpit",9200:"ES-HTTP",
    9300:"ES-Node",27017:"MongoDB",27018:"MongoDB-Shard",33060:"MySQL-X",
}
 
RISK_MAP = {
    21:"HIGH",23:"HIGH",512:"HIGH",513:"HIGH",514:"HIGH",135:"HIGH",
    137:"HIGH",138:"HIGH",139:"HIGH",445:"HIGH",161:"HIGH",1433:"HIGH",
    1521:"HIGH",3306:"HIGH",3389:"HIGH",4444:"HIGH",4445:"HIGH",
    5432:"HIGH",5900:"HIGH",6379:"HIGH",27017:"HIGH",27018:"HIGH",
    25:"MEDIUM",53:"MEDIUM",67:"MEDIUM",110:"MEDIUM",111:"MEDIUM",
    143:"MEDIUM",389:"MEDIUM",500:"MEDIUM",515:"MEDIUM",587:"MEDIUM",
    631:"MEDIUM",1080:"MEDIUM",2049:"MEDIUM",5985:"MEDIUM",5986:"MEDIUM",
    22:"LOW",80:"LOW",443:"LOW",636:"LOW",993:"LOW",995:"LOW",
    1194:"LOW",8080:"LOW",8443:"LOW",8888:"LOW",9200:"LOW",
}
 
# Known CVE hints (port → advisory note)
CVE_HINTS = {
    21:  "⚠ FTP may allow anonymous login or use outdated vsftpd/ProFTPD",
    22:  "ℹ SSH: ensure key-based auth; disable password login",
    23:  "⛔ Telnet transmits credentials in plaintext — replace with SSH",
    445: "⛔ SMB: CVE-2017-0144 (EternalBlue/WannaCry) if unpatched",
    3389:"⛔ RDP: CVE-2019-0708 (BlueKeep) if unpatched Windows",
    6379:"⛔ Redis: no auth by default — CVE-2015-8080, remote code exec",
    27017:"⛔ MongoDB: no auth by default — ensure bindIp is not 0.0.0.0",
    1433:"⛔ MSSQL: brute-force target; disable sa account",
    5900:"⛔ VNC: often misconfigured with weak passwords",
    161: "⛔ SNMP v1/v2c: uses community strings in plaintext",
    4444:"🔴 MSF Listener? Possible active Metasploit handler!",
}
 
TOP_PORTS = [21,22,23,25,53,80,110,111,135,137,138,139,143,161,389,
             443,445,465,500,512,513,514,515,587,631,636,993,995,
             1080,1194,1433,1521,1723,2049,3000,3306,3389,4444,5432,
             5900,5985,6379,6443,8080,8443,8888,9200,27017]
 
# ══ STATE ════════════════════════════════════════════════════════════════════
results  = []
lock     = threading.Lock()
 
# ══ UTILITIES ════════════════════════════════════════════════════════════════
def resolve(target):
    try: return socket.gethostbyname(target)
    except socket.gaierror:
        print(cl(f"\n[!] Cannot resolve: {target}", C.R)); sys.exit(1)
 
def grab_banner(ip, port, timeout=1.5):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        try:
            s.send(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            raw = s.recv(512).decode(errors="ignore").strip()
            return raw.split("\n")[0][:60]
        except: return ""
        finally: s.close()
    except: return ""
 
def os_hint(ip):
    """Best-effort OS guess via TTL (ICMP). Requires root on Linux."""
    try:
        import subprocess
        param = "-n" if os.name == "nt" else "-c"
        out = subprocess.check_output(
            ["ping", param, "1", ip], timeout=2, stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        for line in out.split("\n"):
            if "ttl=" in line.lower():
                ttl = int(line.lower().split("ttl=")[1].split()[0])
                if ttl <= 64:  return "Linux/Unix (TTL≤64)"
                if ttl <= 128: return "Windows (TTL≤128)"
                return "Network Device (TTL>128)"
    except: pass
    return "Unknown"
 
def ping_host(ip):
    param = "-n" if os.name == "nt" else "-c"
    devnull = "nul" if os.name == "nt" else "/dev/null"
    return os.system(f"ping {param} 1 -W 1 {ip} >{devnull} 2>&1") == 0
 
def subnet_live_hosts(cidr, timeout=1):
    """Returns list of responsive IPs in subnet."""
    net   = ipaddress.ip_network(cidr, strict=False)
    live  = []
    lock2 = threading.Lock()
 
    def check(host):
        if ping_host(str(host)):
            with lock2:
                live.append(str(host))
 
    with ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(check, net.hosts()))
    return sorted(live)
 
# ══ SCANNER ═══════════════════════════════════════════════════════════════════
def scan_port(ip, port, timeout, do_banner):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                svc    = SERVICE_MAP.get(port, "Unknown")
                risk   = RISK_MAP.get(port, "LOW")
                banner = grab_banner(ip, port) if do_banner else ""
                cve    = CVE_HINTS.get(port, "")
                with lock:
                    results.append({
                        "port": port, "protocol": "TCP",
                        "service": svc, "risk": risk,
                        "banner": banner, "cve_note": cve,
                        "ts": datetime.now().isoformat(),
                    })
    except: pass
 
def draw_bar(done, total, t0):
    pct = done / total
    b   = int(pct * 30)
    eta = (time.time() - t0) / done * (total - done) if done else 0
    bar = cl("█" * b, C.G) + cl("░" * (30 - b), C.D)
    print(f"\r  [{bar}] {cl(f'{pct*100:5.1f}%',C.Y)} {done}/{total} "
          f"ETA:{cl(f'{eta:.0f}s',C.CY)}  ", end="", flush=True)
 
def run_scan(ip, ports, threads, timeout, do_banner, stealth=False, quiet=False):
    if stealth:
        random.shuffle(ports)
        threads = min(threads, 50)
        timeout = max(timeout, 1.0)
        if not quiet: print(cl("  [stealth] Randomized order, throttled threads", C.M))
 
    total = len(ports)
    t0    = time.time()
 
    with ThreadPoolExecutor(max_workers=threads) as ex:
        fts  = [ex.submit(scan_port, ip, p, timeout, do_banner) for p in ports]
        done = 0
        for _ in as_completed(fts):
            done += 1
            if not quiet and (done % 40 == 0 or done == total):
                draw_bar(done, total, t0)
 
    return time.time() - t0
 
def print_results(target, ip, elapsed, os_guess, quiet):
    sorted_r = sorted(results, key=lambda x: x["port"])
    highs    = [r for r in sorted_r if r["risk"] == "HIGH"]
    meds     = [r for r in sorted_r if r["risk"] == "MEDIUM"]
    lows     = [r for r in sorted_r if r["risk"] == "LOW"]
 
    if not quiet:
        print(f"\n\n  {'═'*62}")
        print(cl(f"  🛸  SCAN COMPLETE — {target} ({ip})", C.BO + C.CY))
        print(f"  {'─'*62}")
        print(f"  Scanned at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  OS Hint    : {cl(os_guess, C.M)}")
        print(f"  Time       : {cl(f'{elapsed:.2f}s', C.Y)}")
        print(f"  Open ports : {cl(str(len(results)), C.G+C.BO)}"
              f"  ({cl(f'{len(highs)} HIGH', C.R)} / "
              f"{cl(f'{len(meds)} MEDIUM', C.Y)} / "
              f"{cl(f'{len(lows)} LOW', C.G)})")
        print(f"  {'═'*62}\n")
 
    if sorted_r:
        if not quiet:
            print(cl(f"  {'PORT':<8}{'SERVICE':<18}{'RISK':<10}{'BANNER'}", C.BO+C.W))
            print(cl(f"  {'─'*8}{'─'*18}{'─'*10}{'─'*28}", C.D))
        for r in sorted_r:
            rc = C.R if r["risk"]=="HIGH" else (C.Y if r["risk"]=="MEDIUM" else C.G)
            if quiet:
                print(f"{r['port']}/{r['protocol']}  {r['service']}  {r['risk']}")
            else:
                print(f"  {cl(str(r['port'])+'  ', C.G+C.BO)}"
                      f"{cl(r['service']+'  ', C.Y):<25}"
                      f"{cl(r['risk'], rc):<18}"
                      f"{cl(r['banner'][:28], C.D)}")
                if r["cve_note"]:
                    print(f"       {cl(r['cve_note'], C.M)}")
 
        # Risk Summary
        if not quiet and highs:
            print(f"\n  {'─'*62}")
            print(cl(f"  ⚠  HIGH RISK PORTS DETECTED — review immediately:", C.R+C.BO))
            for r in highs:
                print(cl(f"     • Port {r['port']} ({r['service']}): {r['cve_note'] or 'Commonly exploited'}", C.R))
 
    else:
        if not quiet: print(cl("  No open ports found.", C.R))
 
    if not quiet:
        print(f"\n  {'═'*62}\n")
 
# ══ REPORT EXPORT ═════════════════════════════════════════════════════════════
def save_reports(target, ip, elapsed, os_guess, mode, fmt):
    stamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    sorted_r = sorted(results, key=lambda x: x["port"])
    meta = {
        "tool": "AntiGravity Port Scanner v6.0",
        "author": "Tarun / github.com/Tarun-30",
        "target": target, "ip": ip, "os_hint": os_guess,
        "mode": mode, "open_count": len(results),
        "scan_time_s": round(elapsed, 2),
        "scanned_at": datetime.now().isoformat(),
        "open_ports": sorted_r,
    }
 
    saved = []
    if fmt in ("txt","both"):
        fn = f"scan_{ip}_{stamp}.txt"
        with open(fn, "w") as f:
            f.write("AntiGravity Port Scanner v6.0 — Scan Report\n")
            f.write("=" * 62 + "\n")
            for k, v in meta.items():
                if k != "open_ports":
                    f.write(f"  {k:<18}: {v}\n")
            f.write("-" * 62 + "\n")
            f.write(f"  {'PORT':<8}{'SERVICE':<18}{'RISK':<10}{'BANNER'}\n")
            f.write("-" * 62 + "\n")
            for r in sorted_r:
                f.write(f"  {r['port']:<8}{r['service']:<18}{r['risk']:<10}"
                        f"{r['banner'][:28]}\n")
                if r["cve_note"]:
                    f.write(f"         NOTE: {r['cve_note']}\n")
            f.write("=" * 62 + "\n")
        saved.append(fn)
 
    if fmt in ("json","both"):
        fn = f"scan_{ip}_{stamp}.json"
        with open(fn, "w") as f:
            json.dump(meta, f, indent=2)
        saved.append(fn)
 
    return saved
 
# ══ ARGUMENT PARSER ══════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        prog="Port Scanner",
        description=cl("Port Scanner v6.0 — Final Release", C.CY),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE EXAMPLES:
  python v6_final.py -t 192.168.1.1
  python v6_final.py -t 10.0.0.0/24 --subnet
  python v6_final.py -t scanme.nmap.org --mode wellknown --banner
  python v6_final.py -t 10.0.0.1 --ports 1-500 --threads 300 --output both
  python v6_final.py -t 192.168.1.1 --stealth --output json --quiet
        """
    )
    p.add_argument("-t","--target",  required=True,   help="IP, hostname, or CIDR subnet")
    p.add_argument("--mode",         default="top",
                   choices=["top","wellknown","full","custom"],
                   help="Scan preset (default: top)")
    p.add_argument("--ports",        help="Custom range e.g. 1-1000")
    p.add_argument("--subnet",       action="store_true", help="Scan all live hosts in CIDR subnet")
    p.add_argument("--threads",      type=int, default=200, help="Threads (default:200)")
    p.add_argument("--timeout",      type=float, default=0.5, help="Timeout seconds (default:0.5)")
    p.add_argument("--banner",       action="store_true",  help="Grab service banners")
    p.add_argument("--stealth",      action="store_true",  help="Slow + randomized scan")
    p.add_argument("--output",       choices=["txt","json","both"], help="Save report")
    p.add_argument("--quiet",        action="store_true",  help="Minimal output")
    return p.parse_args()
 
def build_ports(args):
    if args.mode == "wellknown":  return list(range(1, 1025))
    if args.mode == "full":       return list(range(1, 65536))
    if args.mode == "custom" and args.ports:
        lo, hi = map(int, args.ports.split("-"))
        return list(range(lo, hi + 1))
    return list(TOP_PORTS)
 
# ══ MAIN ══════════════════════════════════════════════════════════════════════
def main():
    args = parse_args()
 
    if not args.quiet:
        print(cl(BANNER, C.CY))
 
    ports = build_ports(args)
 
    targets = []
    if args.subnet:
        if not args.quiet:
            print(cl(f"  🔍 Sweeping subnet {args.target} for live hosts...\n", C.Y))
        targets = subnet_live_hosts(args.target)
        if not args.quiet:
            print(cl(f"  Found {len(targets)} live host(s):", C.G))
            for h in targets: print(f"    {cl('●', C.G)}  {h}")
            print()
    else:
        targets = [args.target]
 
    for target in targets:
        results.clear()
        ip = resolve(target)
        if ip != target and not args.quiet:
            print(cl(f"  Resolved {target} → {ip}", C.D))
 
        os_guess = os_hint(ip)
 
        if not args.quiet:
            print(cl(f"\n  🛸  Scanning {target} ({ip}) | {len(ports)} ports", C.M+C.BO))
 
        elapsed = run_scan(ip, ports[:], args.threads, args.timeout,
                           args.banner, args.stealth, args.quiet)
        print_results(target, ip, elapsed, os_guess, args.quiet)
 
        if args.output:
            saved = save_reports(target, ip, elapsed, os_guess, args.mode, args.output)
            for fn in saved:
                if not args.quiet: print(cl(f"  💾  Saved → {fn}", C.G))
 
    if not args.quiet:
        print(cl("restored.\n", C.CY))
 
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(cl("\n\n  [!] Interrupted. Exiting.\n", C.Y))
        sys.exit(0)