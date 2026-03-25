import streamlit as st
import socket
import threading
import subprocess
import ipaddress
import time
import json
import os
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
# ══ PAGE CONFIG ═══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="AntiGravity Port Scanner",
    page_icon="🛸",
    layout="wide",
    initial_sidebar_state="expanded",
)
 
# ══ CSS ═══════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
 
html, body, [class*="css"] {
    font-family: 'Share Tech Mono', monospace;
    background-color: #080810;
    color: #c8c8d0;
}
 
#MainMenu, footer, header { visibility: hidden; }
 
.stApp {
    background: radial-gradient(ellipse at top, #0d0d20 0%, #080810 60%);
}
 
.main-title {
    font-family: 'Orbitron', monospace;
    font-size: 2.6rem;
    font-weight: 900;
    background: linear-gradient(90deg, #00ff88 0%, #00ccff 50%, #ff00aa 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-align: center;
    letter-spacing: 6px;
    padding-top: 1rem;
    margin-bottom: 0;
}
 
.subtitle {
    text-align: center;
    color: #444;
    font-size: 0.78rem;
    letter-spacing: 8px;
    margin-top: 6px;
}
 
.tagline {
    text-align: center;
    color: #222;
    font-size: 0.72rem;
    letter-spacing: 3px;
    margin-bottom: 1.5rem;
    font-style: italic;
}
 
.section-head {
    font-family: 'Orbitron', monospace;
    font-size: 0.8rem;
    letter-spacing: 4px;
    color: #00ff88;
    border-bottom: 1px solid #0a2a0a;
    padding-bottom: 6px;
    margin: 1.4rem 0 0.8rem 0;
}
 
.stat-card {
    background: linear-gradient(135deg, #0a120a, #080d18);
    border: 1px solid #152515;
    border-radius: 6px;
    padding: 1rem 0.8rem;
    text-align: center;
}
 
.stat-num {
    font-family: 'Orbitron', monospace;
    font-size: 1.8rem;
    font-weight: 700;
    line-height: 1;
}
 
.stat-lbl {
    font-size: 0.62rem;
    letter-spacing: 3px;
    color: #444;
    margin-top: 6px;
}
 
.os-badge {
    display: inline-block;
    background: #0a0a20;
    border: 1px solid #1a1a4a;
    border-radius: 4px;
    padding: 3px 12px;
    color: #8888ff;
    font-size: 0.8rem;
}
 
.host-pill {
    display: inline-block;
    background: #0a1a0a;
    border: 1px solid #1a3a1a;
    border-radius: 20px;
    padding: 3px 12px;
    margin: 3px;
    font-size: 0.78rem;
    color: #00ff88;
}
 
.cve-block {
    background: #150505;
    border: 1px solid #ff333333;
    border-radius: 4px;
    padding: 5px 12px;
    margin: 2px 0 5px 0;
    font-size: 0.77rem;
    color: #ff5555;
}
 
section[data-testid="stSidebar"] {
    background: #060608;
    border-right: 1px solid #111122;
}
 
.stTextInput input, .stNumberInput input {
    background: #0a0a14 !important;
    border: 1px solid #1a1a30 !important;
    color: #00ff88 !important;
    font-family: 'Share Tech Mono', monospace !important;
    border-radius: 4px !important;
}
 
.stButton > button {
    background: linear-gradient(90deg, #00ff88, #00ccff) !important;
    color: #000 !important;
    font-family: 'Orbitron', monospace !important;
    font-weight: 700 !important;
    letter-spacing: 3px !important;
    border: none !important;
    border-radius: 4px !important;
    padding: 0.65rem 1rem !important;
    width: 100% !important;
    font-size: 0.82rem !important;
}
 
.stButton > button:hover { opacity: 0.82 !important; }
 
.stProgress > div > div {
    background: linear-gradient(90deg, #00ff88, #00ccff) !important;
}
 
.stDownloadButton > button {
    background: #0a1a0a !important;
    color: #00ff88 !important;
    border: 1px solid #1a3a1a !important;
    font-family: 'Share Tech Mono', monospace !important;
    border-radius: 4px !important;
    width: 100% !important;
}
 
hr { border-color: #111122 !important; }
 
.footer {
    text-align: center;
    color: #1a1a1a;
    font-size: 0.68rem;
    letter-spacing: 4px;
    margin-top: 3rem;
    padding-bottom: 1rem;
}
</style>
""", unsafe_allow_html=True)
 
# ══ DATA MAPS (identical to v6_final.py) ══════════════════════════════════════
SERVICE_MAP = {
    20:"FTP-Data",   21:"FTP",          22:"SSH",          23:"Telnet",
    25:"SMTP",       53:"DNS",          67:"DHCP",         69:"TFTP",
    80:"HTTP",       110:"POP3",        111:"RPCBind",     123:"NTP",
    135:"RPC/DCOM",  137:"NetBIOS-NS",  138:"NetBIOS-DGM", 139:"NetBIOS-SSN",
    143:"IMAP",      161:"SNMP",        194:"IRC",         389:"LDAP",
    443:"HTTPS",     445:"SMB",         465:"SMTPS",       500:"IKE/ISAKMP",
    512:"rexec",     513:"rlogin",      514:"rsh/syslog",  515:"LPD",
    587:"SMTP-Sub",  631:"IPP",         636:"LDAPS",       993:"IMAPS",
    995:"POP3S",     1080:"SOCKS",      1194:"OpenVPN",    1433:"MSSQL",
    1434:"MSSQL-UDP",1521:"Oracle-DB",  1723:"PPTP",       2049:"NFS",
    2121:"FTP-Alt",  3000:"Dev-HTTP",   3306:"MySQL",      3389:"RDP",
    4444:"MSF-Listener",4445:"MSF-Alt", 5432:"PostgreSQL", 5900:"VNC",
    5985:"WinRM-HTTP",5986:"WinRM-HTTPS",6379:"Redis",     6443:"K8s-API",
    6881:"BitTorrent",7070:"RTSP",      8080:"HTTP-Alt",   8443:"HTTPS-Alt",
    8888:"Jupyter-NB",9090:"Cockpit",   9200:"ES-HTTP",    9300:"ES-Node",
    27017:"MongoDB", 27018:"MongoDB-Shard", 33060:"MySQL-X",
}
 
RISK_MAP = {
    21:"HIGH",  23:"HIGH",  512:"HIGH", 513:"HIGH", 514:"HIGH",
    135:"HIGH", 137:"HIGH", 138:"HIGH", 139:"HIGH", 445:"HIGH",
    161:"HIGH", 1433:"HIGH",1521:"HIGH",3306:"HIGH",3389:"HIGH",
    4444:"HIGH",4445:"HIGH",5432:"HIGH",5900:"HIGH",6379:"HIGH",
    27017:"HIGH",27018:"HIGH",
    25:"MEDIUM",53:"MEDIUM",67:"MEDIUM", 110:"MEDIUM",111:"MEDIUM",
    143:"MEDIUM",389:"MEDIUM",500:"MEDIUM",515:"MEDIUM",587:"MEDIUM",
    631:"MEDIUM",1080:"MEDIUM",2049:"MEDIUM",5985:"MEDIUM",5986:"MEDIUM",
    22:"LOW",80:"LOW",443:"LOW",636:"LOW",993:"LOW",995:"LOW",
    1194:"LOW",8080:"LOW",8443:"LOW",8888:"LOW",9200:"LOW",
}
 
CVE_HINTS = {
    21:   "⚠ FTP may allow anonymous login or use outdated vsftpd/ProFTPD",
    22:   "ℹ SSH: ensure key-based auth; disable password login",
    23:   "⛔ Telnet transmits credentials in plaintext — replace with SSH",
    445:  "⛔ SMB: CVE-2017-0144 (EternalBlue/WannaCry) if unpatched",
    3389: "⛔ RDP: CVE-2019-0708 (BlueKeep) if unpatched Windows",
    6379: "⛔ Redis: no auth by default — CVE-2015-8080, remote code exec",
    27017:"⛔ MongoDB: no auth by default — ensure bindIp is not 0.0.0.0",
    1433: "⛔ MSSQL: brute-force target; disable sa account",
    5900: "⛔ VNC: often misconfigured with weak passwords",
    161:  "⛔ SNMP v1/v2c: uses community strings in plaintext",
    4444: "🔴 MSF Listener? Possible active Metasploit handler!",
    512:  "⛔ rexec: remote exec without encryption — disable immediately",
    513:  "⛔ rlogin: unauthenticated remote login — critical vulnerability",
    514:  "⛔ rsh: remote shell with no auth — replace with SSH",
}
 
TOP_PORTS = [
    21,22,23,25,53,80,110,111,135,137,138,139,143,161,389,
    443,445,465,500,512,513,514,515,587,631,636,993,995,
    1080,1194,1433,1521,1723,2049,3000,3306,3389,4444,5432,
    5900,5985,6379,6443,8080,8443,8888,9200,27017,
]
 
# ══ CORE SCANNER FUNCTIONS (same logic as v6_final.py) ════════════════════════
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
    """TTL-based OS fingerprinting — same as v6_final.py."""
    try:
        param = "-n" if os.name == "nt" else "-c"
        out = subprocess.check_output(
            ["ping", param, "1", ip], timeout=3, stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        for line in out.split("\n"):
            if "ttl=" in line.lower():
                ttl = int(line.lower().split("ttl=")[1].split()[0])
                if ttl <= 64:  return "🐧 Linux / Unix  (TTL ≤ 64)"
                if ttl <= 128: return "🪟 Windows       (TTL ≤ 128)"
                return "📡 Network Device (TTL > 128)"
    except: pass
    return "❓ Unknown"
 
def ping_host(ip):
    param   = "-n" if os.name == "nt" else "-c"
    devnull = "nul" if os.name == "nt" else "/dev/null"
    return os.system(f"ping {param} 1 -W 1 {ip} >{devnull} 2>&1") == 0
 
def subnet_live_hosts(cidr):
    """Ping sweep — identical to v6_final.py subnet_live_hosts()."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    live  = []
    lk    = threading.Lock()
 
    def check(host):
        if ping_host(str(host)):
            with lk: live.append(str(host))
 
    with ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(check, net.hosts()))
    return sorted(live)
 
def scan_port(ip, port, timeout, do_banner, results, results_lock):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                svc    = SERVICE_MAP.get(port, "Unknown")
                risk   = RISK_MAP.get(port, "LOW")
                banner = grab_banner(ip, port) if do_banner else ""
                cve    = CVE_HINTS.get(port, "")
                with results_lock:
                    results.append({
                        "port": port, "protocol": "TCP",
                        "service": svc, "risk": risk,
                        "banner": banner, "cve_note": cve,
                        "ts": datetime.now().isoformat(),
                    })
    except: pass
 
def run_scan(ip, ports, threads, timeout, do_banner, progress_cb):
    results      = []
    results_lock = threading.Lock()
    done         = 0
    total        = len(ports)
 
    with ThreadPoolExecutor(max_workers=threads) as ex:
        fts = [ex.submit(scan_port, ip, p, timeout, do_banner, results, results_lock)
               for p in ports]
        for _ in as_completed(fts):
            done += 1
            progress_cb(done, total, len(results))
    return results
 
# ══ REPORT BUILDERS ═══════════════════════════════════════════════════════════
def build_json(target, ip, os_guess, mode, elapsed, sorted_r):
    return json.dumps({
        "tool": "Port Scanner v6.0",
        "author": "Tarun / github.com/Tarun-30",
        "target": target, "ip": ip, "os_hint": os_guess,
        "mode": mode, "open_count": len(sorted_r),
        "scan_time_s": round(elapsed, 2),
        "scanned_at": datetime.now().isoformat(),
        "open_ports": sorted_r,
    }, indent=2)
 
def build_txt(target, ip, os_guess, mode, elapsed, sorted_r):
    lines = [
        "Port Scanner v6.0 — Scan Report",
        "=" * 62,
        f"  Target    : {target} ({ip})",
        f"  OS Hint   : {os_guess}",
        f"  Mode      : {mode}",
        f"  Open ports: {len(sorted_r)}",
        f"  Scan time : {elapsed:.2f}s",
        f"  Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-" * 62,
        f"  {'PORT':<8}{'SERVICE':<18}{'RISK':<10}{'BANNER'}",
        "-" * 62,
    ]
    for r in sorted_r:
        lines.append(f"  {r['port']:<8}{r['service']:<18}{r['risk']:<10}{r['banner'][:25]}")
        if r["cve_note"]:
            lines.append(f"         NOTE: {r['cve_note']}")
    lines += ["=" * 62, "", "AntiGravity Port Scanner — github.com/Tarun-30"]
    return "\n".join(lines)
 
# ══ PAGE HEADER ═══════════════════════════════════════════════════════════════
st.markdown('<div class="main-title">🛸</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">PORT SCANNER v6.0 — by Tarun-30</div>', unsafe_allow_html=True)
st.markdown('<div class="tagline">"We scan ports others won\'t even float near"</div>', unsafe_allow_html=True)
st.markdown("---")
 
# ══ SIDEBAR ═══════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown('<div class="section-head">TARGET</div>', unsafe_allow_html=True)
    subnet_mode = st.toggle("🌐 Subnet Scan Mode", value=False,
                            help="Scan all live hosts in a CIDR e.g. 192.168.1.0/24")
    if subnet_mode:
        target_in = st.text_input("🌐 CIDR Subnet", placeholder="192.168.1.0/24")
    else:
        target_in = st.text_input("🎯 Target IP / Hostname", placeholder="127.0.0.1")
 
    st.markdown('<div class="section-head">SCAN CONFIG</div>', unsafe_allow_html=True)
    mode = st.selectbox("📡 Scan Mode", [
        "Top Common Ports (~49)",
        "Well-Known (1–1024)",
        "Full Range (1–65535)",
        "Custom Range",
    ])
 
    if mode == "Custom Range":
        c1, c2 = st.columns(2)
        start_p = c1.number_input("Start", min_value=1, max_value=65535, value=1)
        end_p   = c2.number_input("End",   min_value=1, max_value=65535, value=1000)
    else:
        start_p, end_p = 1, 1024
 
    threads = st.slider("🧵 Threads",    min_value=10,  max_value=500, value=200, step=10)
    timeout = st.slider("⏱ Timeout (s)", min_value=0.1, max_value=3.0, value=0.5, step=0.1)
 
    st.markdown('<div class="section-head">OPTIONS</div>', unsafe_allow_html=True)
    do_banner = st.toggle("🏷 Banner Grabbing", value=False)
    stealth   = st.toggle("🥷 Stealth Mode", value=False,
                          help="Randomized port order + max 50 threads")
 
    st.markdown("---")
    run_btn = st.button("🚀 LAUNCH SCAN")
    st.markdown("""
<div style='margin-top:1rem;'>
<small style='color:#1e1e1e; font-size:0.65rem; letter-spacing:1px;'>
⚠ Only scan systems you own or have explicit permission to test.
</small></div>""", unsafe_allow_html=True)
 
# ══ IDLE STATE ════════════════════════════════════════════════════════════════
if not run_btn:
    st.markdown("""
<div style='text-align:center; padding:5rem 0; color:#111128;'>
    <div style='font-size:5rem;'>🛸</div>
    <div style='font-family:Orbitron,monospace; font-size:0.85rem; letter-spacing:6px; margin-top:1rem;'>
        AWAITING LAUNCH SEQUENCE
    </div>
    <div style='font-size:0.7rem; letter-spacing:3px; margin-top:0.5rem;'>
        CONFIGURE IN SIDEBAR → LAUNCH SCAN
    </div>
</div>""", unsafe_allow_html=True)
    st.stop()
 
# ══ VALIDATE INPUT ════════════════════════════════════════════════════════════
if not target_in.strip():
    st.error("⚠️ Please enter a target IP, hostname, or CIDR subnet.")
    st.stop()
 
# ══ BUILD PORT LIST ═══════════════════════════════════════════════════════════
if mode == "Top Common Ports (~49)":
    ports_base = list(TOP_PORTS)
elif mode == "Well-Known (1–1024)":
    ports_base = list(range(1, 1025))
elif mode == "Full Range (1–65535)":
    ports_base = list(range(1, 65536))
else:
    ports_base = list(range(int(start_p), int(end_p) + 1))
 
if stealth:
    random.shuffle(ports_base)
    threads = min(threads, 50)
    timeout = max(timeout, 1.0)
 
# ══ RESOLVE / SUBNET SWEEP ════════════════════════════════════════════════════
targets = []
 
if subnet_mode:
    ph = st.empty()
    ph.info(f"🔍 Sweeping subnet **{target_in}** for live hosts...")
    with st.spinner("Ping sweep running..."):
        targets = subnet_live_hosts(target_in.strip())
    ph.empty()
 
    if not targets:
        st.warning("No live hosts found in that subnet.")
        st.stop()
 
    st.markdown('<div class="section-head">LIVE HOSTS FOUND</div>', unsafe_allow_html=True)
    pills = "".join(f'<span class="host-pill">● {h}</span>' for h in targets)
    st.markdown(f"<div>{pills}</div>", unsafe_allow_html=True)
    st.markdown(f"**{len(targets)} live host(s)** will be scanned.")
    st.markdown("---")
else:
    try:
        ip = socket.gethostbyname(target_in.strip())
        targets = [target_in.strip()]
    except socket.gaierror:
        st.error(f"❌ Cannot resolve: `{target_in}`")
        st.stop()
 
# ══ SCAN EACH TARGET ══════════════════════════════════════════════════════════
for target in targets:
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        st.warning(f"⚠ Cannot resolve {target} — skipping"); continue
 
    st.markdown(f'<div class="section-head">SCANNING — {target} ({ip})</div>',
                unsafe_allow_html=True)
 
    # OS Fingerprint
    with st.spinner(f"Fingerprinting OS for {ip}..."):
        os_guess = os_hint(ip)
 
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🎯 Target",  target)
    m2.metric("💻 OS Hint", os_guess.split("(")[0].strip())
    m3.metric("🔢 Ports",   f"{len(ports_base):,}")
    m4.metric("🧵 Threads", threads if not stealth else f"{threads} (stealth)")
 
    if stealth:
        st.info("🥷 Stealth mode — randomized order, capped threads, raised timeout")
 
    prog_bar  = st.progress(0, text="Initializing...")
    status_ph = st.empty()
    t0        = time.time()
 
    def make_cb(pb, sp):
        def cb(done, total, open_count):
            pct = done / total
            pb.progress(pct, text=f"Scanning {done}/{total} — {open_count} open found")
            if done % 150 == 0 or done == total:
                sp.markdown(
                    f"`{datetime.now().strftime('%H:%M:%S')}` "
                    f"**{done}/{total}** scanned | **{open_count}** open"
                )
        return cb
 
    scan_results = run_scan(ip, ports_base[:], threads, timeout,
                            do_banner, make_cb(prog_bar, status_ph))
    elapsed = time.time() - t0
 
    prog_bar.progress(1.0, text=f"✅ Done — {len(scan_results)} open port(s) found")
    status_ph.empty()
 
    sorted_r = sorted(scan_results, key=lambda x: x["port"])
    highs    = [r for r in sorted_r if r["risk"] == "HIGH"]
    meds     = [r for r in sorted_r if r["risk"] == "MEDIUM"]
    lows     = [r for r in sorted_r if r["risk"] == "LOW"]
 
    # ── Stats ──────────────────────────────────────────────────────────────
    s1, s2, s3, s4, s5 = st.columns(5)
    for col, num, lbl, color in [
        (s1, len(sorted_r), "OPEN PORTS",  "#00ff88"),
        (s2, len(highs),    "HIGH RISK",   "#ff3333"),
        (s3, len(meds),     "MEDIUM RISK", "#ffaa00"),
        (s4, len(lows),     "LOW RISK",    "#00ccff"),
        (s5, f"{elapsed:.1f}s", "SCAN TIME", "#555"),
    ]:
        col.markdown(f"""<div class="stat-card">
            <div class="stat-num" style="color:{color}">{num}</div>
            <div class="stat-lbl">{lbl}</div></div>""", unsafe_allow_html=True)
 
    # ── OS fingerprint ──────────────────────────────────────────────────────
    st.markdown(
        f'<div style="margin:0.8rem 0 0.2rem 0;">OS Fingerprint: '
        f'<span class="os-badge">{os_guess}</span></div>',
        unsafe_allow_html=True
    )
 
    # ── Open ports table ────────────────────────────────────────────────────
    if sorted_r:
        st.markdown('<div class="section-head">OPEN PORTS</div>', unsafe_allow_html=True)
 
        risk_filter = st.selectbox(
            "Filter", ["All", "HIGH", "MEDIUM", "LOW"],
            key=f"rf_{ip}", label_visibility="collapsed"
        )
        filtered = sorted_r if risk_filter == "All" else \
                   [r for r in sorted_r if r["risk"] == risk_filter]
 
        h1, h2, h3, h4 = st.columns([1, 2, 1.5, 4])
        h1.markdown("**PORT**"); h2.markdown("**SERVICE**")
        h3.markdown("**RISK**"); h4.markdown("**BANNER / NOTE**")
 
        for r in filtered:
            c1, c2, c3, c4 = st.columns([1, 2, 1.5, 4])
            ri  = r["risk"]
            ico = {"HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢"}.get(ri,"⚪")
            c1.markdown(f"`{r['port']}`")
            c2.markdown(f"**{r['service']}**")
            c3.markdown(f"{ico} **{ri}**")
            bnr = f"`{r['banner'][:45]}`" if r["banner"] else ""
            tip = r["cve_note"] if r["cve_note"] else None
            cve = " ⚠️" if r["cve_note"] else ""
            c4.markdown(f"{bnr}{cve}", help=tip)
 
        # ── CVE Alerts ──────────────────────────────────────────────────────
        cve_ports = [r for r in sorted_r if r["cve_note"]]
        if cve_ports:
            st.markdown('<div class="section-head">🚨 CVE / SECURITY ALERTS</div>',
                        unsafe_allow_html=True)
            for r in cve_ports:
                ico = "🔴" if r["risk"] == "HIGH" else "🟡"
                st.error(f"{ico} **Port {r['port']} ({r['service']})** — {r['cve_note']}")
 
        # ── High Risk Summary (mirrors v6 terminal output) ──────────────────
        if highs:
            st.markdown('<div class="section-head">⚠ HIGH RISK SUMMARY</div>',
                        unsafe_allow_html=True)
            for r in highs:
                note = r["cve_note"] or "Commonly exploited — review immediately"
                st.markdown(
                    f'<div class="cve-block">• Port <b>{r["port"]}</b> '
                    f'({r["service"]}) — {note}</div>',
                    unsafe_allow_html=True
                )
    else:
        st.info(f"No open ports found on {ip}.")
 
    # ── Export ──────────────────────────────────────────────────────────────
    st.markdown('<div class="section-head">💾 EXPORT REPORT</div>', unsafe_allow_html=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    e1, e2 = st.columns(2)
    e1.download_button("⬇️ Download JSON",
        data=build_json(target, ip, os_guess, mode, elapsed, sorted_r),
        file_name=f"scan_{ip}_{stamp}.json",
        mime="application/json", key=f"json_{ip}_{stamp}")
    e2.download_button("⬇️ Download TXT",
        data=build_txt(target, ip, os_guess, mode, elapsed, sorted_r),
        file_name=f"scan_{ip}_{stamp}.txt",
        mime="text/plain", key=f"txt_{ip}_{stamp}")
 
    st.markdown("---")
 
# ══ FOOTER ════════════════════════════════════════════════════════════════════
st.markdown(
    '<div class="footer">PORT SCANNER v6.0 • TARUN-30 • '
    'GITHUB.COM/TARUN-30 • 🌍 RESTORED</div>',
    unsafe_allow_html=True
)
 