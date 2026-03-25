import streamlit as st
import socket
import threading
import time
import json
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
# ══ PAGE CONFIG ═══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Port Scanner",
    page_icon="🛸",
    layout="wide",
    initial_sidebar_state="expanded",
)
 
# ══ CUSTOM CSS ════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
 
/* Base */
html, body, [class*="css"] {
    font-family: 'Share Tech Mono', monospace;
    background-color: #0a0a0f;
    color: #e0e0e0;
}
 
/* Hide Streamlit branding */
#MainMenu, footer, header { visibility: hidden; }
 
/* App background */
.stApp {
    background: linear-gradient(135deg, #0a0a0f 0%, #0d0d1a 50%, #0a0f0a 100%);
}
 
/* Title */
.main-title {
    font-family: 'Orbitron', monospace;
    font-size: 2.4rem;
    font-weight: 900;
    background: linear-gradient(90deg, #00ff88, #00ccff, #ff00aa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-align: center;
    letter-spacing: 4px;
    margin-bottom: 0;
    text-shadow: none;
}
 
.subtitle {
    text-align: center;
    color: #555;
    font-size: 0.85rem;
    letter-spacing: 6px;
    margin-top: 4px;
    margin-bottom: 2rem;
}
 
/* Cards */
.stat-card {
    background: linear-gradient(135deg, #0f1a0f, #0a1520);
    border: 1px solid #1a3a1a;
    border-radius: 8px;
    padding: 1.2rem;
    text-align: center;
    margin: 4px;
}
 
.stat-number {
    font-family: 'Orbitron', monospace;
    font-size: 2rem;
    font-weight: 700;
}
 
.stat-label {
    font-size: 0.7rem;
    letter-spacing: 3px;
    color: #666;
    margin-top: 4px;
}
 
/* Result rows */
.port-row {
    display: flex;
    align-items: center;
    padding: 10px 16px;
    margin: 4px 0;
    border-radius: 6px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.88rem;
    border-left: 3px solid;
    background: rgba(255,255,255,0.02);
    transition: background 0.2s;
}
 
.port-row:hover { background: rgba(255,255,255,0.05); }
 
.risk-HIGH  { border-color: #ff4444; }
.risk-MEDIUM{ border-color: #ffaa00; }
.risk-LOW   { border-color: #00ff88; }
 
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: bold;
    letter-spacing: 2px;
}
 
.badge-HIGH   { background: #ff444422; color: #ff4444; border: 1px solid #ff4444; }
.badge-MEDIUM { background: #ffaa0022; color: #ffaa00; border: 1px solid #ffaa00; }
.badge-LOW    { background: #00ff8822; color: #00ff88; border: 1px solid #00ff88; }
 
/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d0d0d;
    border-right: 1px solid #1a1a2e;
}
 
/* Inputs */
.stTextInput input, .stNumberInput input, .stSelectbox select {
    background: #0f0f1a !important;
    border: 1px solid #1a2a1a !important;
    color: #00ff88 !important;
    font-family: 'Share Tech Mono', monospace !important;
    border-radius: 4px !important;
}
 
/* Button */
.stButton > button {
    background: linear-gradient(90deg, #00ff88, #00ccff) !important;
    color: #000 !important;
    font-family: 'Orbitron', monospace !important;
    font-weight: 700 !important;
    letter-spacing: 2px !important;
    border: none !important;
    border-radius: 4px !important;
    padding: 0.6rem 2rem !important;
    width: 100% !important;
    font-size: 0.85rem !important;
    transition: opacity 0.2s !important;
}
 
.stButton > button:hover { opacity: 0.85 !important; }
 
/* Progress */
.stProgress > div > div { background: linear-gradient(90deg, #00ff88, #00ccff) !important; }
 
/* Divider */
hr { border-color: #1a2a1a !important; }
 
/* Alerts */
.cve-note {
    background: #1a0a0a;
    border: 1px solid #ff444433;
    border-radius: 4px;
    padding: 6px 12px;
    margin: 4px 0 8px 24px;
    font-size: 0.78rem;
    color: #ff6666;
}
</style>
""", unsafe_allow_html=True)
 
# ══ DATA ══════════════════════════════════════════════════════════════════════
SERVICE_MAP = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP",69:"TFTP",80:"HTTP",110:"POP3",111:"RPCBind",123:"NTP",
    135:"RPC/DCOM",137:"NetBIOS-NS",139:"NetBIOS-SSN",143:"IMAP",
    161:"SNMP",389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",
    587:"SMTP-Sub",636:"LDAPS",993:"IMAPS",995:"POP3S",1080:"SOCKS",
    1194:"OpenVPN",1433:"MSSQL",1521:"Oracle-DB",1723:"PPTP",
    2049:"NFS",3000:"Dev-HTTP",3306:"MySQL",3389:"RDP",
    4444:"MSF-Listener",5432:"PostgreSQL",5900:"VNC",5985:"WinRM",
    6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
    9200:"ES-HTTP",27017:"MongoDB",
}
 
RISK_MAP = {
    21:"HIGH",23:"HIGH",135:"HIGH",137:"HIGH",139:"HIGH",445:"HIGH",
    161:"HIGH",1433:"HIGH",1521:"HIGH",3306:"HIGH",3389:"HIGH",
    4444:"HIGH",5432:"HIGH",5900:"HIGH",6379:"HIGH",27017:"HIGH",
    25:"MEDIUM",53:"MEDIUM",110:"MEDIUM",143:"MEDIUM",389:"MEDIUM",
    22:"LOW",80:"LOW",443:"LOW",8080:"LOW",8443:"LOW",
}
 
CVE_HINTS = {
    21:"⚠ FTP may allow anonymous login or use outdated vsftpd/ProFTPD",
    23:"⛔ Telnet transmits credentials in plaintext — replace with SSH",
    445:"⛔ SMB: CVE-2017-0144 (EternalBlue/WannaCry) if unpatched",
    3389:"⛔ RDP: CVE-2019-0708 (BlueKeep) if unpatched Windows",
    6379:"⛔ Redis: no auth by default — CVE-2015-8080",
    27017:"⛔ MongoDB: no auth by default — check bindIp",
    1433:"⛔ MSSQL: disable sa account, check open exposure",
    5900:"⛔ VNC: often misconfigured with weak passwords",
    161:"⛔ SNMP v1/v2c uses community strings in plaintext",
    4444:"🔴 Possible active Metasploit listener!",
}
 
TOP_PORTS = [21,22,23,25,53,80,110,111,135,137,138,139,143,161,389,
             443,445,465,587,993,995,1080,1433,1521,2049,3000,3306,
             3389,4444,5432,5900,6379,8080,8443,8888,9200,27017]
 
# ══ SCANNER ═══════════════════════════════════════════════════════════════════
results = []
results_lock = threading.Lock()
 
def grab_banner(ip, port, timeout=1.2):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            raw = s.recv(256).decode(errors="ignore").strip()
            return raw.split("\n")[0][:55]
        except: return ""
        finally: s.close()
    except: return ""
 
def scan_port(ip, port, timeout, do_banner):
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
                        "port": port, "service": svc,
                        "risk": risk, "banner": banner, "cve": cve
                    })
    except: pass
 
# ══ UI ════════════════════════════════════════════════════════════════════════
st.markdown('<div class="main-title">🛸</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">PORT SCANNER — by Tarun-30</div>', unsafe_allow_html=True)
st.markdown("---")
 
# ── SIDEBAR ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Scan Config")
 
    target = st.text_input("🎯 Target IP / Hostname", placeholder="e.g. 127.0.0.1")
 
    mode = st.selectbox("📡 Scan Mode", [
        "Top Common Ports (~40)",
        "Well-Known (1–1024)",
        "Full Range (1–65535)",
        "Custom Range",
    ])
 
    if mode == "Custom Range":
        col1, col2 = st.columns(2)
        start_port = col1.number_input("Start", min_value=1, max_value=65535, value=1)
        end_port   = col2.number_input("End",   min_value=1, max_value=65535, value=1000)
    else:
        start_port, end_port = None, None
 
    threads    = st.slider("🧵 Threads",   min_value=10, max_value=500, value=200, step=10)
    timeout    = st.slider("⏱ Timeout (s)", min_value=0.1, max_value=3.0, value=0.5, step=0.1)
    do_banner  = st.toggle("🏷 Banner Grabbing", value=False)
    stealth    = st.toggle("🥷 Stealth Mode",    value=False)
 
    st.markdown("---")
    st.markdown("##### ⚠️ Legal Notice")
    st.markdown("""
<small style='color:#555;'>Only scan systems you own or have explicit permission to test. Unauthorized scanning may be illegal.</small>
""", unsafe_allow_html=True)
 
# ── MAIN AREA ─────────────────────────────────────────────────────────────────
run_btn = st.button("🚀 LAUNCH SCAN")
 
if run_btn:
    if not target:
        st.error("⚠️ Please enter a target IP or hostname.")
        st.stop()
 
    # Resolve host
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        st.error(f"❌ Cannot resolve host: `{target}`")
        st.stop()
 
    # Build port list
    if mode == "Top Common Ports (~40)":
        ports = list(TOP_PORTS)
    elif mode == "Well-Known (1–1024)":
        ports = list(range(1, 1025))
    elif mode == "Full Range (1–65535)":
        ports = list(range(1, 65536))
    else:
        ports = list(range(int(start_port), int(end_port) + 1))
 
    if stealth:
        random.shuffle(ports)
        threads = min(threads, 50)
        timeout = max(timeout, 1.0)
 
    results.clear()
    total    = len(ports)
    t_start  = time.time()
 
    # ── Scan info bar
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🎯 Target",  f"{target}")
    c2.metric("📡 Mode",    mode.split("(")[0].strip())
    c3.metric("🔢 Ports",   f"{total:,}")
    c4.metric("🧵 Threads", threads)
 
    st.markdown("---")
 
    # ── Progress
    prog_bar  = st.progress(0, text="Initializing scan...")
    status_tx = st.empty()
    results_ph = st.empty()
 
    with ThreadPoolExecutor(max_workers=threads) as ex:
        fts  = [ex.submit(scan_port, ip, p, timeout, do_banner) for p in ports]
        done = 0
        for _ in as_completed(fts):
            done += 1
            pct = done / total
            open_now = len(results)
            prog_bar.progress(pct, text=f"Scanning... {done}/{total} ports  |  {open_now} open found")
            if done % 100 == 0 or done == total:
                status_tx.markdown(
                    f"`[{datetime.now().strftime('%H:%M:%S')}]` "
                    f"Scanned **{done}/{total}** — **{open_now}** open ports so far"
                )
 
    elapsed = time.time() - t_start
    prog_bar.progress(1.0, text="✅ Scan complete!")
    status_tx.empty()
 
    sorted_r = sorted(results, key=lambda x: x["port"])
    highs    = [r for r in sorted_r if r["risk"] == "HIGH"]
    meds     = [r for r in sorted_r if r["risk"] == "MEDIUM"]
    lows     = [r for r in sorted_r if r["risk"] == "LOW"]
 
    # ── Summary stats
    st.markdown("### 📊 Results")
    s1, s2, s3, s4, s5 = st.columns(5)
    s1.markdown(f"""<div class="stat-card">
        <div class="stat-number" style="color:#00ff88">{len(sorted_r)}</div>
        <div class="stat-label">OPEN PORTS</div></div>""", unsafe_allow_html=True)
    s2.markdown(f"""<div class="stat-card">
        <div class="stat-number" style="color:#ff4444">{len(highs)}</div>
        <div class="stat-label">HIGH RISK</div></div>""", unsafe_allow_html=True)
    s3.markdown(f"""<div class="stat-card">
        <div class="stat-number" style="color:#ffaa00">{len(meds)}</div>
        <div class="stat-label">MEDIUM RISK</div></div>""", unsafe_allow_html=True)
    s4.markdown(f"""<div class="stat-card">
        <div class="stat-number" style="color:#00ccff">{len(lows)}</div>
        <div class="stat-label">LOW RISK</div></div>""", unsafe_allow_html=True)
    s5.markdown(f"""<div class="stat-card">
        <div class="stat-number" style="color:#888">{elapsed:.1f}s</div>
        <div class="stat-label">SCAN TIME</div></div>""", unsafe_allow_html=True)
 
    st.markdown("---")
 
    if sorted_r:
        # Filter buttons
        st.markdown("### 🔍 Open Ports")
        f1, f2, f3, f4 = st.columns(4)
        show_filter = f1.selectbox("Filter by risk", ["All", "HIGH", "MEDIUM", "LOW"], label_visibility="collapsed")
 
        filtered = sorted_r if show_filter == "All" else [r for r in sorted_r if r["risk"] == show_filter]
 
        # Table header
        h1, h2, h3, h4, h5 = st.columns([1, 2, 1.5, 3, 1])
        h1.markdown("**PORT**"); h2.markdown("**SERVICE**")
        h3.markdown("**RISK**"); h4.markdown("**BANNER**"); h5.markdown("**CVE**")
        st.markdown("---")
 
        for r in filtered:
            col1, col2, col3, col4, col5 = st.columns([1, 2, 1.5, 3, 1])
            rc = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(r["risk"], "⚪")
            col1.markdown(f"`{r['port']}`")
            col2.markdown(f"**{r['service']}**")
            col3.markdown(f"{rc} {r['risk']}")
            col4.markdown(f"`{r['banner'][:40]}`" if r["banner"] else "—")
            col5.markdown("⚠️" if r["cve"] else "—", help=r["cve"] if r["cve"] else "")
 
        # ── CVE Alerts
        if highs:
            st.markdown("---")
            st.markdown("### 🚨 CVE / Security Alerts")
            for r in highs:
                if r["cve"]:
                    st.error(f"**Port {r['port']} ({r['service']})** — {r['cve']}")
 
        # ── Export
        st.markdown("---")
        st.markdown("### 💾 Export Report")
        report = {
            "tool": "Port Scanner",
            "target": target, "ip": ip,
            "scanned_at": datetime.now().isoformat(),
            "scan_time_s": round(elapsed, 2),
            "total_ports_scanned": total,
            "open_ports": sorted_r,
        }
        e1, e2 = st.columns(2)
        e1.download_button(
            "⬇️ Download JSON",
            data=json.dumps(report, indent=2),
            file_name=f"scan_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
        txt = f"Port Scanner Report\nTarget: {target} ({ip})\nDate: {datetime.now()}\n\n"
        txt += f"{'PORT':<8}{'SERVICE':<18}{'RISK':<10}{'BANNER'}\n" + "-"*60 + "\n"
        for r in sorted_r:
            txt += f"{r['port']:<8}{r['service']:<18}{r['risk']:<10}{r['banner'][:25]}\n"
        e2.download_button(
            "⬇️ Download TXT",
            data=txt,
            file_name=f"scan_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
    else:
        st.info("No open ports found in the scanned range.")
 
    st.markdown(f"""
    <div style='text-align:center; color:#333; font-size:0.75rem; margin-top:2rem; letter-spacing:3px;'>
    PORT SCANNER • TARUN-30 • SCAN COMPLETED IN {elapsed:.2f}s
    </div>
    """, unsafe_allow_html=True)
 