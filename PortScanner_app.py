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

# == PAGE CONFIG ===============================================================
st.set_page_config(
    page_title="Port Scanner",
    page_icon="🛸",
    layout="wide",
    initial_sidebar_state="expanded",
)

# == CSS =======================================================================
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

# == DATA MAPS =================================================================
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
    23:   "⛔ Telnet transmits credentials in plaintext -- replace with SSH",
    445:  "⛔ SMB: CVE-2017-0144 (EternalBlue/WannaCry) if unpatched",
    3389: "⛔ RDP: CVE-2019-0708 (BlueKeep) if unpatched Windows",
    6379: "⛔ Redis: no auth by default -- CVE-2015-8080, remote code exec",
    27017:"⛔ MongoDB: no auth by default -- ensure bindIp is not 0.0.0.0",
    1433: "⛔ MSSQL: brute-force target; disable sa account",
    5900: "⛔ VNC: often misconfigured with weak passwords",
    161:  "⛔ SNMP v1/v2c: uses community strings in plaintext",
    4444: "🔴 MSF Listener? Possible active Metasploit handler!",
    512:  "⛔ rexec: remote exec without encryption -- disable immediately",
    513:  "⛔ rlogin: unauthenticated remote login -- critical vulnerability",
    514:  "⛔ rsh: remote shell with no auth -- replace with SSH",
}

REMEDIATION_MAP = {
    20: [
        "Disable FTP-Data if not actively used.",
        "If FTP is required, switch to SFTP (port 22) or FTPS (port 990).",
        "Use firewall rules to allow FTP only from trusted IPs.",
    ],
    21: [
        "Disable anonymous FTP login immediately.",
        "Replace FTP with SFTP or FTPS for encrypted file transfers.",
        "Update FTP server software (vsftpd, ProFTPD) to the latest version.",
        "Restrict FTP access via firewall to specific trusted IPs.",
        "Enable logging and monitor for brute-force attempts.",
    ],
    22: [
        "Disable password-based authentication; use SSH key-based auth only.",
        "Change the default SSH port to a non-standard port to reduce noise.",
        "Use fail2ban or similar tools to block brute-force attempts.",
        "Disable root login over SSH (set PermitRootLogin no).",
        "Keep OpenSSH updated to the latest version.",
        "Restrict SSH access to specific IPs via firewall rules.",
    ],
    23: [
        "DISABLE TELNET IMMEDIATELY -- it sends all data in plaintext.",
        "Replace Telnet with SSH for all remote administration.",
        "Block port 23 at the firewall level.",
        "If Telnet is required for legacy devices, isolate them on a separate VLAN.",
    ],
    25: [
        "Enable SMTP authentication (SMTP AUTH) to prevent open relay.",
        "Use STARTTLS or switch to port 587 (submission) with TLS.",
        "Configure SPF, DKIM, and DMARC records to prevent email spoofing.",
        "Restrict relay to authorized users and domains only.",
        "Monitor for outgoing spam activity.",
    ],
    53: [
        "Restrict DNS zone transfers (AXFR) to authorized secondary servers.",
        "Enable DNSSEC to prevent DNS spoofing and cache poisoning.",
        "Use response rate limiting (RRL) to mitigate DNS amplification attacks.",
        "Keep DNS software (BIND, Unbound) up to date.",
        "Restrict recursive queries to internal clients only.",
    ],
    67: [
        "Ensure the DHCP server is authorized and monitored.",
        "Enable DHCP snooping on managed switches to prevent rogue DHCP servers.",
        "Use static IP assignments for critical infrastructure.",
        "Monitor DHCP logs for unusual lease activity.",
    ],
    69: [
        "Disable TFTP unless absolutely required (firmware updates, PXE boot).",
        "TFTP has NO authentication -- restrict access via firewall.",
        "Isolate TFTP to a management VLAN only.",
        "Use SCP or SFTP as a secure alternative.",
    ],
    80: [
        "Redirect all HTTP traffic to HTTPS (port 443).",
        "Implement security headers (HSTS, CSP, X-Frame-Options).",
        "Keep the web server (Apache, Nginx, IIS) updated.",
        "Use a Web Application Firewall (WAF) for additional protection.",
        "Regularly scan for web vulnerabilities (XSS, SQLi, etc.).",
    ],
    110: [
        "Replace POP3 with POP3S (port 995) for encrypted email retrieval.",
        "Disable plaintext POP3 if encrypted alternative is available.",
        "Enforce strong passwords for email accounts.",
        "Monitor for brute-force login attempts.",
    ],
    111: [
        "Disable RPCBind if not needed (common on Linux systems).",
        "Block port 111 at the firewall for external traffic.",
        "If required, restrict access to internal trusted networks only.",
        "Keep rpcbind and related NFS services updated.",
    ],
    123: [
        "Restrict NTP to trusted time sources only.",
        "Disable NTP monlist command to prevent amplification attacks.",
        "Use ntpd with 'restrict default noquery' configuration.",
        "Keep NTP software updated.",
    ],
    135: [
        "Block port 135 at the firewall for external access.",
        "Disable DCOM if not required (Windows Component Services).",
        "Apply all Windows security patches (CVE-2003-0352, etc.).",
        "Use network segmentation to limit RPC exposure.",
    ],
    137: [
        "Disable NetBIOS over TCP/IP in network adapter settings.",
        "Block ports 137-139 at the perimeter firewall.",
        "Use DNS for name resolution instead of NetBIOS.",
        "If required internally, restrict to trusted subnets only.",
    ],
    138: [
        "Disable NetBIOS over TCP/IP in network adapter settings.",
        "Block ports 137-139 at the perimeter firewall.",
        "NetBIOS Datagram Service is rarely needed -- disable if possible.",
    ],
    139: [
        "Disable NetBIOS Session Service if SMB over port 445 is available.",
        "Block port 139 at the perimeter firewall.",
        "If file sharing is required, use SMB v3 with encryption.",
        "Require signing for all SMB communications.",
    ],
    143: [
        "Replace IMAP with IMAPS (port 993) for encrypted email access.",
        "Disable plaintext IMAP once IMAPS is configured.",
        "Enforce strong password policies for mail accounts.",
        "Use fail2ban to mitigate brute-force attacks.",
    ],
    161: [
        "⛔ Change default SNMP community strings ('public', 'private').",
        "Upgrade from SNMPv1/v2c to SNMPv3 with authentication and encryption.",
        "Restrict SNMP access to management network only via firewall/ACLs.",
        "Disable SNMP write access if not required.",
        "Monitor SNMP logs for unauthorized access attempts.",
    ],
    194: [
        "Disable IRC service if not intentionally running.",
        "IRC is often used by botnets -- investigate if unexpected.",
        "Block port 194 at the perimeter firewall.",
    ],
    389: [
        "Use LDAPS (port 636) or LDAP with STARTTLS for encrypted queries.",
        "Restrict LDAP access to internal trusted networks.",
        "Disable anonymous LDAP binding.",
        "Regularly audit LDAP ACLs and permissions.",
    ],
    443: [
        "Keep TLS certificates valid and up to date.",
        "Disable old TLS versions (TLS 1.0, TLS 1.1); enforce TLS 1.2+.",
        "Implement HSTS to enforce HTTPS connections.",
        "Use strong cipher suites and disable weak ones.",
        "Regularly scan with tools like SSL Labs for misconfigurations.",
    ],
    445: [
        "⛔ Apply all Windows patches -- especially MS17-010 (EternalBlue).",
        "Disable SMBv1 completely (Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
        "Block port 445 from external networks at the firewall.",
        "Require SMB signing and encryption (SMBv3).",
        "Use network segmentation to limit SMB exposure.",
        "Monitor for lateral movement and unusual SMB traffic.",
    ],
    465: [
        "Ensure TLS certificates are valid for SMTPS.",
        "Consider using port 587 (SMTP Submission) with STARTTLS instead.",
        "Restrict SMTPS relay to authenticated users only.",
    ],
    500: [
        "Keep IKE/IPSec implementations updated.",
        "Use strong pre-shared keys or certificate-based auth.",
        "Disable aggressive mode IKE if not needed.",
        "Restrict VPN access to authorized IP ranges.",
    ],
    512: [
        "⛔ DISABLE rexec IMMEDIATELY -- no encryption, no proper authentication.",
        "Replace with SSH for all remote command execution.",
        "Block port 512 at the firewall.",
        "Remove rexec packages from the system.",
    ],
    513: [
        "⛔ DISABLE rlogin IMMEDIATELY -- allows unauthenticated remote login.",
        "Replace with SSH for all remote login needs.",
        "Block port 513 at the firewall.",
        "Remove rlogin packages (rsh-server) from the system.",
    ],
    514: [
        "⛔ DISABLE rsh IMMEDIATELY -- remote shell with no encryption.",
        "Replace with SSH for secure remote shell access.",
        "If using as syslog, switch to rsyslog with TLS encryption.",
        "Block port 514 at the firewall for external traffic.",
    ],
    515: [
        "Restrict LPD access to internal print servers only.",
        "Use IPP (port 631) with authentication as a modern alternative.",
        "Block port 515 from external networks.",
    ],
    587: [
        "Require TLS (STARTTLS) for all SMTP submissions.",
        "Enforce strong authentication for mail submission.",
        "Monitor for unauthorized relay attempts.",
        "Implement rate limiting to prevent spam abuse.",
    ],
    631: [
        "Restrict IPP/CUPS access to local network only.",
        "Require authentication for CUPS administration.",
        "Keep CUPS updated to patch known vulnerabilities.",
        "Block port 631 from external networks.",
    ],
    636: [
        "Keep TLS certificates valid and up to date.",
        "Restrict LDAPS to authorized clients only.",
        "Disable anonymous binds in LDAPS.",
    ],
    993: [
        "Keep TLS certificates valid for IMAPS.",
        "Enforce strong passwords and monitor for brute-force.",
        "Consider using multi-factor authentication for email.",
    ],
    995: [
        "Keep TLS certificates valid for POP3S.",
        "Enforce strong passwords and monitor login attempts.",
        "Consider migrating to IMAP/IMAPS for better functionality.",
    ],
    1080: [
        "Disable the SOCKS proxy if not intentionally configured.",
        "Require authentication for SOCKS proxy access.",
        "SOCKS proxies are frequently abused -- investigate if unexpected.",
        "Restrict proxy access to authorized internal users only.",
    ],
    1194: [
        "Ensure OpenVPN uses strong encryption (AES-256-GCM).",
        "Use certificate-based authentication instead of shared secrets.",
        "Keep OpenVPN server updated to the latest version.",
        "Restrict VPN access with firewall rules.",
    ],
    1433: [
        "⛔ Disable the 'sa' account or set a very strong password.",
        "Block port 1433 from external/public networks.",
        "Enable SQL Server audit logging.",
        "Use Windows Authentication mode instead of mixed mode.",
        "Apply all SQL Server security patches.",
        "Encrypt connections using TLS.",
    ],
    1434: [
        "Disable SQL Server Browser Service if not needed.",
        "Block UDP port 1434 at the firewall.",
        "This port is used for SQL Server instance discovery -- restrict access.",
    ],
    1521: [
        "Change default Oracle listener password.",
        "Block port 1521 from external networks.",
        "Enable Oracle Database audit logging.",
        "Apply all Oracle Critical Patch Updates (CPU).",
        "Restrict TNS listener to specific IP addresses.",
    ],
    1723: [
        "⚠ PPTP is considered insecure -- migrate to L2TP/IPSec or OpenVPN.",
        "If PPTP must be used, enforce strong MS-CHAPv2 passwords.",
        "Block port 1723 from untrusted networks.",
    ],
    2049: [
        "Restrict NFS exports to specific IPs in /etc/exports.",
        "Use NFSv4 with Kerberos authentication.",
        "Block port 2049 from external networks.",
        "Avoid using no_root_squash in NFS exports.",
    ],
    2121: [
        "Same mitigations as FTP (port 21) -- replace with SFTP.",
        "Disable anonymous login and use strong credentials.",
        "Restrict access via firewall to trusted IPs.",
    ],
    3000: [
        "Development servers should NOT be exposed to the internet.",
        "Use a reverse proxy (Nginx) with authentication in production.",
        "Bind to localhost (127.0.0.1) instead of 0.0.0.0.",
        "Disable debug mode in production environments.",
    ],
    3306: [
        "⛔ Block port 3306 from external/public networks.",
        "Disable remote root login (use bind-address = 127.0.0.1).",
        "Run mysql_secure_installation to remove defaults.",
        "Use strong passwords and limit user privileges.",
        "Enable MySQL audit logging.",
        "Encrypt connections using TLS/SSL.",
    ],
    3389: [
        "⛔ Apply all Windows patches -- especially CVE-2019-0708 (BlueKeep).",
        "Enable Network Level Authentication (NLA) for RDP.",
        "Use a VPN or gateway to access RDP -- never expose directly to internet.",
        "Enforce strong passwords and account lockout policies.",
        "Restrict RDP access to specific IPs via Windows Firewall.",
        "Consider using RDP over SSH tunnel for additional encryption.",
        "Enable RDP logging and monitor for brute-force attempts.",
    ],
    4444: [
        "🔴 INVESTIGATE IMMEDIATELY -- port 4444 is commonly used by Metasploit.",
        "Check for malware, reverse shells, or unauthorized backdoors.",
        "Run antivirus/anti-malware scans on the host.",
        "Block port 4444 at the firewall and audit all processes using it.",
        "Review system logs for signs of compromise.",
    ],
    4445: [
        "🔴 INVESTIGATE IMMEDIATELY -- alternate Metasploit listener port.",
        "Same remediation as port 4444 -- scan for malware and backdoors.",
        "Block port 4445 at the firewall.",
    ],
    5432: [
        "⛔ Block port 5432 from external/public networks.",
        "Restrict access in pg_hba.conf to specific IPs and users.",
        "Use md5 or scram-sha-256 authentication (never 'trust').",
        "Enable PostgreSQL logging and auditing.",
        "Encrypt connections using SSL.",
        "Keep PostgreSQL updated to the latest version.",
    ],
    5900: [
        "⛔ Use a VPN to access VNC -- never expose directly to the internet.",
        "Set a strong VNC password (default is often weak or empty).",
        "Use SSH tunneling for encrypted VNC access.",
        "Block port 5900 at the perimeter firewall.",
        "Consider RDP or a more secure remote desktop alternative.",
    ],
    5985: [
        "Restrict WinRM (HTTP) to internal management networks.",
        "Use WinRM over HTTPS (port 5986) instead.",
        "Configure TrustedHosts to limit allowed connections.",
        "Enable WinRM logging and monitoring.",
    ],
    5986: [
        "Ensure valid TLS certificates are configured for WinRM HTTPS.",
        "Restrict access to management networks only.",
        "Configure TrustedHosts and use Kerberos authentication.",
    ],
    6379: [
        "⛔ Set a strong password using 'requirepass' in redis.conf.",
        "Bind Redis to 127.0.0.1 or internal IPs only (not 0.0.0.0).",
        "Block port 6379 from external networks.",
        "Disable dangerous commands (FLUSHALL, CONFIG) using 'rename-command'.",
        "Use Redis ACLs (v6+) for fine-grained access control.",
        "Enable TLS for encrypted connections.",
    ],
    6443: [
        "Restrict Kubernetes API access with RBAC policies.",
        "Use network policies to limit API server exposure.",
        "Enable audit logging for all API requests.",
        "Use TLS with valid certificates for API communication.",
        "Never expose the K8s API directly to the internet.",
    ],
    6881: [
        "Disable BitTorrent if not intentionally running.",
        "BitTorrent on a server may indicate unauthorized P2P usage.",
        "Block port 6881 at the firewall if not needed.",
    ],
    7070: [
        "Restrict RTSP access to authorized clients only.",
        "Use authentication for RTSP streams.",
        "Block port 7070 from external networks if not needed.",
    ],
    8080: [
        "Apply the same security measures as HTTP (port 80).",
        "Ensure this is not a development/debugging server exposed to production.",
        "Use a reverse proxy with TLS termination.",
        "Restrict access via firewall if it's for internal use.",
    ],
    8443: [
        "Apply the same security measures as HTTPS (port 443).",
        "Keep TLS certificates valid and use strong cipher suites.",
        "Restrict access if this is an admin/management interface.",
    ],
    8888: [
        "Set a strong token/password for Jupyter Notebook.",
        "Never expose Jupyter directly to the internet.",
        "Use JupyterHub with proper multi-user authentication.",
        "Bind to localhost and access via SSH tunnel.",
    ],
    9090: [
        "Restrict Cockpit/monitoring dashboard access to admins.",
        "Use strong authentication and TLS.",
        "Block from external networks if it's for internal management.",
    ],
    9200: [
        "Enable authentication for Elasticsearch (X-Pack Security or Open Distro).",
        "Block ports 9200/9300 from external networks.",
        "Bind Elasticsearch to internal IPs only.",
        "Disable dynamic scripting if not needed.",
        "Keep Elasticsearch updated to the latest version.",
    ],
    9300: [
        "Block port 9300 (ES node-to-node) from external networks.",
        "Restrict to internal cluster communications only.",
        "Enable TLS for inter-node transport.",
    ],
    27017: [
        "⛔ Enable MongoDB authentication (--auth flag or security.authorization).",
        "Bind MongoDB to 127.0.0.1 or internal IPs only (not 0.0.0.0).",
        "Block port 27017 from external networks.",
        "Use TLS/SSL for encrypted connections.",
        "Create specific database users with minimal privileges.",
        "Disable HTTP interface and REST API if enabled.",
    ],
    27018: [
        "Same remediation as MongoDB (port 27017).",
        "Enable authentication and restrict shard access.",
        "Block port 27018 from external networks.",
    ],
    33060: [
        "Apply the same mitigations as MySQL (port 3306).",
        "Restrict MySQL X Protocol access to trusted applications.",
        "Block port 33060 from external networks.",
    ],
}

TOP_PORTS = [
    21,22,23,25,53,80,110,111,135,137,138,139,143,161,389,
    443,445,465,500,512,513,514,515,587,631,636,993,995,
    1080,1194,1433,1521,1723,2049,3000,3306,3389,4444,5432,
    5900,5985,6379,6443,8080,8443,8888,9200,27017,
]

# == CORE SCANNER FUNCTIONS ====================================================
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
    """TTL-based OS fingerprinting."""
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
    """Ping sweep to find live hosts in a subnet."""
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
                remediation = REMEDIATION_MAP.get(port, [
                    "Close this port if the service is not needed.",
                    "Restrict access via firewall rules to trusted IPs.",
                    "Keep the running service updated to the latest version.",
                ])
                with results_lock:
                    results.append({
                        "port": port, "protocol": "TCP",
                        "service": svc, "risk": risk,
                        "banner": banner, "cve_note": cve,
                        "remediation": remediation,
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

# == REPORT BUILDERS ===========================================================
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
        "Port Scanner v6.0 -- Scan Report",
        "=" * 78,
        f"  Target    : {target} ({ip})",
        f"  OS Hint   : {os_guess}",
        f"  Mode      : {mode}",
        f"  Open ports: {len(sorted_r)}",
        f"  Scan time : {elapsed:.2f}s",
        f"  Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-" * 78,
        f"  {'PORT':<8}{'SERVICE':<18}{'RISK':<10}{'BANNER'}",
        "-" * 78,
    ]
    for r in sorted_r:
        lines.append(f"  {r['port']:<8}{r['service']:<18}{r['risk']:<10}{r['banner'][:25]}")
        if r["cve_note"]:
            lines.append(f"         NOTE: {r['cve_note']}")
    # Remediation Guide
    lines += ["", "=" * 78, "  REMEDIATION GUIDE -- How to Resolve Open Port Risks", "=" * 78, ""]
    for r in sorted_r:
        steps = r.get("remediation", [])
        if steps:
            risk_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(r["risk"], "⚪")
            lines.append(f"  {risk_icon} Port {r['port']} ({r['service']}) -- Risk: {r['risk']}")
            for i, step in enumerate(steps, 1):
                lines.append(f"      {i}. {step}")
            lines.append("")
    lines += ["=" * 78, "", "Port Scanner -- github.com/Tarun-30"]
    return "\n".join(lines)

# == PAGE HEADER ===============================================================
st.markdown('<div class="main-title">🛸</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">PORT SCANNER v6.0 -- by Tarun-30</div>', unsafe_allow_html=True)
st.markdown('<div class="tagline">"We scan ports others won\'t even float near"</div>', unsafe_allow_html=True)
st.markdown("---")

# == SIDEBAR ===================================================================
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
        "Well-Known (1-1024)",
        "Full Range (1-65535)",
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
WARNING: Only scan systems you own or have explicit permission to test.
</small></div>""", unsafe_allow_html=True)

# == SESSION STATE INIT ========================================================
if "scan_done" not in st.session_state:
    st.session_state.scan_done    = False
    st.session_state.scan_targets = {}   # ip -> {sorted_r, os_guess, elapsed, target, mode}

# == IDLE STATE ================================================================
if not run_btn and not st.session_state.scan_done:
    st.markdown("""
<div style='text-align:center; padding:5rem 0; color:#111128;'>
    <div style='font-family:Orbitron,monospace; font-size:5rem;'>
        🛸
    </div>
    <div style='font-family:Orbitron,monospace; font-size:0.85rem; letter-spacing:6px; margin-top:1rem;'>
        AWAITING LAUNCH SEQUENCE
    </div>
    <div style='font-size:0.7rem; letter-spacing:3px; margin-top:0.5rem;'>
        CONFIGURE IN SIDEBAR → LAUNCH SCAN
    </div>
</div>""", unsafe_allow_html=True)
    st.stop()

# == RUN SCAN (only when button pressed) =======================================
if run_btn:
    if not target_in.strip():
        st.error("Please enter a target IP, hostname, or CIDR subnet.")
        st.stop()

    # Build port list
    if mode == "Top Common Ports (~49)":
        ports_base = list(TOP_PORTS)
    elif mode == "Well-Known (1-1024)":
        ports_base = list(range(1, 1025))
    elif mode == "Full Range (1-65535)":
        ports_base = list(range(1, 65536))
    else:
        ports_base = list(range(int(start_p), int(end_p) + 1))

    if stealth:
        random.shuffle(ports_base)
        threads = min(threads, 50)
        timeout = max(timeout, 1.0)

    # Resolve targets
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
        pills = "".join(f'<span class="host-pill">* {h}</span>' for h in targets)
        st.markdown(f"<div>{pills}</div>", unsafe_allow_html=True)
        st.markdown(f"**{len(targets)} live host(s)** will be scanned.")
        st.markdown("---")
    else:
        try:
            ip = socket.gethostbyname(target_in.strip())
            targets = [target_in.strip()]
        except socket.gaierror:
            st.error(f"Cannot resolve: `{target_in}`")
            st.stop()

    # Clear previous results
    st.session_state.scan_targets = {}

    for target in targets:
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            st.warning(f"Cannot resolve {target} -- skipping"); continue

        st.markdown(f'<div class="section-head">SCANNING -- {target} ({ip})</div>',
                    unsafe_allow_html=True)

        with st.spinner(f"Fingerprinting OS for {ip}..."):
            os_guess = os_hint(ip)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("🎯 Target",  target)
        m2.metric("💻 OS Hint", os_guess.split("(")[0].strip())
        m3.metric("🔢 Ports",   f"{len(ports_base):,}")
        m4.metric("🧵 Threads", threads if not stealth else f"{threads} (stealth)")

        if stealth:
            st.info("🥷 Stealth mode -- randomized order, capped threads, raised timeout")

        prog_bar  = st.progress(0, text="Initializing...")
        status_ph = st.empty()
        t0        = time.time()

        def make_cb(pb, sp):
            def cb(done, total, open_count):
                pct = done / total
                pb.progress(pct, text=f"Scanning {done}/{total} -- {open_count} open found")
                if done % 150 == 0 or done == total:
                    sp.markdown(
                        f"`{datetime.now().strftime('%H:%M:%S')}` "
                        f"**{done}/{total}** scanned | **{open_count}** open"
                    )
            return cb

        scan_results = run_scan(ip, ports_base[:], threads, timeout,
                                do_banner, make_cb(prog_bar, status_ph))
        elapsed = time.time() - t0

        prog_bar.progress(1.0, text=f"✅ Done -- {len(scan_results)} open port(s) found")
        status_ph.empty()

        # -- SAVE TO SESSION STATE --
        st.session_state.scan_targets[ip] = {
            "target":   target,
            "ip":       ip,
            "os_guess": os_guess,
            "mode":     mode,
            "elapsed":  elapsed,
            "sorted_r": sorted(scan_results, key=lambda x: x["port"]),
            "stamp":    datetime.now().strftime("%Y%m%d_%H%M%S"),
        }

    st.session_state.scan_done = True

# == DISPLAY RESULTS (reads from session_state -- survives filter reruns) ======
if st.session_state.scan_done and st.session_state.scan_targets:
    for ip, data in st.session_state.scan_targets.items():
        target   = data["target"]
        os_guess = data["os_guess"]
        elapsed  = data["elapsed"]
        sorted_r = data["sorted_r"]
        stamp    = data["stamp"]
        highs    = [r for r in sorted_r if r["risk"] == "HIGH"]
        meds     = [r for r in sorted_r if r["risk"] == "MEDIUM"]
        lows     = [r for r in sorted_r if r["risk"] == "LOW"]

        st.markdown(f'<div class="section-head">RESULTS -- {target} ({ip})</div>',
                    unsafe_allow_html=True)

        # Stats
        s1, s2, s3, s4, s5 = st.columns(5)
        for col, num, lbl, color in [
            (s1, len(sorted_r),     "OPEN PORTS",  "#00ff88"),
            (s2, len(highs),        "HIGH RISK",   "#ff3333"),
            (s3, len(meds),         "MEDIUM RISK", "#ffaa00"),
            (s4, len(lows),         "LOW RISK",    "#00ccff"),
            (s5, f"{elapsed:.1f}s", "SCAN TIME",   "#555"),
        ]:
            col.markdown(f"""<div class="stat-card">
                <div class="stat-num" style="color:{color}">{num}</div>
                <div class="stat-lbl">{lbl}</div></div>""", unsafe_allow_html=True)

        # OS badge
        st.markdown(
            f'<div style="margin:0.8rem 0 0.2rem 0;">OS Fingerprint: '
            f'<span class="os-badge">{os_guess}</span></div>',
            unsafe_allow_html=True
        )

        if sorted_r:
            # Filter controls
            st.markdown('<div class="section-head">🔍 FILTER</div>', unsafe_allow_html=True)
            risk_filter = st.multiselect(
                "Filter by Risk Level",
                ["HIGH", "MEDIUM", "LOW"],
                default=["HIGH", "MEDIUM", "LOW"],
                key=f"risk_filter_{ip}"
            )
            filtered_r = [r for r in sorted_r if r["risk"] in risk_filter]

            # Port Table
            st.markdown('<div class="section-head">📋 OPEN PORTS</div>', unsafe_allow_html=True)
            for r in filtered_r:
                ri   = r["risk"]
                ico  = {"HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢"}.get(ri, "⚪")
                c1, c2, c3, c4 = st.columns([1, 3, 2, 5])
                c1.markdown(f"`{r['port']}`")
                c2.markdown(f"**{r['service']}**")
                c3.markdown(f"{ico} **{ri}**")
                bnr = f"`{r['banner'][:45]}`" if r["banner"] else ""
                tip = r["cve_note"] if r["cve_note"] else None
                cve = " ⚠️" if r["cve_note"] else ""
                c4.markdown(f"{bnr}{cve}", help=tip)

            # CVE Alerts
            cve_ports = [r for r in sorted_r if r["cve_note"]]
            if cve_ports:
                st.markdown('<div class="section-head">🚨 CVE / SECURITY ALERTS</div>',
                            unsafe_allow_html=True)
                for r in cve_ports:
                    ico = "🔴" if r["risk"] == "HIGH" else "🟡"
                    st.error(f"{ico} **Port {r['port']} ({r['service']})** -- {r['cve_note']}")

            # High Risk Summary
            if highs:
                st.markdown('<div class="section-head">⚠ HIGH RISK SUMMARY</div>',
                            unsafe_allow_html=True)
                for r in highs:
                    note = r["cve_note"] or "Commonly exploited -- review immediately"
                    st.markdown(
                        f'<div class="cve-block">* Port <b>{r["port"]}</b> '
                        f'({r["service"]}) -- {note}</div>',
                        unsafe_allow_html=True
                    )

            # === REMEDIATION GUIDE ============================================
            st.markdown('<div class="section-head">🛡️ REMEDIATION GUIDE — How to Resolve Risks</div>',
                        unsafe_allow_html=True)
            st.markdown(
                '<div style="color:#555; font-size:0.75rem; letter-spacing:1px; '
                'margin-bottom:0.8rem;">'
                'Expand each port below for step-by-step remediation instructions.</div>',
                unsafe_allow_html=True
            )

            # Group by risk for ordered display
            for risk_group, risk_label, risk_color, risk_icon in [
                (highs,  "HIGH RISK",   "#ff3333", "🔴"),
                (meds,   "MEDIUM RISK", "#ffaa00", "🟡"),
                (lows,   "LOW RISK",    "#00ccff", "🟢"),
            ]:
                if not risk_group:
                    continue
                st.markdown(
                    f'<div style="color:{risk_color}; font-family:Orbitron,monospace; '
                    f'font-size:0.72rem; letter-spacing:3px; margin:1rem 0 0.4rem 0;">'
                    f'{risk_icon} {risk_label} PORTS</div>',
                    unsafe_allow_html=True
                )
                for r in risk_group:
                    steps = r.get("remediation", [])
                    with st.expander(
                        f"{risk_icon} Port {r['port']} -- {r['service']}  "
                        f"({'⚠ ' + r['cve_note'][:50] if r['cve_note'] else 'Open port detected'})"
                    ):
                        if r["cve_note"]:
                            st.warning(f"**Security Note:** {r['cve_note']}")
                        if steps:
                            st.markdown("**Remediation Steps:**")
                            for i, step in enumerate(steps, 1):
                                st.markdown(f"{i}. {step}")
                        else:
                            st.info("No specific remediation available. "
                                    "Close the port if not needed, and restrict access via firewall.")

            # Summary quick-action box
            if highs:
                st.markdown("---")
                high_list = ", ".join(
                    f"Port {r['port']} ({r['service']})" for r in highs[:5]
                )
                dots = "..." if len(highs) > 5 else ""
                st.error(
                    f"🚨 **{len(highs)} HIGH-RISK port(s) detected!** "
                    f"Expand each port above for detailed remediation steps. "
                    f"Priority: {high_list}{dots}"
                )
        else:
            st.info(f"No open ports found on {ip}.")

        # Export
        st.markdown('<div class="section-head">💾 EXPORT REPORT</div>', unsafe_allow_html=True)
        e1, e2 = st.columns(2)
        e1.download_button("⬇️ Download JSON",
            data=build_json(target, ip, os_guess, data["mode"], elapsed, sorted_r),
            file_name=f"scan_{ip}_{stamp}.json",
            mime="application/json", key=f"json_{ip}_{stamp}")
        e2.download_button("⬇️ Download TXT",
            data=build_txt(target, ip, os_guess, data["mode"], elapsed, sorted_r),
            file_name=f"scan_{ip}_{stamp}.txt",
            mime="text/plain", key=f"txt_{ip}_{stamp}")

        st.markdown("---")

# == FOOTER ====================================================================
st.markdown(
    '<div class="footer">PORT SCANNER v6.0 • TARUN-30 • '
    'GITHUB.COM/TARUN-30</div>',
    unsafe_allow_html=True
)
