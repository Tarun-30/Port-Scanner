# Port Scanner

> _"We scan ports others won't even float near."_

A beginner-to-advanced Python port scanner built progressively across 6 versions — from a simple single-threaded script to a full-featured CLI tool with subnet scanning, CVE alerts, OS fingerprinting hints, and JSON/TXT report export.

**No external libraries required.** Pure Python standard library only.

---

## 📁 Version History

| Version | File                      | What's New                                             |
| ------- | ------------------------- | ------------------------------------------------------ |
| v1.0    | `v1_basic.py`             | Basic single-threaded TCP scanner                      |
| v2.0    | `v2_threaded.py`          | Multi-threading, validation, scan timer                |
| v3.0    | `v3_service_detection.py` | Service names, banner grabbing, color output           |
| v4.0    | `v4_scan_modes.py`        | 5 scan modes, UDP scanning, risk tagging, progress bar |
| v5.0    | `v5_cli_reports.py`       | Full argparse CLI, JSON + TXT report export            |
| v6.0    | `v6_final.py`             | Subnet scanning, OS hints, CVE alerts, stealth mode    |
| Web App | `PortScanner_app.py`      | 🛸 Cyberpunk Streamlit UI, 🛡️ Remediation Guide, Emojis |

---

## 🚀 Quick Start

```bash
git clone https://github.com/Tarun-30/PortScanner
cd PortScanner

# Run the Web Dashboard (Recommended)
pip install streamlit
streamlit run PortScanner_app.py

# Or run the final CLI version (if in versions folder)
python v6_final.py -t 192.168.1.1
```

---

## 🔧 Usage (v6.0 — Final)

```
python v6_final.py -t <target> [options]
```

### Options

| Flag             | Description                                       | Default      |
| ---------------- | ------------------------------------------------- | ------------ |
| `-t`, `--target` | IP, hostname, or CIDR subnet                      | _(required)_ |
| `--mode`         | `top` / `wellknown` / `full` / `custom`           | `top`        |
| `--ports`        | Custom range e.g. `1-1000` (with `--mode custom`) | —            |
| `--subnet`       | Ping sweep + scan all live hosts in CIDR          | off          |
| `--threads`      | Number of concurrent threads                      | `200`        |
| `--timeout`      | Socket timeout in seconds                         | `0.5`        |
| `--banner`       | Attempt to grab service banners                   | off          |
| `--stealth`      | Randomized order, throttled threads               | off          |
| `--output`       | Save report: `txt` / `json` / `both`              | —            |
| `--quiet`        | Minimal output, pipe-friendly                     | off          |

### Examples

```bash
# Quick top-ports scan
python v6_final.py -t 192.168.1.1

# Well-known ports (1-1024) with banners
python v6_final.py -t scanme.nmap.org --mode wellknown --banner

# Custom range, save JSON report
python v6_final.py -t 10.0.0.1 --mode custom --ports 1-500 --output json

# Subnet ping sweep + scan all live hosts
python v6_final.py -t 192.168.1.0/24 --subnet --mode top

# Stealth scan, save both report formats
python v6_final.py -t 10.0.0.5 --stealth --output both

# Quiet mode (scriptable, pipe output)
python v6_final.py -t 10.0.0.1 --quiet | grep HIGH
```

---

## 📊 Sample Output

```
  ╔══════════════════════════════════════════════════════════════╗
  ║             Port Scanner  v6.0 — Final Release               ║
  ╚══════════════════════════════════════════════════════════════╝

  PORT     SERVICE           RISK      BANNER
  ──────── ──────────────── ───────── ────────────────────────────
  22       SSH               LOW
  80       HTTP              LOW       HTTP/1.1 200 OK
  3306     MySQL             HIGH
       ⛔ MySQL: brute-force target; disable sa account
  3389     RDP               HIGH
       ⛔ RDP: CVE-2019-0708 (BlueKeep) if unpatched

  ⚠  HIGH RISK PORTS DETECTED — review immediately:
     • Port 3306 (MySQL): brute-force target; disable sa account
     • Port 3389 (RDP): CVE-2019-0708 (BlueKeep) if unpatched
```

---

## ⚙️ Scan Modes

| Mode        | Ports Scanned         | Speed          |
| ----------- | --------------------- | -------------- |
| `top`       | ~45 most common ports | Very fast      |
| `wellknown` | 1–1024                | Fast           |
| `full`      | 1–65535               | Slow (minutes) |
| `custom`    | You define the range  | Depends        |

---

## 🔍 Features by Version

### v1.0 — Basic

- Single-threaded TCP connect scan
- Simple console output

### v2.0 — Threaded

- `ThreadPoolExecutor` for parallel scanning
- Thread-safe result collection
- Port validation, timing

### v3.0 — Service Detection

- 60+ port-to-service mappings
- HTTP HEAD + raw banner grabbing
- ANSI color-coded output

### v4.0 — Scan Modes

- 5 scan presets
- UDP best-effort scanning
- Risk tagging: HIGH / MEDIUM / LOW
- Animated progress bar with ETA
- Ping/host-up check

### v5.0 — CLI & Reports

- Full `argparse` CLI
- JSON structured report
- TXT formatted report
- `--quiet` for pipe-friendly output

### v6.0 — Final

- Subnet scanning with ping sweep
- OS fingerprinting (TTL-based)
- CVE alert notes per open port
- `--stealth` randomized scan mode
- Dual interactive + CLI mode
- Full scan metadata in reports

### Web App — `PortScanner_app.py`

- Full **Streamlit dashboard** with interactive 🛸 cyberpunk aesthetics.
- 🛡️ **Comprehensive Remediation Guide** with step-by-step mitigation advice per port.
- 🔴 Native **Emoji support** for visual identification of risk levels and critical CVEs.
- Detailed visual summaries of HIGH, MEDIUM, and LOW risk findings.
- One-click downloads for JSON and TXT reports from the browser.

---

## ⚠️ Legal Disclaimer

This tool is for **educational purposes and authorized security testing only.**  
Only scan systems you own or have explicit written permission to test.  
Unauthorized port scanning may be illegal in your jurisdiction.

---

## 👨‍💻 Author

**Tarun Gupta** — BTech (Cybersecurity),  
GitHub: [github.com/Tarun-30](https://github.com/Tarun-30)

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.
