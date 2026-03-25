# Changelog — Port Scanner

All notable changes to this project are documented here.

---

## [v6.0] — Final Release

### Added

- Subnet scanning: pass a CIDR (e.g. `192.168.1.0/24`) with `--subnet` to auto ping-sweep and scan all live hosts
- OS fingerprinting hint via TTL analysis from ping response
- CVE alert notes for 15+ commonly exploited open ports (displayed inline and in reports)
- `--stealth` flag: randomizes port order, caps threads at 50, raises timeout
- High-risk port summary block printed at end of output
- Dual mode: works both as CLI tool and interactively
- Full scan metadata included in JSON/TXT reports

---

## [v5.0] — CLI Args + Report Export

### Added

- Full `argparse` CLI — no interactive prompts required
- `--mode` flag: `top`, `wellknown`, `full`, `custom`
- `--ports` for custom range (e.g. `--ports 1-500`)
- `--output` flag: save results as `txt`, `json`, or `both`
- Structured JSON report with scan metadata
- Formatted TXT report with table layout
- `--quiet` flag for pipe-friendly minimal output (e.g. `| grep HIGH`)

---

## [v4.0] — Scan Modes + UDP + Progress Bar

### Added

- 5 scan presets: Top Ports / Well-Known (1-1024) / Full (1-65535) / Custom Range / Single Port
- UDP scanning (best-effort ICMP unreachable method)
- Animated progress bar with percentage, count, and ETA
- Risk tagging per port: HIGH / MEDIUM / LOW
- Ping/host-up check before scan begins
- Configurable timeout and thread count

---

## [v3.0] — Service Detection + Banner Grabbing

### Added

- Built-in `SERVICE_MAP` with 60+ port-to-service-name mappings
- Banner grabbing: HTTP HEAD request with raw recv fallback
- ANSI color-coded terminal output (green/yellow/red)
- Formatted results table with PORT / SERVICE / BANNER columns

---

## [v2.0] — Multi-Threaded

### Added

- `ThreadPoolExecutor` for concurrent port scanning
- Thread-safe result collection with `threading.Lock`
- Port range validation (0–65535, start ≤ end)
- Inline progress counter
- Scan time measurement

---

## [v1.0] — Basic

### Initial Release

- Single-threaded TCP connect scan using `socket.connect_ex()`
- Simple start/end port range input
- Prints open ports to console
- Timestamps scan start and end
