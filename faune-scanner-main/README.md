# Vaeil

TCP port scanner with automatic CVE detection and HTML report generation.

---

## Features
![demo](demo.gif)
- Fast multi-threaded TCP port scanning
- Service and banner detection
- Automatic CVE lookup via NVD API
- HTML report generation with risk scoring
- Threat intelligence on dangerous ports

---

## Installation

```bash
pip install -e .
```

---

## Usage

```bash
# Basic scan
vaeil <target> -s <start_port> -e <end_port>

# Scan with CVE detection
vaeil <target> -s 1 -e 1024 --cve

# Full scan
vaeil <target> -s 1 -e 65535 --cve
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-s` | Start port | 1 |
| `-e` | End port | 1024 |
| `-t` | Timeout (seconds) | 1.0 |
| `-T` | Thread count | 100 |
| `--cve` | Enable CVE lookup | off |

---

## Example

```bash
vaeil 192.168.1.1 -s 1 -e 1024 --cve
```

Generates a timestamped HTML report with open ports, banners, CVE findings, and a global risk score.

---

## Legal

For authorized targets only. The author takes no responsibility for misuse.

---

*Built by Faune — offensive mindset.*
