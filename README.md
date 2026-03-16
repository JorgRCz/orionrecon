<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/OWASP-Top%2010-red?style=for-the-badge"/>
</p>

<h1 align="center">⭐ OrionRecon</h1>
<p align="center"><b>Attack Surface Reconnaissance & Vulnerability Assessment Toolkit</b></p>
<p align="center">
  Modular · Automated · OWASP Top 10 · Professional PDF Reports
</p>

---

> ⚠️ **For authorized use only.** This tool must only be used on systems you own or have explicit written permission to test. Unauthorized use may be illegal. The author assumes no liability for misuse.

---

## What is OrionRecon?

OrionRecon is a modular, automated reconnaissance and vulnerability assessment framework designed for professional penetration testers. It chains together 15+ industry-standard tools and native checks into a single pipeline — from passive OSINT to active vulnerability scanning — and delivers results through an interactive dark-theme HTML dashboard and a branded PDF report.

---

## Features at a Glance

| Category | Coverage |
|---|---|
| 🌐 Passive Recon | Subdomain enum, email harvesting, historical URLs, ASN/CIDR mapping |
| 🔫 Active Scanning | Port discovery, service version detection, OS fingerprinting |
| 💊 Vulnerability Detection | Nuclei templates (CVEs, misconfigs, exposures) |
| 🔬 Tech Fingerprinting | Wappalyzer-like stack detection, security header analysis |
| 🔟 OWASP Top 10 | A01→A10 automated checks with finding classification |
| ☁️ Cloud Recon | AWS S3, GCP GCS, Azure Blob, DigitalOcean Spaces, CNAME detection |
| 🎯 Subdomain Takeover | 25+ services (AWS, Heroku, GitHub Pages, Netlify, Vercel...) |
| 🔒 TLS/SSL | Weak protocols, cipher suites, Heartbleed, POODLE, cert analysis |
| 🌐 CORS | Origin reflection, null origin, wildcard + credentials |
| 🛡 WAF/CDN Detection | wafw00f + native signatures |
| 💥 Fuzzing | Directory, parameter and vhost fuzzing via ffuf |
| 🕷️ Web Crawling | Endpoint discovery, forms, interesting parameters |
| 🔐 Secrets Scanner | API keys, tokens, passwords in JS files |
| 📸 Screenshots | Visual capture of all discovered URLs |
| 📊 Reports | Interactive HTML dashboard + branded PDF |

---

## OWASP Top 10 Coverage

| ID | Category | Checks |
|---|---|---|
| A01 | Broken Access Control | Path traversal, CORS misconfigs, forced browsing, takeover |
| A02 | Cryptographic Failures | TLS weak protocols, HSTS absent, cookies without Secure flag |
| A03 | Injection | SQL injection (error-based), reflected XSS, LFI/path traversal |
| A05 | Security Misconfiguration | 8 security headers, CSP analysis, technology disclosure |
| A07 | Auth Failures | Default credentials (15 services), JWT alg:none, weak JWT secrets |
| A10 | SSRF | SSRF parameter detection (30+ patterns) |

---

## Modules

```
modules/
├── recon/          theHarvester · subfinder · amass · crt.sh · dnsx
│                   alterx · gau (Wayback) · asnmap · Shodan
├── scanning/       nmap · nuclei · httpx · naabu · sslscan/testssl
│                   CORS scanner · CORS scanner
├── owasp/          HeaderChecker (A05) · InjectionProber (A03/A10)
│                   AuthChecker (A07) — default creds + JWT
├── tech/           Native Wappalyzer-like fingerprinting
├── waf/            wafw00f + native WAF/CDN signatures
├── takeover/       Subdomain takeover (25+ cloud services)
├── secrets/        JS secrets scanner (regex patterns)
├── screenshots/    gowitness
├── crawl/          katana (JS-aware crawler)
├── cloud/          AWS S3 · GCP GCS · Azure Blob · DO Spaces
├── fuzzing/        ffuf (directories · parameters · vhosts)
└── reporting/      Interactive HTML dashboard + WeasyPrint PDF
```

---

## Installation

```bash
git clone https://github.com/JorgRCz/orionrecon.git
cd orionrecon
bash install.sh
```

`install.sh` automatically installs:
- Python dependencies (`pip`)
- Go tools: subfinder, nuclei, ffuf, httpx, naabu, dnsx, alterx, katana, asnmap, gau, gowitness, amass
- System tools: nmap, sslscan, testssl.sh, wafw00f
- SecLists wordlists
- Global `orionrecon` command

### Requirements

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| Go | 1.21+ |
| OS | Kali Linux / Parrot OS / Ubuntu 22.04+ |

---

## Quick Start

```bash
# Check installed tools
orionrecon check

# Full automated scan + PDF report
orionrecon scan target.com --pdf

# Specific modules only
orionrecon scan target.com -m recon nmap nuclei tls cloud owasp

# OWASP-focused scan
orionrecon scan target.com -m headers injection auth cors tls

# Passive OSINT only
orionrecon recon target.com

# Nmap with multiple profiles
orionrecon nmap 192.168.1.1 -p quick web vuln

# Directory + parameter fuzzing
orionrecon fuzz https://target.com -m directories parameters

# Tech fingerprinting
orionrecon tech https://target.com

# Regenerate report from existing session
orionrecon report ./sessions/target.com_20240101_120000/
```

---

## Available Modules

| Flag | Module | Description |
|---|---|---|
| `recon` | OSINT | Subdomain enum, emails, IPs, historical URLs, ASN |
| `nmap` | Port Scan | Port discovery + service detection |
| `nuclei` | Vuln Scan | CVE & misconfiguration templates |
| `tech` | Fingerprinting | Technology stack detection |
| `waf` | WAF/CDN | Firewall & CDN detection |
| `cors` | CORS | Cross-Origin policy misconfigurations |
| `tls` | TLS/SSL | Protocol weaknesses, cert analysis |
| `takeover` | Subdomain Takeover | Dangling CNAME detection |
| `fuzzing` | Fuzzing | Directory, parameter, vhost brute-force |
| `crawl` | Crawl | JS-aware endpoint discovery |
| `secrets` | Secrets | API keys & tokens in JS files |
| `cloud` | Cloud | S3/GCS/Azure bucket enumeration |
| `screenshots` | Screenshots | Visual capture (requires `--screenshots`) |
| `headers` | **OWASP A05** | Security headers & cookie flags |
| `injection` | **OWASP A03/A10** | SQLi, XSS, LFI, SSRF detection |
| `auth` | **OWASP A07** | Default credentials, JWT security |

---

## Nmap Profiles

| Profile | Description |
|---|---|
| `quick` | Top 100 ports, fast (-T4) |
| `stealth` | SYN scan, slow, all ports |
| `full` | All ports + versions + scripts + OS |
| `vuln` | NSE vulnerability scripts |
| `udp` | Top 200 UDP ports |
| `web` | Web ports only (80, 443, 8080...) |
| `smb` | SMB vulnerabilities |
| `aggressive` | Full aggressive scan |

---

## Dashboard

Each scan produces an interactive HTML report at `sessions/<target>_<timestamp>/report.html`:

<details>
<summary>📋 Dashboard sections</summary>

- **Overview** — severity stats, severity bar, WAF summary, executed modules, top critical/high findings
- **Findings** — full sortable table with severity filters, search, expandable evidence rows
- **Recon** — subdomains, alive hosts (IPs + CNAMEs), emails, ASN/CIDR ranges, GAU interesting URLs
- **Nmap Artillery** — ports and services per profile
- **Tech Detection** — technology stack by category, missing security headers
- **WAF/CDN** — detected firewalls with confidence and method
- **CORS** — vulnerable endpoints with origin reflection details
- **TLS/SSL** — weak protocols, cipher suites, vulnerabilities (Heartbleed, etc.), cert info
- **Subdomain Takeover** — vulnerable subdomains with CNAME chains
- **Fuzzing** — discovered paths filtered by status code
- **Crawl** — endpoints, forms, interesting parameters
- **Secrets** — exposed API keys and tokens
- **Screenshots** — visual gallery
- **Cloud** — discovered buckets and cloud services
- **OWASP Top 10** — interactive grid mapping all findings to OWASP 2021 categories
- **Timeline** — chronological scan events
- **Export** — JSON data export, CSV (hosts + emails), PDF print

</details>

---

## Configuration

Copy `config.example.yaml` → `config.yaml` and customize:

```yaml
api_keys:
  shodan: "YOUR_KEY"       # Enables Shodan in recon
  virustotal: "YOUR_KEY"   # Enables VT in theHarvester

general:
  sessions_dir: "./sessions"
  max_threads: 10

nuclei:
  severity: ["critical", "high", "medium"]
  rate_limit: 150
```

---

## Scope Control

```bash
# Only scan specific subdomains
orionrecon scan target.com --scope "^(api|app|admin)\."

# Exclude certain hosts
orionrecon scan target.com --exclude "staging|dev|test"
```

---

## Output

```
sessions/
└── target.com_20240101_120000/
    ├── report.html       # Interactive dashboard
    ├── report.pdf        # Branded PDF report
    ├── results.json      # Complete raw data
    ├── recon_hosts.csv   # Discovered hosts (exportable)
    └── recon_emails.csv  # Discovered emails (exportable)
```

---

## Disclaimer

This tool is intended **only** for:
- Systems you own
- Authorized penetration testing engagements (with written permission)
- CTF competitions and lab environments
- Defensive security research

**Unauthorized use is illegal and unethical. The author assumes no liability for misuse.**

---

<p align="center">
  <b>OrionRecon</b> · Built by <b>Jorge RC</b><br/>
  <i>Attack Surface Recon Toolkit</i>
</p>
