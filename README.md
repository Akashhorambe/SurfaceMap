```markdown
# Seeker - Multi-Source Reconnaissance Tool

Seeker is a Python-based reconnaissance tool built for learning VAPT, bug bounty workflows, and penetration testing fundamentals.

It automates common recon tasks like subdomain enumeration, port scanning, DNS footprinting, WHOIS lookup, banner grabbing, web fingerprinting, WAF detection, technology detection, security header analysis, CVE mapping, subdomain takeover detection, and directory fuzzing.

> **Disclaimer**
> This tool is for educational purposes and authorized security testing only.
> Use it only on systems you own or have explicit written permission to test.

---

## Features

### Target Input

Seeker supports multiple target input types:

- Single domain: `example.com`
- IP address: `192.168.1.1`
- CIDR range: `192.168.1.0/24`
- File containing multiple targets: `targets.txt`

---

### Subdomain Enumeration

Collects subdomains using multiple passive sources:

- crt.sh
- Wayback Machine
- AlienVault OTX
- ThreatMiner
- HackerTarget
- CertSpotter

Also supports:

- Active DNS brute-force
- Optional external subdomain tools if installed:
  - Sublist3R
  - subfinder
  - assetfinder
  - Amass

---

### Subdomain Takeover Detection

Checks for possible subdomain takeover indicators by analyzing CNAME records.

Supported services include:

- GitHub Pages
- Heroku
- AWS S3
- Azure Web Apps
- Netlify
- Vercel
- Shopify
- Zendesk
- Freshdesk
- Tumblr
- WordPress.com
- Pantheon
- Flywheel

---

### Port Scanning

Scans the Nmap Top 100 ports using asynchronous TCP connections.

- Async port scanning
- Retry mechanism for reliability
- Scan scope options:
  - Scan only main target
  - Scan main target and discovered subdomains

---

### Banner Grabbing

Attempts to collect banners from open ports to identify:

- SSH versions
- FTP services
- SMTP services
- Web servers
- Other service banners

---

### WHOIS / RDAP Lookup

Uses RDAP to collect registration information:

- Registrar
- Creation date
- Expiration date
- Last changed date
- Name servers
- Domain status
- Country
- Handle

---

### DNS Footprinting

Retrieves common DNS records:

- A
- AAAA
- MX
- NS
- TXT
- SOA
- CNAME

---

### Web Fingerprinting

For discovered web services, collects:

- HTTP status code
- Page title
- Server header
- Response information

---

### WAF Detection

Detects possible WAF or CDN protection using:

- HTTP response headers
- Cookies
- Server headers
- Behavioral response checks

Common detections include:

- Cloudflare
- Akamai
- Sucuri
- Imperva / Incapsula
- AWS WAF / ELB
- F5 BIG-IP
- Barracuda
- CloudFront

---

### Security Header Analysis

Checks for missing security headers:

- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

---

### Technology Stack Detection

Attempts to identify technologies used by the target web application:

- WordPress
- Drupal
- Joomla
- Shopify
- React
- Vue.js
- Angular
- Next.js
- Bootstrap
- jQuery
- PHP
- ASP.NET
- Laravel
- Express.js
- Nginx
- Apache
- Microsoft IIS

---

### CVE Mapping

Maps banners and server headers to possible CVEs using the NIST NVD API.

Examples:

```
Apache/2.4.49
nginx/1.18.0
PHP/8.1.2
OpenSSH_8.2p1
```

You can optionally set an NVD API key for higher rate limits:

Linux/macOS:

```bash
export NVD_API_KEY=your_api_key_here
```

Windows:

```cmd
set NVD_API_KEY=your_api_key_here
```

---

### Directory Fuzzing

Performs directory fuzzing using a wordlist to discover common paths:

```
/admin
/login
/api
/backup
/.env
/.git
/swagger
/docs
/phpmyadmin
```

You can provide your own wordlist or use the built-in default wordlist.

---

## Output Options

Seeker supports three output modes:

### JSON Output

Structured output useful for automation and reporting.

```
scan_results/example.com_TIMESTAMP.json
```

### CSV Output

Spreadsheet-friendly output.

```
scan_results/example.com_TIMESTAMP.csv
```

### Screen Output

Displays results only in the terminal. No file is saved.

---

## Requirements

Make sure you have Python installed.

Recommended version:

```
Python 3.9 or higher
```

---

## Installation

### 1. Clone or download the repository

```bash
git clone https://github.com/Akashhorambe/SurfaceMap.git
cd Surfacemap
```

### 2. Create a virtual environment

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The `requirements.txt` file should contain:

```
aiohttp
dnspython
beautifulsoup4
rich
```

### 4. Run the tool

```bash
python surfacemap.py
```

---

## Interactive Usage

Run:

```bash
python surfacemap.py
```

Example prompts:

```
1. Enter target (Domain, IP, CIDR, or file): example.com
2. Enter output format (json/csv/screen) [screen]: json

Feature Selection
Enable subdomain enumeration? [Y/n]:
Enable multi-source passive subdomain enumeration? [Y/n]:
Enable external subdomain tools if installed? [y/N]:
Enable active DNS brute-force? [Y/n]:
Enable port scanning? [Y/n]:
Port scan ALL discovered subdomains? Choose 'n' for main target only [Y/n]:
Enable banner grabbing? [Y/n]:
Enable DNS footprinting? [Y/n]:
Enable WHOIS/RDAP lookup? [Y/n]:
Enable HTTP fingerprinting? [Y/n]:
Enable WAF detection? [Y/n]:
Enable security header analysis? [Y/n]:
Enable technology stack detection? [Y/n]:
Enable directory fuzzing? [Y/n]:
Enable CVE mapping from banners/server headers? [Y/n]:
Enable subdomain takeover detection? [Y/n]:
```

---

## Command-Line Options

Seeker is fully interactive, but some options can be prefilled.

```bash
python surfacemap.py -t example.com -o json
```

```bash
python surfacemap.py -t example.com --wordlist /usr/share/wordlists/dirb/common.txt -o csv
```

```bash
python surfacemap.py -t targets.txt -o screen
```

Available options:

```
-t, --target       Target domain, IP, CIDR, or file
--wordlist         Directory fuzzing wordlist path
--sublist3r        Path to Sublist3R.py
-o, --output       Output format: json, csv, screen
```

---

## Output Folder

Scan results are saved inside:

```
scan_results/
```

Example:

```
scan_results/example.com_20250101_153045.json
scan_results/example.com_20250101_153045.csv
```

If output format is `screen`, no file is saved.

---

## Project Structure

```
seeker/
├── surfacemap.py
├── requirements.txt
├── README.md
└── scan_results/
```

---

## Optional External Tools

Seeker can use external subdomain tools if they are already installed on your system.

Supported tools:

- Sublist3R
- subfinder
- assetfinder
- Amass

If these tools are not installed, Seeker will continue working using built-in passive subdomain sources.

---

## Technologies Used

- Python
- asyncio
- aiohttp
- dnspython
- BeautifulSoup4
- Rich
- RDAP
- NIST NVD API

---

## Author

Akash Horambe

---

## License

This project is created for educational purposes only.
```
