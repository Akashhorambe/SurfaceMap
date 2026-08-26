# ==========================================
# Project Name : Seeker
# Purpose      : Recon tool for VAPT / Bug Bounty learning
# Author       : Akash Horambe
# ==========================================

import asyncio
import aiohttp
import argparse
import ipaddress
import json
import csv
import os
import sys
import shutil
import ssl
import re
import tempfile

from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# external libraries
import dns.asyncresolver
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

# console object for colorful output
console = Console()


# simple banner
BANNER = """
[bold cyan]
   ___   _   _   _ __    / _|   __ _    ___    ___    __  __    __ _   _ __ 
  / __| | | | | | '__|  | |_   / _` |  / __|  / _ \\  |  \\/  |  / _` | | '_ \\
  \\__ \\ | |_| | | |     |  _| | (_| | | (__  |  __/  | |\\/| | | (_| | | |_) |
  |___/  \\__,_| |_|     |_|    \\__,_|  \\___|  \\___|  |_|  |_|  \\__,_| | .__/ 
                                                                      |_|   
                           Multi-Source Recon Tool
[/bold cyan]
"""


# ----------------------------------------
# BASIC SETTINGS
# ----------------------------------------

# Nmap top 100 ports
PORT_LIST = [
    7, 9, 13, 20, 21, 22, 23, 25, 26, 37,
    53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444,
    445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
    1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
    6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156
]

WEB_PORTS = [80, 443, 8080, 8000, 8443]
ASSUMED_WEB_PORTS = [80, 443]

# limits so the tool does not overload the target
PORT_LIMIT = 150
DIR_LIMIT = 30
MAX_DIR_WORDS = 800

# small default wordlists
SUBDOMAIN_WORDS = [
    "admin", "api", "dev", "staging", "test", "blog",
    "mail", "vpn", "portal", "app", "demo", "qa",
    "beta", "internal", "uat", "prod", "shop", "secure"
]

DIRECTORY_WORDS = [
    "admin", "administrator", "login", "api", "v1", "v2",
    "console", "dashboard", "panel", "phpmyadmin",
    "backup", "backups", "config", "conf", "debug",
    ".env", ".git", ".git/config", ".svn", ".DS_Store",
    "robots.txt", "sitemap.xml", "wp-admin", "wp-login.php",
    "server-status", "actuator", "swagger", "docs",
    "test", "dev", "staging", "old", "temp", "tmp"
]


# ----------------------------------------
# SMALL HELPER FUNCTIONS
# ----------------------------------------

# check if value is IP address
def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# convert list to normal string for output
def make_string(value):
    if isinstance(value, list):
        return ",".join(map(str, value))
    return str(value)


# simple yes/no input function
def ask_yes_no(question, default=True):
    if default:
        hint = "Y/n"
    else:
        hint = "y/N"

    while True:
        answer = console.input(f"[bold yellow]{question} [{hint}]: [/bold yellow]").strip().lower()

        if answer == "":
            return default

        if answer in ["y", "yes"]:
            return True

        if answer in ["n", "no"]:
            return False

        console.print("[red]Please enter y or n.[/red]")


# load wordlist from file, otherwise use default list
def load_wordlist(path, default_words):
    words = []

    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        words.append(line)
        except Exception:
            words = default_words[:]
    else:
        words = default_words[:]

    # remove duplicate words
    unique_words = []
    for word in words:
        if word not in unique_words:
            unique_words.append(word)

    # limit size
    if len(unique_words) > MAX_DIR_WORDS:
        unique_words = unique_words[:MAX_DIR_WORDS]

    return unique_words


# parse target input: domain, IP, CIDR, or file
def get_targets(user_input):
    targets = []

    if os.path.isfile(user_input):
        with open(user_input, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if line:
                    targets.extend(expand_target(line))
    else:
        targets.extend(expand_target(user_input))

    # remove duplicates
    return list(set(targets))


# expand CIDR or single target
def expand_target(target):
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)

            # stop very big scans
            if network.num_addresses > 65536:
                console.print(f"[red]Network {target} is too large. Skipping.[/red]")
                return []

            return [str(ip) for ip in network]

        ipaddress.ip_address(target)
        return [target]

    except ValueError:
        # if not IP/CIDR, treat as domain
        return [target]


# small function to print table or empty message
def show_table(title, headers, rows, empty_message, style="bold green"):
    if rows:
        table = Table(title=title, show_header=True, header_style=style)

        for header in headers:
            table.add_column(header, overflow="fold")

        for row in rows:
            table.add_row(*[str(item) for item in row])

        console.print(table)
    else:
        console.print(f"[yellow]{empty_message}[/yellow]")


# ----------------------------------------
# WHOIS USING RDAP
# ----------------------------------------

class WhoisChecker:
    async def run(self, session, target):
        result = {
            "source": "RDAP",
            "target": target
        }

        if is_ip(target):
            url = f"https://rdap.org/ip/{target}"
        else:
            url = f"https://rdap.org/domain/{target}"

        try:
            async with session.get(url, timeout=20, allow_redirects=True) as response:
                if response.status != 200:
                    result["error"] = f"RDAP status {response.status}"
                    return result

                text_data = await response.text()
                data = json.loads(text_data)

            # basic values
            result["name"] = data.get("name") or data.get("ldhName")
            result["handle"] = data.get("handle")
            result["country"] = data.get("country")

            # status
            status = data.get("status")
            if isinstance(status, list):
                result["status"] = ", ".join(status)
            elif status:
                result["status"] = status

            # events like registration and expiry
            events = {}
            for event in data.get("events", []):
                action = event.get("eventAction", "").lower()
                date = event.get("eventDate")

                if action and date:
                    events[action] = date

            result["creation_date"] = events.get("registration")
            result["expiration_date"] = events.get("expiration")
            result["last_changed"] = events.get("last changed")

            # name servers
            name_servers = []
            for ns in data.get("nameservers", []):
                if ns.get("ldhName"):
                    name_servers.append(ns["ldhName"].rstrip("."))

            if name_servers:
                result["name_servers"] = sorted(set(name_servers))

            # registrar
            registrar = self.find_registrar(data.get("entities", []))
            if registrar:
                result["registrar"] = registrar

            # remove empty values
            clean_result = {}
            for key, value in result.items():
                if value not in [None, "", []]:
                    clean_result[key] = value

            return clean_result

        except Exception as error:
            result["error"] = str(error)
            return result

    # helper to find registrar from RDAP entities
    def find_registrar(self, entities):
        if not entities:
            return None

        for entity in entities:
            roles = entity.get("roles", [])

            if "registrar" in roles:
                vcard_array = entity.get("vcardArray", [])

                if len(vcard_array) > 1:
                    for field in vcard_array[1]:
                        if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                            return field[3]

                if entity.get("handle"):
                    return entity["handle"]

            nested = entity.get("entities")
            if nested:
                found = self.find_registrar(nested)
                if found:
                    return found

        return None


# ----------------------------------------
# DNS RECORDS
# ----------------------------------------

class DnsChecker:
    async def run(self, domain):
        records = {}

        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

        for record_type in record_types:
            try:
                answers = await resolver.resolve(domain, record_type)
                values = []

                for rdata in answers:
                    if record_type == "MX":
                        values.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
                    elif record_type == "SOA":
                        values.append(
                            f"mname={rdata.mname.to_text().rstrip('.')} "
                            f"rname={rdata.rname.to_text().rstrip('.')} "
                            f"serial={rdata.serial}"
                        )
                    else:
                        values.append(rdata.to_text().rstrip("."))

                if values:
                    records[record_type] = sorted(set(values))

            except Exception:
                # record may not exist, so ignore error
                pass

        return records


# ----------------------------------------
# SUBDOMAIN TAKEOVER CHECK
# ----------------------------------------

class TakeoverChecker:
    FINGERPRINTS = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "amazonaws.com": "AWS S3",
        "azurewebsites.net": "Azure Web Apps",
        "cloudapp.net": "Azure Cloud App",
        "netlify.app": "Netlify",
        "netlify.com": "Netlify",
        "vercel.app": "Vercel",
        "ghost.io": "Ghost",
        "shopify.com": "Shopify",
        "unbouncepages.com": "Unbounce",
        "zendesk.com": "Zendesk",
        "freshdesk.com": "Freshdesk",
        "tumblr.com": "Tumblr",
        "bitbucket.io": "Bitbucket",
        "wordpress.com": "WordPress.com",
        "pantheonsite.io": "Pantheon",
        "flywheelsites.com": "Flywheel"
    }

    def __init__(self):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    async def check(self, host, semaphore):
        async with semaphore:
            if is_ip(host):
                return None

            a_exists = True
            cname = None

            # check A record
            try:
                await self.resolver.resolve(host, "A")
            except Exception:
                a_exists = False

            # check CNAME record
            try:
                answers = await self.resolver.resolve(host, "CNAME")
                cname = str(answers[0].target).rstrip(".")
            except Exception:
                pass

            if not cname:
                return None

            # match CNAME with known takeover services
            for fingerprint, service in self.FINGERPRINTS.items():
                if fingerprint in cname.lower():
                    if not a_exists:
                        status = "Dangling CNAME"
                    else:
                        status = "CNAME points to third-party service"

                    return {
                        "subdomain": host,
                        "cname": cname,
                        "service": service,
                        "status": status
                    }

            return None


# ----------------------------------------
# CVE MAPPER
# ----------------------------------------

class CveChecker:
    PATTERNS = [
        (r"Apache/([\d.]+)", "Apache"),
        (r"nginx/([\d.]+)", "nginx"),
        (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS"),
        (r"LiteSpeed/([\d.]+)", "LiteSpeed"),
        (r"openresty/([\d.]+)", "OpenResty"),
        (r"PHP/([\d.]+)", "PHP"),
        (r"OpenSSH[_-]?([\w.]+)", "OpenSSH"),
        (r"vsftpd/([\d.]+)", "vsftpd"),
        (r"ProFTPD/([\d.]+)", "ProFTPD")
    ]

    def __init__(self, session):
        self.session = session
        self.cache = {}
        self.queries = 0
        self.max_queries = 20
        self.delay = 6.0
        self.blocked = False
        self.api_key = os.environ.get("NVD_API_KEY")

    # find product and version from banner/header
    def find_products(self, text):
        if not text:
            return []

        products = []
        seen = set()

        for pattern, product_name in self.PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)

            if match:
                version = match.group(1)

                if not version:
                    continue

                search_query = f"{product_name} {version}".strip()
                key = (product_name.lower(), version.lower())

                if key in seen:
                    continue

                seen.add(key)

                products.append({
                    "product": product_name,
                    "version": version,
                    "search": search_query
                })

        return products

    # query NVD API
    async def find_cves(self, search_query):
        key = search_query.lower()

        if key in self.cache:
            return self.cache[key]

        if self.blocked or self.queries >= self.max_queries:
            return []

        try:
            if self.queries > 0:
                await asyncio.sleep(self.delay)

            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": search_query,
                "resultsPerPage": 5
            }

            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with self.session.get(url, params=params, timeout=20, headers=headers) as response:
                self.queries += 1

                if response.status == 403:
                    self.blocked = True
                    console.print("[yellow]NVD API blocked the request. CVE mapping limited.[/yellow]")
                    return []

                if response.status != 200:
                    return []

                text_data = await response.text()
                data = json.loads(text_data)

                cve_list = []

                for item in data.get("vulnerabilities", []):
                    cve_id = item.get("cve", {}).get("id")
                    if cve_id:
                        cve_list.append(cve_id)

                cve_list = cve_list[:5]
                self.cache[key] = cve_list

                return cve_list

        except Exception:
            return []


# ----------------------------------------
# SUBDOMAIN FINDER
# ----------------------------------------

class SubdomainFinder:
    def __init__(self, session, domain, use_external=False, sublist3r_path=None):
        self.session = session
        self.domain = domain.lower()
        self.use_external = use_external
        self.sublist3r_path = sublist3r_path
        self.wordlist = SUBDOMAIN_WORDS
        self.source_map = {}

    # clean and validate subdomain
    def clean_subdomain(self, value):
        if not value:
            return None

        value = str(value).strip().lower().rstrip(".")
        value = value.replace("*.", "")

        if value.startswith("."):
            value = value[1:]

        if value == self.domain:
            return None

        if value.endswith("." + self.domain):
            return value

        return None

    # add subdomains to source map
    def add_result(self, source, values):
        valid_subs = set()

        for value in values:
            subdomain = self.clean_subdomain(value)

            if subdomain:
                valid_subs.add(subdomain)

                if subdomain not in self.source_map:
                    self.source_map[subdomain] = set()

                self.source_map[subdomain].add(source)

        return valid_subs

    # add URLs by extracting hostname
    def add_urls(self, source, urls):
        hosts = []

        for url in urls:
            if not url:
                continue

            if "://" not in url:
                url = "http://" + url

            try:
                hostname = urlparse(url).hostname
                if hostname:
                    hosts.append(hostname)
            except Exception:
                continue

        return self.add_result(source, hosts)

    # simple JSON request helper
    async def fetch_json(self, url, timeout=20):
        try:
            async with self.session.get(url, timeout=timeout) as response:
                if response.status != 200:
                    return None

                text_data = await response.text()
                return json.loads(text_data)

        except Exception:
            return None

    # simple text request helper
    async def fetch_text(self, url, timeout=20):
        try:
            async with self.session.get(url, timeout=timeout) as response:
                if response.status != 200:
                    return None

                return await response.text()

        except Exception:
            return None

    # crt.sh source
    async def source_crtsh(self):
        data = await self.fetch_json(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=40)

        if not data:
            return set()

        names = []

        for cert in data:
            names.extend(cert.get("name_value", "").split("\n"))

        return self.add_result("crt.sh", names)

    # wayback source
    async def source_wayback(self):
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{self.domain}"
            f"&output=json&fl=original&collapse=urlkey&limit=1000"
        )

        data = await self.fetch_json(url, timeout=25)

        if not data:
            return set()

        urls = []

        if isinstance(data, list):
            for row in data:
                if isinstance(row, list) and row:
                    value = row[0]
                elif isinstance(row, str):
                    value = row
                else:
                    continue

                if value.lower() in ["original", "urlkey"]:
                    continue

                urls.append(value)

        return self.add_urls("wayback", urls)

    # AlienVault source
    async def source_alienvault(self):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        data = await self.fetch_json(url)

        if not data:
            return set()

        hostnames = []

        for record in data.get("passive_dns", []):
            hostname = record.get("hostname")
            if hostname:
                hostnames.append(hostname)

        return self.add_result("alienvault", hostnames)

    # ThreatMiner source
    async def source_threatminer(self):
        url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
        data = await self.fetch_json(url)

        if not data:
            return set()

        return self.add_result("threatminer", data.get("results", []))

    # HackerTarget source
    async def source_hackertarget(self):
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        text = await self.fetch_text(url)

        if not text:
            return set()

        hostnames = []

        for line in text.splitlines():
            line = line.strip()

            if not line or line.lower().startswith("error"):
                continue

            hostnames.append(line.split(",")[0])

        return self.add_result("hackertarget", hostnames)

    # CertSpotter source
    async def source_certspotter(self):
        url = (
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={self.domain}&include_subdomains=true&expand=dns_names"
        )

        data = await self.fetch_json(url)

        if not isinstance(data, list):
            return set()

        dns_names = []

        for issuance in data:
            dns_names.extend(issuance.get("dns_names", []))

        return self.add_result("certspotter", dns_names)

    # run all passive sources
    async def passive_enum(self):
        console.print(f"[cyan][*] Running passive subdomain enumeration for {self.domain}...[/cyan]")

        tasks = [
            self.source_crtsh(),
            self.source_wayback(),
            self.source_alienvault(),
            self.source_threatminer(),
            self.source_hackertarget(),
            self.source_certspotter()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        combined = set()

        for result in results:
            if isinstance(result, set):
                combined.update(result)

        console.print(f"[cyan][+] Found {len(combined)} passive subdomains.[/cyan]")
        return combined

    # run external tools if installed
    async def external_enum(self):
        if not self.use_external:
            return set()

        console.print("[cyan][*] Checking external subdomain tools...[/cyan]")

        jobs = []

        if shutil.which("subfinder"):
            jobs.append(("subfinder", ["subfinder", "-d", self.domain, "-silent"], None))

        if shutil.which("assetfinder"):
            jobs.append(("assetfinder", ["assetfinder", "--subs-only", self.domain], None))

        if shutil.which("amass"):
            jobs.append(("amass", ["amass", "enum", "-passive", "-d", self.domain], None))

        sublist3r_output = None
        sublist3r_cmd = None

        if self.sublist3r_path and os.path.isfile(self.sublist3r_path):
            sublist3r_output = Path(tempfile.gettempdir()) / f"seeker_sublist3r_{self.domain.replace('.', '_')}.txt"
            sublist3r_cmd = [
                sys.executable,
                self.sublist3r_path,
                "-d",
                self.domain,
                "-o",
                str(sublist3r_output)
            ]

        elif shutil.which("sublist3r"):
            sublist3r_output = Path(tempfile.gettempdir()) / f"seeker_sublist3r_{self.domain.replace('.', '_')}.txt"
            sublist3r_cmd = [
                "sublist3r",
                "-d",
                self.domain,
                "-o",
                str(sublist3r_output)
            ]

        if sublist3r_cmd:
            jobs.append(("sublist3r", sublist3r_cmd, sublist3r_output))

        if not jobs:
            console.print("[yellow]No external subdomain tools found.[/yellow]")
            return set()

        found = set()

        for tool_name, command, output_file in jobs:
            console.print(f"[cyan][*] Running {tool_name}...[/cyan]")
            result = await self.run_external_tool(tool_name, command, output_file)
            found.update(result)

        return found

    # helper to run external command
    async def run_external_tool(self, tool_name, command, output_file=None):
        process = None

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180)

            lines = []

            if output_file and os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8", errors="ignore") as file:
                    lines = file.read().splitlines()

                try:
                    os.remove(output_file)
                except Exception:
                    pass
            else:
                lines = stdout.decode("utf-8", errors="ignore").splitlines()

            return self.add_result(tool_name, lines)

        except asyncio.TimeoutError:
            if process:
                try:
                    process.kill()
                except Exception:
                    pass

            console.print(f"[yellow]{tool_name} timed out.[/yellow]")
            return set()

        except Exception as error:
            console.print(f"[yellow]{tool_name} failed: {error}[/yellow]")
            return set()

    # active DNS brute force
    async def brute_force(self, subdomains):
        console.print(f"[cyan][*] Running active DNS brute-force for {self.domain}...[/cyan]")

        if not self.wordlist:
            return subdomains

        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

        async def check_word(word):
            full_domain = f"{word}.{self.domain}"

            try:
                answers = await resolver.resolve(full_domain, "A")
                if answers:
                    return full_domain
            except Exception:
                pass

            return None

        tasks = []

        for word in self.wordlist:
            tasks.append(check_word(word))

        results = await asyncio.gather(*tasks)

        new_subs = set()

        for result in results:
            if result:
                new_subs.update(self.add_result("active_dns", [result]))

        subdomains.update(new_subs)
        return subdomains


# ----------------------------------------
# PORT SCANNER WITH RETRY
# ----------------------------------------

class PortScanner:
    def __init__(self, ports):
        self.ports = ports

    async def scan(self, host, semaphore):
        open_ports = []

        async def check_port(port):
            async with semaphore:
                # try 2 times
                for attempt in range(2):
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port),
                            timeout=2.5
                        )

                        writer.close()
                        await writer.wait_closed()

                        return port

                    except Exception:
                        # small wait before retry
                        if attempt == 0:
                            await asyncio.sleep(0.5)

                return None

        tasks = []

        for port in self.ports:
            tasks.append(check_port(port))

        results = await asyncio.gather(*tasks)

        for port in results:
            if port is not None:
                open_ports.append(port)

        return open_ports


# ----------------------------------------
# BANNER GRABBING
# ----------------------------------------

class BannerGrabber:
    HTTP_PORTS = {80, 8080, 8000, 8443}
    TLS_PORTS = {443, 8443}

    async def grab(self, host, port):
        try:
            ssl_context = None

            if port in self.TLS_PORTS:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_context),
                timeout=4
            )

            # for HTTP ports, send simple HEAD request
            if port in self.HTTP_PORTS or port in self.TLS_PORTS:
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                writer.write(request)
                await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=4)

            writer.close()

            try:
                await writer.wait_closed()
            except Exception:
                pass

            banner = data.decode("utf-8", errors="ignore").strip()
            banner = banner.replace("\x00", "")

            if banner:
                return banner[:1000]

            return None

        except Exception:
            return None


# ----------------------------------------
# WEB FINGERPRINT / WAF / TECH / HEADERS
# ----------------------------------------

class WebChecker:
    WAF_SIGNATURES = {
        "cloudflare": "Cloudflare",
        "sucuri": "Sucuri",
        "akamai": "Akamai",
        "imperva": "Imperva/Incapsula",
        "incapsula": "Imperva/Incapsula",
        "f5-bigip": "F5 BIG-IP",
        "bigip": "F5 BIG-IP",
        "barracuda": "Barracuda",
        "awselb": "AWS ELB/WAF",
        "cloudfront": "CloudFront"
    }

    WAF_BLOCK_WORDS = [
        "blocked", "forbidden", "security", "cloudflare", "attention", "waf",
        "invalid", "rejected", "access denied", "not acceptable", "request rejected"
    ]

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    TECH_SIGNATURES = [
        {"name": "WordPress", "html": ["wp-content", "wp-includes"]},
        {"name": "Drupal", "html": ["drupal.settings", "/sites/default/files"]},
        {"name": "Joomla", "html": ["joomla", "media/jui"]},
        {"name": "Shopify", "html": ["cdn.shopify.com", "shopify.theme"]},
        {"name": "React", "html": ["react-dom", "react.production", "__react"]},
        {"name": "Vue.js", "html": ["vue.min.js", "v-app", "vue@next"]},
        {"name": "Angular", "html": ["ng-version", "angular.min.js"]},
        {"name": "Next.js", "html": ["__next_data__", "/_next/"]},
        {"name": "Bootstrap", "html": ["bootstrap.min.css", "bootstrap.bundle.min.js"]},
        {"name": "jQuery", "html": ["jquery.min.js"]}
    ]

    def __init__(self, session, waf_enabled=True, security_enabled=True, tech_enabled=True):
        self.session = session
        self.waf_enabled = waf_enabled
        self.security_enabled = security_enabled
        self.tech_enabled = tech_enabled

    # check WAF from headers
    def detect_waf(self, headers):
        for header, value in headers.items():
            h = header.lower()
            v = str(value).lower()

            if h in ["cf-ray", "cf-cache-status"]:
                return "Cloudflare"

            if h.startswith("x-sucuri"):
                return "Sucuri"

            if h == "x-akamai-transformed":
                return "Akamai"

            if h in ["x-iinfo", "x-cdn"]:
                if "incapsula" in v or "imperva" in v:
                    return "Imperva/Incapsula"

            if h == "server":
                for signature, name in self.WAF_SIGNATURES.items():
                    if signature in v:
                        return name

            if h == "set-cookie":
                if "__cf_bm" in v:
                    return "Cloudflare"

                if "incap_ses" in v or "visid_incap" in v:
                    return "Imperva/Incapsula"

                if "sucuri" in v:
                    return "Sucuri"

        return "None"

    # small payload test for behavioral WAF detection
    async def behavioral_waf_check(self, base_url):
        payload_url = base_url.rstrip("/") + "/?id=1%27%20OR%20%271%27=%271"

        try:
            async with self.session.get(payload_url, timeout=6, allow_redirects=False) as response:
                header_waf = self.detect_waf(response.headers)

                if header_waf != "None":
                    return header_waf

                text = await response.text()
                low_text = text.lower()

                if response.status in [403, 406, 429, 501, 503]:
                    if any(word in low_text for word in self.WAF_BLOCK_WORDS):
                        return "Possible WAF (behavioral)"

        except Exception:
            pass

        return "None"

    # check missing security headers
    def check_security_headers(self, headers):
        header_names = {header.lower() for header in headers.keys()}

        missing = []
        present = []

        for header in self.SECURITY_HEADERS:
            if header.lower() in header_names:
                present.append(header)
            else:
                missing.append(header)

        return {
            "missing": missing,
            "present": present
        }

    # detect technologies from headers, cookies and HTML
    def detect_tech(self, headers, html):
        technologies = set()

        lower_headers = {header.lower(): str(value).lower() for header, value in headers.items()}

        server = lower_headers.get("server", "")
        powered_by = lower_headers.get("x-powered-by", "")

        try:
            cookie_text = " ".join(headers.getall("Set-Cookie", [])).lower()
        except Exception:
            cookie_text = lower_headers.get("set-cookie", "")

        if "nginx" in server:
            technologies.add("Nginx")

        if "apache" in server:
            technologies.add("Apache")

        if "microsoft-iis" in server or "iis" in server:
            technologies.add("Microsoft IIS")

        if "cloudflare" in server or "cf-ray" in lower_headers:
            technologies.add("Cloudflare")

        if "akamai" in server or "x-akamai-transformed" in lower_headers:
            technologies.add("Akamai")

        if "php" in powered_by or "php" in server:
            technologies.add("PHP")

        if "asp.net" in powered_by or "x-aspnet-version" in lower_headers:
            technologies.add("ASP.NET")

        if "express" in powered_by:
            technologies.add("Express.js")

        if "wp_" in cookie_text:
            technologies.add("WordPress")

        if "phpsessid" in cookie_text:
            technologies.add("PHP")

        if "asp.net_sessionid" in cookie_text:
            technologies.add("ASP.NET")

        if "laravel_session" in cookie_text:
            technologies.add("Laravel")

        if "connect.sid" in cookie_text:
            technologies.add("Express.js")

        if "jsessionid" in cookie_text:
            technologies.add("Java Servlet/JSP")

        if html:
            low_html = html.lower()

            for signature in self.TECH_SIGNATURES:
                for needle in signature["html"]:
                    if needle in low_html:
                        technologies.add(signature["name"])

        return sorted(list(technologies))

    # main fingerprint function
    async def fingerprint(self, host, port):
        if port in [443, 8443]:
            scheme = "https"
        else:
            scheme = "http"

        url = f"{scheme}://{host}:{port}"

        info = {
            "host": host,
            "port": port,
            "url": url,
            "title": "",
            "server": "Unknown",
            "waf": "Disabled" if not self.waf_enabled else "Unknown",
            "status_code": 0,
            "security_headers": {},
            "technologies": []
        }

        try:
            async with self.session.get(url, timeout=6, allow_redirects=True) as response:
                info["status_code"] = response.status
                info["server"] = response.headers.get("Server", "Unknown")

                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")

                if soup.title and soup.title.string:
                    info["title"] = soup.title.string.strip()[:100]
                else:
                    info["title"] = "No Title"

                if self.security_enabled:
                    info["security_headers"] = self.check_security_headers(response.headers)

                if self.tech_enabled:
                    info["technologies"] = self.detect_tech(response.headers, html)

                if self.waf_enabled:
                    info["waf"] = self.detect_waf(response.headers)

                    if info["waf"] == "None":
                        info["waf"] = await self.behavioral_waf_check(url)

        except Exception:
            pass

        return info


# ----------------------------------------
# DIRECTORY FUZZER
# ----------------------------------------

class DirFuzzer:
    def __init__(self, session, wordlist_path=None):
        self.session = session
        self.wordlist = load_wordlist(wordlist_path, DIRECTORY_WORDS)

    async def fuzz(self, base_url, semaphore):
        base_url = base_url.rstrip("/")

        found = []
        seen = set()

        async def check_path(path):
            path = path.strip()

            if not path or path.startswith("#") or path.lower().startswith("http"):
                return None

            path = path.lstrip("/")

            if not path or " " in path:
                return None

            url = f"{base_url}/{path}"

            async with semaphore:
                try:
                    async with self.session.get(url, timeout=5, allow_redirects=False) as response:
                        if response.status != 404:
                            return {
                                "url": url,
                                "status": response.status
                            }
                except Exception:
                    return None

        tasks = []

        for path in self.wordlist:
            tasks.append(check_path(path))

        results = await asyncio.gather(*tasks)

        for result in results:
            if result and result["url"] not in seen:
                seen.add(result["url"])
                found.append(result)

        return found


# ----------------------------------------
# MAIN APPLICATION
# ----------------------------------------

class seekerApp:
    def __init__(self, targets, output_dir, output_format, wordlist, features, sublist3r_path, base_filename):
        self.targets = targets
        self.output_dir = output_dir
        self.output_format = output_format
        self.wordlist = wordlist
        self.features = features
        self.sublist3r_path = sublist3r_path
        self.base_filename = base_filename

        self.results = {
            "tool": "seeker",
            "scan_time": datetime.now().isoformat(),
            "features": self.features,
            "targets": {}
        }

    async def start(self):
        port_sem = asyncio.Semaphore(PORT_LIMIT)
        dir_sem = asyncio.Semaphore(DIR_LIMIT)

        # ssl=False avoids certificate errors for recon
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "seeker/1.0"}) as session:

            # create objects only if feature is enabled
            dir_fuzzer = DirFuzzer(session, self.wordlist) if self.features["dir_fuzz"] else None

            web_checker = WebChecker(
                session,
                waf_enabled=self.features["waf_detection"],
                security_enabled=self.features["security_headers"],
                tech_enabled=self.features["tech_detection"]
            ) if self.features["web_fingerprint"] else None

            port_scanner = PortScanner(PORT_LIST) if self.features["port_scan"] else None
            dns_checker = DnsChecker() if self.features["dns_footprint"] else None
            banner_grabber = BannerGrabber() if self.features["banner_grab"] else None
            whois_checker = WhoisChecker() if self.features["whois_lookup"] else None
            cve_checker = CveChecker(session) if self.features["cve_mapping"] else None

            for target in self.targets:
                console.print(f"\n[bold green]=== Scanning Target: {target} ===[/bold green]")

                target_result = {
                    "subdomains": [],
                    "subdomain_sources": {},
                    "dns_records": {},
                    "whois": {},
                    "takeovers": [],
                    "open_ports": [],
                    "banners": [],
                    "cve_findings": [],
                    "web_data": []
                }

                # WHOIS
                if self.features["whois_lookup"] and whois_checker:
                    console.print("[cyan][*] Running WHOIS/RDAP lookup...[/cyan]")
                    target_result["whois"] = await whois_checker.run(session, target)

                # DNS
                if self.features["dns_footprint"] and dns_checker and not is_ip(target):
                    console.print("[cyan][*] Running DNS footprinting...[/cyan]")
                    target_result["dns_records"] = await dns_checker.run(target)

                # Subdomains
                subdomains = set()
                source_map = {}

                subdomain_enabled = (
                    self.features["subdomain_passive"]
                    or self.features["subdomain_external"]
                    or self.features["subdomain_active"]
                )

                if not is_ip(target) and subdomain_enabled:
                    finder = SubdomainFinder(
                        session,
                        target,
                        use_external=self.features["subdomain_external"],
                        sublist3r_path=self.sublist3r_path
                    )

                    if self.features["subdomain_passive"]:
                        subdomains.update(await finder.passive_enum())

                    if self.features["subdomain_external"]:
                        subdomains.update(await finder.external_enum())

                    if self.features["subdomain_active"]:
                        subdomains = await finder.brute_force(subdomains)

                    # convert sets to lists for JSON
                    source_map = {
                        sub: sorted(list(sources))
                        for sub, sources in finder.source_map.items()
                    }

                target_result["subdomains"] = sorted(list(subdomains))
                target_result["subdomain_sources"] = source_map

                all_hosts = list(dict.fromkeys([target] + sorted(list(subdomains))))

                # Takeover detection
                if self.features["takeover_detection"] and not is_ip(target):
                    console.print("[cyan][*] Checking for subdomain takeover...[/cyan]")

                    takeover_checker = TakeoverChecker()
                    takeover_sem = asyncio.Semaphore(20)

                    takeover_hosts = [host for host in all_hosts if not is_ip(host)]

                    tasks = []
                    for host in takeover_hosts:
                        tasks.append(takeover_checker.check(host, takeover_sem))

                    takeover_results = await asyncio.gather(*tasks, return_exceptions=True)

                    takeovers = []
                    for result in takeover_results:
                        if isinstance(result, dict):
                            takeovers.append(result)

                    target_result["takeovers"] = takeovers

                # decide scan hosts
                if self.features["port_scan"]:
                    if self.features.get("port_scan_all_hosts", True):
                        scan_hosts = all_hosts
                        console.print("[cyan][*] Port scan scope: main target + subdomains[/cyan]")
                    else:
                        scan_hosts = [target]
                        console.print("[yellow][*] Port scan scope: main target only[/yellow]")
                else:
                    scan_hosts = all_hosts

                # Port scan + banner + web
                for host in scan_hosts:
                    open_ports = []
                    web_ports = []

                    if self.features["port_scan"]:
                        console.print(f"[cyan][*] Port scanning {host}...[/cyan]")

                        open_ports = await port_scanner.scan(host, port_sem)

                        if open_ports:
                            target_result["open_ports"].append({
                                "host": host,
                                "ports": open_ports
                            })

                            if self.features["banner_grab"] and banner_grabber:
                                for port in open_ports:
                                    console.print(f"[cyan][*] Banner grabbing {host}:{port}...[/cyan]")

                                    banner = await banner_grabber.grab(host, port)

                                    if banner:
                                        target_result["banners"].append({
                                            "host": host,
                                            "port": port,
                                            "banner": banner
                                        })

                                        # CVE from banner
                                        if self.features["cve_mapping"] and cve_checker:
                                            products = cve_checker.find_products(banner)

                                            for product in products:
                                                cves = await cve_checker.find_cves(product["search"])

                                                if cves:
                                                    target_result["cve_findings"].append({
                                                        "source": "banner",
                                                        "host": host,
                                                        "port": port,
                                                        "url": "",
                                                        "product": product["product"],
                                                        "version": product["version"],
                                                        "cves": cves
                                                    })

                        web_ports = [p for p in open_ports if p in WEB_PORTS]

                    else:
                        if self.features["web_fingerprint"]:
                            web_ports = ASSUMED_WEB_PORTS

                    if not self.features["web_fingerprint"]:
                        continue

                    # web fingerprint
                    for port in web_ports:
                        console.print(f"[cyan][*] HTTP fingerprinting {host}:{port}...[/cyan]")

                        web_info = await web_checker.fingerprint(host, port)

                        # CVE from server header
                        if self.features["cve_mapping"] and cve_checker and web_info.get("server"):
                            products = cve_checker.find_products(web_info["server"])

                            for product in products:
                                cves = await cve_checker.find_cves(product["search"])

                                if cves:
                                    target_result["cve_findings"].append({
                                        "source": "http_server_header",
                                        "host": host,
                                        "port": port,
                                        "url": web_info["url"],
                                        "product": product["product"],
                                        "version": product["version"],
                                        "cves": cves
                                    })

                        if self.features["waf_detection"] and web_info["waf"] not in ["None", "Disabled", "Unknown"]:
                            console.print(
                                f"[bold red]WAF detected on {web_info['url']}:[/bold red] "
                                f"[yellow]{web_info['waf']}[/yellow]"
                            )

                        # directory fuzzing
                        if self.features["dir_fuzz"] and dir_fuzzer and web_info["status_code"] != 0:
                            console.print(f"[cyan][*] Directory fuzzing {web_info['url']}...[/cyan]")
                            web_info["hidden_dirs"] = await dir_fuzzer.fuzz(web_info["url"], dir_sem)
                        else:
                            web_info["hidden_dirs"] = []

                        target_result["web_data"].append(web_info)

                # save this target result
                self.results["targets"][target] = target_result

        self.finish_output()

    # display output on terminal
    def show_report(self):
        console.print("\n[bold magenta]=== seeker FINAL REPORT ===[/bold magenta]\n")

        if not self.results["targets"]:
            console.print("[yellow]No targets scanned.[/yellow]")
            return

        for target, data in self.results["targets"].items():
            console.print(f"[bold cyan]Target:[/bold cyan] {target}")
            console.print()

            # WHOIS
            if self.features["whois_lookup"]:
                whois_data = data.get("whois", {})
                rows = [(k, make_string(v)) for k, v in whois_data.items()]
                show_table("WHOIS / RDAP Lookup", ["Field", "Value"], rows, "No WHOIS data found.", "bold cyan")
                console.print()

            # DNS
            if self.features["dns_footprint"]:
                dns_data = data.get("dns_records", {})
                rows = [(rtype, ", ".join(values)) for rtype, values in dns_data.items()]
                show_table("DNS Footprint", ["Record Type", "Values"], rows, "No DNS records found.")
                console.print()

            # Takeover
            if self.features.get("takeover_detection"):
                takeovers = data.get("takeovers", [])
                rows = [(t["subdomain"], t["cname"], t["service"], t["status"]) for t in takeovers]
                show_table(
                    "Subdomain Takeover Detection",
                    ["Subdomain", "CNAME", "Service", "Status"],
                    rows,
                    "No takeover indicators found.",
                    "bold red"
                )
                console.print()

            # Subdomains
            subdomain_enabled = (
                self.features["subdomain_passive"]
                or self.features["subdomain_external"]
                or self.features["subdomain_active"]
            )

            if subdomain_enabled:
                rows = []

                for sub in data.get("subdomains", []):
                    sources = data.get("subdomain_sources", {}).get(sub, [])
                    source_text = ", ".join(sources[:3])

                    if len(sources) > 3:
                        source_text += f" +{len(sources) - 3}"

                    rows.append((sub, source_text))

                show_table(f"Subdomains for {target}", ["Subdomain", "Sources"], rows, "No subdomains found.")
            else:
                console.print("[yellow]Subdomain enumeration was disabled.[/yellow]")

            console.print()

            # Ports
            if self.features["port_scan"]:
                rows = []

                for item in data.get("open_ports", []):
                    rows.append((item["host"], ", ".join(map(str, item["ports"]))))

                title = "Open Ports"

                if not self.features.get("port_scan_all_hosts", True):
                    title = "Open Ports (Main Target Only)"

                show_table(title, ["Host", "Ports"], rows, "No open ports found.")
            else:
                console.print("[yellow]Port scanning was disabled.[/yellow]")

            console.print()

            # Banners
            if self.features["banner_grab"]:
                rows = []

                for banner in data.get("banners", []):
                    clean_banner = banner["banner"].replace("\r", " ").replace("\n", " | ")[:300]
                    rows.append((banner["host"], banner["port"], clean_banner))

                show_table("Banner Grabbing", ["Host", "Port", "Banner"], rows, "No banners captured.", "bold magenta")
                console.print()

            # Web fingerprint
            if self.features["web_fingerprint"]:
                rows = []

                for web in data.get("web_data", []):
                    rows.append((
                        web["url"],
                        web["status_code"],
                        web["title"],
                        web["server"],
                        web["waf"]
                    ))

                show_table(
                    "Web Fingerprinting & WAF Detection",
                    ["URL", "Status", "Title", "Server", "WAF"],
                    rows,
                    "No web services found.",
                    "bold blue"
                )
            else:
                console.print("[yellow]HTTP fingerprinting was disabled.[/yellow]")

            console.print()

            # Security headers
            if self.features.get("security_headers"):
                rows = []

                for web in data.get("web_data", []):
                    sec = web.get("security_headers")

                    if sec:
                        missing = sec.get("missing", [])
                        rows.append((web["url"], ", ".join(missing) if missing else "None"))

                show_table(
                    "Security Header Analysis",
                    ["URL", "Missing Security Headers"],
                    rows,
                    "No security header results found.",
                    "bold cyan"
                )
                console.print()

            # Technology
            if self.features.get("tech_detection"):
                rows = []

                for web in data.get("web_data", []):
                    tech = web.get("technologies")

                    if tech is not None:
                        rows.append((web["url"], ", ".join(tech) if tech else "None"))

                show_table(
                    "Technology Stack Detection",
                    ["URL", "Technologies"],
                    rows,
                    "No technology results found.",
                    "bold blue"
                )
                console.print()

            # CVE
            if self.features.get("cve_mapping"):
                rows = []

                for finding in data.get("cve_findings", []):
                    rows.append((
                        finding["source"],
                        finding["host"],
                        finding["port"],
                        finding["product"],
                        finding["version"],
                        ", ".join(finding["cves"])
                    ))

                show_table(
                    "CVE Mapping",
                    ["Source", "Host", "Port", "Product", "Version", "CVEs"],
                    rows,
                    "No CVE mappings found.",
                    "bold red"
                )
                console.print()

            # Directory fuzzing
            if self.features["dir_fuzz"]:
                rows = []

                for web in data.get("web_data", []):
                    for found_dir in web.get("hidden_dirs", []):
                        rows.append((web["host"], found_dir["url"], found_dir["status"]))

                if rows:
                    show_table(
                        "Directory Fuzzing Results",
                        ["Host", "URL", "Status"],
                        rows[:50],
                        "No directories found.",
                        "bold yellow"
                    )

                    if len(rows) > 50:
                        console.print(f"[yellow]Showing first 50 of {len(rows)} results.[/yellow]")
                else:
                    console.print("[yellow]No directories found.[/yellow]")

                console.print()

            console.print("-" * 70)
            console.print()

    # save output or show on screen
    def finish_output(self):
        if self.output_format == "screen":
            self.show_report()
            console.print("\n[bold green]✔ Display complete. No file saved.[/bold green]")
            return

        output_dir = Path(self.output_dir or "scan_results")
        output_dir.mkdir(parents=True, exist_ok=True)

        if self.output_format == "csv":
            out_path = output_dir / f"{self.base_filename}.csv"

            with open(out_path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)

                writer.writerow([
                    "Target", "Type", "Host", "Port", "URL",
                    "Title", "Server", "WAF", "Status", "Details"
                ])

                for target, data in self.results["targets"].items():

                    # WHOIS
                    if self.features["whois_lookup"] and data.get("whois"):
                        details = "; ".join(
                            f"{k}={make_string(v)}"
                            for k, v in data["whois"].items()
                        )

                        writer.writerow([
                            target, "whois", target, "", "",
                            "", "", "", "", details[:2000]
                        ])

                    # DNS
                    if self.features["dns_footprint"]:
                        for record_type, values in data.get("dns_records", {}).items():
                            writer.writerow([
                                target, "dns", target, "", "",
                                record_type, "", "", "", ";".join(values)
                            ])

                    # Subdomains
                    for sub in data.get("subdomains", []):
                        sources = data.get("subdomain_sources", {}).get(sub, [])

                        writer.writerow([
                            target, "subdomain", sub, "", "",
                            "", "", "", "", ";".join(sources)
                        ])

                    # Takeover
                    if self.features.get("takeover_detection"):
                        for takeover in data.get("takeovers", []):
                            writer.writerow([
                                target,
                                "takeover",
                                takeover["subdomain"],
                                "",
                                "",
                                "",
                                takeover["service"],
                                "",
                                "",
                                f"cname={takeover['cname']};status={takeover['status']}"
                            ])

                    # Ports
                    if self.features["port_scan"]:
                        for item in data.get("open_ports", []):
                            for port in item["ports"]:
                                writer.writerow([
                                    target, "open_port", item["host"], port, "",
                                    "", "", "", "", ""
                                ])

                    # Banners
                    if self.features["banner_grab"]:
                        for banner in data.get("banners", []):
                            clean_banner = banner["banner"].replace("\r", " ").replace("\n", " | ")

                            writer.writerow([
                                target, "banner", banner["host"], banner["port"], "",
                                "", "", "", "", clean_banner[:2000]
                            ])

                    # CVE
                    if self.features.get("cve_mapping"):
                        for finding in data.get("cve_findings", []):
                            writer.writerow([
                                target,
                                "cve",
                                finding["host"],
                                finding["port"],
                                finding.get("url", ""),
                                finding["product"],
                                finding["version"],
                                "",
                                "",
                                ";".join(finding["cves"])
                            ])

                    # Web data
                    if self.features["web_fingerprint"]:
                        for web in data.get("web_data", []):
                            writer.writerow([
                                target,
                                "web",
                                web["host"],
                                web["port"],
                                web["url"],
                                web["title"],
                                web["server"],
                                web["waf"],
                                web["status_code"],
                                ""
                            ])

                            # security headers
                            if self.features.get("security_headers") and web.get("security_headers"):
                                missing = web["security_headers"].get("missing", [])

                                writer.writerow([
                                    target,
                                    "security_header",
                                    web["host"],
                                    web["port"],
                                    web["url"],
                                    "",
                                    "",
                                    "",
                                    "",
                                    "missing=" + ";".join(missing)
                                ])

                            # technologies
                            if self.features.get("tech_detection") and web.get("technologies") is not None:
                                writer.writerow([
                                    target,
                                    "technology",
                                    web["host"],
                                    web["port"],
                                    web["url"],
                                    "",
                                    "",
                                    "",
                                    "",
                                    ";".join(web["technologies"])
                                ])

                            # directories
                            if self.features["dir_fuzz"]:
                                for found_dir in web.get("hidden_dirs", []):
                                    writer.writerow([
                                        target,
                                        "dir",
                                        web["host"],
                                        web["port"],
                                        found_dir["url"],
                                        "",
                                        "",
                                        "",
                                        found_dir["status"],
                                        ""
                                    ])

        else:
            out_path = output_dir / f"{self.base_filename}.json"

            with open(out_path, "w", encoding="utf-8") as file:
                json.dump(self.results, file, indent=4)

        console.print(f"\n[bold green]✔ Scan complete! Results saved to:[/bold green] [cyan]{out_path}[/cyan]")


# ----------------------------------------
# INTERACTIVE MODE
# ----------------------------------------

def start_interactive_mode(args):
    console.print("[bold cyan]>> seeker Interactive Mode Started[/bold cyan]\n")

    # target input
    if args.target:
        target = args.target
        console.print(f"[bold cyan]Target:[/bold cyan] {target}")
    else:
        target = console.input("[bold yellow]1. Enter target (Domain, IP, CIDR, or file): [/bold yellow]").strip()

    if not target:
        console.print("[red]Target cannot be empty. Exiting.[/red]")
        sys.exit(1)

    targets = get_targets(target)

    if not targets:
        console.print("[red]No valid targets found. Exiting.[/red]")
        sys.exit(1)

    console.print(f"[bold]Parsed {len(targets)} target(s).[/bold]")

    # output format
    if args.output:
        output_format = args.output.lower()

        if output_format not in ["json", "csv", "screen"]:
            output_format = "screen"

        console.print(f"[bold cyan]Output format:[/bold cyan] {output_format}")
    else:
        output_raw = console.input("[bold yellow]2. Enter output format (json/csv/screen) [screen]: [/bold yellow]").strip().lower()

        if output_raw in ["json", "csv"]:
            output_format = output_raw
        else:
            output_format = "screen"

    console.print("\n[bold cyan]Feature Selection[/bold cyan]")

    features = {}
    sublist3r_path = None

    # check if target has domain names
    has_domain = any(not is_ip(t) for t in targets)

    # subdomain features
    if has_domain:
        enable_sub = ask_yes_no("Enable subdomain enumeration?", True)

        if enable_sub:
            features["subdomain_passive"] = ask_yes_no("Enable passive subdomain enumeration?", True)
            features["subdomain_external"] = ask_yes_no("Enable external subdomain tools if installed?", False)

            if features["subdomain_external"]:
                if args.sublist3r:
                    sublist3r_path = args.sublist3r
                    console.print(f"[bold cyan]Using Sublist3R path:[/bold cyan] {sublist3r_path}")
                else:
                    sublist3r_path = console.input(
                        "[bold yellow]Optional path to Sublist3R.py (leave blank to skip): [/bold yellow]"
                    ).strip() or None

            features["subdomain_active"] = ask_yes_no("Enable active DNS brute-force?", True)
        else:
            features["subdomain_passive"] = False
            features["subdomain_external"] = False
            features["subdomain_active"] = False
    else:
        console.print("[yellow]Target appears IP/CIDR only. Subdomain enumeration disabled.[/yellow]")
        features["subdomain_passive"] = False
        features["subdomain_external"] = False
        features["subdomain_active"] = False

    # port scan features
    features["port_scan"] = ask_yes_no("Enable port scanning?", True)

    if features["port_scan"]:
        features["port_scan_all_hosts"] = ask_yes_no(
            "Port scan ALL discovered subdomains? Choose 'n' for main target only",
            True
        )
        features["banner_grab"] = ask_yes_no("Enable banner grabbing?", True)
    else:
        features["port_scan_all_hosts"] = False
        features["banner_grab"] = False

    # DNS and WHOIS
    features["dns_footprint"] = ask_yes_no("Enable DNS footprinting?", True)
    features["whois_lookup"] = ask_yes_no("Enable WHOIS/RDAP lookup?", True)

    # web features
    features["web_fingerprint"] = ask_yes_no("Enable HTTP fingerprinting?", True)

    if features["web_fingerprint"]:
        features["waf_detection"] = ask_yes_no("Enable WAF detection?", True)
        features["security_headers"] = ask_yes_no("Enable security header analysis?", True)
        features["tech_detection"] = ask_yes_no("Enable technology stack detection?", True)
        features["dir_fuzz"] = ask_yes_no("Enable directory fuzzing?", True)

        if features["dir_fuzz"]:
            if args.wordlist:
                wordlist = args.wordlist

                if not os.path.exists(wordlist):
                    console.print(f"[yellow]Wordlist not found. Using default wordlist.[/yellow]")
                    wordlist = None
                else:
                    console.print(f"[bold cyan]Using wordlist:[/bold cyan] {wordlist}")
            else:
                wordlist = console.input(
                    "[bold yellow]Enter directory wordlist path (leave blank for default): [/bold yellow]"
                ).strip()

                if wordlist and not os.path.exists(wordlist):
                    console.print("[yellow]Wordlist not found. Using default wordlist.[/yellow]")
                    wordlist = None
        else:
            wordlist = None
    else:
        features["waf_detection"] = False
        features["security_headers"] = False
        features["tech_detection"] = False
        features["dir_fuzz"] = False
        wordlist = None
        console.print("[yellow]HTTP fingerprinting disabled. Related web features will be skipped.[/yellow]")

    # CVE mapping
    if features["port_scan"] or features["web_fingerprint"]:
        features["cve_mapping"] = ask_yes_no("Enable CVE mapping from banners/server headers?", True)
    else:
        features["cve_mapping"] = False

    # takeover detection
    if has_domain:
        features["takeover_detection"] = ask_yes_no("Enable subdomain takeover detection?", True)
    else:
        features["takeover_detection"] = False

    if not features["port_scan"] and features["web_fingerprint"]:
        console.print("[yellow]Port scanning disabled. HTTP checks will try ports 80 and 443 directly.[/yellow]")

    # stop if nothing enabled
    if not any(features.values()):
        console.print("[red]No features enabled. Exiting.[/red]")
        sys.exit(0)

    return target, targets, wordlist, output_format, features, sublist3r_path


# ----------------------------------------
# MAIN FUNCTION
# ----------------------------------------

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(prog="seeker.py", description="seeker - Multi-Source Recon Tool")
    parser.add_argument("-t", "--target", help="Target domain, IP, CIDR, or file")
    parser.add_argument("--wordlist", help="Directory fuzzing wordlist path")
    parser.add_argument("--sublist3r", help="Path to Sublist3R.py")
    parser.add_argument("-o", "--output", choices=["json", "csv", "screen"], help="Output format")

    args = parser.parse_args()

    target, targets, wordlist, output_format, features, sublist3r_path = start_interactive_mode(args)

    # create safe file name
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    if os.path.isfile(target):
        safe_target = Path(target).stem
    else:
        safe_target = target.replace("/", "_").replace("\\", "_").replace(":", "_")

    safe_target = safe_target.strip(".") or "target"
    base_filename = f"seeker_{safe_target}_{run_id}"

    if output_format != "screen":
        output_dir = Path("scan_results")
        output_dir.mkdir(parents=True, exist_ok=True)

        expected_file = output_dir / f"{base_filename}.{output_format}"

        console.print(f"\n[bold green]✔ Directory ready.[/bold green]")
        console.print(f"[bold green]✔ Results will be saved to:[/bold green] [cyan]{expected_file}[/cyan]")
    else:
        output_dir = None
        console.print("\n[bold yellow]✔ Output will be displayed on screen only.[/bold yellow]")

    app = seekerApp(
        targets=targets,
        output_dir=str(output_dir) if output_dir else None,
        output_format=output_format,
        wordlist=wordlist,
        features=features,
        sublist3r_path=sublist3r_path,
        base_filename=base_filename
    )

    asyncio.run(app.start())


# entry point
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user (Ctrl+C). Exiting...[/bold red]")
        sys.exit(0)
    except Exception as error:
        console.print(f"\n[bold red]Unexpected error: {error}[/bold red]")
        sys.exit(1)
