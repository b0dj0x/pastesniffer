#!/usr/bin/env python3
"""
PasteSniffer -- Dark Web Paste Site Scraper: Leaked Emails, Combos, Keys
"""

import sys, os, json, time, argparse, re, hashlib, threading
from datetime import datetime, timezone
from urllib.parse import quote, urljoin
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    sys.exit("[!] pip install requests")
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    from rich import box
except ImportError:
    sys.exit("[!] pip install rich")

console = Console()
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ASCII = [
    "██████╗  █████╗ ███████╗████████╗███████╗██████╗ ██╗     ██╗████████╗",
    "██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║     ██║╚══██╔══╝",
    "██████╔╝███████║███████╗   ██║   █████╗  ██████╔╝██║     ██║   ██║   ",
    "██╔═══╝ ██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗██║     ██║   ██║   ",
    "██║     ██║  ██║███████║   ██║   ███████╗██║  ██║███████╗██║   ██║   ",
    "╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝   ",
]

UA = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

PASTE_SOURCES = {
    "Pastebin": {
        "search": "https://pastebin.com/search?q={query}",
        "api": "https://pastebin.com/api/api_post.php",
        "raw": "https://pastebin.com/raw/{id}",
        "recent": "https://pastebin.com/rss",
    },
    "GitHub Gist": {
        "search": "https://gist.github.com/search?q={query}",
        "api": "https://api.github.com/search/gists?q={query}&per_page=20",
        "recent": "https://gist.github.com.atom",
    },
    "GitLab Snippets": {
        "search": "https://gitlab.com/explore/snippets?search={query}",
        "api": "https://gitlab.com/api/v4/snippets?search={query}",
    },
    "Hastebin": {
        "search": "https://hastebin.com/search?q={query}",
    },
    "DPaste": {
        "search": "https://dpaste.org/search/?q={query}",
    },
    "Paste.ee": {
        "search": "https://paste.ee/search?q={query}",
        "api": "https://paste.ee/api",
    },
    "Rentry": {
        "search": "https://rentry.co/search?q={query}",
    },
    "JustPaste.it": {
        "search": "https://justpaste.it/search?q={query}",
    },
    "PasteBin.eu": {
        "search": "https://pastebin.eu/search?q={query}",
    },
    "PasteBin.pl": {
        "search": "https://pastebin.pl/search?q={query}",
    },
    "PasteBin.uk": {
        "search": "https://pastebin.uk/search?q={query}",
    },
    "PasteBin.gg": {
        "search": "https://paste.gg/search?q={query}",
    },
    "PasteBin.dev": {
        "search": "https://paste.dev/search?q={query}",
    },
    "PasteBin.rs": {
        "search": "https://paste.rs/search?q={query}",
    },
    "CodePen": {
        "search": "https://codepen.io/search/pens?q={query}",
    },
    "Paste.sr.ht": {
        "search": "https://paste.sr.ht/search?q={query}",
    },
}

DARK_WEB_PASTE = {
    "Ahmia": "https://ahmia.fi/api/v1/search/?q={query}",
    "OnionLand": "https://onionlandsearchengine.net/search?query={query}",
    "Darknet Live": "https://darknet.live/api/search?q={query}",
    "Tor Search": "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/search?q={query}",
}

BREACH_APIS = {
    "XposedOrNot": "https://api.xposedornot.com/v1/breach-analytics/{query}",
    "Hudson Rock": "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={query}",
    "EmailRep.io": "https://emailrep.io/{query}",
    "HIBP Passwords": "https://api.pwnedpasswords.com/range/{hash_prefix}",
    "BreachDirectory": "https://breachdirectory.org/api/email/{query}",
}

OSINT_LINKS = {
    "email": [
        ("Google", "https://www.google.com/search?q=%22{q}%22"),
        ("Google Dork Pastebin", "https://www.google.com/search?q=%22{q}%22+site%3Apastebin.com"),
        ("Google Dork GitHub", "https://www.google.com/search?q=%22{q}%22+site%3Agist.github.com"),
        ("DuckDuckGo", "https://duckduckgo.com/?q=%22{q}%22"),
        ("Yandex", "https://yandex.com/search/?text=%22{q}%22"),
        ("Bing", "https://www.bing.com/search?q=%22{q}%22"),
        ("Shodan", "https://www.shodan.io/search?query={q}"),
        ("Censys", "https://search.censys.io/hosts?q={q}"),
        ("VirusTotal", "https://www.virustotal.com/gui/search/{q}"),
        ("URLScan", "https://urlscan.io/search/#{q}"),
        ("GreyNoise", "https://viz.greynoise.io/query/?q={q}"),
        ("Intelligence X", "https://intelx.io/?s={q}"),
        ("DeHashed", "https://www.dehashed.com/search?query={q}"),
        ("IntelX", "https://intelx.io/?s={q}"),
        ("Have I Been Pwned", "https://haveibeenpwned.com/account/{q}"),
        ("Hunter.io", "https://hunter.io/email-verifier/{q}"),
        ("RocketReach", "https://rocketreach.co/{q}"),
        ("EmailRep", "https://emailrep.io/{q}"),
        ("BreachDirectory", "https://breachdirectory.org/"),
        ("LeakCheck", "https://leakcheck.io/"),
        ("Snusbase", "https://snusbase.com/"),
        ("Pastebin Search", "https://pastebin.com/search?q={q}"),
        ("GitHub Gist", "https://gist.github.com/search?q={q}"),
        ("GitLab Snippets", "https://gitlab.com/explore/snippets?search={q}"),
        ("Reddit", "https://www.reddit.com/search/?q=%22{q}%22"),
    ],
    "domain": [
        ("Google", "https://www.google.com/search?q=%22{q}%22"),
        ("Shodan", "https://www.shodan.io/search?query={q}"),
        ("Censys", "https://search.censys.io/hosts?q={q}"),
        ("VirusTotal", "https://www.virustotal.com/gui/domain/{q}"),
        ("URLScan", "https://urlscan.io/search/#{q}"),
        ("GreyNoise", "https://viz.greynoise.io/query/?q={q}"),
        ("OTX AlienVault", "https://otx.alienvault.com/indicator/domain/{q}"),
        ("Pulsedive", "https://pulsedive.com/search/?q={q}"),
        ("ThreatCrowd", "https://www.threatcrowd.org/domain.php?domain={q}"),
        ("Intelligence X", "https://intelx.io/?s={q}"),
        ("crt.sh", "https://crt.sh/?q={q}"),
        ("SecurityTrails", "https://securitytrails.com/domain/{q}"),
        ("DNSDumpster", "https://dnsdumpster.com/"),
        ("Robtex", "https://www.robtex.com/dns-records/{q}"),
        ("Whois", "https://who.is/whois/{q}"),
    ],
    "ip": [
        ("Google", "https://www.google.com/search?q=%22{q}%22"),
        ("Shodan", "https://www.shodan.io/host/{q}"),
        ("Censys", "https://search.censys.io/hosts/{q}"),
        ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{q}"),
        ("AbuseIPDB", "https://www.abuseipdb.com/check/{q}"),
        ("GreyNoise", "https://viz.greynoise.io/ip/{q}"),
        ("IPInfo", "https://ipinfo.io/{q}"),
        ("IPQualityScore", "https://www.ipqualityscore.com/ip-reputation/{q}"),
        ("OTX AlienVault", "https://otx.alienvault.com/indicator/ip/{q}"),
        ("Pulsedive", "https://pulsedive.com/search/?q={q}"),
        ("ThreatCrowd", "https://www.threatcrowd.org/ip.php?ip={q}"),
        ("Intelligence X", "https://intelx.io/?s={q}"),
        ("Robtex", "https://www.robtex.com/ip-lookup/{q}"),
        ("IP-API", "https://ip-api.com/json/{q}"),
    ],
}

LEAK_PATTERNS = {
    "email:password": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*[:|;\t]\s*\S+",
        "severity": "critical",
        "description": "Email:Password combos",
    },
    "email": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "severity": "high",
        "description": "Email addresses",
    },
    "password_field": {
        "pattern": r"(?i)(password|passwd|pwd|pass|secret|token|api[_-]?key)\s*[:=]\s*\S+",
        "severity": "critical",
        "description": "Password fields",
    },
    "aws_key": {
        "pattern": r"(?i)(AKIA[0-9A-Z]{16})",
        "severity": "critical",
        "description": "AWS Access Keys",
    },
    "aws_secret": {
        "pattern": r"(?i)(aws_secret_access_key|secret_key)\s*[:=]\s*[A-Za-z0-9/+=]{40}",
        "severity": "critical",
        "description": "AWS Secret Keys",
    },
    "github_token": {
        "pattern": r"ghp_[0-9a-zA-Z]{30,40}|github_pat_[0-9a-zA-Z]{70,90}",
        "severity": "critical",
        "description": "GitHub Tokens",
    },
    "gitlab_token": {
        "pattern": r"glpat-[0-9a-zA-Z\-_]{10,}",
        "severity": "critical",
        "description": "GitLab Tokens",
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z-]+",
        "severity": "critical",
        "description": "Slack Tokens",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        "severity": "critical",
        "description": "Slack Webhooks",
    },
    "google_api": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "critical",
        "description": "Google API Keys",
    },
    "stripe_key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,99}|pk_live_[0-9a-zA-Z]{24,99}|sk_test_[0-9a-zA-Z]{24,99}",
        "severity": "critical",
        "description": "Stripe API Keys",
    },
    "sendgrid": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "critical",
        "description": "SendGrid API Keys",
    },
    "twilio": {
        "pattern": r"(?i)twilio.*?['\"]?SK[0-9a-fA-F]{32}",
        "severity": "critical",
        "description": "Twilio API Keys",
    },
    "mailgun": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "description": "Mailgun API Keys",
    },
    "heroku": {
        "pattern": r"(?i)heroku.*?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "severity": "high",
        "description": "Heroku API Keys",
    },
    "private_key": {
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private Keys",
    },
    "credit_card": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "critical",
        "description": "Credit Card Numbers",
    },
    "ssn": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "severity": "critical",
        "description": "Social Security Numbers",
    },
    "ip_address": {
        "pattern": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "severity": "medium",
        "description": "IP Addresses",
    },
    "onion_address": {
        "pattern": r"[a-z2-7]{16,56}\.onion",
        "severity": "medium",
        "description": ".onion Addresses",
    },
    "crypto_btc": {
        "pattern": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "severity": "medium",
        "description": "Bitcoin Addresses",
    },
    "crypto_eth": {
        "pattern": r"\b0x[a-fA-F0-9]{40}\b",
        "severity": "medium",
        "description": "Ethereum Addresses",
    },
    "crypto_xmr": {
        "pattern": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
        "severity": "medium",
        "description": "Monero Addresses",
    },
    "hash_md5": {
        "pattern": r"\b[a-fA-F0-9]{32}\b",
        "severity": "high",
        "description": "MD5 Hashes",
    },
    "hash_sha1": {
        "pattern": r"\b[a-fA-F0-9]{40}\b",
        "severity": "high",
        "description": "SHA1 Hashes",
    },
    "hash_sha256": {
        "pattern": r"\b[a-fA-F0-9]{64}\b",
        "severity": "high",
        "description": "SHA256 Hashes",
    },
    "database_dump": {
        "pattern": r"(?i)(INSERT\s+INTO|CREATE\s+TABLE|DROP\s+TABLE|mysql|postgresql|mongodb|sqlite)",
        "severity": "high",
        "description": "Database Dump Markers",
    },
    "username_list": {
        "pattern": r"(?i)(username|user|login|nick)\s*[:=]\s*\S+",
        "severity": "high",
        "description": "Username Fields",
    },
}

DISPOSABLE_DOMAINS = {
    "tempmail.com", "throwaway.email", "guerrillamail.com", "mailinator.com",
    "yopmail.com", "guerrillamailblock.com", "sharklasers.com", "grr.la",
    "dispostable.com", "tempail.com", "tempr.email", "temp-mail.org",
    "fakeinbox.com", "trashmail.com", "maildrop.cc", "mailnesia.com",
    "temp-mail.io", "burnermail.io", "10minutemail.com", "discard.email",
}


def banner():
    console.clear()
    for l in ASCII:
        console.print(f"[bold yellow]{l}[/bold yellow]", justify="center")
    console.print()
    console.print("[bold white]  Dark Web Paste Site Scraper -- Leaked Emails, Combos, Keys[/bold white]", justify="center")
    console.print("[bold red]  Made by b0dj0x · https://b0dj0x.cc[/bold red]\n")


class PasteSniffer:
    def __init__(self, timeout=10, max_threads=5):
        self.timeout = timeout
        self.max_threads = max_threads
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.s.verify = False
        self.tor_session = None
        self.results = {
            "emails": [],
            "combos": [],
            "api_keys": [],
            "passwords": [],
            "private_keys": [],
            "hashes": [],
            "ips": [],
            "onions": [],
            "crypto_addresses": [],
            "credit_cards": [],
            "ssns": [],
            "databases": [],
            "raw_matches": [],
        }
        self.seen = set()
        self.stats = defaultdict(int)

    def _get_tor_session(self):
        if self.tor_session is None:
            self.tor_session = requests.Session()
            self.tor_session.proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            }
            self.tor_session.headers["User-Agent"] = UA
            self.tor_session.verify = False
        return self.tor_session

    def _dedupe(self, value, category):
        key = f"{category}:{value.lower().strip()}"
        if key in self.seen:
            return False
        self.seen.add(key)
        return True

    def add_finding(self, category, value, source="", context=""):
        value = value.strip()
        if not value or len(value) < 3:
            return
        if not self._dedupe(value, category):
            return
        finding = {
            "value": value,
            "source": source,
            "context": context[:200] if context else "",
            "timestamp": datetime.now().isoformat(),
        }
        self.results[category].append(finding)
        self.stats[category] += 1

    def extract_leaks(self, content, source="Unknown"):
        for cat, info in LEAK_PATTERNS.items():
            matches = re.findall(info["pattern"], content)
            for match in matches:
                match = match.strip() if isinstance(match, str) else match[0] if match else ""
                if not match:
                    continue
                mapped = self._map_pattern_to_category(cat)
                if mapped:
                    context_start = max(0, content.find(match[:30]) - 50)
                    context = content[context_start:context_start + 200] if context_start >= 0 else ""
                    self.add_finding(mapped, match, source=source, context=context)

    def _map_pattern_to_category(self, pattern_name):
        mapping = {
            "email:password": "combos",
            "email": "emails",
            "password_field": "passwords",
            "aws_key": "api_keys",
            "aws_secret": "api_keys",
            "github_token": "api_keys",
            "gitlab_token": "api_keys",
            "slack_token": "api_keys",
            "slack_webhook": "api_keys",
            "google_api": "api_keys",
            "stripe_key": "api_keys",
            "sendgrid": "api_keys",
            "twilio": "api_keys",
            "mailgun": "api_keys",
            "heroku": "api_keys",
            "private_key": "private_keys",
            "credit_card": "credit_cards",
            "ssn": "ssns",
            "ip_address": "ips",
            "onion_address": "onions",
            "crypto_btc": "crypto_addresses",
            "crypto_eth": "crypto_addresses",
            "crypto_xmr": "crypto_addresses",
            "hash_md5": "hashes",
            "hash_sha1": "hashes",
            "hash_sha256": "hashes",
            "database_dump": "databases",
            "username_list": "emails",
        }
        return mapping.get(pattern_name)

    def search_pastebin(self, query):
        results = []
        url = f"https://pastebin.com/search?q={quote(query)}"
        try:
            resp = self.s.get(url, timeout=min(self.timeout, 8))
            if resp.status_code == 200:
                ids = re.findall(r'<a href="/([A-Za-z0-9]+)"', resp.text)
                unique_ids = list(dict.fromkeys(ids))[:20]
                for pid in unique_ids:
                    raw_url = f"https://pastebin.com/raw/{pid}"
                    results.append({"id": pid, "url": raw_url, "source": "Pastebin"})
                console.print(f"  [green]✓[/green] Pastebin: {len(results)} pastes found")
            else:
                console.print(f"  [dim]✗ Pastebin: HTTP {resp.status_code}[/dim]")
        except:
            console.print(f"  [dim]✗ Pastebin: Timeout[/dim]")
        return results

    def search_gist(self, query):
        results = []
        try:
            resp = self.s.get(
                f"https://api.github.com/search/gists?q={quote(query)}&per_page=20",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", [])[:20]:
                    gist_id = item.get("id", "")
                    files = item.get("files", {})
                    for fname, finfo in files.items():
                        raw_url = finfo.get("raw_url", "")
                        if raw_url:
                            results.append({
                                "id": gist_id,
                                "url": raw_url,
                                "filename": fname,
                                "source": "GitHub Gist",
                            })
                console.print(f"  [green]✓[/green] GitHub Gist: {len(results)} files found")
            else:
                console.print(f"  [dim]✗ GitHub Gist: HTTP {resp.status_code}[/dim]")
        except:
            console.print(f"  [dim]✗ GitHub Gist: Timeout[/dim]")
        return results

    def search_gitlab(self, query):
        results = []
        try:
            resp = self.s.get(
                f"https://gitlab.com/api/v4/snippets?search={quote(query)}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data[:20]:
                    sid = item.get("id", "")
                    results.append({
                        "id": str(sid),
                        "url": f"https://gitlab.com/snippets/{sid}",
                        "source": "GitLab Snippet",
                    })
                console.print(f"  [green]✓[/green] GitLab: {len(results)} snippets found")
            else:
                console.print(f"  [dim]✗ GitLab: HTTP {resp.status_code}[/dim]")
        except:
            console.print(f"  [dim]✗ GitLab: Timeout[/dim]")
        return results

    def search_dpaste(self, query):
        results = []
        try:
            resp = self.s.get(
                f"https://dpaste.org/api/?q={quote(query)}&format=json",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
                if isinstance(data, list):
                    for item in data[:10]:
                        results.append({
                            "id": item.get("id", ""),
                            "url": f"https://dpaste.org/{item.get('id', '')}/",
                            "source": "DPaste",
                        })
                console.print(f"  [green]✓[/green] DPaste: {len(results)} pastes found")
            else:
                console.print(f"  [dim]✗ DPaste: HTTP {resp.status_code}[/dim]")
        except:
            console.print(f"  [dim]✗ DPaste: Timeout[/dim]")
        return results

    def search_paste_ee(self, query):
        results = []
        try:
            resp = self.s.get(
                f"https://paste.ee/search?q={quote(query)}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                ids = re.findall(r'/p/([a-zA-Z0-9]+)', resp.text)
                unique_ids = list(dict.fromkeys(ids))[:20]
                for pid in unique_ids:
                    results.append({
                        "id": pid,
                        "url": f"https://paste.ee/p/{pid}",
                        "source": "Paste.ee",
                    })
                console.print(f"  [green]✓[/green] Paste.ee: {len(results)} pastes found")
            else:
                console.print(f"  [dim]✗ Paste.ee: HTTP {resp.status_code}[/dim]")
        except:
            console.print(f"  [dim]✗ Paste.ee: Timeout[/dim]")
        return results

    def search_rentry(self, query):
        results = []
        try:
            resp = self.s.get(
                f"https://rentry.co/api/search/{quote(query)}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
                entries = data.get("entries", data) if isinstance(data, dict) else data
                if isinstance(entries, list):
                    for item in entries[:20]:
                        slug = item.get("slug", item.get("uri", ""))
                        if slug:
                            results.append({
                                "id": slug,
                                "url": f"https://rentry.co/{slug}",
                                "source": "Rentry",
                            })
                console.print(f"  [green]✓[/green] Rentry: {len(results)} entries found")
            else:
                console.print(f"  [dim]✗ Rentry: HTTP {resp.status_code}[/dim]")
        except:
            console.print(f"  [dim]✗ Rentry: Timeout[/dim]")
        return results

    def search_ahmia(self, query):
        results = []
        try:
            resp = self._get_tor_session().get(
                f"https://ahmia.fi/api/v1/search/?q={quote(query)}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", [])[:20]:
                    results.append({
                        "title": item.get("title", "N/A"),
                        "url": item.get("url", ""),
                        "source": "Ahmia (Dark Web)",
                    })
                console.print(f"  [green]✓[/green] Ahmia: {len(results)} results")
            else:
                console.print(f"  [dim]✗ Ahmia: HTTP {resp.status_code}[/dim]")
        except:
            console.print(f"  [dim]✗ Ahmia: Timeout[/dim]")
        return results

    def search_all(self, query):
        all_results = []
        console.print(f"[bold cyan]  Searching Paste Sites...[/bold cyan]\n")
        all_results.extend(self.search_pastebin(query))
        all_results.extend(self.search_gist(query))
        all_results.extend(self.search_gitlab(query))
        all_results.extend(self.search_dpaste(query))
        all_results.extend(self.search_paste_ee(query))
        all_results.extend(self.search_rentry(query))
        try:
            all_results.extend(self.search_ahmia(query))
        except:
            pass
        return all_results

    def fetch_and_sniff(self, url, source="Unknown"):
        try:
            session = self.s
            if ".onion" in url:
                session = self._get_tor_session()
            resp = session.get(url, timeout=min(self.timeout, 10))
            if resp.status_code == 200:
                self.extract_leaks(resp.text, source=source)
                return True
        except:
            pass
        return False

    def sniff_pastes(self, query, max_pastes=20):
        console.print(f"[bold cyan]  Sniffing paste content for: {query}[/bold cyan]\n")
        all_results = self.search_all(query)
        paste_urls = []
        for r in all_results:
            url = r.get("url", "")
            source = r.get("source", "Unknown")
            if url:
                paste_urls.append((url, source))

        paste_urls = paste_urls[:max_pastes]
        console.print(f"\n[bold cyan]  Fetching and sniffing {len(paste_urls)} pastes...[/bold cyan]\n")

        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(paste_urls) or 1)) as executor:
            futures = {executor.submit(self.fetch_and_sniff, url, src): (url, src) for url, src in paste_urls}
            for future in as_completed(futures):
                url, src = futures[future]
                try:
                    success = future.result()
                    if success:
                        console.print(f"  [green]✓[/green] Sniffed: {url[:60]}")
                    else:
                        console.print(f"  [dim]✗ Failed: {url[:60]}[/dim]")
                except:
                    console.print(f"  [dim]✗ Error: {url[:60]}[/dim]")

    def breach_check(self, email):
        console.print(f"\n[bold cyan]  Breach Check: {email}[/bold cyan]\n")

        # XposedOrNot
        try:
            resp = self.s.get(f"https://api.xposedornot.com/v1/breach-analytics/{email}", timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                breaches = data.get("breaches", [])
                if breaches:
                    console.print(f"  [red]✗[/red] XposedOrNot: {len(breaches)} breaches found")
                    for b in breaches[:5]:
                        console.print(f"    [dim]• {b.get('name', b.get('breach', 'Unknown'))}[/dim]")
                else:
                    console.print(f"  [green]✓[/green] XposedOrNot: No breaches found")
        except:
            console.print(f"  [dim]✗ XposedOrNot: Timeout[/dim]")

        # Hudson Rock
        try:
            resp = self.s.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}", timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                stealers = data.get("stealers", [])
                if stealers:
                    console.print(f"  [red]✗[/red] Hudson Rock: {len(stealers)} infostealer logs found")
                else:
                    console.print(f"  [green]✓[/green] Hudson Rock: No infostealer data")
        except:
            console.print(f"  [dim]✗ Hudson Rock: Timeout[/dim]")

        # EmailRep
        try:
            resp = self.s.get(f"https://emailrep.io/{email}", timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                rep = data.get("reputation", "unknown")
                console.print(f"  [yellow]![/yellow] EmailRep.io: Reputation = {rep}")
        except:
            console.print(f"  [dim]✗ EmailRep.io: Timeout[/dim]")

    def password_check(self, password):
        console.print(f"\n[bold cyan]  Password Breach Check[/bold cyan]\n")
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        try:
            resp = self.s.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=self.timeout)
            if resp.status_code == 200:
                hashes = {}
                for line in resp.text.splitlines():
                    h, c = line.split(":")
                    hashes[h] = int(c)
                if suffix in hashes:
                    console.print(f"  [bold red]  FOUND {hashes[suffix]:,} times in breaches![/bold red]")
                else:
                    console.print(f"  [green]  Not found in known breaches[/green]")
        except:
            console.print(f"  [dim]  Connection failed[/dim]")

    def sniff_raw(self, filepath):
        console.print(f"\n[bold cyan]  Scanning Local File: {filepath}[/bold cyan]\n")
        if not os.path.exists(filepath):
            console.print(f"[red]  File not found: {filepath}[/red]")
            return
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        self.extract_leaks(content, source=os.path.basename(filepath))

    def sniff_url(self, url):
        console.print(f"\n[bold cyan]  Scanning URL: {url}[/bold cyan]\n")
        self.fetch_and_sniff(url, source=url)

    def get_osint_links(self, query, target_type="email"):
        links = OSINT_LINKS.get(target_type, OSINT_LINKS["email"])
        return [(name, url.format(q=quote(query))) for name, url in links]

    def show_findings(self):
        console.print(f"\n[bold yellow]  === PasteSniffer Findings ===[/bold yellow]\n")

        total = sum(len(v) for v in self.results.values())
        console.print(f"  [bold white]Total findings: {total}[/bold white]\n")

        if self.results["emails"]:
            table = Table(title="Leaked Emails", box=box.ROUNDED)
            table.add_column("#", style="green", width=4)
            table.add_column("Email", style="yellow", width=35)
            table.add_column("Source", style="dim", width=20)
            for i, f in enumerate(self.results["emails"][:30], 1):
                table.add_row(str(i), f["value"], f["source"][:20])
            console.print(table)
            console.print()

        if self.results["combos"]:
            table = Table(title="Email:Password Combos", box=box.ROUNDED)
            table.add_column("#", style="green", width=4)
            table.add_column("Combo", style="red", width=60)
            table.add_column("Source", style="dim", width=20)
            for i, f in enumerate(self.results["combos"][:30], 1):
                table.add_row(str(i), f["value"][:60], f["source"][:20])
            console.print(table)
            console.print()

        if self.results["api_keys"]:
            table = Table(title="Leaked API Keys / Tokens", box=box.ROUNDED)
            table.add_column("#", style="green", width=4)
            table.add_column("Key", style="red", width=60)
            table.add_column("Source", style="dim", width=20)
            for i, f in enumerate(self.results["api_keys"][:30], 1):
                table.add_row(str(i), f["value"][:60], f["source"][:20])
            console.print(table)
            console.print()

        if self.results["passwords"]:
            table = Table(title="Leaked Passwords", box=box.ROUNDED)
            table.add_column("#", style="green", width=4)
            table.add_column("Credential", style="red", width=60)
            table.add_column("Source", style="dim", width=20)
            for i, f in enumerate(self.results["passwords"][:30], 1):
                table.add_row(str(i), f["value"][:60], f["source"][:20])
            console.print(table)
            console.print()

        if self.results["private_keys"]:
            console.print(f"[bold red]  Private Keys Found ({len(self.results['private_keys'])}):[/bold red]")
            for f in self.results["private_keys"][:5]:
                console.print(f"  [red]• {f['value'][:60]}...[/red]")
            console.print()

        if self.results["credit_cards"]:
            console.print(f"[bold red]  Credit Cards Found ({len(self.results['credit_cards'])}):[/bold red]")
            for f in self.results["credit_cards"][:5]:
                console.print(f"  [red]• {f['value']}[/red]")
            console.print()

        if self.results["hashes"]:
            table = Table(title="Hashes", box=box.ROUNDED)
            table.add_column("#", style="green", width=4)
            table.add_column("Hash", style="cyan", width=70)
            for i, f in enumerate(self.results["hashes"][:20], 1):
                table.add_row(str(i), f["value"])
            console.print(table)
            console.print()

        if self.results["crypto_addresses"]:
            console.print(f"[bold yellow]  Crypto Addresses ({len(self.results['crypto_addresses'])}):[/bold yellow]")
            for f in self.results["crypto_addresses"][:10]:
                console.print(f"  [cyan]• {f['value']}[/cyan]")
            console.print()

        if self.results["onions"]:
            console.print(f"[bold magenta]  .onion Addresses ({len(self.results['onions'])}):[/bold magenta]")
            for f in self.results["onions"][:10]:
                console.print(f"  [magenta]• {f['value']}[/magenta]")
            console.print()

    def show_stats(self):
        console.print(f"\n[bold yellow]  === Sniffing Stats ===[/bold yellow]\n")
        table = Table(box=box.ROUNDED)
        table.add_column("Category", style="yellow", width=20)
        table.add_column("Count", style="white", width=10)
        table.add_column("Severity", style="red", width=10)
        sev_map = {
            "emails": "high",
            "combos": "critical",
            "api_keys": "critical",
            "passwords": "critical",
            "private_keys": "critical",
            "credit_cards": "critical",
            "ssns": "critical",
            "hashes": "high",
            "ips": "medium",
            "onions": "medium",
            "crypto_addresses": "medium",
            "databases": "high",
        }
        for cat, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            sev = sev_map.get(cat, "info")
            color = "red" if sev == "critical" else "yellow" if sev == "high" else "cyan"
            table.add_row(cat, str(count), f"[{color}]{sev}[/{color}]")
        if not self.stats:
            table.add_row("No findings yet", "-", "-")
        console.print(table)

    def export_results(self, filename):
        export = {
            "scan_time": datetime.now().isoformat(),
            "stats": dict(self.stats),
            "results": {k: v for k, v in self.results.items() if v},
        }
        with open(filename, "w") as f:
            json.dump(export, f, indent=2)
        console.print(f"\n[green]  Results exported to {filename}[/green]")

    def export_combos(self, filename):
        combos = self.results.get("combos", [])
        if not combos:
            console.print("[yellow]  No combos to export[/yellow]")
            return
        with open(filename, "w") as f:
            for c in combos:
                f.write(c["value"] + "\n")
        console.print(f"\n[green]  {len(combos)} combos exported to {filename}[/green]")


def main():
    p = argparse.ArgumentParser(
        prog="pastesniffer",
        description="PasteSniffer -- Dark Web Paste Site Scraper: Leaked Emails, Combos, Keys")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    p.add_argument("--threads", type=int, default=5, help="Max threads (default: 5)")
    p.add_argument("--output", "-o", help="Export results to JSON file")
    p.add_argument("--export-combos", help="Export combos to file (email:password)")

    sub = p.add_subparsers(dest="command", help="Command to execute")

    sniff_p = sub.add_parser("sniff", help="Search paste sites and extract leaks")
    sniff_p.add_argument("query", help="Keyword/email/domain to search")
    sniff_p.add_argument("--max-pastes", type=int, default=20, help="Max pastes to fetch")

    breach_p = sub.add_parser("breach", help="Check email against breach databases")
    breach_p.add_argument("email", help="Email to check")

    password_p = sub.add_parser("password", help="Check if password is breached")
    password_p.add_argument("pwd", help="Password to check")

    file_p = sub.add_parser("file", help="Scan a local file for leaks")
    file_p.add_argument("path", help="File path to scan")

    url_p = sub.add_parser("url", help="Scan a URL for leaks")
    url_p.add_argument("target", help="URL to scan")

    osint_p = sub.add_parser("osint", help="Generate OSINT links for target")
    osint_p.add_argument("query", help="Target (email/domain/IP)")
    osint_p.add_argument("--type", choices=["email", "domain", "ip"], default="email", help="Target type")

    sub.add_parser("patterns", help="Show all leak detection patterns")
    sub.add_parser("sources", help="Show all paste site sources")

    args = p.parse_args()
    banner()

    ps = PasteSniffer(timeout=args.timeout, max_threads=args.threads)

    if args.command == "sniff":
        ps.sniff_pastes(args.query, max_pastes=args.max_pastes)
        ps.show_findings()
        ps.show_stats()
    elif args.command == "breach":
        ps.breach_check(args.email)
    elif args.command == "password":
        ps.password_check(args.pwd)
    elif args.command == "file":
        ps.sniff_raw(args.path)
        ps.show_findings()
        ps.show_stats()
    elif args.command == "url":
        ps.sniff_url(args.target)
        ps.show_findings()
        ps.show_stats()
    elif args.command == "osint":
        links = ps.get_osint_links(args.query, args.type)
        console.print(f"\n[bold cyan]  OSINT Links for {args.query} ({args.type})[/bold cyan]\n")
        for i, (name, url) in enumerate(links, 1):
            console.print(f"  [green]{i:2d}.[/green] [bold white]{name}[/bold white]")
            console.print(f"      {url}")
    elif args.command == "patterns":
        console.print(f"\n[bold cyan]  Leak Detection Patterns[/bold cyan]\n")
        table = Table(box=box.ROUNDED, show_lines=True)
        table.add_column("#", style="green", width=4)
        table.add_column("Pattern", style="yellow", width=18)
        table.add_column("Description", style="white", width=30)
        table.add_column("Severity", style="red", width=10)
        for i, (name, info) in enumerate(LEAK_PATTERNS.items(), 1):
            sev = info["severity"]
            color = "red" if sev == "critical" else "yellow" if sev == "high" else "cyan"
            table.add_row(str(i), name, info["description"], f"[{color}]{sev}[/{color}]")
        console.print(table)
    elif args.command == "sources":
        console.print(f"\n[bold cyan]  Paste Site Sources[/bold cyan]\n")
        for i, (name, info) in enumerate(PASTE_SOURCES.items(), 1):
            search = info.get("search", "N/A")
            console.print(f"  [green]{i:2d}.[/green] [bold white]{name}[/bold white]")
            console.print(f"      {search}")
        console.print(f"\n[bold cyan]  Dark Web Paste Sources[/bold cyan]\n")
        for i, (name, url) in enumerate(DARK_WEB_PASTE.items(), 1):
            console.print(f"  [green]{i:2d}.[/green] [bold white]{name}[/bold white]")
            console.print(f"      {url}")
    else:
        p.print_help()

    if args.output and (ps.results["emails"] or ps.results["combos"] or ps.results["api_keys"]):
        ps.export_results(args.output)
    if hasattr(args, "export_combos") and args.export_combos:
        ps.export_combos(args.export_combos)

    console.print("\n[bold green]  Done.[/bold green]\n")


if __name__ == "__main__":
    main()
