#!/usr/bin/env python3
"""
Bug Bounty Program Domain Extractor

Collects bug bounty and vulnerability disclosure program domains from multiple
public sources. Supports interactive source selection and outputs a deduplicated
domain list.

Usage:
    python3 extractor.py                        # Interactive menu
    python3 extractor.py -s 1,2,7               # Select specific sources
    python3 extractor.py -s 0 -o targets.txt    # All sources, custom output
"""

import sys
import re
import csv
import io
import json
import random
import time
import logging
import argparse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------

SOURCES = {
    1:  {"name": "Bounty Targets Data",     "desc": "domains.txt + wildcards (arkadiyt/bounty-targets-data)"},
    2:  {"name": "HackerOne Programs",       "desc": "in-scope targets from HackerOne"},
    3:  {"name": "Bugcrowd Programs",        "desc": "in-scope targets from Bugcrowd"},
    4:  {"name": "Intigriti Programs",       "desc": "in-scope targets from Intigriti"},
    5:  {"name": "YesWeHack Programs",       "desc": "in-scope targets from YesWeHack"},
    6:  {"name": "Federacy Programs",        "desc": "in-scope targets from Federacy"},
    7:  {"name": "Disclose.io Database",     "desc": "vulnerability disclosure programs"},
    8:  {"name": "Chaos (ProjectDiscovery)", "desc": "public bug bounty recon data"},
    9:  {"name": "CISA VDP Directory",       "desc": "US gov vulnerability disclosure policies"},
    10: {"name": "Search Dorking",            "desc": "Brave Search for bug bounty / disclosure / security.txt pages"},
    11: {"name": "Security.txt Scraper",     "desc": "check domains for /.well-known/security.txt"},
    12: {"name": "FireBounty",               "desc": "firebounty.com VDP + bug bounty aggregator (~176k programs)"},
}

PLATFORM_URLS = {
    2: ("hackerone",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"),
    3: ("bugcrowd",   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"),
    4: ("intigriti",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json"),
    5: ("yeswehack",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json"),
    6: ("federacy",   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/federacy_data.json"),
}

SEARCH_QUERIES = [
    # Direct / self-hosted programs (not on platforms) — highest priority
    '"powered by bugcrowd" -site:bugcrowd.com',
    '"submit vulnerability report"',
    '"submit vulnerability report" "powered by bugcrowd" "powered by hackerone"',
    '"submit vulnerability report" -site:hackerone.com -site:bugcrowd.com -site:synack.com -site:openbugbounty.org',
    'inurl:/.well-known/security.txt intext:bounty -hackerone -bugcrowd -synack',
    'intext:"CVSS score" "eligible for a reward" -hackerone -bugcrowd',
    # General bug bounty / disclosure
    "bug bounty program",
    "responsible disclosure policy",
    "vulnerability disclosure program",
    '"report a security vulnerability"',
    '"security.txt" contact bounty',
    "coordinated disclosure policy",
    '"bug bounty" scope rewards',
    '"responsible disclosure" hall of fame',
    '"vulnerability reward program"',
    '"security researcher" acknowledgements',
    'inurl:security.txt contact',
    'inurl:responsible-disclosure',
    'inurl:bug-bounty',
    '"submit a vulnerability"',
    '"security bounty" program',
    '"powered by hackerone" -site:hackerone.com',
]


SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url, timeout=30):
    """Make an HTTP GET request with error handling and one retry on timeout."""
    headers = {"User-Agent": "BugBountyExtractor/1.0 (security-research)"}
    for attempt in range(2):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            resp.raise_for_status()
            return resp
        except requests.exceptions.Timeout:
            if attempt == 0:
                logger.warning(f"Timeout fetching {url}, retrying...")
                continue
            logger.warning(f"Timeout fetching {url} after retry")
        except requests.exceptions.RequestException as exc:
            logger.warning(f"Error fetching {url}: {exc}")
            break
    return None


def extract_domain(url):
    """Extract a clean domain from a URL string."""
    if not url:
        return None
    url = url.strip()
    if not url:
        return None
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        if domain:
            domain = domain.lower().strip(".")
            domain = re.sub(r'^www\.', '', domain)
            return domain
    except Exception:
        pass
    return None


def clean_domain(domain):
    """Clean and validate a domain string."""
    if not domain:
        return None
    domain = domain.strip().lower()
    domain = re.sub(r'^\*\.', '', domain)
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0].split(':')[0].split('?')[0]
    domain = domain.strip('.')
    if not domain:
        return None
    if '.' not in domain:
        return None
    if ' ' in domain:
        return None
    if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain):
        return None
    return domain


# ---------------------------------------------------------------------------
# Source fetchers
# ---------------------------------------------------------------------------

def fetch_bounty_targets_domains():
    """Source 1: Fetch domains.txt and wildcards.txt from arkadiyt/bounty-targets-data."""
    domains = set()
    base = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"

    resp = make_request(f"{base}/domains.txt")
    if resp:
        for line in resp.text.splitlines():
            d = clean_domain(line)
            if d:
                domains.add(d)
        logger.info(f"[Bounty Targets] domains.txt: {len(domains)} domains")

    wildcard_count = 0
    resp = make_request(f"{base}/wildcards.txt")
    if resp:
        for line in resp.text.splitlines():
            d = clean_domain(line)
            if d:
                domains.add(d)
                wildcard_count += 1
        logger.info(f"[Bounty Targets] wildcards.txt: {wildcard_count} wildcard domains")

    return domains


def fetch_platform_domains(platform_name, url, bounty_only=False):
    """Sources 2-6: Fetch platform-specific JSON and extract in-scope domains.

    Each platform uses different JSON field names:
      - HackerOne:  asset_identifier / asset_type  (WILDCARD, URL - uppercase)
      - Bugcrowd:   target / type                   (api, website - lowercase)
      - Intigriti:  endpoint / type                  (url, wildcard - lowercase)
      - YesWeHack:  target / type                   (web-application, api)
      - Federacy:   target / type                   (website)

    If bounty_only=True, only include programs that offer monetary rewards.
    """
    domains = set()
    resp = make_request(url)
    if not resp:
        return domains

    try:
        data = resp.json()
    except json.JSONDecodeError:
        logger.warning(f"[{platform_name}] Failed to parse JSON")
        return domains

    # Accepted asset types across all platforms (lowercase comparison)
    VALID_TYPES = {
        "url", "domain", "wildcard", "other", "website",
        "api", "web-application", "web_application", "android",
        "ios", "hardware", "smart_contract", "executable",
    }

    skipped = 0
    for program in data:
        # Bounty-only filter: skip programs that don't pay
        if bounty_only:
            has_bounty = False
            # HackerOne: offers_bounties (bool)
            if program.get("offers_bounties"):
                has_bounty = True
            # Bugcrowd: max_payout > 0
            elif (program.get("max_payout") or 0) > 0:
                has_bounty = True
            # Intigriti: max_bounty.value > 0
            elif isinstance(program.get("max_bounty"), dict) and (program["max_bounty"].get("value") or 0) > 0:
                has_bounty = True
            # YesWeHack: max_bounty > 0 (int)
            elif isinstance(program.get("max_bounty"), (int, float)) and program["max_bounty"] > 0:
                has_bounty = True
            # Federacy: offers_awards (bool)
            elif program.get("offers_awards"):
                has_bounty = True
            if not has_bounty:
                skipped += 1
                continue

        targets = program.get("targets", {})
        in_scope = targets.get("in_scope", [])
        for target in in_scope:
            # Get asset type from whichever field the platform uses
            asset_type = (
                target.get("asset_type", "") or
                target.get("type", "")
            ).lower().strip()

            # Get the actual target value from whichever field exists
            asset_id = (
                target.get("asset_identifier", "") or  # HackerOne
                target.get("target", "") or             # Bugcrowd / YesWeHack / Federacy
                target.get("endpoint", "") or           # Intigriti
                target.get("uri", "")                   # Bugcrowd alt field
            )

            if not asset_id or not isinstance(asset_id, str):
                continue

            if asset_type not in VALID_TYPES:
                continue

            # Try cleaning directly first, then fall back to URL extraction
            d = clean_domain(asset_id)
            if d:
                domains.add(d)
            else:
                d = extract_domain(asset_id)
                if d:
                    d = clean_domain(d)
                    if d:
                        domains.add(d)

    if bounty_only:
        logger.info(f"[{platform_name}] Extracted {len(domains)} domains (bounty-only, skipped {skipped} non-paying)")
    else:
        logger.info(f"[{platform_name}] Extracted {len(domains)} domains")
    return domains


def fetch_disclose_io_domains():
    """Source 7: Fetch disclose.io program list and extract domains."""
    domains = set()
    url = "https://raw.githubusercontent.com/disclose/diodb/master/program-list.json"
    resp = make_request(url)
    if not resp:
        return domains

    try:
        data = resp.json()
    except json.JSONDecodeError:
        logger.warning("[Disclose.io] Failed to parse JSON")
        return domains

    for program in data:
        for field in ("policy_url", "contact_url", "program_url"):
            val = program.get(field, "")
            if val and isinstance(val, str) and val.startswith("http"):
                d = extract_domain(val)
                if d:
                    d = clean_domain(d)
                    if d:
                        domains.add(d)

    logger.info(f"[Disclose.io] Extracted {len(domains)} domains")
    return domains


def fetch_chaos_domains():
    """Source 8: Fetch ProjectDiscovery Chaos index and extract domains."""
    domains = set()
    url = "https://chaos-data.projectdiscovery.io/index.json"
    resp = make_request(url)
    if not resp:
        return domains

    try:
        data = resp.json()
    except json.JSONDecodeError:
        logger.warning("[Chaos] Failed to parse JSON")
        return domains

    for program in data:
        program_url = program.get("program_url", "")
        if program_url:
            d = extract_domain(program_url)
            if d:
                d = clean_domain(d)
                if d:
                    domains.add(d)
        name = program.get("name", "")
        if "." in name:
            d = clean_domain(name)
            if d:
                domains.add(d)

    logger.info(f"[Chaos] Extracted {len(domains)} domains")
    return domains


def fetch_cisa_vdp_domains():
    """Source 9: Fetch CISA / .gov domain data for VDP programs."""
    domains = set()

    url = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-federal.csv"
    resp = make_request(url)
    if resp:
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            domain_name = row.get("Domain Name", "").strip()
            if domain_name:
                d = clean_domain(domain_name)
                if d:
                    domains.add(d)
        logger.info(f"[CISA] Federal .gov domains: {len(domains)}")

    vdp_url = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv"
    resp2 = make_request(vdp_url)
    if resp2:
        reader = csv.DictReader(io.StringIO(resp2.text))
        count_before = len(domains)
        for row in reader:
            domain_name = row.get("Domain Name", "").strip()
            if domain_name:
                d = clean_domain(domain_name)
                if d:
                    domains.add(d)
        logger.info(f"[CISA] Full .gov list: {len(domains) - count_before} additional domains")

    return domains


# Domains to skip (search engines, CDNs, not real targets)
SKIP_DOMAINS = {
    "brave.com", "search.brave.com", "google.com", "bing.com",
    "youtube.com", "wikipedia.org", "reddit.com", "twitter.com",
    "x.com", "facebook.com", "linkedin.com", "github.com",
    "medium.com", "yahoo.com", "mojeek.com",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]


def _extract_and_clean(urls):
    """Extract clean domains from a list of URLs, filtering noise."""
    domains = set()
    for url in urls:
        d = extract_domain(url)
        if d:
            d = clean_domain(d)
            if d and d not in SKIP_DOMAINS:
                domains.add(d)
    return domains


def _search_brave(query, session):
    """Search Brave and extract result URLs."""
    domains = set()
    for page in range(3):
        offset = page * 10
        try:
            resp = session.get(
                "https://search.brave.com/search",
                params={"q": query, "source": "web", "offset": offset},
                timeout=15,
            )
            if resp.status_code == 429:
                logger.info(f"[Brave] Rate-limited on '{query}' offset={offset}")
                return domains, True  # rate_limited=True
            if resp.status_code != 200:
                break
            urls = re.findall(
                r'class="snippet[^"]*"[^>]*>.*?href="(https?://[^"]+)"',
                resp.text, re.DOTALL,
            )
            if not urls:
                break
            domains.update(_extract_and_clean(urls))
        except Exception as exc:
            logger.warning(f"[Brave] Error: {exc}")
            break
        time.sleep(3)
    return domains, False


def _search_mojeek(query):
    """Search Mojeek (independent search engine, VPS-friendly)."""
    domains = set()
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(
            "https://www.mojeek.com/search",
            params={"q": query},
            headers=headers, timeout=15,
        )
        if resp.status_code == 200:
            urls = re.findall(r'href="(https?://(?!.*mojeek)[^"]{15,})"', resp.text)
            urls = [u for u in urls if not any(x in u for x in
                    [".css", ".js", ".png", ".svg", ".woff", "cdn.", "static."])]
            domains.update(_extract_and_clean(urls))
    except Exception as exc:
        logger.warning(f"[Mojeek] Error: {exc}")
    return domains, False


def _search_yahoo(query, session):
    """Search Yahoo (powered by Bing, VPS-friendly with consent cookie)."""
    domains = set()
    from urllib.parse import unquote
    try:
        resp = session.get(
            "https://search.yahoo.com/search",
            params={"p": query, "n": 20},
            timeout=15,
        )
        if resp.status_code == 200:
            # Yahoo wraps URLs through redirect: RU=<encoded_url>
            encoded_urls = re.findall(r'RU=([^"&/]+)', resp.text)
            for encoded in encoded_urls:
                url = unquote(unquote(encoded))
                if url.startswith("http"):
                    domains.update(_extract_and_clean([url]))
    except Exception as exc:
        logger.warning(f"[Yahoo] Error: {exc}")
    return domains, False


def fetch_search_domains():
    """Source 10: Search the internet for bug bounty / disclosure pages.

    Rotates queries across 3 search engines (Brave, Mojeek, Yahoo) to avoid
    rate-limiting. Each engine only gets ~1/3 of total queries. If one engine
    gets rate-limited, its queries are redistributed to the others.
    """
    domains = set()

    # --- Setup sessions ---
    brave_session = requests.Session()
    brave_session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    })
    # Warm up Brave with homepage visit for cookies
    try:
        brave_session.get("https://search.brave.com/", timeout=10)
    except Exception:
        pass

    yahoo_session = requests.Session()
    yahoo_session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    yahoo_session.cookies.set("EuConsent", "true", domain=".yahoo.com")

    engines = [
        ("Brave",  lambda q: _search_brave(q, brave_session)),
        ("Mojeek", lambda q: _search_mojeek(q)),
        ("Yahoo",  lambda q: _search_yahoo(q, yahoo_session)),
    ]
    active_engines = list(engines)  # Engines that haven't been rate-limited

    total_queries = len(SEARCH_QUERIES)
    print(f"    [*] Multi-engine search ({total_queries} queries across Brave + Mojeek + Yahoo)...")

    for i, query in enumerate(SEARCH_QUERIES, 1):
        if not active_engines:
            print("    [!] All engines rate-limited. Stopping.")
            break

        # Pick engine via round-robin on active engines
        engine_name, search_fn = active_engines[i % len(active_engines)]

        logger.info(f"[Search] [{engine_name}] query {i}/{total_queries}: {query}")
        print(f"    [{i:>2}/{total_queries}] [{engine_name:6}] {query}")

        before = len(domains)
        try:
            found, rate_limited = search_fn(query)
            domains.update(found)
            new = len(domains) - before
            print(f"           -> {len(found)} domains ({new} new)")

            if rate_limited:
                print(f"    [!] {engine_name} rate-limited. Removing from rotation.")
                active_engines = [e for e in active_engines if e[0] != engine_name]
        except Exception as exc:
            logger.warning(f"[Search] Error for '{query}': {exc}")
            print(f"           -> error: {exc}")

        time.sleep(random.uniform(3, 6))

    logger.info(f"[Search] Total extracted: {len(domains)} domains")
    return domains


def _check_single_security_txt(domain):
    """Check a single domain for security.txt and extract referenced domains."""
    found_domains = set()
    headers = {"User-Agent": "BugBountyExtractor/1.0 (security-research)"}

    for path in SECURITY_TXT_PATHS:
        url = f"https://{domain}{path}"
        try:
            resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 10:
                content = resp.text
                if any(field in content for field in ("Contact:", "Policy:", "Acknowledgments:")):
                    urls = re.findall(r'https?://[^\s<>"\']+', content)
                    for u in urls:
                        d = extract_domain(u)
                        if d:
                            d = clean_domain(d)
                            if d:
                                found_domains.add(d)
                    found_domains.add(domain)
                    return found_domains
        except requests.exceptions.RequestException:
            pass

    return found_domains


def fetch_security_txt_domains(seed_domains, max_workers=10, max_domains=500):
    """Source 11: Check seed domains for security.txt files."""
    domains = set()
    check_list = list(seed_domains)[:max_domains]

    logger.info(f"[Security.txt] Checking {len(check_list)} domains (max {max_workers} threads)")
    print(f"    [*] Checking {len(check_list)} domains for security.txt...")

    checked = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_single_security_txt, d): d for d in check_list}
        for future in as_completed(futures):
            checked += 1
            if checked % 50 == 0:
                print(f"    [*] Checked {checked}/{len(check_list)} domains...")
            try:
                result = future.result()
                domains.update(result)
            except Exception as exc:
                logger.warning(f"[Security.txt] Error checking {futures[future]}: {exc}")

    logger.info(f"[Security.txt] Found {len(domains)} domains with security.txt")
    return domains


def fetch_firebounty_domains(max_pages=200, bounty_only=False):
    """Source 12: Scrape firebounty.com for VDP and bug bounty program domains.

    FireBounty aggregates ~176k programs. Program titles are actual domain names.
    Scrapes pages in parallel (5 threads) for speed.
    If bounty_only=True, uses reward=Reward filter (paid programs only).
    """
    domains = set()
    headers = {"User-Agent": "BugBountyExtractor/1.0 (security-research)"}
    # type=Bounty filters for actual bug bounty programs (not just VDP/security.txt)
    bounty_param = "&type=Bounty" if bounty_only else ""

    def _fetch_page(page_num):
        """Fetch a single page and extract domain titles."""
        page_domains = []
        try:
            resp = requests.get(
                f"https://firebounty.com/?page={page_num}{bounty_param}",
                headers=headers, timeout=60,
            )
            if resp.status_code == 200:
                matches = re.findall(
                    r'href="/(\d+-[^"]+)"[^>]*>\s*([^<]+?)\s*</a>',
                    resp.text,
                )
                seen = set()
                for slug, title in matches:
                    title = title.strip()
                    if slug not in seen and "." in title:
                        seen.add(slug)
                        d = clean_domain(title)
                        if d:
                            page_domains.append(d)
        except Exception as exc:
            logger.warning(f"[FireBounty] Error on page {page_num}: {exc}")
        return page_domains

    # Detect total pages from page 1
    logger.info(f"[FireBounty] Fetching up to {max_pages} pages (5 threads)...")
    print(f"    [*] Scraping firebounty.com (up to {max_pages} pages, 5 threads)...")

    try:
        resp = requests.get(f"https://firebounty.com/?page=1{bounty_param}", headers=headers, timeout=60)
        page_nums = re.findall(r'page=(\d+)', resp.text)
        if page_nums:
            total_pages = min(int(max(page_nums, key=int)), max_pages)
        else:
            total_pages = max_pages
        logger.info(f"[FireBounty] Total pages detected: {total_pages}")

        # Extract page 1 domains while we have it
        matches = re.findall(r'href="/(\d+-[^"]+)"[^>]*>\s*([^<]+?)\s*</a>', resp.text)
        seen = set()
        for slug, title in matches:
            title = title.strip()
            if slug not in seen and "." in title:
                seen.add(slug)
                d = clean_domain(title)
                if d:
                    domains.add(d)
    except Exception as exc:
        logger.warning(f"[FireBounty] Error fetching page 1: {exc}")
        total_pages = max_pages

    # Fetch remaining pages in parallel
    fetched = 1
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(_fetch_page, p): p
            for p in range(2, total_pages + 1)
        }
        for future in as_completed(futures):
            fetched += 1
            page_domains = future.result()
            domains.update(page_domains)
            if fetched % 50 == 0:
                print(f"    [*] Scraped {fetched}/{total_pages} pages ({len(domains):,} domains)...")

    logger.info(f"[FireBounty] Extracted {len(domains)} domains from {fetched} pages")
    return domains


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def display_menu():
    """Display interactive source selection menu and return selected source IDs."""
    print("\n" + "=" * 65)
    print("  Bug Bounty Program Domain Extractor")
    print("=" * 65)
    print("\n  Select sources to fetch (comma-separated, or '0' for all):\n")

    for sid, info in SOURCES.items():
        print(f"    [{sid:>2}] {info['name']:<28} - {info['desc']}")

    print(f"\n    [ 0] All Sources")
    print()

    while True:
        try:
            selection = input("  Enter selection: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.")
            sys.exit(0)

        if not selection:
            print("  Please enter at least one source number.")
            continue

        parts = [p.strip() for p in selection.replace(" ", ",").split(",") if p.strip()]
        try:
            ids = [int(p) for p in parts]
        except ValueError:
            print("  Invalid input. Enter numbers separated by commas (e.g., 1,2,7).")
            continue

        if 0 in ids:
            return list(SOURCES.keys())

        invalid = [i for i in ids if i not in SOURCES]
        if invalid:
            print(f"  Invalid source(s): {invalid}. Valid range: 0-{max(SOURCES.keys())}")
            continue

        return ids


# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------

def run(selected_sources=None, output_file="domains.txt", interactive=True, bounty_only=False):
    """
    Main entry point.

    Args:
        selected_sources: List of source IDs to use (None = show menu)
        output_file: Path to output file
        interactive: Whether to show the interactive menu

    Returns:
        dict with results summary
    """
    if selected_sources is None:
        if interactive:
            selected_sources = display_menu()
        else:
            selected_sources = list(SOURCES.keys())

    print(f"\n  [*] Running {len(selected_sources)} source(s)...\n")

    if bounty_only:
        print("  [!] Bounty-only mode: filtering for programs that pay rewards\n")

    all_domains = set()
    source_stats = {}

    if 1 in selected_sources:
        print("  [+] Fetching Bounty Targets Data...")
        domains = fetch_bounty_targets_domains()
        source_stats["Bounty Targets Data"] = len(domains)
        all_domains.update(domains)
        print(f"      Found {len(domains):,} domains")

    for sid in [2, 3, 4, 5, 6]:
        if sid in selected_sources:
            platform_name, url = PLATFORM_URLS[sid]
            display_name = SOURCES[sid]["name"]
            print(f"  [+] Fetching {display_name}...")
            domains = fetch_platform_domains(platform_name, url, bounty_only=bounty_only)
            source_stats[display_name] = len(domains)
            all_domains.update(domains)
            print(f"      Found {len(domains):,} domains")

    if 7 in selected_sources:
        print("  [+] Fetching Disclose.io Database...")
        domains = fetch_disclose_io_domains()
        source_stats["Disclose.io Database"] = len(domains)
        all_domains.update(domains)
        print(f"      Found {len(domains):,} domains")

    if 8 in selected_sources:
        print("  [+] Fetching Chaos (ProjectDiscovery)...")
        domains = fetch_chaos_domains()
        source_stats["Chaos (ProjectDiscovery)"] = len(domains)
        all_domains.update(domains)
        print(f"      Found {len(domains):,} domains")

    if 9 in selected_sources:
        print("  [+] Fetching CISA VDP Directory...")
        domains = fetch_cisa_vdp_domains()
        source_stats["CISA VDP Directory"] = len(domains)
        all_domains.update(domains)
        print(f"      Found {len(domains):,} domains")

    if 10 in selected_sources:
        print("  [+] Running Search Dorking (Brave Search)...")
        domains = fetch_search_domains()
        source_stats["Search Dorking"] = len(domains)
        all_domains.update(domains)
        print(f"      Found {len(domains):,} domains")

    if 11 in selected_sources:
        print("  [+] Running Security.txt Scraper...")
        if all_domains:
            domains = fetch_security_txt_domains(all_domains)
        else:
            print("    [!] No seed domains available. Skipping security.txt check.")
            domains = set()
        source_stats["Security.txt Scraper"] = len(domains)
        all_domains.update(domains)
        print(f"      Found {len(domains):,} domains")

    if 12 in selected_sources:
        print("  [+] Fetching FireBounty programs...")
        domains = fetch_firebounty_domains(max_pages=200, bounty_only=bounty_only)
        source_stats["FireBounty"] = len(domains)
        all_domains.update(domains)
        print(f"      Found {len(domains):,} domains")

    sorted_domains = sorted(all_domains)

    with open(output_file, "w") as f:
        for domain in sorted_domains:
            f.write(domain + "\n")

    print("\n" + "=" * 65)
    print("  Summary")
    print("=" * 65)
    for source_name, count in source_stats.items():
        print(f"  [+] {source_name:<30} -> {count:>8,} domains")
    print(f"\n  [+] Total unique domains: {len(sorted_domains):,}")
    print(f"  [+] Written to: {output_file}")
    print("=" * 65 + "\n")

    return {
        "programs_found": sorted_domains,
        "domains_checked": len(sorted_domains),
        "source_stats": source_stats,
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Bug Bounty Program Domain Extractor - Collect domains from public sources"
    )
    parser.add_argument("-o", "--output", default="domains.txt",
                        help="Output file path (default: domains.txt)")
    parser.add_argument("-s", "--sources", type=str, default=None,
                        help="Comma-separated source IDs to use (e.g., 1,2,7). "
                             "Use 0 for all. Skips interactive menu.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("-b", "--bounty-only", action="store_true",
                        help="Only extract programs that offer monetary bounties/rewards")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()]
    )

    selected = None
    interactive = True
    if args.sources is not None:
        parts = [p.strip() for p in args.sources.split(",") if p.strip()]
        try:
            ids = [int(p) for p in parts]
            if 0 in ids:
                selected = list(SOURCES.keys())
            else:
                selected = ids
            interactive = False
        except ValueError:
            print("[!] Invalid --sources value. Use comma-separated numbers.")
            sys.exit(1)

    run(selected_sources=selected, output_file=args.output, interactive=interactive,
        bounty_only=args.bounty_only)


if __name__ == "__main__":
    main()
