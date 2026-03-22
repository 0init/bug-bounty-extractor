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
}

PLATFORM_URLS = {
    2: ("hackerone",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"),
    3: ("bugcrowd",   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"),
    4: ("intigriti",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json"),
    5: ("yeswehack",  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json"),
    6: ("federacy",   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/federacy_data.json"),
}

SEARCH_QUERIES = [
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
    # Direct / self-hosted programs (not on platforms)
    '"powered by bugcrowd" -site:bugcrowd.com',
    '"submit vulnerability report"',
    '"submit vulnerability report" -site:hackerone.com -site:bugcrowd.com -site:synack.com -site:openbugbounty.org',
    '"powered by hackerone" -site:hackerone.com',
    'inurl:/.well-known/security.txt intext:bounty -hackerone -bugcrowd -synack',
    'intext:"CVSS score" "eligible for a reward" -hackerone -bugcrowd',
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


def fetch_platform_domains(platform_name, url):
    """Sources 2-6: Fetch platform-specific JSON and extract in-scope domains.

    Each platform uses different JSON field names:
      - HackerOne:  asset_identifier / asset_type  (WILDCARD, URL - uppercase)
      - Bugcrowd:   target / type                   (api, website - lowercase)
      - Intigriti:  endpoint / type                  (url, wildcard - lowercase)
      - YesWeHack:  target / type                   (web-application, api)
      - Federacy:   target / type                   (website)
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

    for program in data:
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


def _brave_search(query, pages=3):
    """Search Brave and extract result URLs. Works reliably from VPS/server IPs."""
    domains = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }
    # Domains to skip (search engines, CDNs, not real targets)
    SKIP_DOMAINS = {
        "brave.com", "google.com", "bing.com", "youtube.com",
        "wikipedia.org", "reddit.com", "twitter.com", "x.com",
        "facebook.com", "linkedin.com", "github.com", "medium.com",
    }

    for page in range(pages):
        offset = page * 10
        try:
            resp = requests.get(
                "https://search.brave.com/search",
                params={"q": query, "source": "web", "offset": offset},
                headers=headers, timeout=15,
            )
            if resp.status_code == 429:
                logger.info(f"[Brave] Rate-limited on '{query}' offset={offset}")
                return domains  # Return what we have, signal caller to back off
            if resp.status_code != 200:
                logger.warning(f"[Brave] HTTP {resp.status_code} for '{query}' offset={offset}")
                break
            # Brave puts result URLs inside snippet containers
            urls = re.findall(
                r'class="snippet[^"]*"[^>]*>.*?href="(https?://[^"]+)"',
                resp.text, re.DOTALL,
            )
            if not urls:
                break  # No more results
            for url in urls:
                d = extract_domain(url)
                if d:
                    d = clean_domain(d)
                    if d and d not in SKIP_DOMAINS:
                        domains.add(d)
        except Exception as exc:
            logger.warning(f"[Brave] Error for '{query}': {exc}")
            break
        time.sleep(3)

    return domains


def fetch_search_domains():
    """Source 10: Search the internet for bug bounty / disclosure pages via Brave Search.

    Brave Search works reliably from VPS/server IPs (unlike Google and DuckDuckGo
    which block datacenter IPs with CAPTCHAs). Runs multiple targeted queries with
    pagination to discover domains that have bug bounty programs or security.txt.
    """
    domains = set()

    total_queries = len(SEARCH_QUERIES)
    print(f"    [*] Brave Search ({total_queries} queries x 3 pages each)...")
    delay = 5  # Start with 5s between queries
    rate_limited = False

    for i, query in enumerate(SEARCH_QUERIES, 1):
        logger.info(f"[Search] Brave query {i}/{total_queries}: {query}")
        print(f"    [{i:>2}/{total_queries}] {query}")
        before = len(domains)
        try:
            found = _brave_search(query, pages=3)
            domains.update(found)
            new = len(domains) - before
            print(f"           -> {len(found)} domains ({new} new)")

            if len(found) == 0 and not rate_limited:
                # Likely rate-limited, increase delay
                rate_limited = True
                delay = 15
                print(f"    [!] Rate-limited by Brave. Waiting {delay}s between queries...")
            elif len(found) > 0:
                rate_limited = False
                delay = 5
        except Exception as exc:
            logger.warning(f"[Search] Error for '{query}': {exc}")
            print(f"           -> error: {exc}")
        time.sleep(delay)

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

def run(selected_sources=None, output_file="domains.txt", interactive=True):
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
            domains = fetch_platform_domains(platform_name, url)
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

    run(selected_sources=selected, output_file=args.output, interactive=interactive)


if __name__ == "__main__":
    main()
