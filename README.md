# Bug Bounty Program Domain Extractor

Collects bug bounty and vulnerability disclosure program domains from **11 public sources** and outputs a deduplicated, sorted list ready for security research.

---

## Installation

```bash
git clone https://github.com/0init/bug-bounty-extractor.git
cd bug-bounty-extractor
pip3 install -r requirements.txt
```

### Requirements

- Python 3.8+
- `requests` (HTTP client)
- `googlesearch-python` (optional, for Google Dorking - source 10)

---

## Usage

### Interactive Mode (default)

```bash
python3 extractor.py
```

This shows a menu where you pick which sources to use:

```
=================================================================
  Bug Bounty Program Domain Extractor
=================================================================

  Select sources to fetch (comma-separated, or '0' for all):

    [ 1] Bounty Targets Data        - domains.txt + wildcards (arkadiyt/bounty-targets-data)
    [ 2] HackerOne Programs         - in-scope targets from HackerOne
    [ 3] Bugcrowd Programs          - in-scope targets from Bugcrowd
    [ 4] Intigriti Programs         - in-scope targets from Intigriti
    [ 5] YesWeHack Programs         - in-scope targets from YesWeHack
    [ 6] Federacy Programs          - in-scope targets from Federacy
    [ 7] Disclose.io Database       - vulnerability disclosure programs
    [ 8] Chaos (ProjectDiscovery)   - public bug bounty recon data
    [ 9] CISA VDP Directory         - US gov vulnerability disclosure policies
    [10] Google Dorking             - search for 'bug bounty' / 'responsible disclosure' pages
    [11] Security.txt Scraper       - check domains for /.well-known/security.txt

    [ 0] All Sources

  Enter selection:
```

Type source numbers separated by commas (e.g. `1,2,3,7`) or `0` for all.

### Non-Interactive Mode

Skip the menu by passing source IDs with `-s`:

```bash
# Fetch from specific sources
python3 extractor.py -s 1,2,3

# Fetch from all sources
python3 extractor.py -s 0

# Custom output file
python3 extractor.py -s 1,7,8 -o my_targets.txt

# Verbose logging
python3 extractor.py -s 0 -o targets.txt -v
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-s`, `--sources` | Comma-separated source IDs (0 = all) | Interactive menu |
| `-o`, `--output` | Output file path | `domains.txt` |
| `-v`, `--verbose` | Enable debug logging | Off |

---

## Sources

| # | Source | Description | Auth Required |
|---|--------|-------------|---------------|
| 1 | **Bounty Targets Data** | Aggregated domains + wildcards from [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) (updated every 30 min) | No |
| 2 | **HackerOne Programs** | In-scope domains from HackerOne programs | No |
| 3 | **Bugcrowd Programs** | In-scope domains from Bugcrowd programs | No |
| 4 | **Intigriti Programs** | In-scope domains from Intigriti programs | No |
| 5 | **YesWeHack Programs** | In-scope domains from YesWeHack programs | No |
| 6 | **Federacy Programs** | In-scope domains from Federacy programs | No |
| 7 | **Disclose.io Database** | [disclose.io](https://disclose.io) vulnerability disclosure program list | No |
| 8 | **Chaos (ProjectDiscovery)** | [Chaos](https://chaos.projectdiscovery.io) bug bounty recon data index | No |
| 9 | **CISA VDP Directory** | US federal .gov domains with vulnerability disclosure policies | No |
| 10 | **Google Dorking** | Google searches for "bug bounty", "responsible disclosure" pages | No (rate-limited) |
| 11 | **Security.txt Scraper** | Checks collected domains for `/.well-known/security.txt` (RFC 9116) | No |

> **Note:** Source 11 (Security.txt) runs on domains already collected from other sources. Run it together with at least one other source.

> **Note:** Source 10 (Google Dorking) requires `googlesearch-python`. If not installed, the source is skipped with a warning.

---

## Output

The script writes one domain per line to the output file, sorted alphabetically and deduplicated:

```
example.com
github.com
hackerone.com
...
```

A summary is printed after each run:

```
=================================================================
  Summary
=================================================================
  [+] Bounty Targets Data            ->   38,026 domains
  [+] HackerOne Programs             ->   12,451 domains
  [+] Disclose.io Database           ->    1,394 domains
  [+] Chaos (ProjectDiscovery)       ->      224 domains

  [+] Total unique domains: 43,891
  [+] Written to: domains.txt
=================================================================
```

---

## Examples

```bash
# Quick start - get all platform targets
python3 extractor.py -s 1,2,3,4,5,6

# Only disclosure/VDP programs
python3 extractor.py -s 7,9

# Everything including Google dorking and security.txt checks
python3 extractor.py -s 0 -o all_targets.txt -v

# Just HackerOne + Bugcrowd for a quick list
python3 extractor.py -s 2,3 -o h1_bc_targets.txt
```

---

## How It Works

1. You select which sources to fetch from
2. The script downloads domain lists from public GitHub repos, APIs, and databases
3. Domains are cleaned (strip wildcards, protocols, paths) and validated
4. All domains are deduplicated across sources
5. The final sorted list is written to the output file

No API keys are needed. All sources are publicly available. The Google Dorking source adds a 3-second delay between queries to avoid rate limiting.

---

## Disclaimer

This tool is intended for **authorized security research and bug bounty hunting only**. Always ensure you have proper authorization before testing any target. Respect program scope and rules.
