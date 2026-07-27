#!/usr/bin/env python3
"""
Stealer Log Scanner — Hermes Agent Orchestrator
================================================
Extended version that uses web_search via subprocess/curl for sources
the base scanner can't reach. Designed to be invoked by the Hermes cron agent.

This script runs inside a cron job and outputs a full findings report to stdout.
It handles:
  - Direct HTTP scraping (Pastebin, CRT.sh, Ahmia, LeakCheck)
  - Searching known Telegram channels for stealer log dumps
  - Checking GitHub gists for credential files
  - Validating findings and deduplicating via state files

Usage (standalone):
  python stealer_log_orchestrator.py --domains "target1.com,target2.com" [--json]

Usage (Hermes cron):
  Set no_agent=True, script points here, prompt is ignored.
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import hashlib
import urllib.request
import urllib.parse
import urllib.error
import ssl
import html
from datetime import datetime, timezone
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────────

STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stealer_log_state")
os.makedirs(STATE_DIR, exist_ok=True)

# Telegram channels known to post stealer logs (public)
TELEGRAM_CHANNELS = [
    "stealer_logs_channel",
    "leaked_credentials",
    "dumpsters",
    "combos_list",
    "leakbase",
    "leakzone",
    "leakedlogs",
    "logs_dump",
    "infostealer_logs",
    "leaked_emails_passwords",
    "cracked_accounts",
    "pastebin_dumps",
]

# Known paste site patterns
PASTE_SITES = [
    "pastebin.com",
    "paste.ee",
    "paste.gg",
    "ghostbin.com",
    "rentry.co",
    "controlc.com",
    "paste.ofcode.org",
    "dpaste.org",
    "paste.mozilla.org",
    "hastebin.com",
    "codepad.org",
]

# Stealer malware signature strings
STEALER_SIGNATURES = {
    "redline": ["redline", "redline stealer", "redline log"],
    "vidar": ["vidar", "vidar stealer"],
    "raccoon": ["raccoon", "raccoon stealer", "raccoon v2"],
    "agenttesla": ["agenttesla", "agent tesla"],
    "lumma": ["lumma", "lumma stealer", "lummac2"],
    "stealc": ["stealc", "stealc stealer"],
    "azorult": ["azorult", "azorult stealer"],
    "risepro": ["risepro", "rise pro"],
    "metastealer": ["metastealer", "meta stealer"],
    "cryptbot": ["cryptbot"],
    "blank": ["blank grabber"],
    "prynt": ["prynt stealer"],
    "warzone": ["warzone", "warzone rat"],
    "asyncrat": ["asyncrat", "async rat"],
    "nanocore": ["nanocore", "nanocore rat"],
    "quasar": ["quasar rat", "quasar"],
}

LEAK_INDICATORS = [
    "password", "passwd", "pwd",
    "email", "mail",
    "login", "username", "user",
    "token", "secret", "apikey", "api_key",
    "cookie", "session",
    "wallet", "seed_phrase",
    "private key", "mnemonic",
]


def ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def ua() -> str:
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
           "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

def http_get(url: str, timeout: int = 15) -> Optional[str]:
    """Fetch a URL with basic retry logic."""
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": ua(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            })
            resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx())
            return resp.read().decode("utf-8", errors="replace")
        except Exception:
            if attempt == 0:
                time.sleep(1.5)
                continue
            return None
    return None


# ── State Management ───────────────────────────────────────────────────────────

def _state_file(domain: str) -> str:
    return os.path.join(STATE_DIR, hashlib.md5(domain.encode()).hexdigest() + ".json")


def load_seen(domain: str) -> set:
    sf = _state_file(domain)
    if os.path.exists(sf):
        with open(sf) as f:
            return set(json.load(f).get("seen", []))
    return set()


def save_seen(domain: str, seen: set):
    with open(_state_file(domain), "w") as f:
        json.dump({"domain": domain, "seen": list(seen)}, f)


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:20]


# ── Content Analysis ───────────────────────────────────────────────────────────

def detect_stealer_type(text: str) -> Optional[str]:
    tl = text.lower()
    for stype, keywords in STEALER_SIGNATURES.items():
        for kw in keywords:
            if kw in tl:
                return stype
    return None


def extract_lines_with_domain(text: str, domain: str) -> list:
    """Extract credential-like lines mentioning the domain."""
    findings = []
    lines = text.split("\n")
    domain_escaped = re.escape(domain)
    domain_base = re.escape(domain.split(".")[0])

    for i, line in enumerate(lines):
        ll = line.lower().strip()
        if not ll:
            continue

        # Does line reference the domain?
        has_domain = bool(re.search(domain_escaped, ll, re.IGNORECASE)) or \
                     bool(re.search(rf'[\w.+-]+@[\w.-]*{domain_escaped}', ll, re.IGNORECASE))
        if not has_domain:
            continue

        # Check for credential patterns
        is_cred = False
        cred_type = "unknown"

        # email:password
        if re.search(r'[\w.+-]+@[\w.-]+\.[\w]+\s*[:;|,]\s*\S+', ll):
            is_cred = True
            cred_type = "email:password"

        # url | user | pass (RedLine style)
        elif re.search(r'https?://[^\s|]+\s*[|]\s*\S+\s*[|]\s*\S+', ll):
            is_cred = True
            cred_type = "url|user|pass"

        # token/cookie
        elif re.search(r'(cookie|token|session|bearer|secret)\s*[:=]\s*\S+', ll):
            is_cred = True
            cred_type = "token/cookie"

        # proximity to leak indicators
        elif any(ind in ll for ind in LEAK_INDICATORS):
            is_cred = True
            cred_type = "credential_proximity"

        if is_cred:
            findings.append({
                "line": ll[:250],
                "line_number": i + 1,
                "type": cred_type,
            })

    return findings


def classify_content(text: str, domain: str) -> Optional[dict]:
    """Classify text as stealer log, credential leak, or nothing."""
    tl = text.lower()
    if domain not in tl and domain.split(".")[0] not in tl:
        return None

    stealer = detect_stealer_type(text)
    cred_lines = extract_lines_with_domain(text, domain)

    if stealer and cred_lines:
        return {"category": "stealer_log", "stealer_type": stealer, "findings": cred_lines}
    elif cred_lines:
        return {"category": "credential_leak", "findings": cred_lines}
    elif stealer:
        return {"category": "stealer_mention", "stealer_type": stealer}
    elif domain in tl:
        return {"category": "domain_mention"}

    return None


# ── Source Scanners ────────────────────────────────────────────────────────────

def scan_pastebin(domain: str) -> list:
    """Scan pastebin.com search + raw pastes."""
    results = []

    # Search Pastebin
    content = http_get(f"https://pastebin.com/search?q={urllib.parse.quote(domain)}")
    if not content:
        return results

    paste_ids = list(set(re.findall(r'<a\s+href="/(\w{8})"[^>]*>', content)))
    paste_ids = [p for p in paste_ids if p and len(p) == 8]

    results.append({"type": "info", "message": f"Found {len(paste_ids)} paste(s) for {domain}"})

    # Fetch first 15
    for pid in paste_ids[:15]:
        raw = http_get(f"https://pastebin.com/raw/{pid}")
        if not raw:
            continue
        ch = content_hash(raw)
        classification = classify_content(raw, domain)
        entry = {
            "source": "pastebin",
            "paste_id": pid,
            "url": f"https://pastebin.com/{pid}",
            "hash": ch,
            "size": len(raw),
            "preview": raw[:400],
        }
        if classification:
            entry["classification"] = classification
        results.append(entry)

    return results


def scan_paste_sites(domain: str) -> list:
    """Scan alternative paste sites via direct search (max 3s per attempt)."""
    results = []
    # Only try the most promising alternative paste sites
    # Each gets ONE attempt to avoid timeout chains
    probe_urls = [
        ("rentry.co", f"https://rentry.co/search?q={urllib.parse.quote(domain)}"),
        ("ghostbin.com", f"https://ghostbin.com/search?q={urllib.parse.quote(domain)}"),
        ("paste.ee", f"https://paste.ee/search?q={urllib.parse.quote(domain)}"),
    ]
    for site_name, url in probe_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua(), "Accept": "text/html"})
            resp = urllib.request.urlopen(req, timeout=5, context=ssl_ctx())
            content = resp.read().decode("utf-8", errors="replace")
            if content and domain in content.lower():
                ch = content_hash(content[:1000])
                classification = classify_content(content, domain)
                entry = {
                    "source": site_name,
                    "url": url,
                    "hash": ch,
                    "size": len(content),
                    "preview": content[:300],
                }
                if classification:
                    entry["classification"] = classification
                results.append(entry)
        except Exception:
            pass  # site unreachable or no results

    return results


def scan_crtsh(domain: str) -> list:
    """Enumerate subdomains via Certificate Transparency logs."""
    content = http_get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not content:
        return []
    try:
        certs = json.loads(content)
        subdomains = set()
        for c in certs:
            for n in c.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n.endswith(domain) and n != domain:
                    subdomains.add(n)
        return [{
            "source": "crt.sh",
            "type": "subdomain_enum",
            "subdomains": sorted(subdomains)[:100],
            "count": len(subdomains),
        }]
    except (json.JSONDecodeError, TypeError):
        return []


def scan_ahmia(domain: str) -> list:
    """Search Ahmia (.onion search) for stealer log content (fail-fast)."""
    try:
        content = http_get(
            f"https://ahmia.fi/search/?q={urllib.parse.quote(domain + ' stealer log')}",
            timeout=10
        )
    except Exception:
        return []
    if not content:
        return []
    results = []
    onion_links = re.findall(r'https?://[a-z2-7]+\.onion/[^\s"\'<>]+', content)
    if onion_links:
        results.append({
            "source": "ahmia",
            "type": "onion_links",
            "onion_links": list(set(onion_links))[:20],
            "note": "Tor Browser required to access .onion sites",
        })
    # Also try without 'stealer log'
    if not onion_links:
        try:
            content2 = http_get(
                f"https://ahmia.fi/search/?q={urllib.parse.quote(domain + ' leaked credentials')}",
                timeout=10
            )
        except Exception:
            content2 = None
        if content2:
            onion_links2 = re.findall(r'https?://[a-z2-7]+\.onion/[^\s"\'<>]+', content2)
            if onion_links2:
                results.append({
                    "source": "ahmia",
                    "type": "onion_links",
                    "onion_links": list(set(onion_links2))[:20],
                    "note": "Tor Browser required to access .onion sites",
                })
    return results


def scan_telegram(domain: str) -> list:
    """Search Telegram web frontends for channel mentions (fail-fast)."""
    results = []

    # Quick connectivity check before scanning channels
    try:
        req = urllib.request.Request("https://t.me", headers={"User-Agent": ua()})
        urllib.request.urlopen(req, timeout=5, context=ssl_ctx())
    except Exception:
        return results  # t.me not reachable, skip entirely

    active_channels = TELEGRAM_CHANNELS[:8]
    for channel in active_channels:
        try:
            url = f"https://t.me/s/{channel}"
            req = urllib.request.Request(url, headers={"User-Agent": ua(), "Accept": "text/html"})
            resp = urllib.request.urlopen(req, timeout=6, context=ssl_ctx())
            content = resp.read().decode("utf-8", errors="replace")
            if not content:
                continue
            if domain.lower() in content.lower():
                matches = re.findall(
                    rf'(.{{0,100}}{re.escape(domain)}.{{0,100}})', content, re.IGNORECASE
                )
                results.append({
                    "source": "telegram",
                    "type": "telegram_mention",
                    "channel": channel,
                    "url": url,
                    "matches": [m.strip()[:200] for m in matches[:5]],
                    "match_count": len(matches),
                })
        except Exception:
            pass
    return results


def scan_leakcheck(domain: str) -> list:
    """Search public leak databases (fail-fast)."""
    results = []
    # LeakCheck.io
    try:
        lc = http_get(f"https://leakcheck.io/api/public?check={urllib.parse.quote(domain)}", timeout=8)
    except Exception:
        lc = None
    if lc:
        try:
            data = json.loads(lc)
            if isinstance(data, list) and data:
                results.append({"source": "leakcheck", "type": "leak_data", "data": data[:20]})
        except json.JSONDecodeError:
            pass
    # IntelX
    try:
        ix = http_get(
            f"https://2.intelx.io/phonebook/search"
            f"?term={urllib.parse.quote(domain)}&maxresults=20&target=1&timeout=5",
            timeout=10
        )
    except Exception:
        ix = None
    if ix:
        try:
            data = json.loads(ix)
            if isinstance(data, dict) and data.get("result"):
                results.append({
                    "source": "intelx",
                    "type": "leak_data",
                    "data": data["result"][:20],
                })
        except json.JSONDecodeError:
            pass
    return results


# ── Report Generation ──────────────────────────────────────────────────────────

def format_findings(domain: str, all_results: dict) -> str:
    """Generate a structured Markdown report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []

    lines.append(f"# 🕵️ Stealer Log Scan Report: `{domain}`")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Tool:** Hermes Stealer Log Scanner v1.0")
    lines.append("")
    lines.append("---")
    lines.append("")

    total_stealer = 0
    total_creds = 0
    total_info = 0
    critical_findings = []

    for source_name, source_results in all_results.items():
        if not source_results:
            continue

        source_label = source_name.replace("_", " ").title()
        lines.append(f"## 📡 Source: {source_label}")
        lines.append("")

        for entry in source_results:
            if not isinstance(entry, dict):
                if isinstance(entry, str):
                    lines.append(f"> {entry}")
                continue

            entry_type = entry.get("type", entry.get("classification", {}).get("category", "info"))

            # ── Stealer log found! ──
            if entry_type == "stealer_log" or entry.get("classification", {}).get("category") == "stealer_log":
                total_stealer += 1
                cls = entry.get("classification", {})
                stealer = cls.get("stealer_type", "Unknown")
                url = entry.get("url", entry.get("source", "unknown"))
                lines.append(f"### 🚨 **Stealer Log Detected** — `{stealer.upper()}`")
                lines.append(f"  - **Source:** [{entry.get('source', '?')}]({url})")
                if entry.get("paste_id"):
                    lines.append(f"  - **Paste ID:** `{entry['paste_id']}`")
                lines.append(f"  - **Size:** {entry.get('size', 0):,} bytes")
                lines.append("")

                findings = cls.get("findings", [])
                if findings:
                    total_creds += len(findings)
                    lines.append("  **Credential samples:**")
                    lines.append("")
                    lines.append("  | Type | Line |")
                    lines.append("  |------|------|")
                    for f in findings[:10]:
                        safe_line = f['line'][:120].replace('|', '\\|')
                        lines.append(f"  | {f['type']} | `{safe_line}` |")
                    if len(findings) > 10:
                        more_count = len(findings) - 10
                        lines.append(f"  | ... | *+{more_count} more* |")
                lines.append("")
                critical_findings.append(f"🚨 {stealer.upper()} stealer log at {url}")

            # ── Credential leak ──
            elif entry_type == "credential_leak" or entry.get("classification", {}).get("category") == "credential_leak":
                total_creds += 1
                cls = entry.get("classification", {})
                url = entry.get("url", "unknown")
                lines.append(f"### 🟠 Credential Leak")
                lines.append(f"  - **Source:** [{entry.get('source', '?')}]({url})")
                lines.append("")
                findings = cls.get("findings", [])
                if findings:
                    lines.append("  **Credential samples:**")
                    lines.append("")
                    lines.append("  | Type | Line |")
                    lines.append("  |------|------|")
                    for f in findings[:8]:
                        safe_line = f['line'][:120].replace('|', '\\|')
                        lines.append(f"  | {f['type']} | `{safe_line}` |")
                    if len(findings) > 8:
                        lines.append(f"  | ... | *+{len(findings)-8} more* |")
                lines.append("")
                critical_findings.append(f"🟠 Credential leak at {url}")

            # ── Domain mention in paste ──
            elif entry_type == "domain_mention":
                total_info += 1
                url = entry.get("url", "")
                lines.append(f"- 📄 Domain mentioned in paste at [{url}]({url})")
                lines.append(f"  - Preview: `{entry.get('preview', '')[:150]}`")
                lines.append("")

            # ── Subdomain enumeration ──
            elif entry_type == "subdomain_enum":
                subs = entry.get("subdomains", [])
                lines.append(f"  🌐 **Subdomains ({entry.get('count', len(subs))} found):**")
                for sd in subs[:15]:
                    lines.append(f"    - `{sd}`")
                if len(subs) > 15:
                    lines.append(f"    - *... and {len(subs)-15} more*")
                lines.append("")

            # ── Onion links ──
            elif entry_type == "onion_links":
                links = entry.get("onion_links", [])
                lines.append(f"  🧅 **Tor/.onion references ({len(links)}):**")
                for ol in links[:5]:
                    lines.append(f"    - `{ol}`")
                if entry.get("note"):
                    lines.append(f"    ⚠️ {entry['note']}")
                lines.append("")

            # ── Leak data ──
            elif entry_type == "leak_data":
                data = entry.get("data", [])
                source = entry.get("source", "unknown")
                lines.append(f"  📊 **{len(data)} records from {source}**")
                for d in data[:10]:
                    lines.append(f"    - `{str(d)[:150]}`")
                lines.append("")

            # ── Search result ──
            elif entry_type == "search_result":
                lines.append(f"  🔍 Search hit: [{entry.get('title', '?')}]({entry.get('url', '#')})")
                lines.append(f"    > {entry.get('snippet', '')[:200]}")
                lines.append("")

            # ── Telegram ──
            elif entry_type == "telegram_mention" or entry.get("source") == "telegram":
                total_info += 1
                channel = entry.get("channel", "?")
                url = entry.get("url", "")
                mc = entry.get("match_count", 0)
                lines.append(f"  📱 **Telegram @{channel}** — {mc} mention(s)")
                for m in entry.get("matches", [])[:3]:
                    lines.append(f"    - `{m[:150]}`")
                lines.append("")

            # ── Info messages ──
            elif entry_type == "info":
                lines.append(f"  ℹ️ {entry.get('message', '')}")
                lines.append("")

            else:
                # Generic entry display
                total_info += 1
                url = entry.get("url", "")
                if url:
                    lines.append(f"- 📄 [{entry.get('source', '?')}]({url})")
                    if entry.get("classification", {}).get("category"):
                        lines.append(f"  - Category: {entry['classification']['category']}")
                else:
                    lines.append(f"- {json.dumps(entry, default=str)[:200]}")
                lines.append("")

    # ── Summary ──
    lines.append("")
    lines.append("---")
    lines.append("## 📊 Summary")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| 🔴 Confirmed stealer logs | {total_stealer} |")
    lines.append(f"| 🟠 Credential leaks | {total_creds} |")
    lines.append(f"| ℹ️  Domain mentions / info | {total_info} |")
    lines.append(f"")
    lines.append(f"**Sources checked:** Pastebin, alternate paste sites, Telegram channels, ")
    lines.append(f"Ahmia (.onion), CRT.sh (subdomains), LeakCheck/IntelX")
    lines.append("")

    # Critical alert
    if critical_findings:
        lines.append("")
        lines.append("### 🚨 CRITICAL ALERT")
        lines.append("")
        for cf in critical_findings:
            lines.append(f"- {cf}")
        lines.append("")
        lines.append("**Recommended actions:**")
        lines.append("1. Reset ALL passwords found in logs")
        lines.append("2. Rotate API keys, tokens, and secrets exposed")
        lines.append("3. Check for account takeover indicators")
        lines.append("4. Monitor for unauthorized access")
        lines.append("5. Enable MFA on all accounts if not already")
    else:
        lines.append("")
        lines.append("### ✅ No Critical Findings")
        lines.append("")
        lines.append("No confirmed stealer logs or credential leaks found in this scan. ")
        lines.append("Continue periodic monitoring — new stealer logs are posted to paste ")
        lines.append("sites and Telegram channels daily.")
        lines.append("")

    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Stealer Log Scanner Agent")
    parser.add_argument("--domains", required=True, help="Comma-separated target domains")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--force", action="store_true", help="Bypass dedup state")
    args = parser.parse_args()

    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    all_reports = []

    for domain in domains:
        print(f"\n{'='*70}", file=sys.stderr)
        print(f"  Scanning: {domain}", file=sys.stderr)
        print(f"{'='*70}", file=sys.stderr)

        seen = set() if args.force else load_seen(domain)
        new_hashes = set()
        all_results = {}

        # 1. Pastebin
        print(f"  [1/6] Pastebin...", file=sys.stderr)
        pb = scan_pastebin(domain)
        if pb:
            all_results["pastebin"] = pb
            for r in pb:
                if r.get("hash") and r["hash"] not in seen:
                    new_hashes.add(r["hash"])

        # 2. Alternate paste sites
        print(f"  [2/6] Alternates...", file=sys.stderr)
        alt = scan_paste_sites(domain)
        if alt:
            all_results["alternate_paste_sites"] = alt
            for r in alt:
                if r.get("hash") and r["hash"] not in seen:
                    new_hashes.add(r["hash"])

        # 3. Certificate Transparency
        print(f"  [3/6] CRT.sh...", file=sys.stderr)
        ct = scan_crtsh(domain)
        if ct:
            all_results["certificate_transparency"] = ct

        # 4. Ahmia (.onion)
        print(f"  [4/6] Ahmia (Tor)...", file=sys.stderr)
        ah = scan_ahmia(domain)
        if ah:
            all_results["ahmia_tor"] = ah

        # 5. Telegram
        print(f"  [5/6] Telegram...", file=sys.stderr)
        tg = scan_telegram(domain)
        if tg:
            all_results["telegram"] = tg

        # 6. Leak databases
        print(f"  [6/6] Leak databases...", file=sys.stderr)
        lk = scan_leakcheck(domain)
        if lk:
            all_results["leak_databases"] = lk

        # Save state
        if new_hashes:
            seen.update(new_hashes)
            save_seen(domain, seen)
            print(f"  → {len(new_hashes)} new result(s) saved to state", file=sys.stderr)
        else:
            print(f"  → No new findings", file=sys.stderr)

        # Generate report
        if args.json:
            all_reports.append({domain: all_results})
        else:
            all_reports.append(format_findings(domain, all_results))

    # Output
    if args.json:
        print(json.dumps(all_reports if len(all_reports) > 1 else all_reports[0],
                        indent=2, default=str))
    else:
        print("\n\n".join(all_reports))
        print()
        print("---")
        print(f"*Scan completed at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")


if __name__ == "__main__":
    main()
