#!/usr/bin/env python3
"""
Stealer Log Scanner — Lightweight Version
==========================================
Fast fail-proof scanner for credential leaks and stealer logs.

Searches:
  1. Pastebin (search + raw pastes)
  2. Certificate Transparency logs (subdomain discovery)
  3. Ahmia (.onion search engine)
  4. Telegram public channels (fail-fast)
  5. Leak database APIs

Every step has a hard timeout. Total per-domain scan ≤ 60s.
No external dependencies — stdlib only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import hashlib
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

# ── Config ─────────────────────────────────────────────────────────────────────

STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stealer_log_state")
os.makedirs(STATE_DIR, exist_ok=True)

TELEGRAM_CHANNELS = [
    "stealer_logs_channel", "leaked_credentials", "dumpsters",
    "combos_list", "leakbase", "leakzone", "leakedlogs", "logs_dump",
]

STEALER_SIGNATURES = {
    "redline": ["redline stealer", "redline log", "redline"],
    "vidar": ["vidar stealer", "vidar"],
    "raccoon": ["raccoon stealer", "raccoon v2"],
    "lumma": ["lumma stealer", "lummac2"],
    "stealc": ["stealc stealer"],
    "agenttesla": ["agenttesla", "agent tesla"],
    "azorult": ["azorult"],
    "risepro": ["risepro", "rise pro"],
    "warzone": ["warzone rat"],
    "asyncrat": ["asyncrat", "async rat"],
    "nanocore": ["nanocore rat"],
}

CRED_INDICATORS = [
    "password", "passwd", "pwd", "email", "mail",
    "login", "username", "token", "secret",
    "apikey", "api_key", "cookie", "session",
    "wallet", "seed", "private key", "mnemonic",
]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/125.0.0.0 Safari/537.36")


# ── Helpers ────────────────────────────────────────────────────────────────────

def fetch(url: str, timeout: int = 10) -> Optional[str]:
    """Fetch URL via curl (urllib has TLS issues on this platform)."""
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-A", UA,
             "-o", "-", url],
            capture_output=True, timeout=timeout + 5
        )
        if r.returncode == 0 and r.stdout:
            return r.stdout.decode("utf-8", errors="replace")
        return None
    except Exception:
        return None


def state_file(domain: str) -> str:
    h = hashlib.md5(domain.encode()).hexdigest()
    return os.path.join(STATE_DIR, f"{h}.json")


def load_seen(domain: str) -> set:
    sf = state_file(domain)
    if os.path.exists(sf):
        with open(sf) as f:
            return set(json.load(f).get("seen", []))
    return set()


def save_seen(domain: str, seen: set):
    with open(state_file(domain), "w") as f:
        json.dump({"domain": domain, "seen": list(seen)}, f)


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:20]


# ── Analysis ───────────────────────────────────────────────────────────────────

def detect_stealer(text: str) -> Optional[str]:
    tl = text.lower()
    for stype, keywords in STEALER_SIGNATURES.items():
        for kw in keywords:
            if kw in tl:
                return stype
    return None


def extract_findings(text: str, domain: str) -> list:
    """Extract credential-like lines mentioning the domain."""
    findings = []
    domain_esc = re.escape(domain)
    for i, line in enumerate(text.split("\n")):
        ll = line.lower().strip()
        if not ll:
            continue
        if domain not in ll and domain.split(".")[0] not in ll:
            if not re.search(rf'[\w.+-]+@[\w.-]*{domain_esc}', ll):
                continue
        # email:password
        if re.search(r'[\w.+-]+@[\w.-]+\.[\w]+\s*[:;|,]\s*\S+', ll):
            findings.append({"line": ll[:200], "n": i+1, "type": "email:pass"})
        elif re.search(r'https?://[^\s|]+\s*[|]\s*\S+\s*[|]\s*\S+', ll):
            findings.append({"line": ll[:200], "n": i+1, "type": "url|user|pass"})
        elif re.search(r'(cookie|token|session|secret)\s*[:=]\s*\S+', ll):
            findings.append({"line": ll[:200], "n": i+1, "type": "token"})
        elif any(ind in ll for ind in CRED_INDICATORS):
            findings.append({"line": ll[:200], "n": i+1, "type": "cred_prox"})
    return findings


def classify(text: str, domain: str) -> Optional[dict]:
    tl = text.lower()
    if domain not in tl and domain.split(".")[0] not in tl:
        return None

    # Skip HTML boilerplate / Cloudflare walls / CAPTCHA pages
    if text.strip().startswith("<!") or text.strip().startswith("<html"):
        if "<script" in tl and ("cf-ray" in tl or "cloudflare" in tl or "just a moment" in tl):
            return None  # Cloudflare wall

    stealer = detect_stealer(text)
    findings = extract_findings(text, domain)
    if stealer and findings:
        return {"cat": "stealer_log", "stealer": stealer, "findings": findings}
    if findings:
        return {"cat": "credential_leak", "findings": findings}
    if stealer:
        return {"cat": "stealer_mention", "stealer": stealer}
    if domain in tl:
        return {"cat": "domain_mention"}
    return None


# ── Scanners ───────────────────────────────────────────────────────────────────

def scan_pastebin(domain: str) -> list:
    """Pastebin search + raw fetch (fast)."""
    results = []
    html = fetch(f"https://pastebin.com/search?q={urllib.parse.quote(domain)}", timeout=8)
    if not html:
        return results

    pids = list(set(re.findall(r'<a\s+href="/(\w{8})"[^>]*>', html)))
    pids = [p for p in pids if len(p) == 8]
    results.append({"type": "info", "msg": f"{len(pids)} paste(s) found"})

    for pid in pids[:8]:  # max 8 pastes
        raw = fetch(f"https://pastebin.com/raw/{pid}", timeout=6)
        if not raw:
            continue
        h = content_hash(raw)
        cls = classify(raw, domain)
        e = {"source": "pastebin", "id": pid, "url": f"https://pastebin.com/{pid}",
             "hash": h, "size": len(raw), "preview": raw[:300]}
        if cls:
            e["cls"] = cls
        results.append(e)
    return results


def scan_crtsh(domain: str) -> list:
    """CRT.sh for subdomain enumeration."""
    text = fetch(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
    if not text:
        return []
    try:
        certs = json.loads(text)
        subs = set()
        for c in certs:
            for n in str(c.get("name_value", "")).split("\n"):
                n = n.strip().lower()
                if n.endswith(domain) and n != domain:
                    subs.add(n)
        return [{"source": "crt.sh", "type": "subdomains",
                 "subdomains": sorted(subs)[:100], "count": len(subs)}]
    except Exception:
        return []


def scan_ahmia(domain: str) -> list:
    """Ahmia .onion search."""
    html = fetch(f"https://ahmia.fi/search/?q={urllib.parse.quote(domain)}", timeout=8)
    if not html:
        return []
    links = list(set(re.findall(r'https?://[a-z2-7]+\.onion[^\s"\'<>]*', html)))
    if links:
        return [{"source": "ahmia", "type": "onion", "links": links[:15],
                 "note": "Tor Browser required for .onion access"}]
    return []


def scan_telegram(domain: str) -> list:
    """Telegram public channel check."""
    # Quick connectivity check
    if not fetch("https://t.me", timeout=5):
        return []
    results = []
    for ch in TELEGRAM_CHANNELS:
        html = fetch(f"https://t.me/s/{ch}", timeout=6)
        if not html:
            continue
        if domain.lower() in html.lower():
            matches = re.findall(rf'(.{{0,100}}{re.escape(domain)}.{{0,100}})', html, re.I)
            results.append({
                "source": "telegram", "type": "mention",
                "channel": ch, "url": f"https://t.me/s/{ch}",
                "matches": [m.strip()[:150] for m in matches[:5]],
                "count": len(matches),
            })
    return results


def scan_leaks(domain: str) -> list:
    """Public leak DB APIs."""
    results = []
    # LeakCheck.io
    resp = fetch(f"https://leakcheck.io/api/public?check={urllib.parse.quote(domain)}", timeout=6)
    if resp:
        try:
            d = json.loads(resp)
            if isinstance(d, list) and d:
                results.append({"source": "leakcheck", "type": "leak_data", "data": d[:15]})
        except Exception:
            pass
    # IntelX
    resp2 = fetch(
        f"https://2.intelx.io/phonebook/search"
        f"?term={urllib.parse.quote(domain)}&maxresults=15&target=1&timeout=4",
        timeout=8
    )
    if resp2:
        try:
            d = json.loads(resp2)
            if isinstance(d, dict) and d.get("result"):
                results.append({"source": "intelx", "type": "leak_data", "data": d["result"][:15]})
        except Exception:
            pass
    return results


# ── Report ─────────────────────────────────────────────────────────────────────

def make_report(domain: str, results: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []
    lines.append(f"# Stealer Log Scan: {domain}")
    lines.append(f"**{now}**")
    lines.append("")
    lines.append("---")
    lines.append("")

    stealer_count = 0
    cred_count = 0
    info_count = 0
    alerts = []

    for src_name, entries in results.items():
        if not entries:
            continue
        label = src_name.replace("_", " ").title()
        lines.append(f"## [Source] {label}")
        lines.append("")

        for e in entries:
            t = e.get("type", "")
            src = e.get("source", src_name)
            url = e.get("url", "")
            cls = e.get("cls", {})

            # Stealer log
            if cls and cls.get("cat") == "stealer_log":
                stealer_count += 1
                st = cls.get("stealer", "?")
                lines.append(f"### [CRITICAL] Stealer Log — {st.upper()}")
                if url:
                    lines.append(f"  - **URL:** [{src}]({url})")
                if e.get("id"):
                    lines.append(f"  - **ID:** `{e['id']}`")
                lines.append(f"  - **Size:** {e.get('size', 0):,}B")
                fds = cls.get("findings", [])
                if fds:
                    cred_count += len(fds)
                    lines.append("")
                    lines.append("  | Type | Line |")
                    lines.append("  |------|------|")
                    for f in fds[:8]:
                        safe = f['line'][:100].replace('|', '\\|')
                        lines.append(f"  | {f['type']} | `{safe}` |")
                    if len(fds) > 8:
                        lines.append(f"  | ... | *+{len(fds)-8} more* |")
                lines.append("")
                alerts.append(f"[CRITICAL] {st.upper()} stealer log at {url or src}")
                continue

            # Credential leak
            if cls and cls.get("cat") == "credential_leak":
                cred_count += 1
                lines.append(f"### [LEAK] Credential Leak")
                if url:
                    lines.append(f"  - **URL:** [{src}]({url})")
                fds = cls.get("findings", [])
                if fds:
                    lines.append("")
                    lines.append("  | Type | Line |")
                    lines.append("  |------|------|")
                    for f in fds[:6]:
                        safe = f['line'][:100].replace('|', '\\|')
                        lines.append(f"  | {f['type']} | `{safe}` |")
                    if len(fds) > 6:
                        lines.append(f"  | ... | *+{len(fds)-6} more* |")
                lines.append("")
                alerts.append(f"[LEAK] Credential leak at {url or src}")
                continue

            # Domain mention
            if cls and cls.get("cat") == "domain_mention":
                info_count += 1
                lines.append(f"- [INFO] Domain mention [{src}]({url or '#'})")
                if e.get("preview"):
                    lines.append(f"  - `{e['preview'][:120]}`")
                lines.append("")
                continue

            if cls and cls.get("cat") == "stealer_mention":
                info_count += 1
                lines.append(f"- [STEALER] Mention of `{cls.get('stealer', '?')}`")
                if url:
                    lines.append(f"  - [{url}]({url})")
                lines.append("")
                continue

            # Subdomains
            if t == "subdomains":
                subs = e.get("subdomains", [])
                lines.append(f"  [SUBDOMAINS] ({e.get('count', len(subs))} found):")
                for s in subs[:15]:
                    lines.append(f"    - `{s}`")
                if len(subs) > 15:
                    lines.append(f"    - *... +{len(subs)-15}*")
                lines.append("")
                continue

            # Onion links
            if t == "onion":
                links = e.get("links", [])
                lines.append(f"  [TOR] Links ({len(links)}):")
                for l in links[:5]:
                    lines.append(f"    - `{l}`")
                if e.get("note"):
                    lines.append(f"    [NOTE] {e['note']}")
                lines.append("")
                continue

            # Leak data
            if t == "leak_data":
                data = e.get("data", [])
                lines.append(f"  [LEAK-DB] {len(data)} records from {e.get('source', src)}")
                for d in data[:8]:
                    lines.append(f"    - `{str(d)[:120]}`")
                lines.append("")
                continue

            # Telegram mention
            if t == "mention":
                info_count += 1
                ch = e.get("channel", "?")
                mc = e.get("count", 0)
                lines.append(f"  [TELEGRAM] @{ch} — {mc} mention(s)")
                for m in e.get("matches", [])[:3]:
                    lines.append(f"    - `{m[:120]}`")
                lines.append("")
                continue

            # Info
            if t == "info":
                lines.append(f"  [INFO] {e.get('msg', '')}")
                lines.append("")
                continue

    # Summary
    lines.append("---")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Stealer logs | {stealer_count} |")
    lines.append(f"| Credential leaks | {cred_count} |")
    lines.append(f"| Mentions | {info_count} |")
    lines.append("")
    lines.append("**Sources:** Pastebin, CRT.sh, Ahmia, Telegram, LeakCheck/IntelX")
    lines.append("")

    if alerts:
        lines.append("### CRITICAL ALERTS")
        lines.append("")
        for a in alerts:
            lines.append(f"- {a}")
        lines.append("")
        lines.append("**Actions:**")
        lines.append("1. Reset all exposed passwords")
        lines.append("2. Rotate API keys/tokens")
        lines.append("3. Check for account takeover")
        lines.append("4. Enable MFA where missing")
    else:
        lines.append("### No Critical Findings")
        lines.append("")
        lines.append("No stealer logs or credential leaks found in this scan.")
        lines.append("New logs appear daily — continue periodic monitoring.")
        lines.append("")

    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Stealer Log Scanner")
    parser.add_argument("--domains", required=True, help="Comma-separated domains")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--force", action="store_true", help="Ignore dedup state")
    args = parser.parse_args()

    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    reports = []
    total_start = time.time()

    for domain in domains:
        domain_start = time.time()
        seen = set() if args.force else load_seen(domain)
        new_hashes = set()
        all_results = {}
        domain_timeout = 55  # seconds max per domain

        print(f"  Scanning: {domain}", file=sys.stderr)

        # 1. Pastebin (max 20s)
        print(f"  [1/6] Pastebin...", file=sys.stderr)
        if time.time() - domain_start < domain_timeout:
            try:
                r = scan_pastebin(domain)
                if r:
                    all_results["pastebin"] = r
                    for e in r:
                        if e.get("hash") and e["hash"] not in seen:
                            new_hashes.add(e["hash"])
            except Exception:
                pass

        # 2. Alternate paste sites (max 15s)
        print(f"  [2/6] Alternates...", file=sys.stderr)
        if time.time() - domain_start < domain_timeout:
            try:
                for name, url_fn in [
                    ("rentry.co", lambda: f"https://rentry.co/search?q={urllib.parse.quote(domain)}"),
                    ("ghostbin.com", lambda: f"https://ghostbin.com/search?q={urllib.parse.quote(domain)}"),
                ]:
                    html = fetch(url_fn(), timeout=5)
                    if html and domain in html.lower():
                        h = content_hash(html[:500])
                        cls = classify(html, domain)
                        e = {"source": name, "url": url_fn(), "hash": h,
                             "size": len(html), "preview": html[:250]}
                        if cls:
                            e["cls"] = cls
                        all_results.setdefault("alternates", []).append(e)
                        if h and h not in seen:
                            new_hashes.add(h)
            except Exception:
                pass

        # 3. CRT.sh (max 10s)
        print(f"  [3/6] CRT.sh...", file=sys.stderr)
        if time.time() - domain_start < domain_timeout:
            try:
                r = scan_crtsh(domain)
                if r:
                    all_results["certificates"] = r
            except Exception:
                pass

        # 4. Ahmia (max 8s)
        print(f"  [4/6] Ahmia...", file=sys.stderr)
        if time.time() - domain_start < domain_timeout:
            try:
                r = scan_ahmia(domain)
                if r:
                    all_results["ahmia"] = r
            except Exception:
                pass

        # 5. Telegram (max 10s)
        print(f"  [5/6] Telegram...", file=sys.stderr)
        if time.time() - domain_start < domain_timeout:
            try:
                r = scan_telegram(domain)
                if r:
                    all_results["telegram"] = r
            except Exception:
                pass

        # 6. Leak DBs (max 10s)
        print(f"  [6/6] Leak DBs...", file=sys.stderr)
        if time.time() - domain_start < domain_timeout:
            try:
                r = scan_leaks(domain)
                if r:
                    all_results["leak_databases"] = r
            except Exception:
                pass

        # Save state
        if new_hashes:
            seen.update(new_hashes)
            save_seen(domain, seen)
            print(f"  → {len(new_hashes)} new result(s)", file=sys.stderr)
        else:
            print(f"  → No new findings", file=sys.stderr)

        # Report
        if args.json:
            reports.append({domain: all_results})
        else:
            reports.append(make_report(domain, all_results))

        elapsed = time.time() - domain_start
        print(f"  ⏱ {elapsed:.1f}s", file=sys.stderr)

    # Output
    total = time.time() - total_start
    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2, default=str))
    else:
        print("\n\n".join(reports))
        print()
        print("---")
        print(f"*Scan finished in {total:.0f}s — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")

    print(f"Total: {total:.1f}s", file=sys.stderr)


if __name__ == "__main__":
    main()
