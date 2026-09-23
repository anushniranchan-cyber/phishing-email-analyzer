#!/usr/bin/env python3
"""
Phishing Email Analyzer & IOC Extraction Tool
============================================
Automates phishing email triage for SOC analysts:

  1. Header forensics  - spoofing signals (From vs Return-Path vs Reply-To),
                         Received-chain analysis, SPF/DKIM/DMARC results
  2. URL extraction    - pulls & defangs URLs from text/HTML bodies
  3. Attachment intel  - extracts attachments, computes SHA-256
  4. Threat intel      - correlates URLs/hashes against VirusTotal and
                         sender IPs against AbuseIPDB
  5. Sandbox hook      - pluggable detonation interface (bring your own
                         ANY.RUN / Hybrid Analysis API key)
  6. Reporting         - risk score (0-100) + markdown triage report

Usage:
    python phishing_analyzer.py suspicious.eml --report triage.md
    python phishing_analyzer.py suspicious.eml --vt-key $VT_API_KEY \\
        --abuseipdb-key $ABUSEIPDB_KEY --report triage.md

Requires: requests  (pip install -r requirements.txt)
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

try:
    import requests
except ImportError:
    requests = None

URL_RE = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DEFANG_DOT = re.compile(r"\.")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def defang(url: str) -> str:
    """Defang a URL so it's safe to paste into tickets/reports."""
    url = url.replace("http", "hxxp", 1)
    return url.replace(".", "[.]")


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 1. Header forensics
# ---------------------------------------------------------------------------

def analyze_headers(msg):
    """Return (findings list, extracted sender IPs)."""
    findings = []
    ips = []

    from_addrs = getaddresses(msg.get_all("From", []))
    return_path = getaddresses(msg.get_all("Return-Path", []))
    reply_to = getaddresses(msg.get_all("Reply-To", []))

    from_addr = from_addrs[0][1].lower() if from_addrs else ""
    rp_addr = return_path[0][1].lower() if return_path else ""
    rt_addr = reply_to[0][1].lower() if reply_to else ""

    if from_addr and rp_addr and from_addr.split("@")[-1] != rp_addr.split("@")[-1]:
        findings.append({
            "severity": "HIGH",
            "check": "Envelope mismatch",
            "detail": f"From domain ({from_addr}) != Return-Path domain ({rp_addr}) — classic spoofing signal.",
        })
    if rt_addr and from_addr and rt_addr != from_addr:
        findings.append({
            "severity": "MEDIUM",
            "check": "Reply-To mismatch",
            "detail": f"Replies go to {rt_addr} instead of {from_addr} — credential-harvest setup.",
        })

    # Received chain -> sender IPs
    for hdr in msg.get_all("Received", []):
        for ip in IP_RE.findall(hdr):
            if not ip.startswith(("10.", "192.168.", "172.16.", "127.")) and ip not in ips:
                ips.append(ip)
    if ips:
        findings.append({
            "severity": "INFO",
            "check": "Origin IPs",
            "detail": f"External hops observed: {', '.join(ips[:5])}",
        })

    # Authentication-Results: SPF / DKIM / DMARC
    auth = " ".join(msg.get_all("Authentication-Results", [])).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if m:
            result = m.group(1)
            sev = "HIGH" if result in ("fail", "softfail") else "INFO"
            findings.append({
                "severity": sev,
                "check": mech.upper(),
                "detail": f"{mech.upper()} result: {result}",
            })
        elif auth:
            findings.append({"severity": "LOW", "check": mech.upper(),
                             "detail": f"No {mech.upper()} result published."})

    # Date anomaly (future-dated or very old)
    try:
        d = parsedate_to_datetime(msg.get("Date", ""))
        now = datetime.now(timezone.utc)
        delta = abs((now - d).total_seconds()) / 3600
        if delta > 72:
            findings.append({"severity": "LOW", "check": "Date anomaly",
                             "detail": f"Date header is {delta:.0f}h off current time — possible forgery."})
    except Exception:
        findings.append({"severity": "LOW", "check": "Date anomaly",
                         "detail": "Unparseable Date header."})

    return findings, ips


# ---------------------------------------------------------------------------
# 2 & 3. Body URLs + attachments
# ---------------------------------------------------------------------------

def extract_artifacts(msg):
    urls, attachments = set(), []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = str(part.get("Content-Disposition", ""))
        payload = part.get_payload(decode=True) or b""

        if ctype in ("text/plain", "text/html"):
            try:
                text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                text = ""
            for u in URL_RE.findall(text):
                urls.add(u.rstrip(".,;:!)"))
        elif "attachment" in disp or part.get_filename():
            attachments.append({
                "filename": part.get_filename() or "unnamed",
                "size": len(payload),
                "sha256": sha256_of(payload),
                "content_type": ctype,
            })
    return sorted(urls), attachments


# ---------------------------------------------------------------------------
# 4. Threat intel correlation
# ---------------------------------------------------------------------------

def vt_lookup(ioc: str, ioc_type: str, api_key: str):
    """Query VirusTotal v3 for a URL or file hash. Returns stats dict or None."""
    if not api_key or requests is None:
        return None
    try:
        if ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                             headers={"x-apikey": api_key}, timeout=20)
        else:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{ioc}",
                             headers={"x-apikey": api_key}, timeout=20)
        if r.status_code == 200:
            return r.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception as e:
        print(f"[!] VirusTotal lookup failed for {ioc[:60]}: {e}", file=sys.stderr)
    return None


def abuseipdb_lookup(ip: str, api_key: str):
    """Check an IP against AbuseIPDB. Returns abuse score or None."""
    if not api_key or requests is None:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=20)
        if r.status_code == 200:
            return r.json()["data"]["abuseConfidenceScore"]
    except Exception as e:
        print(f"[!] AbuseIPDB lookup failed for {ip}: {e}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# 5. Sandbox detonation hook
# ---------------------------------------------------------------------------

class SandboxClient:
    """Pluggable detonation interface.

    Wire in your sandbox of choice by subclassing and implementing
    ``detonate`` — e.g. ANY.RUN (api.any.run) or Hybrid Analysis
    (hybrid-analysis.com). Keeping the interface vendor-neutral means the
    triage pipeline doesn't care which sandbox the SOC pays for.
    """

    def detonate(self, file_hash: str, filename: str) -> dict:
        raise NotImplementedError(
            "Subclass SandboxClient and implement detonate() with your sandbox API."
        )


# ---------------------------------------------------------------------------
# 6. Risk scoring + report
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"HIGH": 25, "MEDIUM": 12, "LOW": 4, "INFO": 0}

def risk_score(header_findings, vt_hits, abuse_scores):
    score = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in header_findings)
    score += sum(15 for v in vt_hits if v and v.get("malicious", 0) > 0)
    score += sum(10 for s in abuse_scores if s and s >= 50)
    return min(score, 100)


def verdict(score: int) -> str:
    if score >= 70:
        return "🔴 MALICIOUS — escalate to IR, block IOCs"
    if score >= 35:
        return "🟠 SUSPICIOUS — analyst review required"
    return "🟢 LIKELY BENIGN — monitor"


def build_report(subject, from_addr, date, header_findings, urls, url_intel,
                 attachments, file_intel, ips, ip_intel, score):
    lines = [
        "# 🎣 Phishing Triage Report",
        "",
        f"**Subject:** {subject or '(none)'}",
        f"**From:** {from_addr or '(none)'}",
        f"**Date:** {date or '(none)'}",
        f"**Analyzed:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"## Verdict: {verdict(score)}  (risk score {score}/100)",
        "",
        "## Header forensics",
        "",
        "| Severity | Check | Detail |",
        "|---|---|---|",
    ]
    for f in header_findings:
        lines.append(f"| {f['severity']} | {f['check']} | {f['detail']} |")
    lines += ["", "## URLs extracted", ""]
    if urls:
        lines += ["| URL (defanged) | VT malicious |", "|---|---|"]
        for u, stats in zip(urls, url_intel):
            mal = stats.get("malicious", "?") if stats else "n/a (no key)"
            lines.append(f"| {defang(u)} | {mal} |")
    else:
        lines.append("_None found._")
    lines += ["", "## Attachments", ""]
    if attachments:
        lines += ["| File | SHA-256 | VT malicious |", "|---|---|---|"]
        for a, stats in zip(attachments, file_intel):
            mal = stats.get("malicious", "?") if stats else "n/a (no key)"
            lines.append(f"| {a['filename']} ({a['size']}B) | `{a['sha256'][:16]}…` | {mal} |")
    else:
        lines.append("_None found._")
    lines += ["", "## Sender IPs (AbuseIPDB)", ""]
    if ips:
        lines += ["| IP | Abuse confidence |", "|---|---|"]
        for ip, s in zip(ips, ip_intel):
            lines.append(f"| {ip} | {s if s is not None else 'n/a (no key)'} |")
    else:
        lines.append("_None found._")
    lines += ["", "_Generated by phishing-email-analyzer 🛡️_"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Phishing email triage & IOC extractor")
    ap.add_argument("eml", help="Path to the .eml file")
    ap.add_argument("--report", default="triage_report.md", help="Markdown report output path")
    ap.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"),
                    help="VirusTotal v3 API key (or $VT_API_KEY)")
    ap.add_argument("--abuseipdb-key", default=os.environ.get("ABUSEIPDB_KEY"),
                    help="AbuseIPDB API key (or $ABUSEIPDB_KEY)")
    args = ap.parse_args()

    with open(args.eml, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    from_addrs = getaddresses(msg.get_all("From", []))
    from_addr = from_addrs[0][1] if from_addrs else ""

    print("[*] Running header forensics…")
    header_findings, ips = analyze_headers(msg)

    print("[*] Extracting URLs and attachments…")
    urls, attachments = extract_artifacts(msg)
    print(f"    → {len(urls)} URL(s), {len(attachments)} attachment(s)")

    url_intel, file_intel, ip_intel = [], [], []
    if args.vt_key:
        print("[*] Correlating against VirusTotal…")
        url_intel = [vt_lookup(u, "url", args.vt_key) for u in urls]
        file_intel = [vt_lookup(a["sha256"], "hash", args.vt_key) for a in attachments]
    else:
        print("[!] No VirusTotal key — skipping VT correlation (set --vt-key).")
        url_intel = [None] * len(urls)
        file_intel = [None] * len(attachments)

    if args.abuseipdb_key:
        print("[*] Checking sender IPs against AbuseIPDB…")
        ip_intel = [abuseipdb_lookup(ip, args.abuseipdb_key) for ip in ips]
    else:
        print("[!] No AbuseIPDB key — skipping IP reputation (set --abuseipdb-key).")
        ip_intel = [None] * len(ips)

    score = risk_score(header_findings, url_intel, ip_intel)
    report = build_report(msg.get("Subject"), from_addr, msg.get("Date"),
                          header_findings, urls, url_intel,
                          attachments, file_intel, ips, ip_intel, score)
    with open(args.report, "w") as fh:
        fh.write(report)

    print(f"\n{'='*55}\n  {verdict(score)}  (score {score}/100)\n{'='*55}")
    print(f"[+] Report written to {args.report}")
    print(f"[+] IOCs: {len(urls)} URLs, {len(attachments)} file hashes, {len(ips)} IPs")


if __name__ == "__main__":
    main()
