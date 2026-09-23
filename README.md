# 🎣 Phishing Email Analyzer & IOC Extraction Tool

> **What used to take a SOC analyst 30+ minutes of manual triage, now takes seconds.**

An automated phishing triage pipeline built for blue teams. Drop in a `.eml` file, get back a verdict, a risk score, extracted IOCs, and a ready-to-share markdown report — with threat-intel correlation baked in.

## ⚡ Demo

```bash
$ python phishing_analyzer.py samples/suspicious_mailbox_deactivation.eml

[*] Running header forensics…
[*] Extracting URLs and attachments…
    → 1 URL(s), 1 attachment(s)
[!] No VirusTotal key — skipping VT correlation (set --vt-key).

=======================================================
  🔴 MALICIOUS — escalate to IR, block IOCs  (score 100/100)
=======================================================
[+] Report written to triage_report.md
[+] IOCs: 1 URLs, 1 file hashes, 0 IPs
```

## 🔍 What it does

| Stage | Details |
|-------|---------|
| **Header forensics** | Detects From vs Return-Path vs Reply-To mismatches, analyzes the `Received` chain for origin IPs, parses SPF/DKIM/DMARC from `Authentication-Results`, flags date anomalies |
| **URL extraction** | Pulls URLs from text & HTML bodies, auto-defangs them (`hxxp://evil[.]com`) for safe handling |
| **Attachment intel** | Extracts attachments, computes SHA-256 fingerprints |
| **Threat intel** | Correlates URLs & file hashes against **VirusTotal**, sender IPs against **AbuseIPDB** |
| **Sandbox hook** | Pluggable `SandboxClient` interface — wire in ANY.RUN / Hybrid Analysis for detonation |
| **Reporting** | Risk score (0–100), severity-weighted verdict, and a markdown triage report ready to paste into a ticket |

## 🚀 Quick start

```bash
git clone https://github.com/anushniranchan-cyber/phishing-email-analyzer.git
cd phishing-email-analyzer
pip install -r requirements.txt

# Basic triage (no API keys needed for header/body analysis)
python phishing_analyzer.py suspicious.eml --report triage.md

# Full intel correlation
export VT_API_KEY="your_key" ABUSEIPDB_KEY="your_key"
python phishing_analyzer.py suspicious.eml --report triage.md
```

## 📊 Sample output

See [`sample_report.md`](sample_report.md) — generated from the bundled sample phish in [`samples/`](samples/).

## 🧠 How the risk score works

Severity-weighted heuristics, tuned from real SOC triage experience:

- **HIGH (+25):** envelope spoofing, SPF/DKIM/DMARC fail
- **MEDIUM (+12):** Reply-To harvesting setup
- **VT malicious hit (+15 per IOC)**, **AbuseIPDB score ≥ 50 (+10 per IP)**

| Score | Verdict |
|-------|---------|
| 70–100 | 🔴 MALICIOUS — escalate to IR, block IOCs |
| 35–69 | 🟠 SUSPICIOUS — analyst review required |
| 0–34 | 🟢 LIKELY BENIGN — monitor |

## 🗺️ Roadmap

- [ ] ANY.RUN / Hybrid Analysis sandbox detonation module
- [ ] YARA rule scanning on attachments
- [ ] QR code / image-based phish (QRishing) extraction
- [ ] Slack/Teams webhook alerting for MALICIOUS verdicts

## 🛠️ Built with

`Python` `VirusTotal API` `AbuseIPDB API` `Email Forensics` `Threat Intelligence`

---

<p align="center"><i>Built by <a href="https://github.com/anushniranchan-cyber">Anush Niranchan Anandh</a> — Security Operations Analyst 🛡️</i></p>
