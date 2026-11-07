# phishing-analyzer

![tests](https://github.com/NavyBoy37/phishing-analyzer/actions/workflows/tests.yml/badge.svg)

## Purpose

When a user hits "Report phishing", someone has to open the email and decide:
real or not, and what do we block? This does that first pass on a saved `.eml`
file. It reads the headers, links and attachments, explains every point it adds
to the score, and pulls out the IOCs ready to paste into a ticket or blocklist.

It runs **fully offline**: nothing gets clicked, fetched, detonated or uploaded.
That makes it safe to run on live phish.

No dependencies, just the Python 3.10+ standard library.

## What it checks

| Area | Checks |
|---|---|
| **Authentication** | SPF / DKIM / DMARC results from `Authentication-Results` |
| **Sender** | Reply-To and Return-Path pointing somewhere other than From. Display names that claim a brand the sending domain doesn't own (`"PayPal Service" <x@mailer.example>`). Lookalike sender domains |
| **Links** | Visible text that shows one domain while the link goes to another. Lookalikes (`paypa1.com`, `rnicrosoft.com`, `paypal.com.verify-login.example`). Bare IPs, URL shorteners, punycode, `user@host` tricks, plain HTTP |
| **Attachments** | SHA-256 of every file. Executables, double extensions (`invoice.pdf.exe`), macro-capable Office files |
| **Language** | Urgency phrases ("within 24 hours", "account will be suspended"), requests for passwords or SSNs |

Lookalike detection checks three things: digits swapped for letters (`0→o`,
`1→l`, `rn→m`), an edit distance of 1–2 from a protected brand, and a protected
brand name sitting in a subdomain of someone else's domain.

Each check has a weight in `config.py`. Links and urgency phrases are capped so
an email with twenty bad links doesn't drown out everything else. Score ≥60 is
**LIKELY PHISHING** and ≥30 is **SUSPICIOUS**.

## Flow

```
reported.eml
     |
parse_functions.py   headers, auth results, Received hops, text/html,
     |               links (with their display text), attachments + hashes
     |
check_functions.py   every check returns {check, weight, detail}
     |               -> capped total -> verdict, plus an IOC list
     |
report_functions.py  console report / JSON
```

## Files

| File | Purpose |
|---|---|
| `config.py` | Weights, verdict thresholds, protected domains, risky extensions, phrases. **The file you tune.** |
| `main.py` | Command line entry point |
| `parse_functions.py` | Turns a `.eml` into a plain dict |
| `check_functions.py` | All checks, lookalike logic, scoring, IOC collection |
| `report_functions.py` | Console and JSON output |
| `unit_test.py` | Tests, run with `python unit_test.py` |
| `sample_emails/` | Two made-up phish and one legitimate email |

## Run

```bash
python main.py sample_emails/*.eml
python main.py reported.eml --json analysis.json
```

```
==============================================================================
credential_harvest.eml:  LIKELY PHISHING  (score 160)
==============================================================================
Subject:     Action required: unusual sign-in on your account
From:        Example Bank Security <security-alert@examp1ebank.example>
Reply-To:    support@helpdesk-mailer.test
Return-Path: bounce-7731@mass-mailer.test
Auth:        SPF=softfail  DKIM=none  DMARC=fail

Why
---
  +30  lookalike_domain       sender domain examp1ebank.example imitates examplebank.example
  +30  lookalike_domain       examplebank.example.secure-session.test imitates examplebank.example
  +25  link_text_mismatch     text says www.examplebank.example but link goes to 198.51.100.61
  +20  dmarc_fail             DMARC=fail
  +20  display_name_spoof     display name 'Example Bank Security' claims examplebank.example but sender domain is examp1ebank.example
  +15  spf_fail               SPF=softfail
  +15  reply_to_mismatch      replies go to support@helpdesk-mailer.test, not examp1ebank.example
  +15  ip_url                 link points at a bare IP: http://198.51.100.61/eb/login.php?id=4471
  ...

IOCs
----
  domains:  198.51.100.61, examplebank.example.secure-session.test, short.example
  relay IPs: 10.0.0.4, 198.51.100.200, 203.0.113.88
```

To get a `.eml`: in Outlook, drag the message to a folder, or use
*File → Save As*. In Gmail, use *⋮ → Download message*. **Don't open the
attachments.** The tool hashes them without running them.

## Sample emails

All made up. The domains use the reserved `.example` / `.test` names and the
IPs come from the RFC 5737 documentation ranges. The "malware" attachments are
one line of plain text each.

| File | Verdict | What's going on |
|---|---|---|
| `credential_harvest.eml` | Likely phishing (160) | Lookalike bank domain, failed DMARC, IP link disguised as the bank's URL, shortener, 24-hour threat |
| `invoice_attachment.eml` | Likely phishing (105) | "Final notice" invoice with `Invoice_20931.pdf.exe` and a macro-enabled spreadsheet. DKIM/DMARC fail |
| `legit_statement.eml` | Likely clean (0) | Real bank notice: auth passes, links stay on the bank's own domain |

## Limits

- Link extraction from HTML uses a regex, not a full HTML parser, so heavily
  obfuscated markup can slip past it.
- `registered_domain()` takes the last two labels, so `example.co.uk` style
  domains are treated as `co.uk`.
- It only checks what's in the file. Domain age, reputation and sandbox
  detonation need an online service (VirusTotal, urlscan.io), and leaving
  those out is deliberate.
