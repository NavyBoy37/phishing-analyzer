"""
parse_functions.py - opens a .eml file and pulls out everything the checks
need into one plain dict:

  {subject, from_name, from_address, from_domain, reply_to, return_path,
   auth, received, text, html, links, attachments}
"""

import email
import hashlib
import html
import os
import re
import sys
from email import policy
from email.utils import getaddresses, parseaddr


# ----------------------------------------------------------------- headers
def domain_of(address):
    address = (address or "").strip().strip("<>").lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def parse_auth_results(message):
    """
    Pulls spf/dkim/dmarc out of Authentication-Results. Missing = "none".
    Uses the first header, which is the one the receiving server added.
    """
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    headers = message.get_all("Authentication-Results") or []
    if not headers:
        return results
    for mechanism in results:
        match = re.search(mechanism + r"\s*=\s*(\w+)", str(headers[0]), re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


def parse_received(message):
    """Returns the Received hops oldest first, with any IPs found in each."""
    hops = []
    for header in reversed(message.get_all("Received") or []):
        text = " ".join(str(header).split())
        ips = re.findall(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", text)
        from_host = re.search(r"from\s+(\S+)", text)
        hops.append({"from": from_host.group(1) if from_host else "", "ips": ips, "raw": text})
    return hops


# -------------------------------------------------------------------- body
URL_PATTERN = re.compile(r"""https?://[^\s"'<>\)\]]+""", re.IGNORECASE)
ANCHOR_PATTERN = re.compile(r"""<a\s[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
                            re.IGNORECASE | re.DOTALL)
TAG_PATTERN = re.compile(r"<[^>]+>")


def strip_tags(markup):
    return " ".join(html.unescape(TAG_PATTERN.sub(" ", markup)).split())


def extract_links(text, html_body):
    """
    Every link with the text the reader actually sees. Links in the plain text
    part have no separate display text, so text = url.
    """
    links = []
    seen = set()
    for href, inner in ANCHOR_PATTERN.findall(html_body):
        href = html.unescape(href.strip())
        if not href.lower().startswith(("http://", "https://")):
            continue
        links.append({"url": href, "text": strip_tags(inner)})
        seen.add(href)

    # bare URLs in the HTML, with anchors removed first so a fake display
    # URL ("www.yourbank.com" over an IP link) doesn't count as a real link
    html_without_anchors = strip_tags(ANCHOR_PATTERN.sub(" ", html_body))
    for url in URL_PATTERN.findall(text + " " + html_without_anchors):
        url = url.rstrip(".,;:!?")
        if url not in seen:
            links.append({"url": url, "text": url})
            seen.add(url)
    return links


def url_host(url):
    match = re.match(r"https?://(?:[^/@]*@)?([^/:?#]+)", url, re.IGNORECASE)
    return match.group(1).lower() if match else ""


# ------------------------------------------------------------- attachments
def extract_attachments(message):
    attachments = []
    for part in message.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": part.get_filename() or "(no name)",
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    return attachments


# ------------------------------------------------------------------ loading
def _body_text(message, subtype):
    part = message.get_body(preferencelist=(subtype,))
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        return (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")


def load_email(path):
    print("Opening " + path + "...")
    if not os.path.exists(path):
        print("File does not exist: " + path)
        sys.exit(1)

    with open(path, "rb") as eml_file:
        message = email.message_from_binary_file(eml_file, policy=policy.default)

    from_name, from_address = parseaddr(str(message.get("From", "")))
    reply_to = [addr for _, addr in getaddresses([str(message.get("Reply-To", ""))]) if addr]
    text = _body_text(message, "plain")
    html_body = _body_text(message, "html")

    return {
        "file": os.path.basename(path),
        "subject": str(message.get("Subject", "")),
        "date": str(message.get("Date", "")),
        "from_name": from_name,
        "from_address": from_address.lower(),
        "from_domain": domain_of(from_address),
        "reply_to": [addr.lower() for addr in reply_to],
        "return_path": parseaddr(str(message.get("Return-Path", "")))[1].lower(),
        "auth": parse_auth_results(message),
        "received": parse_received(message),
        "text": text,
        "html": html_body,
        "links": extract_links(text, html_body),
        "attachments": extract_attachments(message),
    }
