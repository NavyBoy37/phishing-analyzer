"""
check_functions.py - runs every check against a parsed email.

Each check returns a list of hits:
  {check, weight, detail}
score_email() totals them (with caps) into a score and verdict.
"""

import re

import config
from parse_functions import domain_of, url_host

LINK_CHECKS = ["link_text_mismatch", "lookalike_domain", "ip_url", "shortener_url",
               "punycode_url", "credentials_in_url", "plain_http_url"]


# ------------------------------------------------------------------ helpers
def hit(check, detail):
    return {"check": check, "weight": config.WEIGHTS[check], "detail": detail}


def registered_domain(host):
    """
    Last two labels. Naive (gets co.uk wrong) but good enough to tell
    paypal.com from paypal.com.account-verify.example.
    """
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def normalize_homoglyphs(text):
    text = text.lower()
    for fake, real in config.HOMOGLYPHS.items():
        text = text.replace(fake, real)
    return text


def edit_distance(a, b):
    """Plain Levenshtein, row by row."""
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(previous[j] + 1,                    # delete
                               current[j - 1] + 1,                 # insert
                               previous[j - 1] + (char_a != char_b)))  # swap
        previous = current
    return previous[-1]


def lookalike_of(host):
    """Returns the protected domain this host is imitating, or None."""
    if not host:
        return None
    base = registered_domain(host)
    if base in config.PROTECTED_DOMAINS:
        return None

    base_label = base.split(".")[0]
    host_tokens = re.split(r"[.\-]", host.lower())

    for protected in config.PROTECTED_DOMAINS:
        brand = protected.split(".")[0]
        # paypa1.com, rnicrosoft.com
        if normalize_homoglyphs(base_label) == normalize_homoglyphs(brand):
            return protected
        # examplbank.example, paypall.com
        if len(brand) >= 5 and 0 < edit_distance(base_label, brand) <= 2:
            return protected
        # paypal.com.verify-login.example, examplebank-secure.example
        if len(brand) >= 4 and brand in host_tokens:
            return protected
    return None


def looks_like_domain(text):
    return re.search(r"\b[a-z0-9\-]+(\.[a-z0-9\-]+)+\b", text.lower()) is not None


# ------------------------------------------------------------------- checks
def check_authentication(parsed):
    hits = []
    auth = parsed["auth"]
    for mechanism in ("spf", "dkim", "dmarc"):
        result = auth[mechanism]
        if result in ("fail", "softfail", "permerror"):
            hits.append(hit(mechanism + "_fail", f"{mechanism.upper()}={result}"))
    if all(auth[m] == "none" for m in auth):
        hits.append(hit("auth_missing", "no SPF/DKIM/DMARC results in headers"))
    return hits


def check_sender(parsed):
    hits = []
    from_domain = parsed["from_domain"]

    for reply in parsed["reply_to"]:
        if registered_domain(domain_of(reply)) != registered_domain(from_domain):
            hits.append(hit("reply_to_mismatch", f"replies go to {reply}, not {from_domain}"))

    return_domain = domain_of(parsed["return_path"])
    if return_domain and registered_domain(return_domain) != registered_domain(from_domain):
        hits.append(hit("return_path_mismatch", f"bounces go to {return_domain}, not {from_domain}"))

    # "Example Bank Security <alerts@totally-unrelated.example>"
    name = parsed["from_name"].lower()
    squashed = re.sub(r"[^a-z0-9]", "", name)
    embedded = re.search(r"[\w.\-]+@([\w.\-]+)", name)
    if embedded and registered_domain(embedded.group(1)) != registered_domain(from_domain):
        hits.append(hit("display_name_spoof",
                        f"display name shows {embedded.group(0)} but sender is {parsed['from_address']}"))
    else:
        for protected in config.PROTECTED_DOMAINS:
            brand = protected.split(".")[0]
            if len(brand) >= 4 and brand in squashed and registered_domain(from_domain) != protected:
                hits.append(hit("display_name_spoof",
                                f"display name '{parsed['from_name']}' claims {protected} "
                                f"but sender domain is {from_domain}"))
                break

    imitated = lookalike_of(from_domain)
    if imitated:
        hits.append(hit("lookalike_domain", f"sender domain {from_domain} imitates {imitated}"))
    return hits


def check_links(parsed):
    hits = []
    for link in parsed["links"]:
        url, text = link["url"], link["text"]
        host = url_host(url)

        if text != url and looks_like_domain(text):
            shown = url_host(text if "://" in text else "http://" + text.strip())
            if shown and registered_domain(shown) != registered_domain(host):
                hits.append(hit("link_text_mismatch", f"text says {shown} but link goes to {host}"))

        imitated = lookalike_of(host)
        if imitated:
            hits.append(hit("lookalike_domain", f"{host} imitates {imitated}"))
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            hits.append(hit("ip_url", f"link points at a bare IP: {url}"))
        if registered_domain(host) in config.URL_SHORTENERS or host in config.URL_SHORTENERS:
            hits.append(hit("shortener_url", f"shortened link hides the destination: {url}"))
        if "xn--" in host:
            hits.append(hit("punycode_url", f"punycode (international lookalike) domain: {host}"))
        if re.match(r"https?://[^/]*@", url, re.IGNORECASE):
            hits.append(hit("credentials_in_url", f"'@' in link hides the real host: {url}"))
        if url.lower().startswith("http://"):
            hits.append(hit("plain_http_url", f"unencrypted link: {url}"))
    return hits


def check_attachments(parsed):
    hits = []
    for attachment in parsed["attachments"]:
        name = attachment["filename"].lower()
        extensions = re.findall(r"\.[a-z0-9]{1,5}", name)
        last = extensions[-1] if extensions else ""

        if len(extensions) >= 2 and last in config.RISKY_EXTENSIONS:
            hits.append(hit("double_extension", f"{attachment['filename']} hides a {last} behind {extensions[-2]}"))
        elif last in config.RISKY_EXTENSIONS:
            hits.append(hit("risky_attachment", f"{attachment['filename']} is executable ({last})"))
        if last in config.MACRO_EXTENSIONS:
            hits.append(hit("macro_attachment", f"{attachment['filename']} can carry macros"))
    return hits


def check_language(parsed):
    hits = []
    body = (parsed["subject"] + " " + parsed["text"] + " " + parsed["html"]).lower()
    body = " ".join(re.sub(r"<[^>]+>", " ", body).split())
    for phrase in config.URGENCY_PHRASES:
        if phrase in body:
            hits.append(hit("urgency_language", f"pressure phrase: \"{phrase}\""))
    for phrase in config.CREDENTIAL_PHRASES:
        if phrase in body:
            hits.append(hit("credential_request", f"asks for sensitive info: \"{phrase}\""))
            break
    return hits


CHECKS = [check_authentication, check_sender, check_links, check_attachments, check_language]


# ------------------------------------------------------------------ scoring
def score_email(parsed):
    hits = []
    for check in CHECKS:
        hits += check(parsed)

    link_points = sum(h["weight"] for h in hits if h["check"] in LINK_CHECKS)
    urgency_points = sum(h["weight"] for h in hits if h["check"] == "urgency_language")
    other_points = sum(h["weight"] for h in hits
                       if h["check"] not in LINK_CHECKS and h["check"] != "urgency_language")
    score = (other_points
             + min(link_points, config.LINK_CATEGORY_CAP)
             + min(urgency_points, config.URGENCY_CAP))

    if score >= config.PHISHING_SCORE:
        verdict = "LIKELY PHISHING"
    elif score >= config.SUSPICIOUS_SCORE:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY CLEAN"
    return {"score": score, "verdict": verdict, "hits": hits}


def collect_iocs(parsed):
    """Indicators an analyst would paste into a blocklist or ticket."""
    hosts = sorted({url_host(link["url"]) for link in parsed["links"]} - {""})
    ips = []
    for hop in parsed["received"]:
        for ip in hop["ips"]:
            if ip not in ips:
                ips.append(ip)
    return {
        "sender": parsed["from_address"],
        "reply_to": parsed["reply_to"],
        "urls": [link["url"] for link in parsed["links"]],
        "domains": hosts,
        "relay_ips": ips,
        "attachment_sha256": [a["sha256"] for a in parsed["attachments"]],
    }
