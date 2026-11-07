"""
config.py - scoring weights and lookup lists live here.
Tune this file, not the logic files.
"""

# ------------------------------------------------------------------ verdict
# Total score at or above these = the verdict. Weights are below.
PHISHING_SCORE = 60
SUSPICIOUS_SCORE = 30

# ------------------------------------------------------------------ weights
# Each check that fires adds its weight to the score. Capped per category in
# check_functions so twenty bad links don't swamp everything else.
WEIGHTS = {
    "spf_fail": 15,
    "dkim_fail": 15,
    "dmarc_fail": 20,
    "auth_missing": 5,
    "reply_to_mismatch": 15,
    "return_path_mismatch": 10,
    "display_name_spoof": 20,
    "link_text_mismatch": 25,
    "lookalike_domain": 30,
    "ip_url": 15,
    "shortener_url": 10,
    "punycode_url": 15,
    "credentials_in_url": 15,
    "plain_http_url": 5,
    "risky_attachment": 35,
    "double_extension": 30,
    "macro_attachment": 25,
    "urgency_language": 5,     # per phrase, capped below
    "credential_request": 15,
}

URGENCY_CAP = 15
LINK_CATEGORY_CAP = 50

# --------------------------------------------------------------- lookup lists
# Domains people get tricked with. Lookalike checks compare every link and
# sender domain against these. Add your own company's domains here.
PROTECTED_DOMAINS = [
    "microsoft.com",
    "office.com",
    "outlook.com",
    "paypal.com",
    "apple.com",
    "amazon.com",
    "google.com",
    "docusign.com",
    "dropbox.com",
    "linkedin.com",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "usps.com",
    "fedex.com",
    "ups.com",
    "irs.gov",
    # the made-up bank used in sample_emails/
    "examplebank.example",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    # the made-up shortener used in sample_emails/
    "short.example",
]

# Attachments that run code when double-clicked.
RISKY_EXTENSIONS = [
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".hta", ".lnk", ".iso", ".img", ".msi", ".jar", ".cpl",
]

# Office formats that can carry macros.
MACRO_EXTENSIONS = [".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xls", ".doc"]

URGENCY_PHRASES = [
    "immediately",
    "urgent",
    "within 24 hours",
    "account will be suspended",
    "account has been suspended",
    "unusual activity",
    "unusual sign-in",
    "final notice",
    "action required",
    "verify your account",
    "failure to",
    "past due",
]

CREDENTIAL_PHRASES = [
    "confirm your password",
    "enter your password",
    "verify your identity",
    "update your payment",
    "login credentials",
    "sign in to restore",
    "social security number",
]

# Characters attackers swap in to fake a domain. Applied before comparing.
HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "rn": "m",
    "vv": "w",
}
