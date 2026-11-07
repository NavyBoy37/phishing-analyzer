"""
unit_test.py - known emails and strings in, expected checks out.
    python unit_test.py

Every function starting with test_ gets run. No test framework needed,
a failed assert prints which test broke and the run exits non-zero.
"""

import email
import sys
import traceback
from email import policy

import check_functions
import parse_functions


def blank_email(**fields):
    """A parsed email with nothing suspicious in it. Override fields per test."""
    parsed = {
        "file": "test.eml", "subject": "hello", "date": "",
        "from_name": "Alice", "from_address": "alice@company.example", "from_domain": "company.example",
        "reply_to": [], "return_path": "alice@company.example",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "received": [], "text": "", "html": "", "links": [], "attachments": [],
    }
    parsed.update(fields)
    return parsed


def checks_fired(parsed):
    return {h["check"] for h in check_functions.score_email(parsed)["hits"]}


# ------------------------------------------------------------------ helpers
def test_registered_domain():
    assert check_functions.registered_domain("mail.paypal.com") == "paypal.com"
    assert check_functions.registered_domain("paypal.com.verify-login.example") == "verify-login.example"


def test_edit_distance():
    assert check_functions.edit_distance("paypal", "paypal") == 0
    assert check_functions.edit_distance("paypa1", "paypal") == 1
    assert check_functions.edit_distance("kitten", "sitting") == 3


def test_lookalike_homoglyph():
    assert check_functions.lookalike_of("paypa1.com") == "paypal.com"
    assert check_functions.lookalike_of("rnicrosoft.com") == "microsoft.com"


def test_lookalike_brand_in_subdomain():
    assert check_functions.lookalike_of("paypal.com.account-verify.example") == "paypal.com"
    assert check_functions.lookalike_of("docusign-review.example") == "docusign.com"


def test_lookalike_leaves_real_domains_alone():
    assert check_functions.lookalike_of("www.paypal.com") is None
    assert check_functions.lookalike_of("login.microsoftonline.example") is None
    assert check_functions.lookalike_of("github.com") is None


# -------------------------------------------------------------- parsing
def test_extract_links_keeps_display_text():
    html = '<p><a href="http://198.51.100.9/x">https://www.paypal.com/login</a></p>'
    links = parse_functions.extract_links("", html)
    assert links == [{"url": "http://198.51.100.9/x", "text": "https://www.paypal.com/login"}]


def test_extract_links_plain_text():
    links = parse_functions.extract_links("go to https://example.com/a, then stop.", "")
    assert links == [{"url": "https://example.com/a", "text": "https://example.com/a"}]


def test_url_host_ignores_userinfo():
    assert parse_functions.url_host("https://paypal.com@evil.example/login") == "evil.example"


def test_parse_auth_results():
    raw = b"Authentication-Results: mx.test; spf=softfail; dkim=none; dmarc=fail\nSubject: x\n\nbody\n"
    message = email.message_from_bytes(raw, policy=policy.default)
    assert parse_functions.parse_auth_results(message) == {"spf": "softfail", "dkim": "none", "dmarc": "fail"}


# --------------------------------------------------------------- checks
def test_clean_email_scores_zero():
    result = check_functions.score_email(blank_email())
    assert result["score"] == 0
    assert result["verdict"] == "LIKELY CLEAN"


def test_auth_failures():
    fired = checks_fired(blank_email(auth={"spf": "fail", "dkim": "pass", "dmarc": "fail"}))
    assert fired == {"spf_fail", "dmarc_fail"}


def test_reply_to_mismatch():
    assert "reply_to_mismatch" in checks_fired(blank_email(reply_to=["payroll@freemail.example"]))
    # a different mailbox on the same domain is fine
    assert checks_fired(blank_email(reply_to=["help@support.company.example"])) == set()


def test_display_name_spoof():
    spoof = blank_email(from_name="PayPal Service", from_address="x@mailer.example", from_domain="mailer.example",
                        return_path="x@mailer.example")
    assert "display_name_spoof" in checks_fired(spoof)

    embedded = blank_email(from_name="ceo@company.example", from_address="ceo@freemail.example",
                           from_domain="freemail.example", return_path="ceo@freemail.example")
    assert "display_name_spoof" in checks_fired(embedded)


def test_link_text_mismatch():
    links = [{"url": "https://login.evil.example/", "text": "www.paypal.com"}]
    assert "link_text_mismatch" in checks_fired(blank_email(links=links))
    # "Click here" isn't a domain, so it can't mismatch
    links = [{"url": "https://login.evil.example/", "text": "Click here"}]
    assert "link_text_mismatch" not in checks_fired(blank_email(links=links))


def test_link_checks():
    links = [
        {"url": "http://203.0.113.5/a", "text": "http://203.0.113.5/a"},
        {"url": "https://bit.ly/abc", "text": "https://bit.ly/abc"},
        {"url": "https://xn--pypal-4ve.com/", "text": "https://xn--pypal-4ve.com/"},
        {"url": "https://paypal.com@evil.example/", "text": "https://paypal.com@evil.example/"},
    ]
    fired = checks_fired(blank_email(links=links))
    assert {"ip_url", "shortener_url", "punycode_url", "credentials_in_url", "plain_http_url"} <= fired


def test_link_points_are_capped():
    links = [{"url": f"http://203.0.113.{i}/", "text": "x"} for i in range(20)]
    result = check_functions.score_email(blank_email(links=links))
    assert result["score"] == 50


def test_attachments():
    attachments = [
        {"filename": "invoice.pdf.exe", "sha256": "a", "size": 1, "content_type": "x"},
        {"filename": "setup.msi", "sha256": "b", "size": 1, "content_type": "x"},
        {"filename": "budget.xlsm", "sha256": "c", "size": 1, "content_type": "x"},
        {"filename": "photo.jpg", "sha256": "d", "size": 1, "content_type": "x"},
    ]
    hits = check_functions.check_attachments(blank_email(attachments=attachments))
    assert [h["check"] for h in hits] == ["double_extension", "risky_attachment", "macro_attachment"]


def test_urgency_is_capped():
    text = "urgent immediately final notice past due action required within 24 hours"
    result = check_functions.score_email(blank_email(text=text))
    assert result["score"] == 15


# ------------------------------------------------------------ end to end
def test_sample_verdicts():
    expected = {
        "sample_emails/credential_harvest.eml": "LIKELY PHISHING",
        "sample_emails/invoice_attachment.eml": "LIKELY PHISHING",
        "sample_emails/legit_statement.eml": "LIKELY CLEAN",
    }
    for path, verdict in expected.items():
        result = check_functions.score_email(parse_functions.load_email(path))
        assert result["verdict"] == verdict, f"{path} got {result['verdict']}"


def test_sample_attachment_hashes():
    parsed = parse_functions.load_email("sample_emails/invoice_attachment.eml")
    names = [a["filename"] for a in parsed["attachments"]]
    assert names == ["Invoice_20931.pdf.exe", "remittance_form.xlsm"]
    assert all(len(a["sha256"]) == 64 for a in parsed["attachments"])


# ------------------------------------------------------------------- runner
def run_tests():
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, test in tests:
        try:
            test()
            print("PASS  " + name)
        except Exception:
            failed += 1
            print("FAIL  " + name)
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if run_tests() else 0)
