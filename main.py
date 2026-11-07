"""
main.py - score one or more suspicious emails saved as .eml files.
    python main.py sample_emails/*.eml
    python main.py reported.eml --json analysis.json

Works fully offline. Nothing is clicked, fetched, or uploaded anywhere.
"""

import argparse

import check_functions
import parse_functions
import report_functions


def get_args():
    parser = argparse.ArgumentParser(description="Offline phishing triage for .eml files.")
    parser.add_argument("emails", nargs="+", help="one or more .eml files")
    parser.add_argument("--json", dest="json_out", help="write every analysis + IOCs to this JSON file")
    return parser.parse_args()


def run():
    args = get_args()
    reports = []

    for path in args.emails:
        # 1. parse headers, body, links, attachments
        parsed = parse_functions.load_email(path)

        # 2. run every check and score it
        result = check_functions.score_email(parsed)
        iocs = check_functions.collect_iocs(parsed)

        # 3. report
        report_functions.print_report(parsed, result, iocs)
        reports.append({"file": parsed["file"], "subject": parsed["subject"],
                        "verdict": result["verdict"], "score": result["score"],
                        "hits": result["hits"], "iocs": iocs})

    if args.json_out:
        report_functions.write_json(reports, args.json_out)


if __name__ == "__main__":
    run()
