"""Command line interface."""
import argparse
import json
import sys

from . import __version__
from .audit import audit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, "error: " + message + "\n")


def main(argv=None):
    parser = Parser(description="Audit documentation authentication claims offline.")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on", choices=["HIGH", "MEDIUM"], default="MEDIUM")
    parser.add_argument("--ignore", default="", metavar="RULE,...")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.path, set(args.ignore.split(",")))
    except (OSError, ValueError, UnicodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 1
    failed = any(f["severity"] == "HIGH" or args.fail_on == "MEDIUM" for f in result["findings"])
    result["summary"]["status"] = "FAIL" if failed else "PASS"
    if args.json:
        print(json.dumps(result, ensure_ascii=True))
    else:
        for f in result["findings"]:
            print('{severity} {rule} {file}:{line} claim={claim} evidence={evidence}'.format(
                **dict(f, claim=json.dumps(f["claim"]), evidence=json.dumps(f["evidence"]))))
        if args.verbose:
            for c in result["verified_claims"]:
                print('VERIFIED {file}:{line} claim={claim}'.format(**dict(c, claim=json.dumps(c["claim"]))))
        print(result["summary"]["status"])
    return 2 if failed else 0
