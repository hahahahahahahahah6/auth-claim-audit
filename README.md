# auth-claim-audit

Offline static auditing of documentation promises about credentials and accounts.
Version 0.1.0; Python 3.9 or later; no runtime dependencies. Audited code is never
executed, no network is accessed, and `.env` files are never opened.

Install and run:

```sh
python3 -m pip install .
auth-claim-audit ./project
auth-claim-audit ./project --json
auth-claim-audit ./project --fail-on HIGH --verbose
auth-claim-audit ./project --ignore documented-no-key-claim-false
python3 -m auth_claim_audit --version
```

The path defaults to the current directory. Exit status is 0 for PASS, 2 for
findings meeting the threshold, and 1 for usage/input errors. `--fail-on` accepts
HIGH or MEDIUM (default MEDIUM). `--ignore` takes comma-separated rule names;
ignored findings are dropped. `--verbose` adds verified claims to human output.
`--json` emits findings, verified_claims, and summary, including status and counts.
`--version` prints 0.1.0. Human findings show severity, rule, relative file and
line, quoted claim, and a single matched source line of evidence.

Root README.md and docs/**/*.md are checked case-insensitively. Backtick and
tilde fenced blocks are excluded; inline code counts as prose. No-key claims
cover “no API key”, required/needed variants, “works without an API key”,
credentials/credential, authentication and auth variants. Lines saying “not
enough”, “not sufficient”, or “insufficient” are excluded. No-account claims
cover account/login/sign-up/signup required/needed and works-without variants.
Key-required claims cover “requires [an] API key”, “API key is required”,
“you need an API key”, “you'll need an API key”, and “an API key is needed”.

| Rule | Severity | Evidence |
| --- | --- | --- |
| documented-no-key-claim-false | HIGH | Required credential or Authorization/Bearer use |
| documented-no-account-claim-false | HIGH | Login import or getpass call |
| documented-key-required-unused | MEDIUM | No production credential evidence |
| documented-no-key-claim-test-only | MEDIUM | Required credential evidence only in tests/fixtures |
| documented-no-account-claim-test-only | MEDIUM | Login evidence only in tests/fixtures |

Python ASTs provide evidence. Environment reads through os.getenv,
os.environ.get and os.environ subscripts recognize credential names containing
API_KEY, APIKEY, TOKEN, SECRET, PASSWORD, PASSWD, ACCESS_KEY, AUTH_TOKEN, or
CLIENT_SECRET, case-insensitively. A following letter prevents a token match:
MYTOKEN counts; TOKENIZER_URL does not. Subscript access is strong evidence.
An assigned read with an assertion or a falsy/None guard that raises, exits or
returns a nonzero error code is also strong evidence. Python has no `or raise`
syntax; an `or sys.exit(...)` guard is recognized. Authorization dictionary keys
and Bearer literals in dictionaries/request calls also count as strong evidence.

| Login evidence | Recognized forms |
| --- | --- |
| Imports | oauthlib, authlib, requests_oauthlib, google_auth_oauthlib, google.auth, msal, oauth and submodules |
| Prompt | getpass.getpass calls, including imported aliases |

Required API keys alone never falsify account claims. Any credential read,
Authorization/Bearer evidence or login evidence satisfies the reverse rule.
Production excludes tests/, fixtures/, docs/, test_*.py and *_test.py.
Test and fixture evidence is reported separately; docs Python is excluded.
Symlink files/directories are skipped, as are invalid Python files.
No claims pass; with no Python source each claim receives its corresponding
finding. Ignored findings are not described as verified claims.

## Limitations

This is static pattern matching, not semantic judgement. Bare optional reads,
including reads with defaults, do not falsify a no-key claim. Authorization
literals may belong to optional features and cause false positives; use
`--ignore` when appropriate. The login evidence table is deliberately small.
Dynamic credential names, constructed strings and config-file keys are missed.
Import alias tracking is per-file; data flow between files is not followed.
Evidence contains one matching code line, so audit human output with the same
care as source code. The scanner never opens `.env` files.

## Neighbours

privacy-claim-audit checks network/telemetry presence rather than credential
requirements. config-claim-audit checks default values rather than whether a
credential is required. readme-claim-audit checks install instructions, flags,
links and versions rather than authentication. Bandit and Ruff check code
issues rather than documentation promises. dotenv-linter checks `.env` syntax
rather than documentation versus code requirement truth.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m build
```

The good fixture passes with optional credential use. The bad root has exactly
two HIGH findings. Audit bad/unused separately for the MEDIUM reverse finding:

```sh
auth-claim-audit tests/fixtures/good
auth-claim-audit tests/fixtures/bad
auth-claim-audit tests/fixtures/bad/unused
```

Together those bad projects produce the three specified rule findings. A single
project cannot simultaneously have strong production credential evidence and
zero production credential evidence, so the reverse case has its own root.
The marker-only bad/.env fixture is protected by a test that rejects attempts
to open any `.env`, in addition to checking output for the marker.

MIT licensed.
