import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auth_claim_audit.audit import audit, evidence
from auth_claim_audit.cli import main

FIXTURES = Path(__file__).parent / 'fixtures'


class AuditTests(unittest.TestCase):
    def project(self, prose='No API key required', code='print(1)', name='app.py'):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / 'README.md').write_text(prose)
        if code is not None:
            file = root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(code)
        return root

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main(list(map(str, args)))
        return status, out.getvalue(), err.getvalue()

    def test_good(self):
        result = audit(FIXTURES / 'good')
        self.assertEqual(result['findings'], [])
        self.assertEqual(len(result['verified_claims']), 2)

    def test_bad(self):
        self.assertEqual({f['rule'] for f in audit(FIXTURES / 'bad')['findings']}, {
            'documented-no-key-claim-false', 'documented-no-account-claim-false'})

    def test_unused(self):
        self.assertEqual(audit(FIXTURES / 'bad' / 'unused')['findings'][0]['rule'], 'documented-key-required-unused')

    def test_env_never_opened(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            for flags in [[], ['--json'], ['--verbose']]:
                status, out, err = self.cli(FIXTURES / 'bad', *flags)
                self.assertEqual(status, 2)
                self.assertNotIn('AUTH_CLAIM_AUDIT_NEVER_READ_MARKER_ONLY', out + err)

    def test_json(self):
        status, out, _ = self.cli(FIXTURES / 'good', '--json')
        self.assertEqual(status, 0)
        self.assertEqual(set(json.loads(out)), {'findings', 'verified_claims', 'summary'})

    def test_verbose(self):
        self.assertIn('VERIFIED', self.cli(FIXTURES / 'good', '--verbose')[1])

    def test_default_path(self):
        import os
        old = os.getcwd()
        try:
            os.chdir(FIXTURES / 'good')
            self.assertEqual(self.cli()[0], 0)
        finally:
            os.chdir(old)

    def test_version(self):
        with self.assertRaises(SystemExit) as exc, contextlib.redirect_stdout(io.StringIO()) as out:
            main(['--version'])
        self.assertEqual(exc.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), '0.1.0')

    def test_missing(self):
        self.assertEqual(self.cli('/path/does/not/exist')[0], 1)

    def test_file_root(self):
        self.assertEqual(self.cli(FIXTURES / 'good' / 'README.md')[0], 1)

    def test_usage(self):
        with self.assertRaises(SystemExit) as exc, contextlib.redirect_stderr(io.StringIO()):
            main(['--fail-on', 'LOW'])
        self.assertEqual(exc.exception.code, 1)

    def test_ignore(self):
        root = self.project(code='import os\nx=os.environ["API_KEY"]')
        self.assertEqual(self.cli(root, '--ignore', 'documented-no-key-claim-false')[0], 0)

    def test_threshold(self):
        root = self.project(code='import os\nx=os.environ["API_KEY"]', name='tests/app.py')
        status, out, _ = self.cli(root, '--fail-on', 'HIGH')
        self.assertEqual(status, 0)
        self.assertIn('MEDIUM documented-no-key-claim-test-only', out)

    def test_symlink_source(self):
        root = self.project(code=None)
        (root / 'link.py').symlink_to(FIXTURES.resolve() / 'bad' / 'app.py')
        self.assertEqual(audit(root)['findings'][0]['evidence'], 'no Python source')

    def test_symlink_docs(self):
        root = self.project(prose='', code='print(1)')
        (root / 'docs').mkdir()
        (root / 'docs' / 'x.md').symlink_to(FIXTURES.resolve() / 'bad' / 'README.md')
        self.assertEqual(audit(root)['summary']['claims'], 0)

    def test_symlink_directory(self):
        root = self.project(prose='', code='print(1)')
        (root / 'docs').symlink_to(FIXTURES.resolve() / 'bad', target_is_directory=True)
        self.assertEqual(audit(root)['summary']['claims'], 0)

    def test_docs_claim_line(self):
        root = self.project(prose='')
        (root / 'docs' / 'nested').mkdir(parents=True)
        (root / 'docs' / 'nested' / 'x.md').write_text('\nRequires api key')
        finding = audit(root)['findings'][0]
        self.assertEqual((finding['file'], finding['line']), ('docs/nested/x.md', 2))

    def test_invalid_source(self):
        self.assertEqual(audit(self.project(code='not python !!!'))['findings'], [])

    def test_unreadable(self):
        with patch('auth_claim_audit.audit.os.access', return_value=False):
            self.assertEqual(self.cli(FIXTURES / 'good')[0], 1)

    def test_no_claims(self):
        self.assertEqual(audit(self.project(prose='Hello'))['findings'], [])

    def test_single_line_evidence(self):
        root = self.project(code='import os\nx = os.environ["API_KEY"]\nprint("unrelated")')
        self.assertEqual(audit(root)['findings'][0]['evidence'], 'x = os.environ["API_KEY"]')


def claim_test(prose, kind):
    def test(self):
        code = 'import os\nx=os.environ["API_KEY"]\nimport oauthlib' if kind != 'key-required' else 'print(1)'
        result = audit(self.project(prose=prose, code=code))
        self.assertEqual(len(result['findings']), 1)
    return test

CLAIMS = {
    'no-key': ['no api key required', 'no api key needed', 'works without an api key', 'no api key',
               'no credentials required', 'no credentials needed', 'works without credentials',
               'no credential required', 'no authentication required', 'no auth required'],
    'no-account': ['no account required', 'no account needed', 'no login required', 'no login needed',
                   'no sign-up required', 'no sign-up needed', 'no signup required', 'no signup needed',
                   'works without an account', 'works without logging in'],
    'key-required': ['requires an api key', 'requires api key', 'api key is required',
                     'you need an api key', "you'll need an api key", 'an api key is needed'],
}
for kind, phrases in CLAIMS.items():
    for index, prose in enumerate(phrases):
        setattr(AuditTests, 'test_claim_' + kind.replace('-', '_') + '_' + str(index), claim_test(prose.upper(), kind))


def evidence_test(code, category, expected):
    def test(self):
        self.assertEqual(bool(evidence(code)[category]), expected)
    return test

CASES = [
    ('import os\nx=os.environ["API_KEY"]', 'strong', True),
    ('import os\nx=os.getenv("TOKEN", "")', 'strong', False),
    ('import os\nx=os.getenv("TOKEN")', 'strong', False),
    ('import os\nx=os.environ.get("TOKEN")', 'any', True),
    ('import os\nx=os.getenv("TOKENIZER_URL")', 'any', False),
    ('import os\nx=os.getenv("MYTOKEN")', 'any', True),
    ('import os\nx=os.getenv("client_secret")', 'any', True),
    ('import os\nx=os.getenv("APIKEY")', 'any', True),
    ('import os\nx=os.getenv("ACCESS_KEY")', 'any', True),
    ('import os\nx=os.getenv("PASSWD")', 'any', True),
    ('import os\nx=os.getenv("TOKEN"); assert x', 'strong', True),
    ('import os\nx=os.getenv("TOKEN")\nif not x: raise SystemExit(1)', 'strong', True),
    ('import os\nx=os.getenv("TOKEN")\nif x is None: exit(1)', 'strong', True),
    ('import os\nx=os.getenv("TOKEN")\nif not x: quit(1)', 'strong', True),
    ('import os, sys\nx=os.getenv("TOKEN")\nif not x: sys.exit(1)', 'strong', True),
    ('import os\ndef f():\n x=os.getenv("TOKEN")\n if not x: return 2', 'strong', True),
    ('import os\ndef f():\n x=os.getenv("TOKEN")\n if not x: return 0', 'strong', False),
    ('import os\nx=os.getenv("TOKEN")\nif not x: print("missing")', 'strong', False),
    ('import os\nx=os.getenv("TOKEN")\nif not y: raise ValueError()', 'strong', False),
    ('headers={"Authorization": "example"}', 'strong', True),
    ('request(headers={"X": "Bearer " + key})', 'strong', True),
    ('message="Bearer example"', 'strong', False),
    ('# Authorization: Bearer\npass', 'strong', False),
    ('import getpass\nx=getpass.getpass()', 'login', True),
    ('from getpass import getpass as prompt\nprompt()', 'login', True),
    ('import os as env\nx=env.environ["TOKEN"]', 'strong', True),
    ('from os import getenv as get\nx=get("TOKEN")\nassert x', 'strong', True),
    ('import os, sys\nx=os.getenv("TOKEN")\nx or sys.exit(1)', 'strong', True),
]
for module in ['oauthlib', 'authlib', 'requests_oauthlib', 'google_auth_oauthlib', 'google.auth', 'msal', 'oauth']:
    CASES.append(('import ' + module, 'login', True))
CASES.extend([('from google.auth import default', 'login', True), ('import oauthlib_extra', 'login', False)])
for index, case in enumerate(CASES):
    setattr(AuditTests, 'test_evidence_' + str(index), evidence_test(*case))


def scenario_test(prose, code, name, rule):
    def test(self):
        findings = audit(self.project(prose, code, name))['findings']
        self.assertEqual([f['rule'] for f in findings], [rule] if rule else [])
    return test

SCENARIOS = [
    ('```\nno api key\n```', 'pass', 'app.py', None),
    ('~~~text\nno api key\n~~~', 'pass', 'app.py', None),
    ('no api key is NOT enough', 'import os\nx=os.environ["TOKEN"]', 'app.py', None),
    ('no api key is not sufficient', 'import os\nx=os.environ["TOKEN"]', 'app.py', None),
    ('no api key is insufficient', 'import os\nx=os.environ["TOKEN"]', 'app.py', None),
    ('No account required', 'import os\nx=os.environ["TOKEN"]', 'app.py', None),
    ('No API key required', 'import oauthlib', 'app.py', None),
    ('Requires api key', 'import os\nx=os.getenv("TOKEN", "")', 'app.py', None),
    ('No API key required', 'import os\nx=os.environ["TOKEN"]', 'test_app.py', 'documented-no-key-claim-test-only'),
    ('No API key required', 'import os\nx=os.environ["TOKEN"]', 'app_test.py', 'documented-no-key-claim-test-only'),
    ('No account required', 'import oauthlib', 'fixtures/app.py', 'documented-no-account-claim-test-only'),
    ('No API key required', 'import os\nx=os.environ["TOKEN"]', 'docs/app.py', None),
    ('No API key required', None, 'app.py', 'documented-no-key-claim-false'),
    ('No account required', None, 'app.py', 'documented-no-account-claim-false'),
    ('Requires api key', None, 'app.py', 'documented-key-required-unused'),
    ('`no api key`', 'import os\nx=os.environ["TOKEN"]', 'app.py', 'documented-no-key-claim-false'),
]
for index, scenario in enumerate(SCENARIOS):
    setattr(AuditTests, 'test_scenario_' + str(index), scenario_test(*scenario))

if __name__ == '__main__':
    unittest.main()
