"""AST evidence and prose claims; never import or execute audited code."""
import ast
import os
import re
from pathlib import Path

PATTERNS = {
    "no-key": r"\b(?:no api key(?: required| needed)?|works without an api key|no credentials? (?:required|needed)|works without credentials|no authentication required|no auth required)\b",
    "no-account": r"\b(?:no (?:account|login|sign-up|signup) (?:required|needed)|works without an account|works without logging in)\b",
    "key-required": r"\b(?:requires (?:an )?api key|api key is required|you need an api key|you'll need an api key|an api key is needed)\b",
}
RULES = {
    "no-key": ("documented-no-key-claim-false", "HIGH"),
    "no-account": ("documented-no-account-claim-false", "HIGH"),
    "key-required": ("documented-key-required-unused", "MEDIUM"),
}
CREDENTIAL = re.compile(r"(?:API_KEY|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|ACCESS_KEY|AUTH_TOKEN|CLIENT_SECRET)(?=$|_|[^a-zA-Z])", re.I)
LOGIN = {"oauthlib", "authlib", "requests_oauthlib", "google_auth_oauthlib", "google.auth", "msal", "oauth"}


def files(root):
    """Walk without following directory or file symlinks, including hidden paths."""
    def walk_error(error):
        raise error
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if not path.is_symlink():
                yield path


def claims(path, root):
    fence = None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not line[marker.end():].strip():
                fence = None
            continue
        if fence or re.search(r"not enough|not sufficient|insufficient", line, re.I):
            continue
        for kind, pattern in PATTERNS.items():
            for match in re.finditer(pattern, line, re.I):
                yield {"kind": kind, "file": path.relative_to(root).as_posix(), "line": number, "claim": match.group()}


def dotted(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return dotted(node.value, aliases) + "." + node.attr
    return ""


def evidence(source):
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    aliases = {}
    login_nodes = []
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                full = alias.name if isinstance(node, ast.Import) else (node.module or "") + "." + alias.name
                aliases[alias.asname or (alias.name.split('.')[0] if isinstance(node, ast.Import) else alias.name)] = full if alias.asname or isinstance(node, ast.ImportFrom) else alias.name.split('.')[0]
                if any(full == name or full.startswith(name + ".") for name in LOGIN):
                    login_nodes.append(node)
    reads, strong, login = [], [], list(login_nodes)
    for node in nodes:
        name = dotted(node.func, aliases) if isinstance(node, ast.Call) else ""
        key = None
        if name in {"os.getenv", "os.environ.get"} and node.args:
            key = node.args[0]
        elif isinstance(node, ast.Subscript) and dotted(node.value, aliases) == "os.environ":
            key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str) and CREDENTIAL.search(key.value):
            reads.append(node)
            if isinstance(node, ast.Subscript):
                strong.append(node)
        if name == "getpass.getpass":
            login.append(node)
        if isinstance(node, ast.Dict):
            if any(isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.lower() == "authorization" for k in node.keys if k):
                strong.append(node)
        if isinstance(node, (ast.Dict, ast.Call)):
            if any(isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("Bearer ") for n in ast.walk(node)):
                strong.append(node)
    variables = set()
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            if any(read in list(ast.walk(node.value)) for read in reads):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                variables.update(n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name))
    def guarded(test):
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return isinstance(test.operand, ast.Name) and test.operand.id in variables
        return (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id in variables
                and len(test.ops) == 1 and isinstance(test.ops[0], (ast.Is, ast.Eq))
                and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None)
    def stops(body):
        for stmt in body:
            # Do not confuse an exit nested in an unexecuted function with a guard exit.
            if isinstance(stmt, ast.Raise):
                return True
            if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, int) and stmt.value.value != 0:
                return True
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and dotted(stmt.value.func, aliases) in {"sys.exit", "exit", "quit", "builtins.exit", "builtins.quit"}:
                return True
        return False
    for node in nodes:
        if isinstance(node, ast.If) and guarded(node.test) and stops(node.body):
            strong.append(node)
        if isinstance(node, ast.Assert) and isinstance(node.test, ast.Name) and node.test.id in variables:
            strong.append(node)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or) and isinstance(node.values[0], ast.Name) and node.values[0].id in variables:
            if any(isinstance(n, ast.Call) and dotted(n.func, aliases) in {"sys.exit", "exit", "quit"} for v in node.values[1:] for n in ast.walk(v)):
                strong.append(node)
    lines = source.splitlines()
    def render(items):
        return [lines[n.lineno - 1].strip() for n in items]
    return {"strong": render(strong), "login": render(login), "any": render(reads + strong + login)}


def audit(path=".", ignore=()):
    root = Path(path)
    if not root.is_dir() or not os.access(root, os.R_OK | os.X_OK):
        raise ValueError("path must be a readable directory")
    production = {"strong": [], "login": [], "any": []}
    testing = {"strong": [], "login": [], "any": []}
    found_claims, source_count = [], 0
    for file in files(root):
        relative = file.relative_to(root)
        if relative.as_posix() == "README.md" or (relative.parts[0] == "docs" and file.suffix == ".md"):
            found_claims.extend(claims(file, root))
        if file.suffix != ".py":
            continue
        source_count += 1
        try:
            data = evidence(file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeError):
            continue
        parts = set(relative.parts[:-1])
        if "docs" in parts:
            continue
        target = testing if parts & {"tests", "fixtures"} or file.name.startswith("test_") or file.name.endswith("_test.py") else production
        for key in target:
            target[key].extend(data[key])
    findings, verified = [], []
    for claim in found_claims:
        kind = claim["kind"]
        rule, severity = RULES[kind]
        proof = []
        if source_count == 0:
            proof = ["no Python source"]
        elif kind == "key-required":
            if not production["any"]:
                proof = ["no production credential evidence"]
        else:
            category = "strong" if kind == "no-key" else "login"
            proof = production[category]
            if not proof and testing[category]:
                proof = testing[category]
                rule = rule.replace("-false", "-test-only")
                severity = "MEDIUM"
        public = {k: v for k, v in claim.items() if k != "kind"}
        if proof and rule not in ignore:
            findings.append(dict(public, rule=rule, severity=severity, evidence=proof[0]))
        elif not proof:
            verified.append(public)
    return {"findings": findings, "verified_claims": verified,
            "summary": {"claims": len(found_claims), "findings": len(findings), "verified": len(verified),
                        "high": sum(f["severity"] == "HIGH" for f in findings), "medium": sum(f["severity"] == "MEDIUM" for f in findings)}}
