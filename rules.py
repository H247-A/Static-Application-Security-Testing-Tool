"""
rules.py — Security detection rules (20 rules total)
Each rule maps to a real CWE (Common Weakness Enumeration)
"""

import ast
from dataclasses import dataclass
from typing import Optional

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

@dataclass
class Finding:
    rule_id:  str
    cwe:      str
    severity: str
    line:     int
    col:      int
    title:    str
    detail:   str
    fix:      str
    filename: str = ""


# ── helpers ────────────────────────────────────────────────────────────────────

def _func_name(node: ast.Call) -> Optional[str]:
    if isinstance(node.func, ast.Name):      return node.func.id
    if isinstance(node.func, ast.Attribute): return node.func.attr
    return None

def _caller_obj(node: ast.Call) -> Optional[str]:
    if isinstance(node.func, ast.Attribute):
        v = node.func.value
        if isinstance(v, ast.Name): return v.id
    return None

def _kw(node: ast.Call, name: str):
    for k in node.keywords:
        if k.arg == name: return k.value
    return None

def _is_true(n)  -> bool: return isinstance(n, ast.Constant) and n.value is True
def _is_false(n) -> bool: return isinstance(n, ast.Constant) and n.value is False

def _is_str_concat(node) -> bool:
    if isinstance(node, ast.JoinedStr): return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)): return True
    return False

def _str_val(node) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str): return node.value
    return None


# ── call-level rules ───────────────────────────────────────────────────────────

def check_sql_injection(node, filename):
    if _func_name(node) != "execute" or not node.args: return []
    if _is_str_concat(node.args[0]):
        return [Finding("S001","CWE-89","CRITICAL",node.lineno,node.col_offset,
            "SQL Injection",
            "SQL query built with string formatting — attacker can inject arbitrary SQL.",
            'Use parameterised queries: cursor.execute("SELECT * FROM t WHERE id=?", (val,))',
            filename)]
    return []

def check_eval_exec(node, filename):
    fn = _func_name(node)
    if fn in ("eval","exec","compile"):
        return [Finding("S002","CWE-95","CRITICAL",node.lineno,node.col_offset,
            f"Code Injection via {fn}()",
            f"{fn}() executes arbitrary code — dangerous with any user-controlled input.",
            "Remove eval/exec. Use ast.literal_eval() for safe expression parsing.",
            filename)]
    return []

def check_weak_hash(node, filename):
    broken = {"md5","sha1"}
    if _caller_obj(node) == "hashlib" and _func_name(node) in broken:
        return [Finding("S003","CWE-327","HIGH",node.lineno,node.col_offset,
            f"Weak Hash Algorithm (hashlib.{_func_name(node)})",
            "MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks.",
            "Use hashlib.sha256() or hashlib.sha3_256() instead.",
            filename)]
    return []

def check_pickle(node, filename):
    if _caller_obj(node) == "pickle" and _func_name(node) in ("loads","load"):
        return [Finding("S004","CWE-502","CRITICAL",node.lineno,node.col_offset,
            "Insecure Deserialization (pickle)",
            "pickle.loads() on untrusted data allows arbitrary code execution.",
            "Use JSON or a safe format. Never deserialise untrusted data with pickle.",
            filename)]
    return []

def check_command_injection(node, filename):
    findings = []
    if _caller_obj(node) == "os" and _func_name(node) == "system":
        findings.append(Finding("S005","CWE-78","CRITICAL",node.lineno,node.col_offset,
            "Command Injection via os.system()",
            "os.system() passes a string to the shell — attackable with shell metacharacters.",
            "Use subprocess.run(['cmd', arg], shell=False) with a list of arguments.",
            filename))
    if _func_name(node) in ("run","Popen","call","check_output","check_call"):
        shell_kw = _kw(node, "shell")
        if shell_kw and _is_true(shell_kw):
            findings.append(Finding("S005","CWE-78","CRITICAL",node.lineno,node.col_offset,
                "Command Injection via subprocess shell=True",
                "shell=True passes command to /bin/sh — enables injection if input is user-controlled.",
                "Pass arguments as a list and use shell=False (the default).",
                filename))
    return findings

def check_ssl_verify(node, filename):
    fn = _func_name(node)
    if fn in ("get","post","put","patch","delete","request","head"):
        v = _kw(node, "verify")
        if v and _is_false(v):
            return [Finding("S006","CWE-295","HIGH",node.lineno,node.col_offset,
                "SSL Certificate Verification Disabled",
                "verify=False disables TLS checks — enables man-in-the-middle attacks.",
                "Remove verify=False. Pass verify='/path/to/ca-bundle.crt' for custom CAs.",
                filename)]
    return []

def check_xxe(node, filename):
    if _func_name(node) in ("parse","fromstring","iterparse"):
        if _caller_obj(node) in ("ET","ElementTree","etree","lxml"):
            return [Finding("S007","CWE-611","HIGH",node.lineno,node.col_offset,
                "XML External Entity (XXE) Injection",
                "Default XML parsers may process external entities — enables file read or SSRF.",
                "Use defusedxml: import defusedxml.ElementTree as ET",
                filename)]
    return []

def check_random(node, filename):
    insecure = {"random","randint","randrange","choice","choices","shuffle","seed"}
    if _caller_obj(node) == "random" and _func_name(node) in insecure:
        return [Finding("S008","CWE-330","MEDIUM",node.lineno,node.col_offset,
            "Insecure Random Number Generation",
            "random module is not cryptographically secure — output is predictable.",
            "Use secrets.token_hex(), secrets.randbelow(), or secrets.choice() instead.",
            filename)]
    return []

def check_yaml_load(node, filename):
    if _caller_obj(node) == "yaml" and _func_name(node) == "load":
        if _kw(node, "Loader") is None:
            return [Finding("S009","CWE-502","HIGH",node.lineno,node.col_offset,
                "Unsafe YAML Load",
                "yaml.load() without Loader= can execute arbitrary Python via !!python/object tags.",
                "Use yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly.",
                filename)]
    return []

def check_tempfile(node, filename):
    if _caller_obj(node) == "tempfile" and _func_name(node) == "mktemp":
        return [Finding("S010","CWE-377","MEDIUM",node.lineno,node.col_offset,
            "Insecure Temporary File (mktemp)",
            "tempfile.mktemp() is vulnerable to TOCTOU race conditions.",
            "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
            filename)]
    return []

def check_xss(node, filename):
    findings = []
    fn = _func_name(node)
    if fn == "Markup":
        if node.args and not isinstance(node.args[0], ast.Constant):
            findings.append(Finding("S013","CWE-79","HIGH",node.lineno,node.col_offset,
                "XSS via Markup()",
                "Markup() marks content as safe HTML — user-controlled input causes XSS.",
                "Never wrap user input in Markup(). Use Jinja2 auto-escaping instead.",
                filename))
    if fn == "mark_safe":
        findings.append(Finding("S013","CWE-79","HIGH",node.lineno,node.col_offset,
            "XSS via mark_safe()",
            "mark_safe() disables HTML escaping — any user-controlled content is an XSS vector.",
            "Remove mark_safe(). Let Django's template engine auto-escape output.",
            filename))
    if fn == "render_template_string":
        if node.args and _is_str_concat(node.args[0]):
            findings.append(Finding("S013","CWE-79","CRITICAL",node.lineno,node.col_offset,
                "Server-Side Template Injection via render_template_string()",
                "Rendering a dynamically built template string enables SSTI and XSS attacks.",
                "Use render_template() with a static .html file. Never build templates dynamically.",
                filename))
    return findings

def check_path_traversal(node, filename):
    findings = []
    fn = _func_name(node)
    if fn == "open" and node.args:
        arg = node.args[0]
        if isinstance(arg, (ast.Name, ast.JoinedStr, ast.BinOp)):
            findings.append(Finding("S014","CWE-22","HIGH",node.lineno,node.col_offset,
                "Path Traversal via open()",
                "open() called with a variable path — attacker may use '../' to access arbitrary files.",
                "Validate with os.path.abspath() and verify the result starts with your base directory.",
                filename))
    if fn == "join" and _caller_obj(node) in ("path", "os"):
        if len(node.args) >= 2 and isinstance(node.args[-1], (ast.Name, ast.JoinedStr)):
            findings.append(Finding("S014","CWE-22","HIGH",node.lineno,node.col_offset,
                "Path Traversal via os.path.join()",
                "os.path.join() with user-controlled segments allows directory traversal.",
                "Use os.path.realpath() and verify the result starts with your intended base path.",
                filename))
    return findings

def check_insecure_cookie(node, filename):
    findings = []
    if _func_name(node) == "set_cookie":
        kws = {k.arg for k in node.keywords}
        missing = []
        if "httponly" not in kws: missing.append("httponly=True")
        if "secure"   not in kws: missing.append("secure=True")
        if "samesite" not in kws: missing.append("samesite='Lax'")
        httponly = _kw(node, "httponly")
        if httponly and _is_false(httponly):
            findings.append(Finding("S015","CWE-1004","HIGH",node.lineno,node.col_offset,
                "Cookie Missing HttpOnly Flag",
                "httponly=False allows JavaScript to read the cookie — session theft via XSS.",
                "Set httponly=True on all session and auth cookies.",
                filename))
        if missing:
            findings.append(Finding("S015","CWE-614","MEDIUM",node.lineno,node.col_offset,
                "Insecure Cookie Configuration",
                f"Cookie missing security flags: {', '.join(missing)}.",
                f"Add: response.set_cookie(..., {', '.join(missing)})",
                filename))
    return findings

def check_debug_mode(node, filename):
    if _func_name(node) == "run":
        d = _kw(node, "debug")
        if d and _is_true(d):
            return [Finding("S016","CWE-94","HIGH",node.lineno,node.col_offset,
                "Debug Mode Enabled in Production",
                "app.run(debug=True) exposes an interactive debugger and full stack traces to attackers.",
                "Set debug=False. Use: debug=os.environ.get('FLASK_DEBUG', False)",
                filename)]
    return []

def check_open_redirect(node, filename):
    if _func_name(node) == "redirect" and node.args:
        arg = node.args[0]
        if isinstance(arg, (ast.Name, ast.JoinedStr, ast.BinOp)):
            return [Finding("S017","CWE-601","MEDIUM",node.lineno,node.col_offset,
                "Open Redirect",
                "redirect() with user-controlled URL lets attackers redirect users to malicious sites.",
                "Validate URLs against an allowlist. Use url_for() for all internal redirects.",
                filename)]
    return []

def check_weak_jwt(node, filename):
    findings = []
    fn = _func_name(node)
    if fn in ("encode","decode"):
        algo = _kw(node, "algorithm")
        if algo:
            val = _str_val(algo)
            if val and val.lower() == "none":
                findings.append(Finding("S018","CWE-327","CRITICAL",node.lineno,node.col_offset,
                    "JWT with 'none' Algorithm",
                    "JWT signed with algorithm='none' has no signature — anyone can forge tokens.",
                    "Use algorithm='HS256' with a strong secret or 'RS256' with a private key.",
                    filename))
        if len(node.args) >= 2:
            secret = _str_val(node.args[1])
            if secret and len(secret) < 16:
                findings.append(Finding("S018","CWE-330","HIGH",node.lineno,node.col_offset,
                    "Weak JWT Secret Key",
                    f"JWT secret is only {len(secret)} characters — vulnerable to brute force.",
                    "Use at least 32 random characters: secrets.token_hex(32)",
                    filename))
    return findings

def check_file_upload(node, filename):
    if _func_name(node) == "save" and _caller_obj(node) and "file" in (_caller_obj(node) or "").lower():
        return [Finding("S019","CWE-434","HIGH",node.lineno,node.col_offset,
            "Unrestricted File Upload",
            "File saved without extension or MIME type validation — attacker can upload malicious scripts.",
            "Check extension against allowlist and validate MIME type before saving.",
            filename)]
    return []


# ── assignment-level rules ─────────────────────────────────────────────────────

SECRET_NAMES = {
    "password","passwd","pwd","secret","api_key","apikey","token","auth_token",
    "private_key","access_key","aws_secret","aws_access_key","client_secret",
    "secret_key","db_password","smtp_password","stripe_secret","jwt_secret"
}

def check_hardcoded_secret(node: ast.Assign, filename: str):
    findings = []
    for target in node.targets:
        if isinstance(target, ast.Name) and target.id.lower() in SECRET_NAMES:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                if len(node.value.value) > 3:
                    findings.append(Finding("S011","CWE-798","CRITICAL",
                        node.lineno, node.col_offset,
                        f"Hardcoded Secret in `{target.id}`",
                        "Credential stored in source code is exposed to anyone with repo access.",
                        "Use environment variables: os.environ.get('SECRET_KEY') or a secrets vault.",
                        filename))
    return findings


# ── import-level rules ────────────────────────────────────────────────────────

DANGEROUS_IMPORTS = {
    "telnetlib": ("S012","CWE-319","MEDIUM",
        "telnetlib sends all data including credentials in plaintext.",
        "Use paramiko or asyncssh for encrypted SSH access."),
    "ftplib":    ("S012","CWE-319","MEDIUM",
        "ftplib uses unencrypted FTP — credentials and data are exposed.",
        "Use ftplib.FTP_TLS or SFTP via paramiko."),
}

def check_dangerous_import(node: ast.Import, filename: str):
    findings = []
    for alias in node.names:
        name = alias.name.split(".")[0]
        if name in DANGEROUS_IMPORTS:
            rid, cwe, sev, detail, fix = DANGEROUS_IMPORTS[name]
            findings.append(Finding(rid,cwe,sev,node.lineno,node.col_offset,
                f"Insecure Module Import: {name}", detail, fix, filename))
    return findings


# ── master lists ───────────────────────────────────────────────────────────────

CALL_RULES = [
    check_sql_injection, check_eval_exec, check_weak_hash, check_pickle,
    check_command_injection, check_ssl_verify, check_xxe, check_random,
    check_yaml_load, check_tempfile,
    check_xss, check_path_traversal, check_insecure_cookie,
    check_debug_mode, check_open_redirect, check_weak_jwt, check_file_upload,
]

RULES_META = [
    ("S001","CWE-89",  "CRITICAL","SQL Injection"),
    ("S002","CWE-95",  "CRITICAL","Code Injection via eval/exec"),
    ("S003","CWE-327", "HIGH",    "Weak Hash Algorithm (MD5/SHA-1)"),
    ("S004","CWE-502", "CRITICAL","Insecure Deserialization (pickle)"),
    ("S005","CWE-78",  "CRITICAL","OS Command Injection"),
    ("S006","CWE-295", "HIGH",    "SSL Certificate Verification Disabled"),
    ("S007","CWE-611", "HIGH",    "XML External Entity (XXE)"),
    ("S008","CWE-330", "MEDIUM",  "Insecure Random Number Generation"),
    ("S009","CWE-502", "HIGH",    "Unsafe YAML Load"),
    ("S010","CWE-377", "MEDIUM",  "Insecure Temporary File"),
    ("S011","CWE-798", "CRITICAL","Hardcoded Credentials"),
    ("S012","CWE-319", "MEDIUM",  "Insecure Module (telnetlib/ftplib)"),
    ("S013","CWE-79",  "HIGH",    "Cross-Site Scripting (XSS)"),
    ("S014","CWE-22",  "HIGH",    "Path Traversal"),
    ("S015","CWE-614", "MEDIUM",  "Insecure Cookie Configuration"),
    ("S016","CWE-94",  "HIGH",    "Debug Mode Enabled"),
    ("S017","CWE-601", "MEDIUM",  "Open Redirect"),
    ("S018","CWE-327", "CRITICAL","Weak JWT Secret / Algorithm"),
    ("S019","CWE-434", "HIGH",    "Unrestricted File Upload"),
    ("S020","CWE-352", "MEDIUM",  "CSRF Protection Missing"),
]
