#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scrubkit — audit and sanitize secrets in a repository before publishing it.

Zero dependencies. Python 3.7+.

Usage:
    scrubkit scan    <path>              scan and report findings
    scrubkit scrub   <path> [--apply]    redact secrets in place
    scrubkit verify  <path>              scan with CI-friendly exit code
    scrubkit extract <src> <dst>         copy source code, skipping junk

Options:
    --json                 machine-readable output
    --rules <file.json>    extra rules (see rules/local.example.json)
    --no-entropy           disable the generic high-entropy detector
    --min-entropy <float>  entropy threshold (default 3.8)
    --ext <a,b,c>          only scan these extensions
    --max-size <mb>        skip files larger than this (default 3)
    --backup               write <file>.bak before redacting
    --quiet                only print the summary

Exit codes:
    0  clean / done
    1  verify: high-severity findings present
    2  usage error
"""
import argparse
import io
import json
import math
import os
import re
import shutil
import sys
from collections import Counter

VERSION = '0.1.0'

# --------------------------------------------------------------------------
# Built-in rules: high-confidence credential patterns
# Each rule: name, pattern (regex), replace, severity
# --------------------------------------------------------------------------
DEFAULT_RULES = [
    # --- cloud providers -----------------------------------------------
    dict(name='aws-access-key-id', severity='high',
         pattern=r'\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b',
         replace='AWS_ACCESS_KEY_ID_EXAMPLE'),
    dict(name='aws-secret-access-key', severity='high',
         pattern=r'(?i)aws_?secret_?access_?key\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
         replace='aws_secret_access_key = "AWS_SECRET_ACCESS_KEY_EXAMPLE"'),
    dict(name='aliyun-access-key-id', severity='high',
         pattern=r'\bLTAI[A-Za-z0-9]{12,24}\b',
         replace='ALIYUN_ACCESS_KEY_ID_EXAMPLE'),
    dict(name='tencentcloud-secret-id', severity='high',
         pattern=r'\bAKID[A-Za-z0-9]{10,40}\b',
         replace='TENCENTCLOUD_SECRET_ID_EXAMPLE'),
    dict(name='google-api-key', severity='high',
         pattern=r'\bAIza[0-9A-Za-z_\-]{35}\b',
         replace='GOOGLE_API_KEY_EXAMPLE'),
    dict(name='azure-storage-key', severity='high',
         pattern=r'(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{60,})',
         replace='AccountKey=AZURE_STORAGE_KEY_EXAMPLE'),

    # --- SaaS / VCS tokens ----------------------------------------------
    dict(name='github-token', severity='high',
         pattern=r'\bgh[pousr]_[A-Za-z0-9]{36,255}\b',
         replace='GITHUB_TOKEN_EXAMPLE'),
    dict(name='gitlab-token', severity='high',
         pattern=r'\bglpat-[A-Za-z0-9_\-]{20,}',
         replace='GITLAB_TOKEN_EXAMPLE'),
    dict(name='slack-token', severity='high',
         pattern=r'\bxox[abposr]-[A-Za-z0-9\-]{10,}',
         replace='SLACK_TOKEN_EXAMPLE'),
    dict(name='stripe-key', severity='high',
         pattern=r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}',
         replace='STRIPE_KEY_EXAMPLE'),
    dict(name='openai-key', severity='high',
         pattern=r'\bsk-[A-Za-z0-9]{32,}\b',
         replace='OPENAI_API_KEY_EXAMPLE'),
    dict(name='anthropic-key', severity='high',
         pattern=r'\bsk-ant-[A-Za-z0-9\-_]{32,}',
         replace='ANTHROPIC_API_KEY_EXAMPLE'),
    dict(name='sendgrid-key', severity='high',
         pattern=r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b',
         replace='SENDGRID_API_KEY_EXAMPLE'),
    dict(name='npm-token', severity='high',
         pattern=r'\bnpm_[A-Za-z0-9]{36}',
         replace='NPM_TOKEN_EXAMPLE'),
    dict(name='pypi-token', severity='high',
         pattern=r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}',
         replace='PYPI_TOKEN_EXAMPLE'),

    # --- generic secrets ------------------------------------------------
    dict(name='private-key-block', severity='high',
         pattern=r'(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]{40,}?(-----END [A-Z ]*PRIVATE KEY-----)',
         replace=r'\1\nREDACTED_PRIVATE_KEY\n\2'),
    dict(name='jwt', severity='high',
         pattern=r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b',
         replace='JWT_EXAMPLE'),
    dict(name='db-dsn-with-credentials', severity='high',
         pattern=r'(?i)\b(?:mysql|mariadb|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp)://[^\s:/@]{1,64}:([^\s@/]{3,128})@',
         replace='DB_DSN_PASSWORD_EXAMPLE'),

    # --- assignment-style (medium) ---------------------------------------
    dict(name='password-assignment', severity='medium',
         pattern=r'(?i)\b(password|passwd|pwd)\s*[:=](?!=)\s*[\'"]([A-Za-z0-9!@#$%^&*_\-+=.]{6,128})[\'"]',
         replace=r'\1 = "PASSWORD_EXAMPLE"'),
    dict(name='generic-api-key', severity='medium',
         pattern=r'(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret)\b\s*[:=]\s*[\'"]([A-Za-z0-9\-_.+/=]{12,256})[\'"]',
         replace=r'\1 = "API_KEY_EXAMPLE"'),
    dict(name='define-key', severity='medium',
         pattern=r'(?i)define\s*\(\s*[\'"]\w*(?:key|secret|token|passwd|password)\w*[\'"]\s*,\s*[\'"]([A-Za-z0-9\-_.+/=]{12,256})[\'"]\s*\)',
         replace='define("SECRET_EXAMPLE", "REDACTED")'),
    dict(name='array-key-arrow', severity='medium',
         pattern=r'(?i)[\'"](?:api[_-]?\w+|secret|token|password|passwd)[\'"]\s*=>\s*[\'"]([A-Za-z0-9\-_.+/=]{16,256})[\'"]',
         replace='"api_key" => "API_KEY_EXAMPLE"'),
    dict(name='bearer-token', severity='medium',
         pattern=r'(?i)bearer\s+([A-Za-z0-9\-_.=]{20,256})',
         replace='Bearer BEARER_TOKEN_EXAMPLE'),
]

# Placeholder markers we never touch
PLACEHOLDER_RX = re.compile(
    r'(?i)(YOUR_|EXAMPLE|REDACTED|REPLACE_WITH|PLACEHOLDER|CHANGEME|xxxx|dummy|sample|test_key|fake)'
)

# Template/placeholder fragments inside a match (DSNs in docs, shell vars, template expressions)
FALSE_POSITIVE_RX = re.compile(
    r'(?i)(username:|user:pass|passwd@|password@|:pwd@|:user@|<[^>]{1,40}>|\$\{[^}]{1,40}\}|\{\{[^}]{1,40}\}|\|\||&&|===|!==)'
)


def is_charset_literal(s):
    """True for look-up tables such as 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'.

    Judged by the share of ascending adjacent pairs across the whole run: a
    charset table is ~100% ascending, while a random token that happens to
    contain '12345678' is not.
    """
    for run in re.findall(r'[A-Za-z0-9]{6,}', s):
        asc = sum(1 for a, b in zip(run, run[1:]) if ord(b) == ord(a) + 1)
        if asc / (len(run) - 1) >= 0.8:
            return True
    return False


def is_noise(text):
    """Text that looks like a secret but is a placeholder, charset table or template."""
    return bool(PLACEHOLDER_RX.search(text)
                or FALSE_POSITIVE_RX.search(text)
                or is_charset_literal(text))


# Rules where group(1) is the key name and the last group is the value
KEYED_RULES = {'password-assignment', 'generic-api-key', 'array-key-arrow', 'define-key'}


def is_self_referential(rule_name, m):
    """True for UI copy such as password: 'password' or api_key = 'api_key'."""
    if rule_name not in KEYED_RULES:
        return False
    groups = [g for g in m.groups() if g]
    if len(groups) < 2:
        return False
    return groups[0].lower() in groups[-1].lower()

# Directory names skipped wholesale
SKIP_DIRS = {
    '.git', '.svn', '.hg', '.idea', '.vscode',
    'node_modules', 'bower_components', 'vendor', 'dist', 'build', 'out',
    '__pycache__', '.pytest_cache', '.mypy_cache', '.tox', '.venv', 'venv',
    'coverage', '.next', '.nuxt', '.svelte-kit', 'target', 'bin', 'obj',
    'uploads', 'attachments', 'cache', '.cache', 'logs', 'tmp', 'temp',
}

# Extensions treated as binary / never scanned
BINARY_EXT = {
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.svgz', '.psd',
    '.ai', '.pdf', '.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.tar',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.class', '.jar', '.o', '.a',
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv', '.webm', '.flac',
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    '.db', '.sqlite', '.sqlite3', '.mdb', '.xdb', '.pack', '.idx',
    '.pem', '.key', '.p12', '.pfx',
}

# Extensions copied by `extract` (source code only)
SOURCE_EXT = {
    '.php', '.phtml', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.vue',
    '.svelte', '.css', '.scss', '.less', '.sass',
    '.html', '.htm', '.tpl', '.twig', '.blade', '.erb', '.ejs',
    '.py', '.rb', '.go', '.rs', '.java', '.kt', '.scala', '.cs', '.c', '.cpp',
    '.h', '.hpp', '.m', '.mm', '.swift', '.lua', '.pl', '.sh', '.bash', '.zsh',
    '.bat', '.ps1', '.sql', '.json', '.xml', '.yml', '.yaml', '.toml', '.ini',
    '.conf', '.cfg', '.md', '.txt', '.csv', '.htaccess', '.gitignore',
    '.editorconfig', '.dockerignore', '.env.example', '.sample', '.dist',
}

STRING_RX = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{24,300})['"]""")
ASSIGN_CTX_RX = re.compile(r'(?:=|=>|:|\bdefine\s*\(|\bconst\s+\w+\s*=|\bputenv\s*\()\s*$')
BAD_STRING_PREFIX = ('sha512-', 'sha256-', 'sha1-', 'data:', 'http://', 'https://', 'utf-')
SKIP_NAME_HINTS = ('integrity', 'checksum', 'hash', 'digest')


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in Counter(s).values())


def mask(value, keep=4):
    """Show a fingerprint without leaking the secret."""
    v = value.strip()
    if len(v) <= keep * 2:
        return '*' * len(v)
    return v[:keep] + '*' * min(len(v) - keep * 2, 12) + v[-keep:]


def is_placeholder(text):
    return bool(PLACEHOLDER_RX.search(text))


def is_binary_file(fp):
    ext = os.path.splitext(fp)[1].lower()
    if ext in BINARY_EXT:
        return True
    try:
        with open(fp, 'rb') as f:
            chunk = f.read(8192)
    except OSError:
        return True
    if b'\x00' in chunk:
        return True
    return False


def iter_files(root, exts=None, max_mb=3):
    """Yield files worth scanning."""
    limit = max_mb * 1024 * 1024
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > limit:
                    continue
            except OSError:
                continue
            if exts:
                if os.path.splitext(fn)[1].lower() not in exts:
                    continue
            if is_binary_file(fp):
                continue
            yield fp


def read_text(fp):
    try:
        with open(fp, 'rb') as f:
            raw = f.read()
    except OSError:
        return None
    for enc in ('utf-8', 'gb18030', 'latin-1'):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode('utf-8', 'ignore'), 'utf-8'


# --------------------------------------------------------------------------
# rule loading
# --------------------------------------------------------------------------
def load_rules(extra_path=None, use_entropy=True, min_entropy=3.8):
    rules = []
    for r in DEFAULT_RULES:
        rx = re.compile(r['pattern'], re.S)
        rules.append(dict(name=r['name'], severity=r['severity'],
                          rx=rx, replace=r['replace'], group=0))

    if extra_path:
        with io.open(extra_path, encoding='utf-8') as f:
            extra = json.load(f)
        for r in extra.get('rules', []):
            flags = re.S
            if 'i' in r.get('flags', ''):
                flags |= re.I
            rules.append(dict(name=r.get('name', 'custom'),
                              severity=r.get('severity', 'medium'),
                              rx=re.compile(r['pattern'], flags),
                              replace=r.get('replace', 'REDACTED'),
                              group=0))

    return dict(rules=rules, entropy=use_entropy, min_entropy=min_entropy)


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------
def scan_text(txt, cfg):
    """Return list of findings: dict(line, col, rule, severity, sample, span)."""
    findings = []
    for r in cfg['rules']:
        for m in r['rx'].finditer(txt):
            sample = m.group(0)
            if is_placeholder(sample) or is_noise(sample):
                continue
            if is_self_referential(r['name'], m):
                continue
            line = txt.count('\n', 0, m.start()) + 1
            findings.append(dict(line=line, rule=r['name'], severity=r['severity'],
                                 sample=sample, span=(m.start(), m.end()),
                                 replace=r['replace']))

    if cfg['entropy']:
        for i, line_txt in enumerate(txt.split('\n'), 1):
            low = line_txt.lower()
            if any(h in low for h in SKIP_NAME_HINTS):
                continue
            for m in STRING_RX.finditer(line_txt):
                s = m.group(1)
                if is_noise(s) or s.lower().startswith(BAD_STRING_PREFIX):
                    continue
                if entropy(s) < cfg['min_entropy']:
                    continue
                has_digit = any(c.isdigit() for c in s)
                has_upper = any(c.isupper() for c in s)
                has_lower = any(c.islower() for c in s)
                hexish = bool(re.fullmatch(r'[0-9a-fA-F]{32,64}', s))
                if not ((has_digit and has_upper and has_lower) or hexish):
                    continue
                ctx = line_txt[max(0, m.start() - 90):m.start()].rstrip()
                if not ASSIGN_CTX_RX.search(ctx) and not (',' in ctx and 'define(' in ctx):
                    continue
                findings.append(dict(line=i, rule='high-entropy-string', severity='medium',
                                     sample=s, span=None, replace='HIGH_ENTROPY_VALUE_EXAMPLE'))
    return findings


def cmd_scan(root, cfg, args):
    results = []
    for fp in iter_files(root, args.ext_set, args.max_size):
        got = read_text(fp)
        if got is None:
            continue
        txt, _enc = got
        found = scan_text(txt, cfg)
        if found:
            results.append((os.path.relpath(fp, root), found))

    total = sum(len(f) for _, f in results)
    high = sum(1 for _, fs in results for f in fs if f['severity'] == 'high')

    if args.json:
        payload = [dict(file=rel,
                        findings=[dict(line=f['line'], rule=f['rule'],
                                       severity=f['severity'], sample=mask(f['sample']))
                                  for f in fs])
                   for rel, fs in results]
        print(json.dumps(dict(files=len(results), findings=total, high=high, results=payload),
                         ensure_ascii=False, indent=2))
        return 1 if (args.strict and high) else 0

    if args.quiet and not results:
        print('clean — no findings')
        return 0

    for rel, fs in results:
        print('\n%s' % rel)
        for f in sorted(fs, key=lambda x: x['line']):
            tag = 'HIGH' if f['severity'] == 'high' else 'MED '
            print('  %s L%-5d %-26s %s' % (tag, f['line'], f['rule'], mask(f['sample'])))

    print('\n%d finding(s) in %d file(s) — %d high severity'
          % (total, len(results), high))
    return 1 if (args.strict and high) else 0


def cmd_scrub(root, cfg, args):
    changed_files = 0
    changed_hits = 0
    for fp in iter_files(root, args.ext_set, args.max_size):
        got = read_text(fp)
        if got is None:
            continue
        txt, enc = got
        original = txt
        new, n = scrub_text(txt, cfg)
        if n:
            changed_files += 1
            changed_hits += n
            rel = os.path.relpath(fp, root)
            if args.apply:
                if args.backup and not os.path.exists(fp + '.bak'):
                    shutil.copy2(fp, fp + '.bak')
                with io.open(fp, 'w', encoding='utf-8', newline='') as f:
                    f.write(new)
                print('  scrubbed %-60s %d' % (rel, n))
            else:
                print('  would scrub %-56s %d' % (rel, n))

    mode = 'applied' if args.apply else 'dry-run'
    print('\n%s: %d replacement(s) across %d file(s)' % (mode, changed_hits, changed_files))
    if not args.apply and changed_files:
        print('re-run with --apply to write changes')
    return 0


def scrub_text(txt, cfg):
    """Apply all rules; returns (new_text, replacement_count)."""
    n = 0
    # Longest spans first to avoid partial overlap damage
    hits = scan_text(txt, cfg)
    hits.sort(key=lambda f: (f['span'][0] if f['span'] else 0), reverse=True)

    # Apply regex rules from the end so offsets stay valid
    applied = 0
    for r in cfg['rules']:
        def _sub(m):
            nonlocal applied
            if is_noise(m.group(0)) or is_self_referential(r['name'], m):
                return m.group(0)
            applied += 1
            rep = r['replace']
            if '\\' in rep:
                try:
                    return m.expand(rep)
                except re.error:
                    return 'REDACTED'
            return rep
        txt = r['rx'].sub(_sub, txt)
    n += applied

    # Entropy pass: replace the whole quoted literal
    if cfg['entropy']:
        def _entropy_sub(m):
            nonlocal n
            s = m.group(1)
            if is_noise(s) or s.lower().startswith(BAD_STRING_PREFIX):
                return m.group(0)
            if entropy(s) < cfg['min_entropy']:
                return m.group(0)
            has_digit = any(c.isdigit() for c in s)
            has_upper = any(c.isupper() for c in s)
            has_lower = any(c.islower() for c in s)
            hexish = bool(re.fullmatch(r'[0-9a-fA-F]{32,64}', s))
            if not ((has_digit and has_upper and has_lower) or hexish):
                return m.group(0)
            n += 1
            quote = m.group(0)[0]
            return quote + 'HIGH_ENTROPY_VALUE_EXAMPLE' + quote

        out_lines = []
        for line_txt in txt.split('\n'):
            low = line_txt.lower()
            if any(h in low for h in SKIP_NAME_HINTS):
                out_lines.append(line_txt)
                continue
            for m in list(STRING_RX.finditer(line_txt)):
                ctx = line_txt[max(0, m.start() - 90):m.start()].rstrip()
                if not ASSIGN_CTX_RX.search(ctx) and not (',' in ctx and 'define(' in ctx):
                    continue
                line_txt = line_txt[:m.start()] + _entropy_sub(m) + line_txt[m.end():]
            out_lines.append(line_txt)
        txt = '\n'.join(out_lines)

    return txt, n


def cmd_extract(src, dst, args):
    os.makedirs(dst, exist_ok=True)
    copied = skipped = 0
    total = 0
    for fp in iter_files(src, None, args.max_size):
        ext = os.path.splitext(fp)[1].lower()
        base = os.path.basename(fp).lower()
        if ext not in SOURCE_EXT and base not in ('.htaccess', '.gitignore', '.editorconfig'):
            skipped += 1
            continue
        rel = os.path.relpath(fp, src)
        out = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        try:
            shutil.copy2(fp, out)
            copied += 1
            total += os.path.getsize(fp)
        except OSError:
            skipped += 1
    print('copied %d file(s), %.1f MB — skipped %d' % (copied, total / 1048576, skipped))
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog='scrubkit',
        description='Audit and sanitize secrets in a repository before publishing.')
    p.add_argument('--version', action='version', version='scrubkit ' + VERSION)
    sub = p.add_subparsers(dest='cmd')

    def common(sp):
        sp.add_argument('path', help='repository or directory')
        sp.add_argument('--rules', help='extra rules file (JSON)')
        sp.add_argument('--no-entropy', action='store_true')
        sp.add_argument('--min-entropy', type=float, default=3.8)
        sp.add_argument('--ext', default='', help='comma separated extensions, e.g. .php,.js')
        sp.add_argument('--max-size', type=float, default=3.0, help='max file size in MB')
        sp.add_argument('--json', action='store_true')
        sp.add_argument('--quiet', action='store_true')
        sp.add_argument('--strict', action='store_true',
                        help='exit 1 when high severity findings exist')

    s = sub.add_parser('scan', help='scan and report')
    common(s)

    r = sub.add_parser('scrub', help='redact secrets')
    common(r)
    r.add_argument('--apply', action='store_true', help='write changes to disk')
    r.add_argument('--backup', action='store_true', help='keep <file>.bak copies')

    v = sub.add_parser('verify', help='scan, exit 1 if high severity found')
    common(v)
    v.set_defaults(strict=True)

    e = sub.add_parser('extract', help='copy source files, skipping junk')
    e.add_argument('src')
    e.add_argument('dst')
    e.add_argument('--max-size', type=float, default=3.0)
    e.add_argument('--json', action='store_true')
    e.add_argument('--quiet', action='store_true')
    e.add_argument('--no-entropy', action='store_true')
    e.add_argument('--min-entropy', type=float, default=3.8)
    e.add_argument('--ext', default='')
    e.add_argument('--rules')
    return p


def main(argv=None):
    p = build_parser()
    args = p.parse_args(argv)
    if not args.cmd:
        p.print_help()
        return 2

    if args.cmd == 'extract':
        return cmd_extract(args.src, args.dst, args)

    if not os.path.isdir(args.path):
        print('error: not a directory: %s' % args.path, file=sys.stderr)
        return 2

    args.ext_set = {('.' + e.strip().lstrip('.')) for e in args.ext.split(',') if e.strip()} or None
    cfg = load_rules(args.rules, not args.no_entropy, args.min_entropy)

    if args.cmd in ('scan', 'verify'):
        return cmd_scan(args.path, cfg, args)
    if args.cmd == 'scrub':
        return cmd_scrub(args.path, cfg, args)
    return 2


if __name__ == '__main__':
    sys.exit(main())
