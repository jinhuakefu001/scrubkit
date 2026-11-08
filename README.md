# scrubkit

**Find and remove secrets before you publish a repository.**

One file. No dependencies. Python 3.7+.

Most secret scanners tell you *where* a key is. `scrubkit` also **rewrites it in place** while keeping your code structurally intact, so the repo still reads like real code after sanitizing.

```console
$ scrubkit scan ./my-project
src/config/db.php
  HIGH L12  db-dsn-with-credentials    mysq************swd@
src/api/client.ts
  HIGH L4   openai-key                 sk-p************7Qx2
  MED  L9   generic-api-key            api_************3f9a

3 finding(s) in 2 file(s) — 2 high severity
```

```console
$ scrubkit scrub ./my-project --apply
  scrubbed src/config/db.php                        1
  scrubbed src/api/client.ts                        2

applied: 3 replacement(s) across 2 file(s)
```

---

## Why another secret scanner

Three problems show up again and again when people open-source an internal project:

1. **`.gitignore` doesn't help retroactively.** The key was committed 8 months ago and is still in history.
2. **Manual redaction breaks code.** You delete a line, now nothing runs, so you revert and ship the leak.
3. **Noisy scanners get ignored.** After the 200th false positive on `ABCDEFGHIJKLMNOPQRSTUVWXYZ`, people stop reading the report.

`scrubkit` is built around those three failures: it detects assignment-style secrets that regex-only tools miss (`define('KEY', 'x')`, `'api_key' => 'x'`), replaces values with meaningful placeholders instead of deleting lines, and filters charset tables / template expressions / documentation examples so the report stays short enough to act on.

---

## Install

```bash
curl -O https://raw.githubusercontent.com/<owner>/scrubkit/main/scrubkit.py
chmod +x scrubkit.py
./scrubkit.py --help
```

Or clone and use it as a library:

```python
from scrubkit import load_rules, scan_text
cfg = load_rules()
findings = scan_text(open('config.php').read(), cfg)
```

---

## Commands

### `scan` — report only

```bash
scrubkit scan ./repo
scrubkit scan ./repo --json > report.json     # machine readable
scrubkit scan ./repo --ext .php,.env,.yml     # limit scope
scrubkit scan ./repo --no-entropy             # regex rules only
```

### `scrub` — redact

```bash
scrubkit scrub ./repo              # dry run, shows what would change
scrubkit scrub ./repo --apply      # write changes
scrubkit scrub ./repo --apply --backup   # keep <file>.bak
```

Placeholders are chosen to be self-explanatory, so `grep -rn "EXAMPLE"` gives you the follow-up list:

| Detected | Replaced with |
|---|---|
| `AKIA...` | `AWS_ACCESS_KEY_ID_EXAMPLE` |
| `AKID...` (Tencent Cloud) | `TENCENTCLOUD_SECRET_ID_EXAMPLE` |
| `LTAI...` (Alibaba Cloud) | `ALIYUN_ACCESS_KEY_ID_EXAMPLE` |
| `ghp_...` / `glpat-...` | `GITHUB_TOKEN_EXAMPLE` / `GITLAB_TOKEN_EXAMPLE` |
| `sk-...` (OpenAI) | `OPENAI_API_KEY_EXAMPLE` |
| `<PEM private key block>` | block body → `REDACTED_PRIVATE_KEY` |
| `mysql://user:pass@host` | password → `DB_DSN_PASSWORD_EXAMPLE` |
| high-entropy literal in an assignment | `HIGH_ENTROPY_VALUE_EXAMPLE` |

### `verify` — CI gate

```bash
scrubkit verify ./repo
# exit 0 = clean, exit 1 = high severity findings
```

```yaml
# .github/workflows/secrets.yml
- name: Scan for secrets
  run: python scrubkit.py verify . --no-entropy
```

### `extract` — copy source without the junk

Useful when archiving a working directory that mixes code with uploads, caches, databases and keys:

```bash
scrubkit extract ./messy-server ./clean-archive
# copied 3918 file(s), 61.2 MB — skipped 2140
```

Keeps source extensions only, skips `node_modules`, `vendor`, `uploads`, `runtime`, binaries, `.pem`, `.db`, archives.

---

## Detection rules

Built in (**22 rules**):

- **Cloud** — AWS access key & secret, Alibaba Cloud, Tencent Cloud, Google API, Azure storage key
- **SaaS / VCS** — GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, SendGrid, npm, PyPI
- **Generic** — PEM private key blocks, JWT, DB DSN with credentials
- **Assignment-style** — `password=`, `api_key=`, `define('X_KEY','v')`, `'key' => 'v'`, `Bearer ...`
- **Entropy fallback** — quoted strings ≥ 24 chars, Shannon entropy ≥ 3.8, in an assignment context

### Adding your own rules

```bash
cp rules/local.example.json ./my-rules.json
scrubkit scan ./repo --rules ./my-rules.json
```

```json
{
  "rules": [
    {
      "name": "internal-api-token",
      "severity": "high",
      "pattern": "corp_[A-Za-z0-9]{32}",
      "replace": "INTERNAL_API_TOKEN_EXAMPLE"
    }
  ]
}
```

Keep `my-rules.json` out of the repo — add it to `.gitignore`.

---

## What it filters out

The entropy detector would drown you in noise without these guards, so all of them are applied before a finding is reported:

- charset tables (`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`)
- integrity hashes (`sha512-...`, lock files are skipped entirely)
- template fragments (`username:password@`, `${VAR}`, `{{ var }}`, `<placeholder>`)
- comparison expressions (`password === 'password'`)
- anything already containing `YOUR_`, `EXAMPLE`, `REDACTED`, `CHANGEME`

---

## Limitations — read before trusting it

- **It does not rewrite Git history.** After scrubbing, the old commits still contain the key. Either rewrite history (`git filter-repo --path ... --invert-paths`, or re-create the repo from a single fresh commit) or **rotate the credential** — rotating is faster and safer.
- **Regex + entropy is heuristic.** It will miss custom token formats that look like ordinary words, and it can flag a random-looking ID. Read the report; don't blindly `--apply` on a repo you haven't inspected.
- **Binary files, `.env`, `.pem`, `.db` are skipped, not cleaned.** They should never be committed in the first place; `extract` refuses to copy them.
- **`--apply` rewrites files as UTF-8.** If a file was GBK/Shift-JIS, encoding is normalized. Verify non-UTF-8 projects before pushing.

---

## 中文说明

一个单文件、零依赖的密钥审计与脱敏工具。

- `scan` 只报告；`scrub --apply` 原地替换成 `XXX_EXAMPLE` 占位符；`verify` 用于 CI 卡口。
- 内置 22 条规则（AWS / 阿里云 / 腾讯云 / GitHub / GitLab / Stripe / OpenAI / JWT / PEM / 数据库 DSN 等），外加熵值兜底。
- 专门处理只靠正则容易漏的写法：`define('KEY','value')`、`'api_key' => 'value'`。
- 自动过滤字符集常量、`sha512-` 校验和、模板占位、比较表达式，避免噪声淹没真问题。
- **不会重写 Git 历史**：脱敏后请务必轮换密钥，或重建仓库历史。

---

## License

MIT — see [LICENSE](LICENSE).
