# dsh-redact — scrub secrets from a DSH session before sharing

Posting a `session.jsonl` to a bug report leaks your API keys, tokens, private keys, emails, and home paths. dsh-redact scrubs them into a safe plain-text copy. Zero dependencies.

```sh
node bin/redact.mjs <session.jsonl.zstd> --out redacted.jsonl
# stderr: redacted: api-key: 2, bearer: 1, email: 1 ...
```

What it scrubs:

- API keys (`sk-*`, `ghp_*`, `github_pat_*`, Slack, Google, AWS `AKIA*`)
- `Bearer`/`Basic` tokens
- PEM private-key blocks
- email addresses
- `SECRET=`/`TOKEN=`/`API_KEY=`-style assignments
- your home directory path → `~`

It outputs plain-text JSONL (not zstd), so it's safe to paste. The original is never modified. This closes the practical half of discussion #962 ("credentials are not confidential from the agent"): even when the log *contains* them, you can share it without *propagating* them.

---

# dsh-redact — 分享前给会话日志脱敏

把 `session.jsonl` 贴到 issue 求助会泄露 API key、token、私钥、邮箱和你的 home 路径。dsh-redact 把它们洗成安全副本，零依赖。

```sh
node bin/redact.mjs <session.jsonl.zstd> --out redacted.jsonl
```

输出纯文本 JSONL，可放心粘贴；原文件永不修改。这是 discussion #962（"凭据对 agent 不保密"）的务实补全：日志里**有**凭据，但你分享时能不再**扩散**它们。
