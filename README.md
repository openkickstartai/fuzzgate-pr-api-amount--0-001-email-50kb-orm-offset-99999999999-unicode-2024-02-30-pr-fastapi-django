# 🛡️ FuzzGate

**PR-level API endpoint fuzz testing engine.** Catch validation bypasses, 500 crashes, and info leaks before they hit production.

FuzzGate extracts endpoints from your FastAPI app, generates thousands of smart boundary inputs, and catches every crash or validation gap — in your CI pipeline.

## 🔥 What It Catches

| Attack Vector | Example Input | Real Impact |
|---|---|---|
| Negative amounts | `amount=-0.001` | Unauthorized withdrawals |
| String bombs | `email="a"*50000` | ORM/DB explosion |
| Offset overflow | `offset=99999999999` | Full table scan DoS |
| Unicode bypass | `\u200b` zero-width | Uniqueness constraint bypass |
| Type confusion | `id="abc"` for int | Uncaught 500 errors |
| Injection probes | `'; DROP TABLE;--` | SQL injection |
| Template injection | `{{7*7}}` | SSTI vulnerabilities |
| Special floats | `NaN, Inf, -0.0` | Logic errors |

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# Scan your FastAPI app
python fuzzgate.py example_app:app

# With options
python fuzzgate.py example_app:app --max-cases 100 --fail-on high -o report.json
```

## 💰 Pricing

| Feature | Free (OSS) | Pro $49/mo | Enterprise $499/mo |
|---|---|---|---|
| Endpoint extraction | ✅ FastAPI | ✅ +Flask, Django | ✅ All frameworks |
| Fuzz strategies | 15 built-in | 200+ advanced | Custom + AI-generated |
| Max endpoints | 10 | Unlimited | Unlimited |
| CI integration | GitHub Actions | +GitLab, Bitbucket | +Jenkins, custom |
| PR auto-comments | ❌ | ✅ | ✅ + merge blocking |
| SARIF output | ❌ | ✅ | ✅ |
| Compliance reports | ❌ | ❌ | ✅ SOC2/PCI/HIPAA |
| Slack/PagerDuty alerts | ❌ | ✅ | ✅ |
| SSO & audit trail | ❌ | ❌ | ✅ |
| Support | Community | Email (24h) | Dedicated + SLA |

## 📊 Why Pay?

- **One prevented incident pays for years of FuzzGate.** A single payment validation bypass costs $10K–$1M+.
- **Save 20+ hours/sprint** vs manual security testing.
- **SOC2/PCI audit evidence** generated automatically — no more scrambling before audits.
- **Shift-left security** — catch issues at PR time, not at 3 AM in production.

## GitHub Actions

```yaml
- uses: actions/checkout@v4
- run: pip install -r requirements.txt
- run: python fuzzgate.py myapp:app --fail-on high -o report.json
```

## License

MIT (Free tier) | Commercial license required for Pro/Enterprise features.
