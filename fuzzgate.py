"""FuzzGate - PR-level API endpoint fuzz testing engine."""
import importlib, json, sys
from dataclasses import dataclass, asdict
from typing import Any

import click
from starlette.testclient import TestClient

FUZZ_VALUES = {
    "str": ["", " " * 5, "a" * 50000, "\x00" * 10, "\u200b" * 20,
            "\u202eadmin", "<script>alert(1)</script>", "';DROP TABLE u;--",
            "{{7*7}}", "2024-02-30", None, 42, True, [], {}],
    "int": [0, -1, 1, 2**31, 2**63, -(2**63), 99999999999, None, "abc", 0.5],
    "float": [0.0, -0.0, float("nan"), float("inf"), float("-inf"),
              -0.001, 1e308, None, "NaN"],
}
LEAK_SIGS = ["Traceback (most recent", 'File "/', "Exception:",
             "SECRET_KEY", "DATABASE_URL", "password"]


@dataclass
class Finding:
    endpoint: str
    method: str
    input_data: Any
    status_code: int
    severity: str
    category: str
    detail: str


def extract_routes(app):
    """Extract routes with parameter type hints from a FastAPI/Starlette app."""
    routes = []
    for r in getattr(app, "routes", []):
        if not hasattr(r, "methods"):
            continue
        hints = {k: v for k, v in getattr(r.endpoint, "__annotations__", {}).items()
                 if k != "return"}
        for m in r.methods:
            if m not in ("HEAD", "OPTIONS"):
                routes.append({"path": r.path, "method": m, "params": hints})
    return routes


def gen_cases(params):
    """Generate fuzz cases from parameter type hints."""
    cases = [{}]
    for name, th in params.items():
        tn = getattr(th, "__name__", str(th)).lower()
        key = "int" if "int" in tn else "float" if "float" in tn else "str"
        cases.extend([{name: v} for v in FUZZ_VALUES[key]])
    return cases


def has_leak(text):
    """Detect stack traces or secrets in response text."""
    low = text.lower()
    return any(sig.lower() in low for sig in LEAK_SIGS)


def fuzz_app(app, max_cases=50):
    """Run fuzz testing against all discovered endpoints."""
    client = TestClient(app, raise_server_exceptions=False)
    findings = []
    for route in extract_routes(app):
        for case in gen_cases(route["params"])[:max_cases]:
            path, params = route["path"], {}
            for k, v in case.items():
                ph = "{" + k + "}"
                if ph in path:
                    path = path.replace(ph, str(v) if v is not None else "null")
                else:
                    params[k] = v
            m = route["method"]
            try:
                if m in ("GET", "DELETE"):
                    resp = client.request(m, path, params=params)
                else:
                    resp = client.request(m, path, json=params or case)
            except Exception as e:
                findings.append(Finding(route["path"], m, case, 0,
                                        "critical", "crash", str(e)[:200]))
                continue
            if resp.status_code >= 500:
                findings.append(Finding(route["path"], m, case, resp.status_code,
                                        "critical", "server_error", f"HTTP {resp.status_code}"))
            elif has_leak(resp.text):
                findings.append(Finding(route["path"], m, case, resp.status_code,
                                        "high", "info_leak", "Sensitive data in response"))
    return findings


def format_report(findings):
    """Format findings for terminal output."""
    lines = []
    for f in findings:
        icon = {"critical": "\U0001f534", "high": "\U0001f7e0"}.get(f.severity, "\u26aa")
        lines.append(f"{icon} [{f.severity.upper()}] {f.method} {f.endpoint}")
        lines.append(f"   Input: {json.dumps(f.input_data, default=str)[:120]}")
        lines.append(f"   {f.detail}")
    return "\n".join(lines)


@click.command()
@click.argument("app_path")
@click.option("--max-cases", default=50, help="Max fuzz cases per endpoint")
@click.option("--fail-on", default="critical",
              type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--output", "-o", default=None, help="JSON report path")
def main(app_path, max_cases, fail_on, output):
    """FuzzGate: fuzz your API endpoints. Usage: fuzzgate myapp:app"""
    mod_path, app_name = app_path.rsplit(":", 1)
    sys.path.insert(0, ".")
    app = getattr(importlib.import_module(mod_path), app_name)
    click.echo(f"\U0001f50d FuzzGate scanning {app_path} ...")
    findings = fuzz_app(app, max_cases)
    if not findings:
        click.echo("\u2705 No issues found!")
        return
    click.echo(f"\n\u26a0\ufe0f  {len(findings)} issues found:\n\n{format_report(findings)}")
    if output:
        with open(output, "w") as f:
            json.dump([asdict(fi) for fi in findings], f, indent=2, default=str)
        click.echo(f"\n\U0001f4c4 Report saved to {output}")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if min(sev_order.get(f.severity, 3) for f in findings) <= sev_order[fail_on]:
        click.echo("\n\u274c FuzzGate: merge blocked due to findings above threshold!")
        sys.exit(1)


if __name__ == "__main__":
    main()
