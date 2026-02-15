"""Tests for FuzzGate core functionality."""
import json
import os
from fuzzgate import extract_routes, gen_cases, fuzz_app, has_leak, Finding, format_report
from example_app import app


def test_extract_routes_finds_all_endpoints():
    routes = extract_routes(app)
    paths = [r["path"] for r in routes]
    assert "/users/{user_id}" in paths
    assert "/search" in paths
    assert "/health" in paths
    assert len(routes) >= 3
    user_route = [r for r in routes if r["path"] == "/users/{user_id}"][0]
    assert "user_id" in user_route["params"]
    assert user_route["params"]["user_id"] is int


def test_gen_cases_produces_boundary_values():
    cases = gen_cases({"amount": float, "name": str})
    float_vals = [c["amount"] for c in cases if "amount" in c]
    str_vals = [c["name"] for c in cases if "name" in c]
    assert any(v is None for v in float_vals), "Should include None for float"
    assert any(isinstance(v, float) and v < 0 for v in float_vals if isinstance(v, (int, float)))
    assert any(isinstance(v, str) and len(v) > 10000 for v in str_vals), "Should include long strings"
    assert any(v == [] for v in str_vals), "Should include type confusion (list)"


def test_gen_cases_empty_params():
    cases = gen_cases({})
    assert cases == [{}]


def test_fuzz_detects_server_errors():
    findings = fuzz_app(app, max_cases=30)
    assert len(findings) > 0, "Should find at least one issue"
    categories = {f.category for f in findings}
    assert "server_error" in categories, "Should detect 500 errors"
    critical = [f for f in findings if f.severity == "critical"]
    assert len(critical) > 0, "500 errors should be critical"


def test_has_leak_detection():
    assert has_leak('Traceback (most recent call last):\n  File "/app.py"')
    assert has_leak("contains SECRET_KEY=abc123 leaked")
    assert has_leak("DATABASE_URL=postgres://user:pass@host/db")
    assert not has_leak('{"status": "ok", "data": []}')
    assert not has_leak("User not found")


def test_finding_dataclass_and_format():
    f = Finding("/api/test", "GET", {"id": -1}, 500, "critical", "server_error", "HTTP 500")
    assert f.severity == "critical"
    assert f.endpoint == "/api/test"
    report = format_report([f])
    assert "CRITICAL" in report
    assert "/api/test" in report
    assert "HTTP 500" in report


def test_fuzz_report_output(tmp_path):
    findings = fuzz_app(app, max_cases=15)
    out_file = str(tmp_path / "report.json")
    with open(out_file, "w") as f:
        from dataclasses import asdict
        json.dump([asdict(fi) for fi in findings], f, default=str)
    with open(out_file) as f:
        data = json.load(f)
    assert isinstance(data, list)
    assert len(data) > 0
    assert "endpoint" in data[0]
    assert "severity" in data[0]
