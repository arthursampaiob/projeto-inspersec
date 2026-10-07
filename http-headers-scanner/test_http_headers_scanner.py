import json

import httpx
import pytest
import respx

from http_headers_scanner import (
    RULES,
    HeaderFinding,
    HeaderRule,
    ScanReport,
    evaluate_header,
    main,
    scan,
)


def test_evaluate_header_missing() -> None:
    rule = HeaderRule(
        header="X-Frame-Options",
        severity="medium",
        description="Frame protection",
        recommendation="Add DENY or SAMEORIGIN",
        must_match=r"^(DENY|SAMEORIGIN)$",
    )
    finding = evaluate_header(rule, {})
    assert finding.status == "missing"
    assert finding.actual_value is None


def test_evaluate_header_ok() -> None:
    rule = HeaderRule(
        header="X-Content-Type-Options",
        severity="medium",
        description="MIME sniffing protection",
        recommendation="Add nosniff",
        must_match=r"^nosniff$",
    )
    headers = {"X-Content-Type-Options": "nosniff"}
    finding = evaluate_header(rule, headers)
    assert finding.status == "ok"
    assert finding.actual_value == "nosniff"


def test_evaluate_header_weak() -> None:
    rule = HeaderRule(
        header="X-Frame-Options",
        severity="medium",
        description="Frame protection",
        recommendation="Add DENY or SAMEORIGIN",
        must_match=r"^(DENY|SAMEORIGIN)$",
    )
    headers = {"X-Frame-Options": "ALLOWALL"}
    finding = evaluate_header(rule, headers)
    assert finding.status == "weak"


def test_scan_report_score_and_grade() -> None:
    findings = [
        HeaderFinding(
            rule=rule,
            status="ok",
            actual_value="valid",
            note="Present",
        )
        for rule in RULES
    ]

    report = ScanReport(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        findings=findings,
    )

    assert report.score == 100
    assert report.grade == "A"


@respx.mock
def test_scan_function() -> None:
    target_url = "https://example.com"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
            },
        )
    )

    report = scan(target_url)
    assert report.status_code == 200
    assert report.final_url == target_url
    assert len(report.findings) == len(RULES)

def test_coop_header() -> None:
    rule = next(
        rule for rule in RULES
        if rule.header == "Cross-Origin-Opener-Policy"
    )

    assert len(RULES) == 7
    assert evaluate_header(rule, {}).status == "missing"
    assert evaluate_header(
        rule, {"Cross-Origin-Opener-Policy": "same-origin"}
    ).status == "ok"
    assert evaluate_header(
        rule, {"Cross-Origin-Opener-Policy": "unsafe-none"}
    ).status == "weak"

@respx.mock
def test_json_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target_url = "https://example.com"
    respx.get(target_url).mock(return_value=httpx.Response(200))
    monkeypatch.setattr("sys.argv", ["headers", target_url, "--json"])

    exit_code = main()
    output = capsys.readouterr().out
    data = json.loads(output)

    assert exit_code == 2  # Sem headers de segurança: nota F
    assert data["url"] == target_url
    assert data["score"] == 0
    assert data["grade"] == "F"
    assert len(data["findings"]) == 7

@respx.mock
def test_verbose_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target_url = "https://example.com"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            headers={"X-Debug": "valor-de-teste"},
        )
    )
    monkeypatch.setattr("sys.argv", ["headers", target_url, "--verbose"])

    main()
    output = capsys.readouterr().out

    assert "Raw response headers:" in output
    assert "x-debug: valor-de-teste" in output.lower()
    assert "HTTP Security Headers Evaluation" in output
    assert output.index("Raw response headers:") < output.index(
        "HTTP Security Headers Evaluation"
    )

@respx.mock
def test_main_grade_a_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target_url = "https://example.com"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
                "Cross-Origin-Opener-Policy": "same-origin",
            },
        )
    )
    monkeypatch.setattr("sys.argv", ["headers", target_url, "--json"])

    exit_code = main()
    data = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert data["score"] == 100
    assert data["grade"] == "A"

@respx.mock
def test_main_grade_c_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target_url = "https://example.com"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
            },
        )
    )
    monkeypatch.setattr("sys.argv", ["headers", target_url, "--json"])

    exit_code = main()
    data = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert data["grade"] == "C"

@respx.mock
def test_main_network_error_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target_url = "https://example.com"
    respx.get(target_url).mock(
        side_effect=httpx.ConnectError("connection failed")
    )
    monkeypatch.setattr("sys.argv", ["headers", target_url])

    assert main() == 2
    assert "Request failed" in capsys.readouterr().out