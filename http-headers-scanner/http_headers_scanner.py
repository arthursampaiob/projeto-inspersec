"""
©AngelaMos | 2026
Copyright (C) 2026 Murilo Miacci
http_headers_scanner.py

Scan a URL and grade its HTTP security headers A–F

When a browser asks a website for a page, the server sends back the
page itself PLUS a bunch of metadata called "HTTP response headers."
...
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Literal

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]

SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5,
}


@dataclass(frozen=True, slots=True)
class HeaderRule:
    """Define a security header and how to evaluate it."""
    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None


@dataclass(frozen=True, slots=True)
class HeaderFinding:
    """Record the result of evaluating one header."""
    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Collect the response details and header findings."""
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]
    response_headers: dict[str, str] = field(default_factory=dict)

    @property
    def score(self) -> int:
        """Calculate the weighted score from the header findings."""
        total = sum(SEVERITY_POINTS[r.severity] for r in RULES)
        if total == 0:
            return 0

        earned = 0.0
        for finding in self.findings:
            full = SEVERITY_POINTS[finding.rule.severity]
            if finding.status == "ok":
                earned += full
            elif finding.status == "weak":
                earned += full / 2

        return int((earned / total) * 100 + 0.5)

    @property
    def grade(self) -> str:
        """Convert the score to a letter grade."""
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


RULES: list[HeaderRule] = [
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="Enforces HTTPS connections and prevents SSL stripping attacks.",
        recommendation=(
            "Add Strict-Transport-Security with a max-age of at least "
            "15768000 seconds (6 months)."
        ),
        must_match=r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        description="Controls resources the user agent is allowed to load for a given page.",
        recommendation="Add a Content-Security-Policy header restricting resource sources.",
    ),
    HeaderRule(
        header="X-Content-Type-Options",
        severity="medium",
        description=(
            "Prevents browsers from MIME-sniffing a response away from "
            "the declared content-type."
        ),
        recommendation="Add X-Content-Type-Options: nosniff.",
        must_match=r"^nosniff$",
    ),
    HeaderRule(
        header="X-Frame-Options",
        severity="medium",
        description=(
            "Indicates whether a browser should be allowed to render "
            "the page in a frame or iframe."
        ),
        recommendation="Add X-Frame-Options: DENY or SAMEORIGIN.",
        must_match=r"^(DENY|SAMEORIGIN)$",
    ),
    HeaderRule(
        header="Referrer-Policy",
        severity="low",
        description="Controls how much referrer information is included with requests.",
        recommendation="Add Referrer-Policy: strict-origin-when-cross-origin.",
        must_match=r"^(no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin)$",
    ),
    HeaderRule(
        header="Permissions-Policy",
        severity="low",
        description=(
            "Allows web developers to selectively enable, disable, and "
            "modify behavior of browser features."
        ),
        recommendation="Add Permissions-Policy to disable unused browser features.",
    ),
    HeaderRule(
        header="Cross-Origin-Opener-Policy",
        severity="low",
        description="Isolates the page from windows opened by other origins.",
        recommendation="Add Cross-Origin-Opener-Policy: same-origin.",
        must_match=r"^same-origin$",
    ),
]


def evaluate_header(
    rule: HeaderRule,
    response_headers: dict[str, str],
) -> HeaderFinding:
    """Check one security header against its rule."""
    target = rule.header.lower()

    actual_value: str | None = None
    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value
            break

    if actual_value is None:
        return HeaderFinding(
            rule=rule,
            status="missing",
            actual_value=None,
            note=f"Header `{rule.header}` is not set",
        )

    if rule.must_match is None:
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note="Present",
        )

    match = re.search(rule.must_match, actual_value, re.IGNORECASE)
    if match and (
        rule.header != "Strict-Transport-Security" or int(match.group(1)) >= 15_768_000
    ):
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note=f"Present and matches `{rule.must_match}`",
        )

    return HeaderFinding(
        rule=rule,
        status="weak",
        actual_value=actual_value,
        note=(f"Present but does not match `{rule.must_match}` (got `{actual_value}`)"),
    )


DEFAULT_USER_AGENT: str = (
    "http-headers-scanner/1.0 "
    "(+https://github.com/CarterPerez-dev/Cybersecurity-Projects)"
)


def scan(
    url: str,
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
    """Fetch a URL and evaluate its response headers."""
    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": user_agent},
    )

    response_headers = dict(response.headers)
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    return ScanReport(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=findings,
        response_headers=response_headers,
    )


STATUS_COLORS: dict[Status, str] = {
    "ok": "green",
    "weak": "yellow",
    "missing": "red",
}

GRADE_COLORS: dict[str, str] = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}


def _render_report(
    report: ScanReport,
    console: Console,
    verbose: bool = False,
) -> None:
    console.print()
    console.print(f"[bold cyan]Scanning:[/bold cyan] {report.url}")
    console.print(f"[bold cyan]Final URL:[/bold cyan] {report.final_url}")
    console.print(f"[bold cyan]Status Code:[/bold cyan] {report.status_code}\n")

    if verbose:
        console.print("[bold]Raw response headers:[/bold]")
        for name, value in report.response_headers.items():
            console.print(f"{name}: {value}", markup=False)
        console.print()

    table = Table(
        title="HTTP Security Headers Evaluation",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Header", style="dim", width=28)
    table.add_column("Severity", width=10)
    table.add_column("Status", width=10)
    table.add_column("Note")

    for finding in report.findings:
        status_color = STATUS_COLORS[finding.status]
        status_str = f"[{status_color}]{finding.status.upper()}[/{status_color}]"

        sev = finding.rule.severity
        sev_color = "red" if sev == "high" else "yellow" if sev == "medium" else "blue"
        sev_str = f"[{sev_color}]{sev.upper()}[/{sev_color}]"

        table.add_row(finding.rule.header, sev_str, status_str, finding.note)

    console.print(table)

    if report.final_url.startswith("http://"):
        console.print(
            "\n[yellow]Note:[/yellow] this response was served over plain "
            "HTTP. Browsers IGNORE HSTS over HTTP."
        )

    grade_color = GRADE_COLORS[report.grade]
    summary_text = (
        f"[bold]Score:[/bold] {report.score}/100 | "
        f"[bold]Grade:[/bold] [{grade_color}]{report.grade}[/{grade_color}]"
    )
    console.print(Panel(summary_text, title="Final Assessment", expand=False))

    actionable = [f for f in report.findings if f.status != "ok"]
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for finding in actionable:
            console.print(
                f"• [bold]{finding.rule.header}:[/bold] {finding.rule.recommendation}"
            )


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headers",
        description="Scan a URL for HTTP security headers and grade the result A–F.",
    )
    parser.add_argument(
        "url",
        help="Full URL to scan (must include http:// or https://).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait before giving up on the request (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the report as JSON instead of a colored table.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show all raw response headers before the evaluation.",
    )
    return parser


def main() -> int:
    """Run the command-line interface and return its exit code."""
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    try:
        report = scan(args.url, timeout=args.timeout)
    except httpx.RequestError as exc:
        console.print(f"[red]Request failed:[/red] {type(exc).__name__}: {exc}")
        return 2

    if args.json:
        data = asdict(report)
        data["score"] = report.score
        data["grade"] = report.grade
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        _render_report(report, console, verbose=args.verbose)

    if report.grade in ("A", "B"):
        return 0
    if report.grade in ("C", "D"):
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
