#!/usr/bin/env python3
"""security-scan: run several security checks and return one unified verdict.

Categories: sast, dependencies, secrets, iac.
Each category uses a real external tool when it is installed (bandit for SAST,
pip-audit for dependencies) and falls back to a built-in engine otherwise, so
the script works on a bare Python install and still scales up when richer tools
are available. Results are merged into one report with a PASS or FAIL decision.

Examples:
    ./security-scan.py --path ./app --format json
    ./security-scan.py --path . --fail-on medium --engine builtin
    ./security-scan.py --path . --only secrets,iac --output report.json --format json

Exit codes: 0 PASS, 1 FAIL (findings at or above --fail-on), 2 usage error,
3 a scanner failed to run (treated as not safe to pass).
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Callable, Iterator, Optional

__version__ = "1.0.0"


# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    category: str
    engine: str
    rule: str
    severity: Severity
    file: str
    line: Optional[int]
    message: str

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "engine": self.engine,
            "rule": self.rule,
            "severity": self.severity.name.lower(),
            "file": self.file,
            "line": self.line,
            "message": self.message,
        }


@dataclass
class ScanResult:
    category: str
    engine: str
    status: str                      # "ok" or "error"
    findings: list
    note: str = ""


@dataclass(frozen=True)
class PatternRule:
    pattern: re.Pattern
    title: str
    severity: Severity


class ToolError(Exception):
    """An external tool could not run or returned unusable output."""


# ----------------------------------------------------------------------------
# Configuration: rules and limits live here, apart from the logic
# ----------------------------------------------------------------------------
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}
MAX_FILE_BYTES = 1_000_000
TOOL_TIMEOUT_SECONDS = 120

SECRET_SUFFIXES = {".py", ".yml", ".yaml", ".json", ".tf", ".ini", ".cfg", ".toml",
                   ".sh", ".js", ".pem", ".env"}
IAC_SUFFIXES = {".tf", ".yml", ".yaml", ".json"}

SECRET_RULES = [
    PatternRule(re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key", Severity.CRITICAL),
    PatternRule(
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
        "Private key", Severity.CRITICAL,
    ),
    PatternRule(
        re.compile(
            r"""(?i)(?:api[_-]?key|secret|password|passwd|token)["']?\s*[:=]\s*"""
            r"""["'](?!\$\{|\{\{)[^"'\s]{8,}["']"""
        ),
        "Hardcoded credential", Severity.HIGH,
    ),
]

IAC_RULES = [
    PatternRule(re.compile(r"""acl\s*[=:]\s*["']?public-read(?:-write)?["']?"""),
                "Public S3 ACL", Severity.HIGH),
    PatternRule(re.compile(r"0\.0\.0\.0/0"), "Open CIDR range", Severity.HIGH),
]

DANGEROUS_CALLS = {
    "eval": Severity.HIGH,
    "exec": Severity.HIGH,
    "pickle.load": Severity.HIGH,
    "pickle.loads": Severity.HIGH,
    "os.system": Severity.HIGH,
    "yaml.load": Severity.MEDIUM,
    "subprocess.call": Severity.MEDIUM,
    "subprocess.run": Severity.MEDIUM,
    "subprocess.Popen": Severity.MEDIUM,
}

# package -> (first fixed version, advisory). Small offline table for the built-in
# engine only. pip-audit, when installed, uses a live vulnerability database.
VULNERABLE_PACKAGES = {
    "requests": ("2.31.0", "CVE-2023-32681"),
    "pyyaml": ("5.4", "CVE-2020-14343"),
    "flask": ("2.3.2", "CVE-2023-30861"),
}

REQUIREMENT_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*"
    r"(?P<op>==|>=|<=|~=|!=|<|>)?\s*(?P<ver>[\w.]+)?"
)


# ----------------------------------------------------------------------------
# File access
# ----------------------------------------------------------------------------
def walk_files(root: Path) -> Iterator[Path]:
    """Yield regular files under root, pruning noisy directories and symlinks."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if not path.is_symlink():
                yield path


def read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(errors="ignore")
    except OSError:
        return None


class ScanContext:
    """Walks the tree once and caches file contents for every scanner."""

    def __init__(self, root: Path):
        self.root = root
        self.files = list(walk_files(root))
        self._cache: dict = {}

    def text(self, path: Path) -> Optional[str]:
        if path not in self._cache:
            self._cache[path] = read_text(path)
        return self._cache[path]

    def rel(self, path) -> str:
        try:
            return str(Path(path).resolve().relative_to(self.root))
        except ValueError:
            return str(path)


def has_suffix(path: Path, suffixes: set) -> bool:
    # Path(".env").suffix is empty, so dotenv files need a name check as well.
    return path.suffix in suffixes or path.name.startswith(".env")


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def is_requirements_file(path: Path) -> bool:
    return path.name.startswith("requirements") and path.suffix == ".txt"


# ----------------------------------------------------------------------------
# Built-in engines (no dependencies, always available)
# ----------------------------------------------------------------------------
def scan_patterns(ctx: ScanContext, suffixes: set, rules: list, category: str) -> list:
    findings = []
    for path in ctx.files:
        if not has_suffix(path, suffixes):
            continue
        text = ctx.text(path)
        if text is None:
            continue
        for rule in rules:
            for match in rule.pattern.finditer(text):
                # The matched value is never copied into the report, so secrets are not leaked.
                findings.append(Finding(category, "builtin", rule.title, rule.severity,
                                        ctx.rel(path), line_of(text, match.start()), rule.title))
    return findings


def builtin_secrets(ctx: ScanContext) -> list:
    return scan_patterns(ctx, SECRET_SUFFIXES, SECRET_RULES, "secrets")


def builtin_iac(ctx: ScanContext) -> list:
    return scan_patterns(ctx, IAC_SUFFIXES, IAC_RULES, "iac")


def dotted_name(node: ast.expr) -> Optional[str]:
    """Resolve a.b.c style call targets; None for anything dynamic."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def uses_shell_true(call: ast.Call) -> bool:
    return any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
               for kw in call.keywords)


def builtin_sast(ctx: ScanContext) -> list:
    findings = []
    for path in ctx.files:
        if path.suffix != ".py":
            continue
        text = ctx.text(path)
        if text is None:
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            print(f"warning: could not parse {ctx.rel(path)}: {exc.msg}", file=sys.stderr)
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted_name(node.func)
            if name not in DANGEROUS_CALLS:
                continue
            severity = DANGEROUS_CALLS[name]
            if name.startswith("subprocess.") and uses_shell_true(node):
                severity = Severity.HIGH
            findings.append(Finding("sast", "builtin", name, severity, ctx.rel(path),
                                    node.lineno, f"Dangerous call: {name}"))
    return findings


def version_tuple(version: str) -> tuple:
    nums = [int(n) for n in re.findall(r"\d+", version)]
    return tuple(nums + [0] * (4 - len(nums)))  # pad so 5.4 equals 5.4.0


def builtin_deps(ctx: ScanContext) -> list:
    findings = []
    for path in ctx.files:
        if not is_requirements_file(path):
            continue
        text = ctx.text(path)
        if text is None:
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = re.split(r"\s#|;", raw, maxsplit=1)[0].strip()
            if not line or line.startswith(("#", "-")):
                continue
            match = REQUIREMENT_LINE.match(line)
            if not match:
                continue
            name = re.sub(r"[-_.]+", "-", match["name"]).lower()
            if name not in VULNERABLE_PACKAGES:
                continue
            fixed, advisory = VULNERABLE_PACKAGES[name]
            if match["op"] == "==" and match["ver"]:
                if version_tuple(match["ver"]) < version_tuple(fixed):
                    findings.append(Finding(
                        "dependencies", "builtin", advisory, Severity.HIGH, ctx.rel(path), lineno,
                        f"{name} {match['ver']} is vulnerable, upgrade to {fixed} or later ({advisory})"))
            else:
                findings.append(Finding(
                    "dependencies", "builtin", advisory, Severity.LOW, ctx.rel(path), lineno,
                    f"{name} is not pinned with ==, cannot confirm it is at or above {fixed} ({advisory})"))
    return findings


# ----------------------------------------------------------------------------
# External tool adapters (used automatically when the tool is installed)
# ----------------------------------------------------------------------------
def run_tool(cmd: list) -> subprocess.CompletedProcess:
    """Run a tool without a shell, with a timeout."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=TOOL_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        raise ToolError(f"{cmd[0]} timed out after {TOOL_TIMEOUT_SECONDS}s")
    except OSError as exc:
        raise ToolError(f"{cmd[0]} could not start: {exc}")


def parse_tool_json(proc: subprocess.CompletedProcess, tool: str):
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        detail = (proc.stderr.strip().splitlines() or ["no output"])[-1]
        raise ToolError(f"{tool} returned no JSON: {detail}")


def external_bandit(ctx: ScanContext) -> list:
    excludes = ",".join(str(ctx.root / d) for d in sorted(SKIP_DIRS))
    proc = run_tool(["bandit", "-r", str(ctx.root), "-f", "json", "-q", "-x", excludes])
    data = parse_tool_json(proc, "bandit")
    findings = []
    for item in data.get("results", []):
        severity = Severity[item.get("issue_severity", "MEDIUM").upper()]
        findings.append(Finding(
            "sast", "bandit", f"{item['test_id']} {item['test_name']}", severity,
            ctx.rel(item["filename"]), item.get("line_number"), item["issue_text"]))
    return findings


def external_pip_audit(ctx: ScanContext) -> list:
    findings = []
    for req in (p for p in ctx.files if is_requirements_file(p)):
        proc = run_tool(["pip-audit", "-r", str(req), "--no-deps", "--disable-pip",
                         "-f", "json", "--progress-spinner", "off"])
        data = parse_tool_json(proc, "pip-audit")
        deps = data.get("dependencies", []) if isinstance(data, dict) else data
        for dep in deps:
            for vuln in dep.get("vulns", []):
                fixes = ", ".join(vuln.get("fix_versions") or []) or "none available"
                findings.append(Finding(
                    "dependencies", "pip-audit", vuln["id"],
                    Severity.HIGH,  # pip-audit reports no severity, so assume the conservative level
                    ctx.rel(req), None,
                    f"{dep['name']} {dep['version']} is vulnerable ({vuln['id']}), fixed in: {fixes}"))
    return findings


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class Check:
    category: str
    builtin: Callable
    external_binary: Optional[str] = None
    external: Optional[Callable] = None


CHECKS = [
    Check("sast", builtin_sast, "bandit", external_bandit),
    Check("dependencies", builtin_deps, "pip-audit", external_pip_audit),
    Check("secrets", builtin_secrets),
    Check("iac", builtin_iac),
]
CATEGORIES = [c.category for c in CHECKS]


def run_check(check: Check, ctx: ScanContext, engine: str) -> ScanResult:
    note = ""
    if engine == "auto" and check.external and shutil.which(check.external_binary):
        try:
            return ScanResult(check.category, check.external_binary, "ok", check.external(ctx))
        except ToolError as exc:
            note = f"{exc}; fell back to built-in engine"
    try:
        return ScanResult(check.category, "builtin", "ok", check.builtin(ctx), note)
    except Exception as exc:  # a crashing scanner must never look like a clean result
        return ScanResult(check.category, "builtin", "error", [], f"{type(exc).__name__}: {exc}")


def build_report(root: Path, results: list, fail_on: Severity) -> dict:
    findings = sorted({f for r in results for f in r.findings},
                      key=lambda f: (-f.severity, f.file, f.line or 0, f.rule))
    errors = [f"{r.category}: {r.note}" for r in results if r.status == "error"]
    if any(f.severity >= fail_on for f in findings):
        decision = "FAIL"
    elif errors:
        decision = "ERROR"
    else:
        decision = "PASS"
    return {
        "tool": "security-scan",
        "version": __version__,
        "path": str(root),
        "time": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "fail_on": fail_on.name.lower(),
        "scanners": [{"category": r.category, "engine": r.engine, "status": r.status,
                      "findings": len(r.findings), "note": r.note} for r in results],
        "summary": {s.name.lower(): sum(f.severity == s for f in findings)
                    for s in sorted(Severity, reverse=True)},
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
        "errors": errors,
    }


def render_text(report: dict) -> str:
    bar = "=" * 60
    lines = [bar, f"  SECURITY SCAN: {report['decision']}", bar,
             f"  Path    : {report['path']}",
             f"  Fail on : {report['fail_on']} and above",
             f"  Total   : {report['total']} findings"]
    lines += [f"    {sev:8s}: {n}" for sev, n in report["summary"].items() if n]
    lines.append("\n  Scanners")
    for s in report["scanners"]:
        extra = f"  ({s['note']})" if s["note"] else ""
        lines.append(f"    {s['category']:13s} {s['engine']:10s} {s['status']:6s} {s['findings']} findings{extra}")
    if report["findings"]:
        lines.append("\n  Findings")
    for i, f in enumerate(report["findings"], 1):
        where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        lines.append(f"    {i:2d}. [{f['severity'].upper():8s}] {f['category']:12s} {f['message']} ({where})")
    lines += [bar, f"  FINAL: {report['decision']}", bar]
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# Command line
# ----------------------------------------------------------------------------
def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run multiple security checks and return one verdict.")
    ap.add_argument("--path", "-p", default=".", help="directory to scan (default: current directory)")
    ap.add_argument("--format", "-f", choices=["json", "text"], default="text")
    ap.add_argument("--fail-on", default="high", choices=[s.name.lower() for s in Severity],
                    help="lowest severity that causes a FAIL (default: high)")
    ap.add_argument("--engine", choices=["auto", "builtin"], default="auto",
                    help="auto uses bandit and pip-audit when installed; builtin never calls external tools")
    ap.add_argument("--only", help=f"comma separated subset of: {', '.join(CATEGORIES)}")
    ap.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)
    args.categories = CATEGORIES
    if args.only:
        wanted = [c.strip() for c in args.only.split(",") if c.strip()]
        unknown = [c for c in wanted if c not in CATEGORIES]
        if unknown:
            ap.error(f"unknown categories: {', '.join(unknown)}")
        args.categories = wanted
    return args


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 2

    ctx = ScanContext(root)
    results = [run_check(c, ctx, args.engine) for c in CHECKS if c.category in args.categories]
    report = build_report(root, results, Severity[args.fail_on.upper()])

    output = json.dumps(report, indent=2) if args.format == "json" else render_text(report)
    if args.output:
        Path(args.output).write_text(output + "\n")
    else:
        print(output)
    return {"PASS": 0, "FAIL": 1, "ERROR": 3}[report["decision"]]


if __name__ == "__main__":
    sys.exit(main())
