<<<<<<< HEAD
# security-scan

A lightweight security scanner that combines **SAST, dependency, secrets and IaC checks** into a single report with a **PASS** or **FAIL** result.

Designed for both local development and CI pipelines.

## What it checks

| Category     | Built-in                                                                               | Optional tool |
| ------------ | -------------------------------------------------------------------------------------- | ------------- |
| SAST         | Python checks for dangerous calls such as `eval`, `exec`, `os.system` and `shell=True` | Bandit        |
| Dependencies | Basic version checks for `requirements*.txt`                                           | pip-audit     |
| Secrets      | AWS keys, private keys and hardcoded credentials                                       | —             |
| IaC          | Common Terraform, YAML and JSON misconfigurations                                      | —             |

Findings from all scanners are normalised into a common format, sorted by severity and combined into a single result.

## Requirements

* Python 3.9+
* No additional dependencies for built-in checks

Optional tools:

```bash
pip install -r requirements-optional.txt
```

## Usage

Scan a project:

```bash
./security-scan.py --path .
```

Generate JSON output:

```bash
./security-scan.py --path . --format json
```

Fail on medium or higher:

```bash
./security-scan.py --path . --fail-on medium
```

Run specific checks:

```bash
./security-scan.py --path . --only secrets,iac
```

Use only built-in scanners:

```bash
./security-scan.py --path . --engine builtin
```

Save the report:

```bash
./security-scan.py --path . --format json --output report.json
```

By default, the scanner uses Bandit and pip-audit when available. If they are not installed, the built-in checks are used.

## Exit codes

| Code | Result                                                 |
| ---: | ------------------------------------------------------ |
|  `0` | PASS                                                   |
|  `1` | FAIL - finding meets the configured severity threshold |
|  `2` | Invalid usage or path                                  |
|  `3` | Scanner error - result cannot be trusted               |

The scanner fails closed: a scanner error does not result in a successful security check.

## Testing

Install pytest:

```bash
pip install pytest
```

Run the tests:

```bash
python -m pytest -v
```

The test suite covers vulnerable and clean applications, secret detection, dependency checks and severity thresholds.

## CI

Example GitHub Actions workflow:

```yaml
- run: pip install -r requirements-optional.txt
- run: ./security-scan.py --path . --format json --output report.json

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: security-report
    path: report.json
```

A non-zero exit code causes the CI job to fail.

## Limitations

This is a **portfolio/teaching-scale security tool**, not a replacement for dedicated security platforms.

* Built-in SAST currently covers Python.
* Secret and IaC detection is pattern-based and may produce false positives.
* The built-in dependency database is intentionally limited; use pip-audit for broader coverage.
* Coverage depends on the scanner and engine being used.

## Project structure

```text
security-scan.py
requirements-optional.txt
examples/
├── vulnerable-app/
└── clean-app/
tests/
```

Test credentials in the example applications are fake and must never be used in a real environment.
=======

>>>>>>> 11a54ada2f1c3c8a403715a00f480547c776fb2d
