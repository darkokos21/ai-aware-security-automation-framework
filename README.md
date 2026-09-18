# AI-Aware Security Automation Framework

A pytest-based security testing framework that combines **API security tests, Playwright UI security tests, and OWASP ZAP scanning**, then normalizes, correlates, and triages the results with an AI layer to produce an executive-level security assessment.

Built as a **QA Automation / SDET / Security Testing** portfolio project, it shows how a conventional test automation stack can be extended into an end-to-end, CI-ready security pipeline.

> **Target:** OWASP Juice Shop, an intentionally vulnerable application used for authorized security testing.
> **Scanner:** OWASP ZAP, used as one of three independent security sources.

---

## Why It Matters

Security findings usually arrive from disconnected tools in different formats, with no shared severity model and no way to tell that three tools found the same issue. This framework treats every source the same way:

- **One finding model.** API test failures, UI test failures, and ZAP alerts are normalized into a single Pydantic schema with severity, confidence, endpoint, CWE, and remediation.
- **Cross-source correlation.** Findings that describe the same vulnerability are merged, so a missing Content Security Policy detected by ZAP, the API suite, and the UI suite becomes one finding with three sources and higher confidence.
- **AI-assisted triage.** Each correlated finding receives a remediation priority, impact statement, and rationale. A deterministic provider keeps the pipeline reproducible in CI, and an optional OpenAI provider shows how a production LLM can be plugged in without changing the workflow.
- **CI-native.** GitHub Actions spins up the target and scanner in Docker, runs every suite, and publishes reports as build artifacts.

---

## Architecture

```text
                    ┌─────────────────────┐
                    │   OWASP Juice Shop  │
                    │   Vulnerable Target │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   API Security Tests    Playwright UI Tests    OWASP ZAP
     pytest/requests        Playwright            Scanner
          │                    │                    │
          └────────────────────┼────────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Finding Normalizer  │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Finding Correlation │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │   AI Triage Layer   │
                    │ severity / priority │
                    │ confidence / impact │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Executive Security  │
                    │     Assessment      │
                    └─────────────────────┘
```

---

## What Is Tested

| Source | Coverage |
|---|---|
| **API security tests** (`api_tests/`) | Authentication and SQL injection bypass, authorization, CORS policy, security headers, HTTP method handling, input validation, rate limiting, sensitive data exposure, smoke checks |
| **UI security tests** (`ui_tests/`) | Browser-level security headers, login flow abuse, reflected and stored XSS |
| **OWASP ZAP** (`zap/`) | Spider plus passive scan by default, optional active scan, with JSON, Markdown, and summary reports |

Tests tagged `@pytest.mark.security` that fail are recorded as findings by a pytest plugin, so a failing test is a security finding, not just a red build.

---

## Quick Start

### Prerequisites

- Python 3.11 or newer
- Docker and Docker Compose

### Setup

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows
# source .venv/bin/activate       # macOS / Linux

pip install -r requirements.txt
playwright install --with-deps chromium

copy .env.example .env            # Windows
# cp .env.example .env            # macOS / Linux
```

### Start the target and scanner

```bash
docker compose -f docker/docker-compose.yml up -d juice-shop zap
```

| Service | URL |
|---|---|
| Juice Shop | http://localhost:31001 |
| ZAP API | http://localhost:31002 |

ZAP publishes the same port it listens on inside the container. ZAP only serves API requests addressed to its own host and port, so a mismatched mapping makes it proxy the request to itself and fail.

### Run the security suites

```bash
pytest api_tests -v
pytest ui_tests -v
```

Each run writes its findings to `reports/api-security-findings.json` or `reports/ui-security-findings.json`.

### Run the ZAP scan

From inside the Docker network, using the runner profile:

```bash
docker compose -f docker/docker-compose.yml --profile runner run --rm secure-test-ops python -m zap.run_scan
```

Add `--active` for an active scan. The scan writes `reports/zap-report.json`, `reports/zap-report.md`, and `reports/zap-summary.json`.

### Run the AI pipeline

```bash
pytest tests -v
```

This collects all three sources, correlates them, runs triage, and writes `reports/ai-security-assessment.md`.

---

## Example Assessment

```text
## Executive Summary

### Findings by Priority
- Critical: 1
- High: 1
- Medium: 4
- Low: 2
- Informational: 1

### Sources
- API security tests
- UI security tests
- ZAP

### Cross-Source Correlations
- 1 finding detected across multiple independent security sources

Total findings: 9
```

Each finding then lists priority, severity, confidence, sources, endpoint, explanation, impact, remediation, and the triage rationale.

---

## AI Providers

| Provider | Purpose |
|---|---|
| `deterministic` (default) | Rule-based triage. Reproducible, no external calls, used in CI. |
| `openai` | LLM-based triage when `OPENAI_API_KEY` is set. Selected with `AI_PROVIDER=openai`. |

Providers share one interface, so adding another is a single class.

---

## CI Pipeline

The GitHub Actions workflow in `.github/workflows/ci.yml`:

1. Installs Python dependencies and Playwright Chromium.
2. Starts Juice Shop and the ZAP daemon with Docker Compose and waits for both.
3. Runs a ZAP baseline scan against Juice Shop and writes `reports/zap-report.json`.
4. Runs the API and UI security suites. These are allowed to fail, because failures are findings.
5. Runs the AI pipeline tests, which must pass.
6. Uploads all reports as a build artifact, plus Docker logs on failure.

The ZAP collector accepts both ZAP's native JSON report, as produced by the baseline scan, and the framework's own flat report format.

---

## Project Structure

```text
├── api_tests/                 API security tests
├── ui_tests/                  Playwright UI security tests
├── tests/                     AI pipeline unit and integration tests
│   └── fixtures/              Committed sample reports used by the tests
├── zap/                       ZAP client, scanner, reporter, run_scan entry point
├── framework/
│   ├── ai/                    Collectors, correlator, triage providers, report generator
│   ├── config/                Pydantic settings loaded from .env
│   ├── browser/               Playwright browser management
│   ├── utils/                 HTTP API client and helpers
│   ├── security_reporter.py   Maps failed security tests to findings
│   └── security_pytest_plugin.py
├── services/                  Health checks for the target and ZAP
├── docker/                    Dockerfile and docker-compose.yml
├── reports/                   Generated reports (gitignored)
├── .github/workflows/ci.yml
├── pytest.ini
└── requirements.txt
```

---

## Technology Stack

| Area | Technology |
|---|---|
| Language | Python 3.11+ |
| Test framework | pytest, pytest-html |
| API testing | requests |
| UI testing | Playwright |
| Security scanner | OWASP ZAP 2.16 |
| Data models | Pydantic v2 |
| AI triage | Deterministic provider, optional OpenAI |
| Target application | OWASP Juice Shop |
| Containers | Docker, Docker Compose |
| CI | GitHub Actions |

---

## License

This project is a portfolio and learning project demonstrating security-focused QA automation, AI-assisted test analysis, and modern automated security testing practices. Run it only against systems you are authorized to test.
