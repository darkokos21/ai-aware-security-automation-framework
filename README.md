# AI-Aware Security Testing Framework

An AI-aware security testing automation framework that combines **API security testing, Playwright UI security testing, OWASP ZAP scanning, cross-source finding correlation, and AI-assisted security triage** into a single pytest-based workflow.

The project is designed as a practical **QA Automation / SDET / Security Testing** portfolio project, demonstrating how modern test automation can be extended with AI-assisted analysis and reporting.

> **Test target:** OWASP Juice Shop — an intentionally vulnerable application used for authorized security testing.  
> **Security scanner:** OWASP ZAP — used as one of the independent security-testing sources.

---

## Features

- API security testing with Python, pytest, and requests
- UI security testing with Playwright
- OWASP ZAP automated security scanning
- Normalized security findings across multiple sources
- Cross-source finding correlation
- AI-assisted severity and remediation-priority triage
- Deterministic AI provider for reproducible results
- Optional OpenAI integration for LLM-based security triage
- Structured security finding models using Pydantic
- Executive Markdown security assessment generation
- Pytest-based end-to-end AI security pipeline
- HTML test reporting
- Docker-based security testing environment
- CI-ready project structure

---

## Security Testing Architecture

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

The framework treats API tests, UI tests, and ZAP as independent security sources. Findings can then be correlated when multiple sources identify the same underlying security issue.

---

## AI Security Triage

The AI layer converts normalized security findings into structured triage results containing:

- Severity
- Remediation priority
- Confidence
- Explanation
- Security impact
- Remediation guidance
- Triage rationale

The current implementation includes a **deterministic provider**, allowing the complete pipeline to run reproducibly without requiring an external AI API.

The architecture is provider-oriented so additional AI providers can be integrated without changing the core reporting workflow.

### AI Providers

The framework supports two AI-triage modes:

- **Deterministic AI provider** — the default provider, used for reproducible local execution and testing without external API dependencies.
- **Optional OpenAI integration** — enables LLM-based security triage when an OpenAI API key is configured.

The deterministic provider makes the complete security pipeline runnable in a controlled and reproducible environment, while the optional OpenAI provider demonstrates how the framework can be extended to use a production AI service.

---

## Cross-Source Correlation

Findings are normalized using a stable fingerprint based on their title and endpoint.

When multiple independent security sources identify the same issue, the framework can represent that relationship in the finding model.

For example, the current Juice Shop assessment detected a CSP-related issue across:

- ZAP
- API security testing
- UI security testing

The AI report identifies this as a cross-source correlation and can increase its remediation priority based on the available evidence.

---

## Executive Security Assessment

The AI pipeline generates:

```text
reports/ai-security-assessment.md
```

The report provides an executive-level overview before listing the individual findings.

Example summary:

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

Individual findings include:

- Priority
- Severity
- Confidence
- Source
- Endpoint
- Explanation
- Impact
- Remediation
- AI triage rationale

---

## Technology Stack

| Area | Technology |
|---|---|
| Language | Python 3.11 |
| Test Framework | pytest |
| API Testing | requests |
| UI Testing | Playwright |
| Security Scanner | OWASP ZAP |
| Data Models | Pydantic |
| Target Application | OWASP Juice Shop |
| Containers | Docker / Docker Compose |
| Reporting | Markdown / pytest HTML |
| CI | GitHub Actions |

---

## Project Structure

```text
AI-Aware Security Testing Framework/
│
├── framework/
│   └── ai/
│       ├── models.py
│       ├── providers.py
│       ├── triage.py
│       └── report_generator.py
│
├── tests/
│   ├── api/
│   ├── ui/
│   ├── zap/
│   ├── test_ai_pipeline.py
│   └── test_ai_report_generator.py
│
├── reports/
│   └── ai-security-assessment.md
│
├── config/
├── docker/
├── .github/
│   └── workflows/
│
├── Dockerfile
├── docker-compose.yml
├── pytest.ini
├── requirements.txt
└── README.md
```

---

## Running the Tests

Activate the virtual environment first:

```powershell
.venv\Scripts\Activate.ps1
```

Run the API security tests:

```powershell
pytest tests/api -v
```

Run the UI security tests:

```powershell
pytest tests/ui -v
```

Run the OWASP ZAP security scan:

```powershell
<ZAP scan command>
```

After the security tests have generated their findings, run the end-to-end AI security pipeline:

```powershell
pytest tests/test_ai_pipeline.py -v
```

The AI pipeline aggregates the security findings, performs cross-source correlation and AI-assisted triage, and generates the executive security assessment:

```text
reports/ai-security-assessment.md
```

Run the AI report-generator tests independently:

```powershell
pytest tests/test_ai_report_generator.py -v
```

Run the complete AI-related test suite:

```powershell
pytest tests -k "test_ai" -v
```

Run the complete test suite:

```powershell
pytest -v
```

---

## AI Pipeline

The end-to-end AI workflow is:

```text
Security Tests
      ↓
Raw Findings
      ↓
Finding Normalization
      ↓
Finding Correlation
      ↓
AI Triage
      ↓
Priority / Severity / Confidence
      ↓
Executive Security Assessment
```

Run the complete pipeline with:

```powershell
pytest tests/test_ai_pipeline.py -v
```

After a successful run, the generated assessment is available at:

```text
reports/ai-security-assessment.md
```

---

## OWASP Juice Shop

The framework uses **OWASP Juice Shop** as its deliberately vulnerable security-testing target.

This is intentional: the project is designed to detect real security weaknesses rather than test against a hardened application where no findings are expected.

The generated findings therefore represent vulnerabilities and security issues exposed by the test target.

**Juice Shop is the target application.**

**OWASP ZAP is the security scanner.**

They serve different roles in the architecture.

---

## Current AI Security Assessment

The current end-to-end pipeline successfully detects and triages findings from the Juice Shop environment across multiple sources.

The demonstrated assessment includes findings such as:

- SQL injection authentication bypass
- Missing Content Security Policy
- CORS misconfiguration
- Unsafe TRACE handling
- Invalid input handling
- Missing Referrer-Policy
- Timestamp disclosure
- Other ZAP-detected findings

The resulting report consolidates these findings into a single security assessment with AI-generated prioritization and remediation guidance.

---

## Test Status

Current AI reporting and pipeline tests:

```text
test_ai_report_generator.py
7 passed

test_ai_pipeline.py
1 passed
```

The AI security reporting workflow is therefore covered by automated tests for:

- Report generation
- Empty reports
- Dynamic priority aggregation
- Security-source reporting
- Cross-source correlation reporting
- Provider identification
- Raw-finding-to-report triage workflow

---

## Project Status

**Core framework:** Complete

**AI triage:** Implemented

**Cross-source correlation:** Implemented

**Executive security reporting:** Implemented

**API security testing:** Implemented

**Playwright UI security testing:** Implemented

**OWASP ZAP integration:** Implemented

**Automated AI pipeline:** Implemented

**Automated test coverage:** Implemented

---

## License

This project is intended as a portfolio and learning project demonstrating security-focused QA automation, AI-assisted test analysis, and modern automated security testing practices.