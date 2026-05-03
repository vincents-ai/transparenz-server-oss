# Security Policy

## Supported Versions

We support the latest release of each package. Security patches are applied to the `main` branch and included in the next release.

| Version | Supported          |
| ------- | ------------------ |
| latest  | ✅                 |
| older   | ❌                 |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, report them via:

- **Email**: security@vincents.ai
- **GitHub Security Advisories**: Use [GitHub's private vulnerability reporting](https://github.com/vincents-ai/transparenz-server-oss/security/advisories/new) for this repository.

We aim to respond within **24 hours** and provide a detailed response within **72 hours**, consistent with EU Cyber Resilience Act (CRA) Article 10 timelines.

### What to Include

- Description of the vulnerability
- Affected component and version
- Steps to reproduce (if applicable)
- Potential impact (e.g., data exposure, privilege escalation, denial of service)
- Any suggested fixes or mitigations

## Security Update Policy

This project implements EU CRA and NIS2 Directive compliance tooling. We follow these SLA commitments:

| Severity | Response Time | Patch Target |
|----------|--------------|-------------|
| Critical / Exploited | 24 hours | 72 hours |
| Critical | 72 hours | 7 days |
| High | 7 days | 14 days |
| Medium / Low | 14 days | 30 days |

## Security Architecture

- **Authentication**: JWT-based with HMAC-SHA256 (RS256 for production)
- **Authorization**: Role-based access control (admin, compliance_officer, viewer)
- **Multi-tenancy**: Row-Level Security (RLS), schema-per-org, or instance-per-org isolation
- **Data encryption**: AES-256 at rest for sensitive fields
- **Audit trail**: Ed25519-signed integrity chain for compliance records
- **Input validation**: All API endpoints validate input before processing

## Coordinated Disclosure

We follow [ISO/IEC 29147](https://www.iso.org/standard/72307.html) vulnerability disclosure guidelines and [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/) for security advisories.

## Third-Party Dependencies

This project uses Go modules with `go.sum` for dependency integrity. We monitor for known vulnerabilities in dependencies and update promptly.
