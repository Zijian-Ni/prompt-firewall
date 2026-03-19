# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Yes             |

## Reporting a Vulnerability

**prompt-firewall** is itself a security tool, so we take vulnerability reports extremely seriously. We appreciate the responsible disclosure of security issues.

### How to Report

**⚠️ Do NOT open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities via one of these channels:

1. **GitHub Security Advisories** (preferred):
   Go to [Security → Advisories → New draft security advisory](https://github.com/Zijian-Ni/prompt-firewall/security/advisories/new)

2. **Direct email**: Send a detailed report to `security@example.com` with the subject line `[prompt-firewall] Security Vulnerability`.

### What to Include in Your Report

Please provide as much of the following as possible:

- **Description**: A clear description of the vulnerability
- **Affected versions**: Which version(s) are affected
- **Attack vector**: How the vulnerability can be exploited
- **Proof of concept**: A minimal reproducible example (code, payload, etc.)
- **Impact assessment**: What an attacker could achieve
- **Suggested fix** (optional but appreciated)

### What to Expect

| Timeline        | Action |
|----------------|--------|
| **48 hours**   | Acknowledgment of your report |
| **7 days**     | Initial assessment and severity triage |
| **30 days**    | Patch development (for confirmed issues) |
| **90 days**    | Public disclosure (coordinated with reporter) |

We will:
- Keep you informed throughout the process
- Credit you in the security advisory (unless you prefer to remain anonymous)
- Work with you on coordinated disclosure timing

### Scope

The following are **in scope**:

- Bypass of detection patterns (attackers can evade the firewall)
- False negative vulnerabilities in critical detectors (injection, jailbreak)
- Denial-of-service via crafted input (regex ReDoS, excessive memory usage)
- Code injection vulnerabilities in the library itself
- Unsafe deserialization in config loading

The following are **out of scope**:

- False positives (benign input being blocked) — please open a regular GitHub issue
- Vulnerabilities in dependencies (report to the upstream project)
- Theoretical attacks without a practical proof of concept

### Responsible Disclosure Guidelines

- **Do not** test against production systems you do not own
- **Do not** publish exploit details before the coordinated disclosure date
- **Do not** attempt to access, modify, or exfiltrate data

We follow the [CERT Coordinated Vulnerability Disclosure](https://vuls.cert.org/confluence/display/CVD/) guidelines.

### Security Architecture Notes

prompt-firewall is designed with defense-in-depth in mind:
- All scanning is performed **locally** — no data is sent to external services
- Pattern databases are loaded from bundled JSON files
- No eval() or dynamic code execution is used in the core library
- PII values are never logged — only counts and types

### Known Limitations

- Pattern-matching detectors can be evaded by novel attack techniques
- The library is a **defense layer**, not a guarantee — it should be used as part of a broader security strategy
- Output scanning is only as good as the canary tokens you configure
- False positive rates vary by use case; tune sensitivity accordingly

### Security Contact

**Zijian Ni** — [GitHub](https://github.com/Zijian-Ni)

PGP key available upon request for encrypted communication.
