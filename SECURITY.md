# Security Policy

`prompt-firewall` is a security tool — we hold ourselves to a higher standard. We take all security reports seriously and respond promptly.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Active support  |
| < 0.1   | ❌ Not supported   |

---

## Reporting a Vulnerability

> ⚠️ **Do NOT open a public GitHub issue for security vulnerabilities.** Public disclosure before a fix is available puts users at risk.

### Preferred Channel: GitHub Security Advisories

Go to **[Security → Advisories → New draft security advisory](https://github.com/Zijian-Ni/prompt-firewall/security/advisories/new)** and submit your report privately. This is the fastest path to a coordinated fix.

### Alternative: Direct Email

Send a detailed report to **security@zijian.dev** with subject line:

```
[prompt-firewall] Security Vulnerability: <brief description>
```

Please encrypt sensitive details using our PGP key (available on request).

---

## What to Include

A high-quality report helps us triage and fix faster. Please include:

| Field | Details |
|---|---|
| **Description** | Clear explanation of the vulnerability and its root cause |
| **Affected versions** | Which version(s) are impacted |
| **Attack vector** | How the vulnerability is triggered (input, config, API, etc.) |
| **Proof of Concept** | Minimal reproducible code or payload demonstrating the issue |
| **Impact** | What an attacker could achieve (bypass, exfiltration, DoS, etc.) |
| **CVSS score** | Optional — your estimate of severity |
| **Suggested fix** | Optional but very welcome |

---

## Response Timeline

| Milestone | Target |
|---|---|
| **Acknowledgment** | Within 48 hours |
| **Initial triage** | Within 7 days |
| **Patch development** | Within 30 days (for confirmed issues) |
| **Public disclosure** | Coordinated with reporter — default 90 days after initial report |

We will:
- Acknowledge your report within 48 hours
- Keep you informed at each stage
- Credit you in the security advisory (unless you prefer anonymity)
- Work with you to agree on the disclosure timeline

If we are unable to reproduce or confirm a vulnerability within 14 days, we will notify you.

---

## Scope

### ✅ In Scope

These are the issue types we care most about:

- **Detection bypass** — An attacker can craft input that evades all detectors (false negative)
- **False negatives in critical detectors** — Known jailbreaks (DAN, AIM, STAN) are not caught
- **ReDoS** — Regex patterns vulnerable to catastrophic backtracking on crafted input
- **Memory exhaustion / DoS** — Specially crafted input causes unbounded memory/CPU use
- **Code injection in config** — Unsafe deserialization of config files (e.g., `from_file()`)
- **Path traversal in rule loading** — Malicious rule filenames escape the rules directory
- **PII leakage in logs** — Matched PII values are exposed in log output
- **Dependency vulnerability** — Critical CVE in a direct dependency (`pydantic`, `regex`, etc.)
- **Middleware bypass** — A crafted HTTP request bypasses the middleware entirely

### ❌ Out of Scope

- Vulnerabilities in the **underlying LLM** itself (report to the model provider)
- **Novel jailbreaks not yet in our signatures** — these are expected limitations; please open a regular issue to add the pattern
- Issues requiring **physical access** to the host
- **Social engineering** attacks
- Issues in **outdated/unsupported versions**
- Theoretical attacks without a working proof of concept
- **Rate limiting / brute force** concerns (out of scope for this library)

---

## Known Limitations

`prompt-firewall` uses **static regex pattern matching**. We are transparent about what it can and cannot do:

1. **Novel jailbreaks** — A jailbreak technique we don't have a signature for will not be caught. This is expected behavior, not a vulnerability. Please open a regular issue to add coverage.

2. **Semantic attacks** — Prompts that are semantically harmful but don't match any pattern will not be blocked. This library is a defense-in-depth layer, not a complete solution.

3. **Multi-turn attacks** — If an attacker spreads an injection across multiple conversation turns, the per-message scan may not detect it. We are working on conversation-level scanning.

4. **Language model evasion** — Attackers who know our pattern library can deliberately craft bypasses. This is an inherent limitation of signature-based detection.

We recommend combining `prompt-firewall` with semantic classification, rate limiting, and human review for high-risk use cases.

---

## Security Best Practices for Users

When integrating `prompt-firewall`:

1. **Use strict mode for production** (`PromptFirewall.strict()`) unless you have specific usability requirements
2. **Scan model output too** — enable `enable_output_scanning=True` in your proxy config
3. **Plant canary tokens** in system prompts to detect extraction attacks
4. **Treat `threat_level=HIGH` as blocked** — don't silently allow high-severity detections
5. **Log blocked requests** (without PII) for threat intelligence
6. **Keep the library updated** — subscribe to security advisories via GitHub Watch → Security alerts
7. **Combine with semantic detection** — use an embedding-based classifier or a guard LLM alongside this library
8. **Don't expose detection reasons to end users** — the `triggered_detectors` field helps you, not attackers

---

## Security Advisories

Past security advisories will be listed at: https://github.com/Zijian-Ni/prompt-firewall/security/advisories

---

## Hall of Fame

We thank the following researchers for responsible disclosure (none yet — be the first!):

*This section will list credited contributors as advisories are resolved.*

---

## License

This security policy is part of the `prompt-firewall` project and is licensed under [Apache-2.0](LICENSE).
