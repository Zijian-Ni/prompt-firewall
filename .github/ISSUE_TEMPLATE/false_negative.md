---
name: False Negative (Attack Not Detected)
about: Report an attack payload that should be blocked but isn't
title: "[FALSE NEGATIVE] "
labels: false-negative, security
assignees: Zijian-Ni
---

## Attack Not Detected

Please describe the attack technique and the payload that slipped through.

> ⚠️ If this is a **security vulnerability** (e.g., a systematic bypass of a critical detector), please report it via [GitHub Security Advisories](https://github.com/Zijian-Ni/prompt-firewall/security/advisories/new) instead of a public issue.

## Payload

```
<paste the attack payload here>
```

> You may sanitize or slightly modify the payload if the full version is too sensitive to share publicly.

## Attack Category

- [ ] Prompt injection
- [ ] Jailbreak (DAN / AIM / STAN / etc.)
- [ ] Encoding obfuscation (base64 / hex / ROT13 / Unicode)
- [ ] PII leakage
- [ ] Token stuffing / repetition
- [ ] Language switching
- [ ] Other: ___

## Expected Behavior

This payload should be blocked with threat level: `[ ] LOW  [ ] MEDIUM  [ ] HIGH  [ ] CRITICAL`

## Current Behavior

```python
from prompt_firewall import PromptFirewall
fw = PromptFirewall()
result = fw.scan("<payload>")
print(result.blocked)    # False (should be True)
print(result.threat_level)
```

## Suggested Pattern

If you have a regex pattern that would catch this, please suggest it:

```
(?i)...
```

## Notes

Any other context, references, or attack research links.
