---
name: False Positive (Benign Input Blocked)
about: Report a legitimate input that is incorrectly blocked
title: "[FALSE POSITIVE] "
labels: false-positive
assignees: Zijian-Ni
---

## False Positive Report

Describe the legitimate use case and the input that was incorrectly flagged.

## Blocked Input

```
<paste the benign input here>
```

## Context / Use Case

Why is this input legitimate? What is the expected use case?

## Current Behavior

```python
from prompt_firewall import PromptFirewall
fw = PromptFirewall()
result = fw.scan("<input>")
print(result.blocked)          # True (incorrect)
print(result.triggered_detectors)  # which detectors fired
print(result.explanation)
```

## Expected Behavior

This input should **not** be blocked, or at most flagged at `LOW` threat level.

## Severity

How much does this false positive impact your use case?
- [ ] Minor — easily worked around
- [ ] Moderate — affects real user workflows
- [ ] Major — blocks a core feature of my application

## Notes

Any additional context that might help us tune the detector without increasing false negatives.
