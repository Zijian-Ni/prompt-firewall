---
name: Bug Report
about: Something is broken or behaving unexpectedly
title: "[BUG] "
labels: bug
assignees: Zijian-Ni
---

## Bug Description

A clear and concise description of what the bug is.

## To Reproduce

```python
from prompt_firewall import PromptFirewall

fw = PromptFirewall()
result = fw.scan("your text here")
# expected: result.blocked == True
# actual: result.blocked == False
```

## Expected Behavior

What did you expect to happen?

## Actual Behavior

What actually happened? Include error messages or wrong outputs.

## Environment

- OS: [e.g. Ubuntu 22.04, macOS 14, Windows 11]
- Python version: [e.g. 3.11.2]
- prompt-firewall version: [e.g. 0.1.0]
- Installed extras: [e.g. `pip install prompt-firewall[proxy]`]

## Additional Context

Any additional context, logs, or screenshots that might help diagnose the issue.
