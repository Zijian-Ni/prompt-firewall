# Pull Request

## Summary

<!-- A concise description of what this PR does -->

## Type of Change

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 🔒 Security fix (fixes a vulnerability or detection gap)
- [ ] 🧹 Refactor (code restructuring, no behavior change)
- [ ] 📝 Documentation update
- [ ] 🎯 New attack pattern / jailbreak signature
- [ ] ⚙️ CI/tooling change

## Related Issues

<!-- Closes #123, Fixes #456 -->

## Changes Made

<!-- List key changes: -->
- 
- 

## Testing

<!-- How did you test this? -->

- [ ] Added unit tests for new code
- [ ] All existing tests pass (`pytest`)
- [ ] Tested against `tests/fixtures/malicious_prompts.json`
- [ ] Verified no new false positives in `tests/fixtures/benign_prompts.json`

## For New Detection Patterns

If you're adding new patterns to `rules/injection_patterns.json` or `rules/jailbreak_signatures.json`:

- [ ] Pattern regex is valid (tested with Python `re` module)
- [ ] Pattern has no catastrophic backtracking (tested with long inputs)
- [ ] Pattern includes `(?i)` for case-insensitivity where appropriate
- [ ] Added test case in `tests/fixtures/malicious_prompts.json`
- [ ] Added corresponding test in `tests/test_detectors/`
- [ ] Copied updated rules to `src/prompt_firewall/rules/` directory

## Security Considerations

<!-- If this PR has security implications, describe them here -->

## Checklist

- [ ] Code follows the project's style (`ruff check` passes)
- [ ] Self-review completed
- [ ] Documentation updated (README, docstrings) if needed
- [ ] CHANGELOG.md updated (if applicable)
