# Source Security Evidence

Review date: 2026-09-09. Scope: release candidate src, tools and tests.
Tool: Bandit 1.9.4. Result: passed after line-specific review; no remaining
reported issues. No directory or rule-wide exclusions are configured.

Scanner provenance review: official Bandit documentation names PyPI bandit;
version 1.9.4 PyPI source links match github.com/PyCQA/bandit. Release upload:
2026-02-25. Operator authorized persistent project-local installation separately.
pip-audit checked the installed scanner and its six dependencies on 2026-09-09:
zero known vulnerabilities. This is provenance and known-vulnerability screening,
not a full source audit or a guarantee that the scanner is free from malicious code.
The ignored .audit-venv is used by the hook, never included in public artifacts.

Initial findings: one B108 medium test-path indicator and five low subprocess
indicators (B404/B603/B607). Replaced the rejected-input temporary path literal
with a forbidden output path. Git executable resolution is now explicit.
Four line-specific nosec annotations cover two subprocess imports and two
argument-array subprocess calls. These calls never use a shell, invoke only
host-selected Git/scanner programs, and do not execute inspected repository code.
The integration test only pushes to disposable local repositories.

VibeGate baseline review: 17 medium lexical indicators remain visible, with
zero high/critical findings. Reviewed groups are shell wrappers and their
documented commands; MIT permission wording; warning text; fixed synthetic
prompt injection; prepare/preflight methods misclassified as install hooks;
and the bounded subprocess calls described above. None is suppressed through
a project-wide tuning rule. These indicators do not certify arbitrary code safe.

27 offline tests pass in a clean, non-editable installation. This includes
real SDK dispatch, denial cases, request ceilings and actual blocked local push.
Synthetic adversarial cases are intentionally retained, not blanket-excluded.

Residual risk: static analysis does not establish absence of all vulnerabilities.
Host PATH, interpreter and scanner checkout must be trusted. Local hooks are
bypassable. Live dangerous-action interception is not yet demonstrated.
Private raw reports remain outside the public candidate; the pre-push workflow
reruns independent scans on committed blobs before ordinary branch publication.
