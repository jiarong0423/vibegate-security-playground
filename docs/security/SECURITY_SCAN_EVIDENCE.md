# Source Security Evidence

Review date: 2026-09-09
Candidate: VibeGate Security Playground 0.2.0, exact 36-path public allowlist

## Final Working-Tree Candidate

- Python unittest discovery: **131 tests passed** in 34.429 seconds.
- Python 3.11 grammar guard: passed across `src`, `tools` and `tests`.
- Wheel build: `vibegate_security_playground-0.2.0-py3-none-any.whl` built
  with setuptools 84.0.0 and no dependency resolution.
- Installed-wheel verification: package imports passed from a disposable target;
  `web/index.html` and `web/architecture.png` were both present.
- Gitleaks 8.30.1: zero leaks with redaction.
- Standard Bandit 1.9.4 over `src`, `tools` and `tests`: exit 0.
- VibeGate `rules-check`: passed, blocking 0, P0 0, P1 0, P2 0.
- VibeGate `export-gate`: passed, blocking 0, P0 0, P1 0, P2 0.
- Release Boundary Safety Gate over the exact 36-file export candidate: passed,
  zero findings. The project virtual environment was outside this scan scope.
- Baseline scanner: critical 0, high 0. Medium lexical matches are expected from
  the intentionally adversarial prompt-injection fixtures and warnings.
- Manifest contract: 36 internal allowlist paths, 36 manifest paths and 36
  candidate files matched exactly.
- `git diff --check`: passed after the final source and documentation edits.

These are working-tree results. Publication remains blocked until the immutable
release guard checks Gitleaks and Bandit across the actual push revision and all
reachable history, then applies the current manifest, evidence, rules-check and
export-gate contract to the branch tip.

## Independent Strict Bandit Review

The restricted local Bandit skill ignores all source `nosec` directives and
therefore remains non-passing with five LOW findings:

| Rule | Location class | Review |
| --- | --- | --- |
| B404 | Production release guard subprocess import | Required to invoke fixed local Git and scanner programs; import alone does not execute input |
| B603 | Production release guard argument-array call | No shell, fixed host commands, bounded timeout, nonzero exit fails closed |
| B404 | Release-guard integration-test subprocess import | Required for a disposable local bare-repository push test |
| B603 | Release-guard integration-test argument-array call | Fixed Git arguments, disposable directories, no shell, 30-second timeout |
| B105 | Dashboard policy-result key | Fixed internal status identifier, not authentication material or a credential |

No directory-wide suppression, baseline or custom Bandit configuration is used.
The standard release scan honors the five line-specific reviewed annotations.
This evidence records a bounded risk acceptance; it does not claim zero warnings.
Trusted local scanner binaries and an exclusive host workspace remain
prerequisites.

## L2 AgentDojo And MCP Review

The live GitHub case pins AgentDojo commit
`089ed468cf3ed0322acc66b0211f26d9d90dbf60` and path
`src/agentdojo/attacks/important_instructions_attacks.py`. The application parses
only `ToolKnowledgeAttack._JB_STRING` with Python AST, verifies the exact
placeholder set and binds it to the fixed zero-argument
`send_synthetic_sample` tool. AgentDojo code is not imported, installed or
executed.

The project-owned MCP server runs over local stdio with a minimal child
environment and three fixed empty-schema tools. The model cannot select a path,
payload, destination, command or authorization result. Client dispatch, server
entry and local received bytes are checked independently.

The bounded live result is summarized in README. Raw provider responses, source
text, request identifiers and local report files remain excluded from the public
candidate.

## Residual Risk

The scanner and gate provide application-level controls, not proof of complete
malware absence or production isolation. Concurrent hostile writers, compromised
scanner binaries, direct tool calls outside Strands, malicious local processes
and disabled Git hooks are outside this release boundary.
