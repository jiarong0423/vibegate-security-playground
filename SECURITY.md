# Security

## Credential Ownership

Review date: 2026-09-09. Owner: the local AWS account operator.
The optional Bedrock smoke runner uses the named profile vibegate-dev through
the AWS SDK credential provider. Temporary credentials are managed by AWS CLI
outside this repository. No credential values belong in source or reports.
Rotation: renew the temporary session with the official AWS login flow.
Revoke: the operator can revoke the IAM user's active sessions and remove its
inference permission; local logout alone is not a substitute for revocation.
Never use root credentials, export login caches, or commit private run logs.
The credential provider necessarily uses credentials to sign requests; the
application must not display or serialize their values.

## Publication Status

Candidate dependency and independent source/secret scans are recorded in
docs/security; the exact export manifest is public-export-manifest.md.
Publication still requires final commit/push approval. Git ignore rules only prevent
accidental staging of untracked files; they do not block force-add or upload.
An active local pre-push hook now checks immutable commit trees and fails closed
on missing release evidence or scanners. It is bypassable via Git --no-verify
or other upload paths; no OS-wide exfiltration barrier is installed.

## Synthetic Cases

This repository is an intentionally adversarial, synthetic testing project.
Do not run it against real user repositories or replace its fixtures with secrets.
The runner accepts no target repository, shell command or network destination.

Effects are bounded by host-selected fixed paths inside a fresh TemporaryDirectory.
The transfer uses a connected local socket pair, not a network server. Deletion
only targets a freshly generated sacrificial file. Fixture MCP settings are data,
not executable MCP configuration. No persistence or privilege escalation occurs.

The application boundary is not an OS sandbox and is not suitable for executing
arbitrary downloaded malware. The tests do not run arbitrary repo code.

Security observations and release blockers are recorded in the project log linked
from README. A failing scanner on an adversarial fixture is expected; blanket
exclusion of this repository from security checks is not recommended.
