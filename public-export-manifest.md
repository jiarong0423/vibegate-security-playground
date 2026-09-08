# Public Export Manifest

Review date: 2026-09-09. Classification: public-export candidate only.
This is an exact allowlist, not permission to export the entire checkout.

- .githooks/pre-push
- .gitignore
- LICENSE
- README.md
- SECURITY.md
- SECURITY_THREAT_MODEL.md
- pyproject.toml
- requirements.lock
- public-export-manifest.md
- docs/security/PACKAGE_REPUTATION_EVIDENCE.md
- docs/security/SECURITY_SCAN_EVIDENCE.md
- docs/security/SECRET_SCAN_EVIDENCE.md
- docs/security/package-runner-allowlist.md
- src/vibegate_playground/__init__.py
- src/vibegate_playground/bedrock_smoke.py
- src/vibegate_playground/demo.py
- src/vibegate_playground/model.py
- tests/test_bedrock_smoke.py
- tests/test_interception.py
- tests/test_release_guard.py
- tools/python.sh
- tools/release_guard.py

All 22 entries are public code, synthetic test cases, licensing, configuration
or sanitized evidence. MIT attribution is explicitly approved for disclosure.
Active private records remain in logs; scratch/isolation evidence stays outside
this candidate. Environments, credentials, local account details, raw reports,
archives and generated build outputs are excluded. Nothing is auto-published.
The enforcing list is ALLOWED in tools/release_guard.py; unexpected files deny
push. Commit/push requires the owner's final approval and metadata review.
