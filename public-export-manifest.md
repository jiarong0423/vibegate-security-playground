# Public Export Manifest

Review date: 2026-09-09
Classification: public release allowlist

Only the paths between the markers below may appear in a published commit. The
release guard parses this block and requires it to match both its internal
allowlist and the complete immutable branch-tip Git tree. Older reachable commits
are still scanned, but they are not required to contain documents introduced by
newer release contracts.

<!-- PUBLIC_ALLOWLIST_START -->
- `.githooks/pre-push`
- `.gitignore`
- `LICENSE`
- `README.md`
- `SECURITY.md`
- `SECURITY_THREAT_MODEL.md`
- `docs/security/MCP_SERVER_ALLOWLIST.md`
- `docs/security/PACKAGE_REPUTATION_EVIDENCE.md`
- `docs/security/SECRET_SCAN_EVIDENCE.md`
- `docs/security/SECURITY_SCAN_EVIDENCE.md`
- `docs/security/package-runner-allowlist.md`
- `public-export-manifest.md`
- `pyproject.toml`
- `requirements.lock`
- `src/vibegate_playground/__init__.py`
- `src/vibegate_playground/bedrock_smoke.py`
- `src/vibegate_playground/dashboard.py`
- `src/vibegate_playground/demo.py`
- `src/vibegate_playground/github_source.py`
- `src/vibegate_playground/live_workflow.py`
- `src/vibegate_playground/mcp_fixture_server.py`
- `src/vibegate_playground/mcp_harness.py`
- `src/vibegate_playground/model.py`
- `src/vibegate_playground/server.py`
- `src/vibegate_playground/web/architecture.png`
- `src/vibegate_playground/web/index.html`
- `tests/test_bedrock_smoke.py`
- `tests/test_compatibility.py`
- `tests/test_dashboard.py`
- `tests/test_github_source.py`
- `tests/test_interception.py`
- `tests/test_live_workflow.py`
- `tests/test_mcp_harness.py`
- `tests/test_release_guard.py`
- `tools/python.sh`
- `tools/release_guard.py`
<!-- PUBLIC_ALLOWLIST_END -->

All 36 paths are public code, synthetic test fixtures, documentation, dependency
contracts or sanitized security evidence. The MIT license and AgentDojo
attribution are approved for disclosure.

Excluded from publication:

- `.env*`, AWS configuration, credentials and login caches;
- local logs, dashboard reports and raw provider evidence;
- build artifacts, package metadata, virtual environments and caches;
- temporary, isolation, archive and downloaded source directories;
- files outside the exact allowlist.

Git ignore rules are convenience controls only. The immutable-tree release guard
enforces this list before ordinary pushes from this checkout. It rejects missing
or additional paths, but it does not replace remote branch protection or review
of commit author metadata.
