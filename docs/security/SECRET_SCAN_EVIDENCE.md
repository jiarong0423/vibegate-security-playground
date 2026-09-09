# Secret Scan Evidence

Review date: 2026-09-09
Tool: Gitleaks 8.30.1
Candidate scope: exact 36-path public allowlist
Result: passed, zero leaks

Gitleaks ran with redaction and no custom exclusions or baseline. The candidate
includes hidden Git hook and ignore files, application source, executable tests,
dependency lock, GUI assets and all public documentation.

Excluded by design:

- `.env*`, AWS configuration, credentials and login caches;
- local decision logs and raw dashboard reports;
- build output, package metadata, virtual environments and caches;
- temporary, archive, isolation and downloaded-source directories.

The final pre-push gate must repeat the scan against every immutable commit tree
reachable from the branch and enforce the current evidence contract on the
branch tip. Working-tree evidence does not replace that check.

Residual risk:

- Pattern matching cannot prove the absence of every secret.
- Existing public history contains non-noreply author metadata. Values are not
  copied into project files or reports. Rewriting already-published history is a
  separate destructive operation and is not authorized by this release.
- Synthetic account and email patterns used by tests are non-production fixtures.
- Git ignore rules do not prevent deliberate force-add; the immutable-tree
  allowlist is the enforcing local control.
