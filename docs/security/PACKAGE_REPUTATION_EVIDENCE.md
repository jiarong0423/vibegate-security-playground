# Package Reputation Evidence

Review date: 2026-09-09. Status: reviewed for this bounded test release.

requirements.lock pins 49 public transitive/runtime packages and SHA-256 hashes.
It includes the optional Bedrock login dependencies. The local ai-security-rules
package is deliberately excluded from registry resolution during installation:
install the reviewed sibling source at version 0.7.0, never an unrelated name.
This is the first lockfile; there is no prior lockfile delta.

Direct origin review:
- strands-agents 1.55.0: official Strands documentation specifies this package.
  PyPI metadata points to the strands-agents organization (harness-sdk).
  Uploaded 2026-09-08; this is a very recent release, with limited soak time.
- boto3 1.43.89: official AWS/Boto documentation and boto/boto3 project agree.
  Uploaded 2026-09-04.
- botocore 1.43.89: matching Boto3 core dependency; CRT extra pins awscrt 0.36.0.
- awscrt 0.36.0: PyPI project links match awslabs/aws-crt-python.
  Uploaded 2026-07-16.

Sources: https://strandsagents.com/docs/user-guide/quickstart/python/
https://github.com/boto/boto3 and https://github.com/awslabs/aws-crt-python.
Package/version metadata was retrieved directly from public PyPI JSON endpoints.

pip-audit 2.10.1 reviewed all 49 pinned public packages: zero known vulnerabilities
at review time. Registry hash-verified installation succeeded in a clean Python
3.13 environment; pip compatibility check passed for 51 installed packages
(49 public packages plus the two local projects). All 27 offline tests passed.
The core wheel was built from reviewed local source, version 0.7.0, not editable.

Residual risk: publisher-link checks and known-vulnerability databases do not
prove supply-chain integrity. All transitive maintainers were not manually
audited. Newly published dependencies and other Python/platform combinations
remain unverified. Accepted review scope is a disposable synthetic test package,
not production certification. Re-resolving the lock requires a new audit.
