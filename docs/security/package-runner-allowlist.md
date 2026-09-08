# Package Runner Allowlist

Review date: 2026-09-09. Owner: project maintainer.
Reviewed installation: a dedicated virtual environment, hash-verified public
dependencies from requirements.lock, then no-dependency installation of the
reviewed sibling ai-security-rules source and this project. Local packages must
not be substituted with registry lookalikes. Build backends are setuptools for
this package and hatchling for the core; build-time dependencies are not covered
by the runtime lock and require a trusted isolated build environment.

No installation occurs automatically during tests, pre-push or model calls.
Independent scanner commands are Gitleaks and Bandit, reviewed versions recorded
in adjacent evidence files. Their absence must stop the gate, not skip a check.
