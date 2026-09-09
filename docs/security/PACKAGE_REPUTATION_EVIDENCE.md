# Package And Dependency Evidence

Review date: 2026-09-09
Status: reviewed for the bounded 0.2.0 synthetic test release

## Locked Runtime

`requirements.lock` pins 49 public runtime and transitive packages with exact
versions and SHA-256 hashes. It includes the optional Bedrock login dependencies.
The lock did not change in the 0.2.0 GUI and live-workflow update.

The direct runtime contract is:

- `strands-agents==1.55.0`
- `mcp==2.1.1`
- `ai-security-rules>=0.7.0,<0.8`
- optional `boto3==1.43.89`
- optional `botocore[crt]==1.43.89`

`ai-security-rules` is deliberately excluded from registry resolution during
installation. The documented install uses the reviewed sibling source at commit
`a6a034f0215fa6e3272bba11c0ae2ef9b6deee1b`, version 0.7.0.

## Provenance Review

- Strands Agents: official Strands Python SDK package and repository.
- MCP: Python MCP SDK package used by the fixed local stdio fixture.
- Boto3 and Botocore: official AWS SDK for Python packages.
- AWS CRT: project link reviewed against `awslabs/aws-crt-python`.
- AgentDojo: MIT-licensed public benchmark source; not installed as a dependency.

Sources:

- https://strandsagents.com/docs/user-guide/quickstart/python/
- https://github.com/strands-agents/sdk-python
- https://github.com/modelcontextprotocol/python-sdk
- https://github.com/boto/boto3
- https://github.com/awslabs/aws-crt-python
- https://github.com/ethz-spylab/agentdojo

Package and version metadata were reviewed from official repositories and public
PyPI metadata. The most recently published dependencies have limited soak time.

## Verification

- Earlier clean-environment `pip-audit 2.10.1` review of all 49 locked public
  packages reported zero known vulnerabilities on 2026-09-09.
- Hash-verified installation and `pip check` passed for the locked environment.
- The reviewed `ai-security-rules` 0.7.0 wheel was built from source rather than
  installed by untrusted registry name.
- Playground 0.2.0 built successfully as a wheel with setuptools 84.0.0.
- Disposable installed-wheel imports passed, including the live workflow, MCP
  harness and dashboard modules.
- Both GUI package assets were present in the installed wheel.
- The complete source checkout passed 131 offline tests.

Python 3.11 grammar compatibility is tested. The review host runs Python 3.13.12;
a native Python 3.11 runtime execution was not available, so this release does
not claim a clean Python 3.11 installation was executed.

## Residual Risk

Registry existence, publisher links, hashes and known-vulnerability databases do
not prove supply-chain integrity. Every transitive maintainer was not manually
audited. Re-resolving the lock, changing a direct dependency or updating the
reviewed sibling core revision requires a new dependency review.
