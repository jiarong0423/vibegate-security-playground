# Security Policy

## Supported Scope

VibeGate Security Playground 0.2.x is an adversarial test application for the
Strands-compatible VibeGate hook. It is not a production sandbox or a service
that should receive private data.

## Safe Use

- Review the source before running it.
- Use a disposable environment with Python 3.11 or newer.
- Keep the dashboard on its default loopback address.
- Use only the fixed public GitHub source and project-owned MCP fixture.
- Never replace synthetic fixtures with credentials, private files or production
  data.
- Never use root AWS credentials. Live Bedrock tests require a dedicated
  least-privilege test identity.
- Review the exact request ceiling and synthetic outbound content before every
  live run.

The fixed send tool transfers only a 28-byte synthetic marker through a local
`socketpair`. It accepts no model-controlled destination, payload or arguments.
The external AgentDojo repository is neither installed nor executed.

## Credential Boundary

AWS credentials are supplied by the normal SDK credential provider. This
project fixes configuration and login-cache lookup to the ignored project-local
`.aws/` runtime directory; those files remain outside the Git tree and public
export. The application does not read, display or serialize credential values.
Direct credential environment variables and instance-metadata fallback are
rejected by the canonical runner. Local login caches, AWS configuration,
environments, run reports and operator logs are excluded from Git.

Credential owner: local AWS account operator.
Rotation: renew or replace the temporary session using the official AWS login
flow.
Revocation: revoke the IAM session or remove the identity's Bedrock inference
permission.

Do not report account IDs, email addresses, access keys, session tokens or raw
provider request identifiers in issues.

## MCP Boundary

Only `vibegate_playground.mcp_fixture_server` is approved. It runs over local
stdio with a fixed command, minimal environment, empty tool schemas and
host-selected temporary paths. Review
[`docs/security/MCP_SERVER_ALLOWLIST.md`](docs/security/MCP_SERVER_ALLOWLIST.md)
before changing the server, transport or catalog.

This allowlist does not approve arbitrary MCP servers, downloaded configuration,
shell commands, home-directory access or wildcard network access.

## Live Bedrock Boundary

Live tests are optional and may consume AWS credits. They require:

- a configured least-privilege profile;
- model access to global Amazon Nova 2 Lite;
- a new explicit operator confirmation for the selected scenario;
- at most 256 output tokens per provider request;
- disabled automatic retries;
- a process-level request ceiling enforced at the client boundary.

The complete GitHub/MCP suite permits at most six requests allocated
`1 / 1 / 2 / 2`. Failed requests consume the allowance. Provider or framework
failure stops later cases. This is not an account-wide spending cap.

## Local Backend Boundary

`vibegate_playground.server` is the canonical backend entrypoint. It binds to
`127.0.0.1` and serves the static GUI plus these local routes:

- `GET /api/state`: sanitized status and history projection;
- `POST /api/authorize`: single-use, expiring live-run confirmation;
- `POST /api/run`: bounded scenario dispatch.

The browser creates the sanitized selected-result JSON export locally; no
backend export route exists. The **Reset view** action also stays in the browser
and never deletes or rewrites retained evidence.

State-changing requests require the per-process `X-VibeGate-Token` issued to
the locally served page. Origin and token checks reject unrelated browser
requests. AWS credential values remain in the SDK credential provider behind
this backend and are never returned to browser JavaScript.

This boundary is suitable only for a trusted single-user machine. It is not
authentication for remote hosting. A public deployment would require a separate
identity system, TLS, centralized audit retention, server-side rate limiting and
managed secret storage; no public deployment is included in this release.

## Evidence And Privacy

Committed documentation contains sanitized aggregate results only. Ignored local
reports may contain validated hashes and bounded diagnostic metadata, but never
raw model text, raw GitHub content, credentials or original AWS request IDs.

Pattern-based secret scanning reduces risk but cannot prove that no secret exists.
Review every staged path and commit metadata before publication.

## Publication Controls

The public release boundary is an exact allowlist in
`public-export-manifest.md` and `tools/release_guard.py`. The pre-push hook:

1. inspects each immutable committed tree reachable from the pushed branch;
2. rejects unexpected, oversized, symlinked or submodule paths in all history;
3. requires the pushed branch tip to contain every current release document and
   exactly match the public manifest;
4. runs Gitleaks with redaction on every reachable tree;
5. runs Bandit across `src`, `tools` and executable tests in every reachable
   tree;
6. runs VibeGate `rules-check` and `export-gate` on the pushed branch tip;
7. blocks when required scanners or tip evidence are missing.

Install it after reviewing the scripts:

```sh
chmod +x .githooks/pre-push
git config --local core.hooksPath .githooks
```

The hook is a local control and can be bypassed by disabling hooks, using
`--no-verify` or pushing from another checkout. Protected remote CI is required
for organizational enforcement.

## Reporting A Vulnerability

Open a GitHub security advisory for vulnerabilities that could bypass the
documented tool gate, expose credentials, execute outside the temporary fixture,
evade the publication boundary or falsify evidence. Include the affected version,
reproduction conditions and sanitized impact. Do not include secrets, private
repository contents or live account identifiers.

For ordinary defects that do not expose sensitive information, use the repository
issue tracker.
