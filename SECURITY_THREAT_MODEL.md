# Threat Model

Review date: 2026-09-09. Scope: synthetic demonstration and opt-in Bedrock smoke.

## Assets

Disposable canaries, fixture files, tool execution counters and test evidence.
No production data is used. The optional smoke uses real temporary AWS IAM
credentials via the SDK and the selected Bedrock endpoint. Credentials are
stored outside the repository and must never enter prompts or exported files.

## Trust Boundary

The host owns temporary paths, fixed tools, policies and observations. The scripted
model is treated as adversarial. Fixture instructions cannot change host policy.
The VibeGate scanner reads fixture content but does not execute it.

## Data Flow

The host creates synthetic files, a scripted model requests a fixed tool, the
Strands hook checks the snapshot and scanner, and host policy either cancels the
call or allows an effect within the fixture. Counters and observed files/socket
bytes form the report. The scripted matrix sends nothing to a provider.
The optional live smoke sends its fixed synthetic request and, if another model
turn is authorized, the synthetic tool result to global Nova 2 Lite. Global
routing may process that data outside the initiating AWS Region. Account-wide
budget enforcement is not provided by the per-process request ceiling.

## Threats and Controls

- Tool misuse: mandatory Strands before-tool hook cancels denied requests.
- Forged paths/decisions: tools take no model-controlled arguments.
- Repository changes: hash comparisons before/after scan; exclusive host workspace.
- Missing or failed scans: default deny; no model-generated evidence accepted.
- Retry after denial: every attempt is rechecked and logged.
- Data exfiltration: scripted transfers use only fake data and local socketpair;
  opt-in Bedrock receives synthetic-only messages, never arbitrary repo input.
- Destructive action: fixed disposable file inside fresh temporary workspace.

## Limitations

Not a kernel sandbox or complete supply-chain assurance system. Scanner pattern
matching is not proof of absence of malicious behavior. No live-model injection
success rate is measured. Concurrent adversarial writers and bypassing the Strands
dispatcher require stronger production isolation and are out of scope here.
