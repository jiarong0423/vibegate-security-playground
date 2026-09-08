"""Local pre-push gate. Inspect immutable commits, never execute their code."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
# Required for fixed local Git and scanner commands.
import subprocess  # nosec B404
import sys
from tempfile import TemporaryDirectory


ALLOWED = frozenset({
    ".gitignore", ".githooks/pre-push", "LICENSE", "README.md", "SECURITY.md",
    "SECURITY_THREAT_MODEL.md", "pyproject.toml", "requirements.lock",
    "tools/python.sh", "tools/release_guard.py",
    "src/vibegate_playground/__init__.py", "src/vibegate_playground/model.py",
    "src/vibegate_playground/demo.py", "src/vibegate_playground/bedrock_smoke.py",
    "tests/test_interception.py", "tests/test_bedrock_smoke.py", "tests/test_release_guard.py",
    "docs/security/PACKAGE_REPUTATION_EVIDENCE.md",
    "docs/security/SECURITY_SCAN_EVIDENCE.md", "docs/security/SECRET_SCAN_EVIDENCE.md",
    "public-export-manifest.md",
    "docs/security/package-runner-allowlist.md",
})
REQUIRED = frozenset({
    "LICENSE", "README.md", "SECURITY.md", "SECURITY_THREAT_MODEL.md",
    "requirements.lock", "public-export-manifest.md",
    "docs/security/PACKAGE_REPUTATION_EVIDENCE.md",
    "docs/security/SECURITY_SCAN_EVIDENCE.md", "docs/security/SECRET_SCAN_EVIDENCE.md",
})


class Blocked(RuntimeError):
    pass


def run(command, *, cwd, env=None):
    executable = shutil.which(command[0])
    if executable is None:
        raise Blocked("Required executable unavailable")
    try:
        # Callers supply fixed programs and argument arrays; never shell input.
        result = subprocess.run([executable, *command[1:]], cwd=cwd, env=env, capture_output=True,  # nosec B603
                                timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Blocked("Required command unavailable or timed out") from error
    if result.returncode:
        # Scanner output can contain sensitive text. Do not echo it into Git logs.
        raise Blocked("Required check failed: " + Path(command[0]).name)
    return result.stdout


def validate_tree(entries):
    names = set()
    total = 0
    for mode, kind, oid, size, name in entries:
        if name not in ALLOWED:
            raise Blocked("Commit contains a path outside the public allowlist")
        if mode not in {"100644", "100755"} or kind != "blob":
            raise Blocked("Symlinks and submodules cannot be exported")
        if size > 250_000:
            raise Blocked("File exceeds export size limit")
        total += size
        names.add(name)
    if total > 5_000_000:
        raise Blocked("Commit exceeds export size limit")
    if REQUIRED - names:
        raise Blocked("Required release evidence or dependency lock is missing")


def scan_commit(root, revision, scanner_root):
    listing = run(["git", "ls-tree", "-rlz", revision], cwd=root)
    entries = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, oid, size = metadata.decode("ascii").split()
        entries.append((mode, kind, oid, int(size) if size != "-" else 0,
                        name.decode("utf-8", errors="strict")))
    validate_tree(entries)
    for executable in ("gitleaks", "bandit"):
        if not shutil.which(executable):
            raise Blocked("Missing independent scanner: " + executable)
    if not (scanner_root / "src/ai_security_rules/cli.py").is_file():
        raise Blocked("Trusted VibeGate scanner is unavailable")
    with TemporaryDirectory(prefix="vibegate-release-check-") as temp:
        snapshot = Path(temp) / "snapshot"
        snapshot.mkdir()
        for mode, kind, oid, size, name in entries:
            target = snapshot / name
            target.parent.mkdir(parents=True, exist_ok=True)
            data = run(["git", "cat-file", "blob", oid], cwd=root)
            if len(data) != size:
                raise Blocked("Git object size mismatch")
            target.write_bytes(data)
        run(["gitleaks", "dir", str(snapshot), "--redact", "--no-banner"], cwd=temp)
        run(["bandit", "-r", str(snapshot / "src"), str(snapshot / "tools"),
             str(snapshot / "tests"), "-q"], cwd=temp)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(scanner_root / "src")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        for mode in ("rules-check", "export-gate"):
            report = Path(temp) / mode
            run([sys.executable, "-m", "ai_security_rules", mode, str(snapshot),
                 "--output-dir", str(report)], cwd=temp, env=env)
            payload = json.loads((report / "local_ai_security_portfolio_report.json").read_text())
            # Gate exit code alone is insufficient; baseline risk also blocks.
            summary = payload.get("portfolio", {})
            if (type(summary.get("critical")) is not int
                    or type(summary.get("high")) is not int
                    or summary["critical"] != 0 or summary["high"] != 0):
                raise Blocked("Baseline evidence missing or high-risk findings present")


def revisions_for_push(root, lines):
    revisions = set()
    for line in lines:
        fields = line.split()
        if len(fields) != 4:
            raise Blocked("Malformed pre-push input")
        local_ref, local_sha, remote_ref, remote_sha = fields
        if not re.fullmatch(r"[0-9a-f]{40,64}", local_sha):
            raise Blocked("Invalid object identifier")
        if set(local_sha) == {"0"}:
            continue
        if not local_ref.startswith("refs/heads/"):
            raise Blocked("Only branch publication is supported")
        # Scan all reachable history, including content removed in later commits.
        commits = run(["git", "rev-list", local_sha], cwd=root).decode().splitlines()
        if len(commits) > 200:
            raise Blocked("History exceeds bounded audit limit")
        revisions.update(commits)
    return sorted(revisions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre-push", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    scanner = root.parent / "ai-security-rules"
    try:
        if args.pre_push:
            revisions = revisions_for_push(root, sys.stdin)
        else:
            head = run(["git", "rev-parse", "--verify", "HEAD"], cwd=root).decode().strip()
            revisions = revisions_for_push(root, [f"refs/heads/main {head} refs/heads/main {'0' * 40}"])
        for revision in revisions:
            scan_commit(root, revision, scanner)
        print("VibeGate release check passed for supplied immutable commits")
        return 0
    except (Blocked, ValueError, KeyError, UnicodeError) as error:
        print("VibeGate publication BLOCKED: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
