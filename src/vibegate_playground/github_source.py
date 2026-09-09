"""Host-configured, bounded public GitHub source acquisition; never executes text."""

import hashlib
import http.client
import math
import re
import time
import urllib.request


ALLOWED_REPOSITORY = "jiarong0423/vibegate-security-playground"
KNOWN_REPOSITORIES = frozenset({
    ALLOWED_REPOSITORY,
    "ethz-spylab/agentdojo",
})
MAX_BYTES = 64 * 1024
MAX_TIMEOUT = 10.0
_TEXT_SUFFIXES = (".py", ".md", ".txt", ".toml", ".json", ".yaml", ".yml",
                  ".html", ".css", ".js", ".ts", ".sh", ".csv", ".rst")


def _safe_path(path):
    if not isinstance(path, str) or len(path) > 512:
        raise ValueError("invalid_source_path")
    parts = path.split("/")
    if any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part)
           or ".." in part for part in parts):
        raise ValueError("invalid_source_path")
    lowered = path.lower()
    if any(re.search(r"(?:^|[_.-])(env|secret|secrets|credential|credentials|token|tokens|"
                     r"password|passwords|passwd|shadow|private|id_rsa|id_ed25519)(?:$|[_.-])",
                     part.lower()) for part in parts):
        raise ValueError("sensitive_source_path")
    if not lowered.endswith(_TEXT_SUFFIXES) and parts[-1] not in ("LICENSE", "NOTICE"):
        raise ValueError("non_text_source_path")
    return path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("source_redirect_forbidden")


class _SourceHTTPSConnection(http.client.HTTPSConnection):
    def getresponse(self):
        # Capture the public socket before getresponse detaches closing connections.
        connection_socket = self.sock
        response = super().getresponse()
        if connection_socket is None:
            response.close()
            raise ValueError("source_socket_unavailable")
        response.set_source_timeout = connection_socket.settimeout
        return response


class _SourceHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_SourceHTTPSConnection, req, context=self._context)


def _read_body(response, timeout, *, network):
    deadline = time.monotonic() + timeout
    read = getattr(response, "read1", None)
    set_timeout = getattr(response, "set_source_timeout", None)
    if not callable(read) or (network and not callable(set_timeout)):
        raise ValueError("source_deadline_transport_required")
    # Chunked read1 can loop over framing/trailers without returning to the clock.
    if response.headers.get("Transfer-Encoding") is not None:
        raise ValueError("source_transfer_encoding_forbidden")
    length = response.headers.get("Content-Length")
    if length is not None:
        if not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > MAX_BYTES:
            raise ValueError("invalid_source_length")
        length = int(length)
    data = bytearray()
    while length is None or len(data) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("source_read_deadline_exceeded")
        if callable(set_timeout):
            set_timeout(remaining)
        size = min(4096, MAX_BYTES + 1 - len(data))
        chunk = read(size)
        if time.monotonic() >= deadline:
            raise TimeoutError("source_read_deadline_exceeded")
        if not isinstance(chunk, bytes):
            raise ValueError("source_bytes_required")
        if len(chunk) > size or len(data) + len(chunk) > MAX_BYTES:
            raise ValueError("source_too_large")
        if not chunk:
            break
        data.extend(chunk)
    if length is not None and len(data) != length:
        raise ValueError("source_length_mismatch")
    return bytes(data)


class GitHubSource:
    """Construct only in trusted host code, never from model-supplied configuration.

    An injected opener is a callable accepting (Request, timeout=seconds), returning
    a context-managed response with status, headers, geturl(), and read1(size).
    Fixture read1 must return promptly; optional set_source_timeout(seconds) allows
    fixtures to exercise the socket deadline contract. Arbitrary injected code
    cannot be interrupted by this adapter.
    Injected responses always carry fixture provenance, even if they use a network.
    Timeout bounds body acquisition using monotonic time and per-read socket limits.
    DNS, connection/TLS setup, and response headers are outside the body deadline
    and retain stdlib connection timeout semantics. Transfer encoding is rejected.
    """

    def __init__(self, *, allowed_paths, allowed_repositories=(ALLOWED_REPOSITORY,),
                 opener=None, timeout=MAX_TIMEOUT):
        if not isinstance(allowed_paths, (list, tuple, set, frozenset)) or not allowed_paths:
            raise ValueError("host_path_allowlist_required")
        self._allowed_paths = frozenset(_safe_path(path) for path in allowed_paths)
        if (not isinstance(allowed_repositories, (list, tuple, set, frozenset))
                or not allowed_repositories
                or any(repository not in KNOWN_REPOSITORIES for repository in allowed_repositories)):
            raise ValueError("host_repository_allowlist_required")
        self._allowed_repositories = frozenset(allowed_repositories)
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT):
            raise ValueError("invalid_source_timeout")
        if opener is not None and not callable(opener):
            raise ValueError("invalid_source_opener")
        self._opener = opener
        self._timeout = timeout

    def fetch_snapshot(self, commit, path="README.md"):
        """Fetch from the fixed repository under this host's path allowlist."""
        return self.fetch(repository=ALLOWED_REPOSITORY, commit=commit, path=path)

    def fetch(self, *, repository, commit, path):
        """Return JSON-compatible provenance and strictly decoded UTF-8 text."""
        if repository not in self._allowed_repositories:
            raise ValueError("repository_not_allowed")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            raise ValueError("full_commit_sha_required")
        path = _safe_path(path)
        if path not in self._allowed_paths:
            raise ValueError("source_path_not_allowed")
        commit = commit.lower()
        url = f"https://raw.githubusercontent.com/{repository}/{commit}/{path}"
        request = urllib.request.Request(url, headers={"Accept": "text/plain",
                                                      "Accept-Encoding": "identity"},
                                         method="GET")
        opener = self._opener
        if opener is None:
            # An explicit empty proxy map prevents urllib's environment proxy lookup.
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), _NoRedirect(), _SourceHTTPSHandler()).open
        with opener(request, timeout=self._timeout) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError("unexpected_source_response")
            encoding = response.headers.get("Content-Encoding", "identity").lower()
            if encoding != "identity":
                raise ValueError("encoded_source_response")
            data = _read_body(response, self._timeout, network=self._opener is None)
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("source_not_utf8") from exc
        if "\x00" in text:
            raise ValueError("source_not_text")
        return {"source_kind": "github_pinned", "repository": repository,
                "commit": commit, "path": path,
                "content_sha256": hashlib.sha256(data).hexdigest(), "text": text,
                "acquisition": "fixture" if self._opener is not None else "network"}
