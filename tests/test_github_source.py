"""Offline boundary and provenance checks for the pinned GitHub adapter."""

import hashlib
import http.client
import io
import json
import unittest
from unittest.mock import Mock, patch

from vibegate_playground.github_source import (
    ALLOWED_REPOSITORY, KNOWN_REPOSITORIES, GitHubSource, MAX_BYTES, _NoRedirect,
    _SourceHTTPSConnection, _SourceHTTPSHandler,
)


COMMIT = "A1" * 20
PATH = "README.md"
URL = f"https://raw.githubusercontent.com/{ALLOWED_REPOSITORY}/{COMMIT.lower()}/{PATH}"


class Response(io.BytesIO):
    def __init__(self, data=b"hello\r\n", *, status=200, headers=None, url=URL):
        super().__init__(data)
        self.status = status
        self.headers = headers or {}
        self.url = url
        self.read_sizes = []
        self.set_source_timeout = Mock()

    def geturl(self):
        return self.url

    def read1(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)


class GitHubSourceTests(unittest.TestCase):
    def test_snapshot_interface(self):
        adapter = GitHubSource(allowed_paths=[PATH], opener=Mock(return_value=Response()))
        result = adapter.fetch_snapshot(COMMIT)
        self.assertEqual(result["path"], PATH)
        self.assertEqual(result["repository"], ALLOWED_REPOSITORY)

    def fetch(self, response, **kwargs):
        opener = Mock(return_value=response)
        adapter = GitHubSource(allowed_paths=[PATH], opener=opener)
        result = adapter.fetch(repository=ALLOWED_REPOSITORY, commit=COMMIT,
                               path=PATH, **kwargs)
        return result, opener

    def test_fixture_provenance_hashes_original_bytes(self):
        data = b"\xef\xbb\xbfhello\r\n"
        response = Response(data)
        result, opener = self.fetch(response)
        self.assertEqual(result, {
            "source_kind": "github_pinned", "repository": ALLOWED_REPOSITORY,
            "commit": COMMIT.lower(), "path": PATH,
            "content_sha256": hashlib.sha256(data).hexdigest(),
            "text": data.decode("utf-8"), "acquisition": "fixture"})
        self.assertEqual(json.loads(json.dumps(result)), result)
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, URL)
        self.assertEqual(request.get_method(), "GET")
        self.assertFalse(request.has_header("Authorization"))
        self.assertEqual(opener.call_args.kwargs, {"timeout": 10.0})
        self.assertEqual(response.read_sizes, [4096, 4096])
        self.assertTrue(response.closed)

    def test_network_configuration_without_network_or_environment(self):
        with patch("urllib.request.build_opener") as build, patch(
                "os.environ", {}) as environment:
            build.return_value.open.return_value = Response()
            result = GitHubSource(allowed_paths=[PATH]).fetch(
                repository=ALLOWED_REPOSITORY, commit=COMMIT, path=PATH)
        self.assertEqual(result["acquisition"], "network")
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], _NoRedirect)
        self.assertIsInstance(build.call_args.args[2], _SourceHTTPSHandler)
        self.assertEqual(environment, {})

    def test_invalid_requests_never_open(self):
        opener = Mock()
        adapter = GitHubSource(allowed_paths=[PATH], opener=opener)
        for field, values in {
            "repository": ["other/repo", ALLOWED_REPOSITORY.upper(), None,
                           ALLOWED_REPOSITORY + "/../repo"],
            "commit": ["main", "a" * 39, "a" * 41, "g" * 40, None, "a" * 40 + "\n"],
            "path": ["other.md", "../README.md", "/README.md", "a//b.md",
                     "a/./b.md", "a\\b.md", "%2e%2e/a.md", "README.md?x=1",
                     "README.md#x", ".env", ".env.txt", "a/credentials.json",
                     "secret.txt", "private-key.txt", "id_rsa.txt", "a.pem", None],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    args = dict(repository=ALLOWED_REPOSITORY, commit=COMMIT, path=PATH)
                    args[field] = value
                    adapter.fetch(**args)
        opener.assert_not_called()

    def test_allowlist_is_required_safe_and_copied(self):
        for paths in (None, [], PATH, [".env"], ["secret.txt"], ["x.exe"]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                GitHubSource(allowed_paths=paths)
        paths = [PATH]
        adapter = GitHubSource(allowed_paths=paths, opener=Mock())
        paths.append("other.md")
        with self.assertRaisesRegex(ValueError, "source_path_not_allowed"):
            adapter.fetch(repository=ALLOWED_REPOSITORY, commit=COMMIT, path="other.md")

    def test_external_benchmark_requires_explicit_host_repository_allowlist(self):
        repository = "ethz-spylab/agentdojo"
        self.assertIn(repository, KNOWN_REPOSITORIES)
        opener = Mock(return_value=Response(url=(
            f"https://raw.githubusercontent.com/{repository}/{COMMIT.lower()}/{PATH}")))
        with self.assertRaisesRegex(ValueError, "repository_not_allowed"):
            GitHubSource(allowed_paths=[PATH], opener=opener).fetch(
                repository=repository, commit=COMMIT, path=PATH)
        result = GitHubSource(allowed_paths=[PATH], allowed_repositories=[repository],
            opener=opener).fetch(repository=repository, commit=COMMIT, path=PATH)
        self.assertEqual(result["repository"], repository)

    def test_unknown_repository_cannot_enter_host_allowlist(self):
        with self.assertRaisesRegex(ValueError, "host_repository_allowlist_required"):
            GitHubSource(allowed_paths=[PATH], allowed_repositories=["other/repo"])

    def test_timeout_bounds(self):
        for timeout in (0, -1, 11, float("inf"), float("nan"), True, "10"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                GitHubSource(allowed_paths=[PATH], timeout=timeout)

    def test_response_boundaries(self):
        for response in (
            Response(status=302), Response(status=404), Response(url="https://example.com"),
            Response(headers={"Content-Length": str(MAX_BYTES + 1)}),
            Response(headers={"Content-Length": "-1"}),
            Response(headers={"Content-Length": "8"}),
            Response(headers={"Content-Encoding": "gzip"}),
            Response(headers={"Transfer-Encoding": "chunked"}),
            Response(b"a" * (MAX_BYTES + 1)), Response(b"\xff"), Response(b"a\x00b"),
        ):
            with self.subTest(headers=response.headers, status=response.status):
                with self.assertRaises(ValueError):
                    self.fetch(response)
                self.assertTrue(response.closed)
        result, _ = self.fetch(Response(b"a" * MAX_BYTES))
        self.assertEqual(len(result["text"]), MAX_BYTES)

    def test_redirect_handler_refuses_all_redirects(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code), self.assertRaises(ValueError):
                _NoRedirect().redirect_request(None, None, code, "", {}, URL)

    def test_network_failure_propagates(self):
        adapter = GitHubSource(allowed_paths=[PATH], opener=Mock(side_effect=TimeoutError))
        with self.assertRaises(TimeoutError):
            adapter.fetch(repository=ALLOWED_REPOSITORY, commit=COMMIT, path=PATH)

    def test_drip_feed_exhausts_total_deadline(self):
        response = Response()
        response.read1 = Mock(return_value=b"a")
        with patch("vibegate_playground.github_source.time.monotonic",
                   side_effect=[0, 0, 4, 4, 8, 8, 10]):
            with self.assertRaisesRegex(TimeoutError, "source_read_deadline_exceeded"):
                self.fetch(response)
        self.assertEqual(response.read1.call_count, 3)
        self.assertEqual([call.args[0] for call in response.set_source_timeout.call_args_list],
                         [10, 6, 2])
        self.assertTrue(response.closed)

    def test_expired_deadline_prevents_next_read(self):
        response = Response()
        response.read1 = Mock(return_value=b"a")
        with patch("vibegate_playground.github_source.time.monotonic",
                   side_effect=[0, 0, 9, 10]):
            with self.assertRaises(TimeoutError):
                self.fetch(response)
        self.assertEqual(response.read1.call_count, 1)
        self.assertTrue(response.closed)

    def test_late_eof_and_late_complete_body_are_rejected(self):
        for data in (b"", b"abc"):
            response = Response(headers={"Content-Length": "3"})
            response.read1 = Mock(return_value=data)
            with self.subTest(data=data), patch(
                    "vibegate_playground.github_source.time.monotonic",
                    side_effect=[0, 0, 11]):
                with self.assertRaises(TimeoutError):
                    self.fetch(response)
            self.assertTrue(response.closed)

    def test_chunked_rejected_before_any_read(self):
        response = Response(headers={"Transfer-Encoding": "chunked"})
        with self.assertRaisesRegex(ValueError, "source_transfer_encoding_forbidden"):
            self.fetch(response)
        self.assertEqual(response.read_sizes, [])

    def test_no_fallback_to_unbounded_read(self):
        response = Response()
        response.read1 = None
        with self.assertRaisesRegex(ValueError, "source_deadline_transport_required"):
            self.fetch(response)

    def test_socket_timeout_closes_response(self):
        response = Response()
        response.read1 = Mock(side_effect=TimeoutError("socket timed out"))
        with self.assertRaises(TimeoutError):
            self.fetch(response)
        self.assertTrue(response.closed)

    def test_connection_captures_socket_before_detachment(self):
        connection = _SourceHTTPSConnection("raw.githubusercontent.com")
        socket = Mock()
        connection.sock = socket
        response = Response()

        def detach_socket():
            connection.sock = None
            return response

        with patch("http.client.HTTPSConnection.getresponse", side_effect=detach_socket):
            self.assertIs(connection.getresponse(), response)
        response.set_source_timeout(2.5)
        socket.settimeout.assert_called_once_with(2.5)
        response.close()

    def test_network_transport_requires_socket_deadline_hook(self):
        response = Response()
        response.set_source_timeout = None
        with patch("urllib.request.build_opener") as build:
            build.return_value.open.return_value = response
            with self.assertRaisesRegex(ValueError, "source_deadline_transport_required"):
                GitHubSource(allowed_paths=[PATH]).fetch_snapshot(COMMIT)
        self.assertTrue(response.closed)

    def test_stdlib_response_multichunk_body(self):
        data = b"abcdef\r\n" * 1024
        socket = Mock()
        socket.makefile.return_value = io.BytesIO(
            b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(data)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n" + data)
        response = http.client.HTTPResponse(socket)
        response.begin()
        response.url = URL
        response.set_source_timeout = socket.settimeout
        with patch("urllib.request.build_opener") as build:
            build.return_value.open.return_value = response
            result = GitHubSource(allowed_paths=[PATH]).fetch_snapshot(COMMIT)
        self.assertEqual(result["text"], data.decode("utf-8"))
        self.assertEqual(result["content_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(socket.settimeout.call_count, 2)
        self.assertTrue(response.closed)
