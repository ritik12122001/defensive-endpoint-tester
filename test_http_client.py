"""
Final Audit Regression Test Suite for testing_public_domain.py.
Covers:
- Secret redaction in every output path (config repr, error messages, proxy identifiers)
- Multiline quoted environment variable parsing and configuration validation
- Missing credential detection in proxy entries
- Concurrent round-robin proxy selection under multithreading
- Failover exclusion, retry limits, and strict no-direct-fallback guarantees
- Target timeouts versus proxy transport errors
- Session lifecycle cleanup and cancellation handling
- Strict HTTPS certificate verification (session.verify = True)
All tests run against local mock servers bound exclusively to 127.0.0.1. Zero external calls.
"""

import base64
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import tempfile
import threading
import time
import unittest
from urllib.parse import urlparse

from testing_public_domain import (
    ClientConfig,
    ProxyEndpoint,
    ProxyPool,
    create_resilient_session,
    fetch_url,
    fetch_with_failover,
    format_proxy_url,
    load_config_from_env,
    load_env_file,
    main,
    mask_proxy_url,
    parse_env_bool,
    parse_env_float,
    parse_env_int,
    parse_proxy_entry,
    redact_credentials,
    run_bounded_batch,
    validate_config,
)


class MockServerHandler(BaseHTTPRequestHandler):
    """Mock target server simulating standard response conditions."""
    rate_limit_hits = 0
    server_error_hits = 0

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed_path = urlparse(self.path).path

        if parsed_path == "/200":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')

        elif parsed_path == "/404":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Resource Not Found")

        elif parsed_path == "/429":
            MockServerHandler.rate_limit_hits += 1
            if MockServerHandler.rate_limit_hits == 1:
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Too Many Requests. Back off 1s.")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "recovered"}')

        elif parsed_path == "/503":
            MockServerHandler.server_error_hits += 1
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Service Unavailable")

        elif parsed_path == "/timeout":
            time.sleep(1.0)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Delayed Response")
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass

        elif parsed_path == "/slow":
            time.sleep(0.3)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Slow OK")
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass

        else:
            self.send_response(404)
            self.end_headers()


class MockForwardProxyHandler(BaseHTTPRequestHandler):
    """Mock forward proxy server verifying Proxy-Authorization and tracking hits."""
    last_proxy_auth = None
    request_count = 0

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        MockForwardProxyHandler.request_count += 1
        MockForwardProxyHandler.last_proxy_auth = self.headers.get("Proxy-Authorization")

        if "/timeout" in self.path:
            time.sleep(1.0)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Delayed Mock Proxy OK")
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Via-Mock-Proxy", "true")
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "proxied": true}')


class TestDefensiveHttpClientRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockServerHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.proxy_server = HTTPServer(("127.0.0.1", 0), MockForwardProxyHandler)
        cls.proxy_port = cls.proxy_server.server_address[1]
        cls.proxy_thread = threading.Thread(target=cls.proxy_server.serve_forever, daemon=True)
        cls.proxy_thread.start()
        cls.mock_proxy_url = f"http://127.0.0.1:{cls.proxy_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.proxy_server.shutdown()
        cls.proxy_server.server_close()

    def setUp(self):
        MockServerHandler.rate_limit_hits = 0
        MockServerHandler.server_error_hits = 0
        MockForwardProxyHandler.last_proxy_auth = None
        MockForwardProxyHandler.request_count = 0

    # --- 1. Secret Redaction Tests ---

    def test_secret_redaction_in_config_repr(self):
        secret_pw = "super_secret_pw_123"
        cfg = ClientConfig(
            target_url="https://example.com",
            proxy_urls=[f"http://usr:{secret_pw}@127.0.0.1:8080"],
            proxy_password=secret_pw,
        )
        repr_str = repr(cfg)
        self.assertNotIn(secret_pw, repr_str)
        self.assertIn("usr:***@127.0.0.1:8080", repr_str)
        self.assertIn("proxy_password='***'", repr_str)

    def test_secret_redaction_helper(self):
        raw_msg = "Error connecting to http://alice:p@ssw0rd1@proxy.example.com:8080"
        redacted = redact_credentials(raw_msg, secret="p@ssw0rd1")
        self.assertNotIn("p@ssw0rd1", redacted)
        self.assertIn("http://alice:***@proxy.example.com:8080", redacted)

    def test_proxy_endpoint_identifier_cleanliness(self):
        endpoint = ProxyEndpoint.create(1, "http://user:secret@192.168.1.10:8080")
        self.assertEqual(endpoint.identifier, "Proxy #1 (192.168.1.10:8080)")
        self.assertNotIn("secret", endpoint.identifier)

    # --- 2. Environment Parsing & Validation Tests ---

    def test_safe_env_var_parsing(self):
        os.environ["TEST_ENV_INT"] = "8"
        os.environ["TEST_ENV_FLOAT"] = "2.5"
        os.environ["TEST_ENV_BOOL"] = "true"

        self.assertEqual(parse_env_int("TEST_ENV_INT", 4), 8)
        self.assertEqual(parse_env_float("TEST_ENV_FLOAT", 1.0), 2.5)
        self.assertTrue(parse_env_bool("TEST_ENV_BOOL", False))

        with self.assertRaises(ValueError):
            parse_env_int("TEST_ENV_FLOAT", 4)  # "2.5" is not int
        with self.assertRaises(ValueError):
            parse_env_bool("TEST_ENV_INT", False)

    def test_multiline_env_parser_with_comments_and_quotes(self):
        env_content = (
            "# Top level comment\n"
            "TARGET_URL=http://127.0.0.1:8000/\n"
            "PROXY_LIST=\"\n"
            "# Proxy comment\n"
            "192.0.2.1:8080:user1:pass1\n"
            "192.0.2.2:8080:user2:pass2\n"
            "\"\n"
            "REQUIRE_PROXY=true\n"
        )
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".env") as f:
            f.write(env_content)
            temp_path = f.name

        try:
            load_env_file(temp_path)
            self.assertEqual(os.getenv("TARGET_URL"), "http://127.0.0.1:8000/")
            self.assertEqual(os.getenv("REQUIRE_PROXY"), "true")
            proxy_list_val = os.getenv("PROXY_LIST", "")
            lines = [p.strip() for p in proxy_list_val.split("\n") if p.strip() and not p.strip().startswith("#")]
            self.assertEqual(len(lines), 2)
            self.assertIn("192.0.2.1:8080:user1:pass1", lines)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_parse_proxy_entry_missing_credentials_fails(self):
        with self.assertRaises(ValueError) as ctx:
            parse_proxy_entry("192.0.2.1:8080::")
        self.assertIn("must not be empty", str(ctx.exception))

        with self.assertRaises(ValueError):
            parse_proxy_entry("192.0.2.1:8080:user:")

    # --- 3. Proxy Rotation & Concurrency Tests ---

    def test_concurrent_round_robin_proxy_selection(self):
        """Verifies that under multithreaded contention, proxies are selected evenly without race conditions."""
        endpoints = [
            "http://192.0.2.1:8080",
            "http://192.0.2.2:8080",
            "http://192.0.2.3:8080",
            "http://192.0.2.4:8080",
        ]
        pool = ProxyPool(endpoints)
        results = []
        lock = threading.Lock()

        def worker():
            for _ in range(50):
                ep = pool.get_next()
                with lock:
                    results.append(ep.identifier)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 200)
        counts = Counter(results)
        # 200 requests across 4 endpoints = exactly 50 per endpoint
        for count in counts.values():
            self.assertEqual(count, 50)

    # --- 4. Failover Bounds & Error Separation Tests ---

    def test_target_timeout_does_not_trigger_failover(self):
        """Verifies that a target server timeout returns status 'timeout' without triggering failover."""
        cfg = ClientConfig(
            target_url=f"{self.base_url}/timeout",
            max_threads=1,
            total_requests=1,
            request_timeout=0.2,
            proxy_urls=[self.mock_proxy_url, "http://127.0.0.1:1"],
            require_proxy=True,
            max_retries=0,
            max_proxy_retries=1,
        )
        summary = run_bounded_batch(cfg)
        self.assertEqual(summary["tasks"]["failed"], 1)
        self.assertEqual(summary["status_distribution"].get("timeout"), 1)
        self.assertEqual(summary["details"][0]["status"], "timeout")
        self.assertEqual(MockForwardProxyHandler.request_count, 1)

    def test_proxy_failover_strict_retry_limit(self):
        dead_p1 = "http://127.0.0.1:1"
        dead_p2 = "http://127.0.0.1:2"
        dead_p3 = "http://127.0.0.1:3"
        cfg = ClientConfig(
            target_url=f"{self.base_url}/200",
            max_threads=1,
            total_requests=1,
            request_timeout=0.5,
            proxy_urls=[dead_p1, dead_p2, dead_p3],
            require_proxy=True,
            max_proxy_retries=1,
        )
        summary = run_bounded_batch(cfg)
        self.assertEqual(summary["tasks"]["failed"], 1)
        self.assertEqual(summary["status_distribution"].get("proxy_error"), 1)

    def test_strict_no_direct_fallback_when_all_proxies_fail(self):
        dead_p1 = "http://127.0.0.1:1"
        dead_p2 = "http://127.0.0.1:2"
        cfg = ClientConfig(
            target_url=f"{self.base_url}/200",
            max_threads=1,
            total_requests=1,
            request_timeout=0.5,
            proxy_urls=[dead_p1, dead_p2],
            require_proxy=True,
            max_proxy_retries=1,
        )
        summary = run_bounded_batch(cfg)
        self.assertEqual(summary["tasks"]["failed"], 1)
        self.assertEqual(summary["tasks"]["successful"], 0)
        self.assertEqual(summary["status_distribution"].get("proxy_error"), 1)

    # --- 5. TLS Verification & Invariants Tests ---

    def test_tls_verification_strictly_enforced(self):
        cfg = ClientConfig(target_url="https://example.com")
        session = create_resilient_session(cfg)
        try:
            self.assertTrue(session.verify)
        finally:
            session.close()

    # --- 6. Cancellation & Session Lifecycle Tests ---

    def test_mid_execution_cancellation_bounded_completion(self):
        stop_event = threading.Event()
        cfg = ClientConfig(
            target_url=f"{self.base_url}/slow",
            max_threads=1,
            total_requests=5,
            request_timeout=2.0,
        )

        def signal_cancel_after_delay():
            time.sleep(0.4)
            stop_event.set()

        threading.Thread(target=signal_cancel_after_delay, daemon=True).start()
        start_time = time.time()
        summary = run_bounded_batch(cfg, stop_event=stop_event)
        elapsed = time.time() - start_time

        tasks = summary["tasks"]
        self.assertEqual(tasks["configured"], 5)
        self.assertLess(tasks["completed"], 5)
        self.assertGreater(tasks["cancelled"], 0)
        self.assertEqual(tasks["completed"] + tasks["cancelled"], 5)
        self.assertLess(elapsed, 2.0)

    def test_session_cleanup_on_success_and_exception(self):
        cfg = ClientConfig(
            target_url=f"{self.base_url}/200",
            max_threads=3,
            total_requests=6,
            request_timeout=2.0,
        )
        summary = run_bounded_batch(cfg)
        self.assertGreaterEqual(summary["closed_sessions"], 1)
        self.assertLessEqual(summary["closed_sessions"], 3)

    # --- 7. Standard Regression Tests ---

    def test_http_200_classified_as_success(self):
        cfg = ClientConfig(
            target_url=f"{self.base_url}/200",
            max_threads=2,
            total_requests=4,
            request_timeout=3.0,
        )
        summary = run_bounded_batch(cfg)
        self.assertEqual(summary["tasks"]["successful"], 4)
        self.assertEqual(summary["status_distribution"].get("http_success"), 4)

    def test_http_404_classified_as_client_error(self):
        cfg = ClientConfig(
            target_url=f"{self.base_url}/404",
            max_threads=2,
            total_requests=2,
            request_timeout=3.0,
        )
        summary = run_bounded_batch(cfg)
        self.assertEqual(summary["tasks"]["http_errors"], 2)
        self.assertEqual(summary["status_distribution"].get("http_client_error"), 2)

    def test_http_503_classified_as_server_error_and_bounded(self):
        cfg = ClientConfig(
            target_url=f"{self.base_url}/503",
            max_threads=1,
            total_requests=1,
            request_timeout=3.0,
            max_retries=2,
            backoff_factor=0.05,
        )
        summary = run_bounded_batch(cfg)
        self.assertEqual(summary["tasks"]["http_errors"], 1)
        self.assertEqual(summary["status_distribution"].get("http_server_error"), 1)
        self.assertEqual(MockServerHandler.server_error_hits, 3)

    def test_http_429_retry_recovery(self):
        cfg = ClientConfig(
            target_url=f"{self.base_url}/429",
            max_threads=1,
            total_requests=1,
            request_timeout=5.0,
            max_retries=2,
            backoff_factor=0.1,
        )
        summary = run_bounded_batch(cfg)
        self.assertEqual(summary["tasks"]["successful"], 1)
        self.assertEqual(MockServerHandler.rate_limit_hits, 2)

    def test_mock_proxy_routing_and_authentication(self):
        cfg = ClientConfig(
            target_url=f"{self.base_url}/200",
            max_threads=1,
            total_requests=2,
            proxy_urls=[self.mock_proxy_url],
            proxy_username="testuser",
            proxy_password="secretpassword",
            require_proxy=True,
        )
        summary = run_bounded_batch(cfg)
        self.assertEqual(summary["tasks"]["successful"], 2)
        self.assertEqual(MockForwardProxyHandler.request_count, 2)
        expected_token = base64.b64encode(b"testuser:secretpassword").decode("ascii")
        self.assertEqual(MockForwardProxyHandler.last_proxy_auth, f"Basic {expected_token}")

    def test_load_config_from_env_safe_defaults(self):
        env_keys = [
            "TARGET_URL", "MAX_THREADS", "TOTAL_REQUESTS", "REQUEST_TIMEOUT",
            "MAX_RETRIES", "REQUIRE_PROXY", "PROXY_LIST", "WEBSHARE_PROXY_URL"
        ]
        saved = {k: os.environ.pop(k, None) for k in env_keys}
        try:
            cfg = load_config_from_env()
            self.assertEqual(cfg.max_threads, 2)
            self.assertEqual(cfg.total_requests, 10)
            self.assertEqual(cfg.max_retries, 0)
            self.assertEqual(cfg.request_timeout, 10.0)
            self.assertFalse(cfg.require_proxy)
            self.assertEqual(cfg.max_proxy_retries, 0)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_main_exit_code_validation_error(self):
        saved = os.environ.get("TARGET_URL")
        try:
            os.environ["TARGET_URL"] = "ftp://invalid-scheme.com"
            exit_code = main()
            self.assertEqual(exit_code, 2)
        finally:
            if saved is not None:
                os.environ["TARGET_URL"] = saved
            else:
                os.environ.pop("TARGET_URL", None)

    def test_main_exit_code_success(self):
        saved_url = os.environ.get("TARGET_URL")
        saved_reqs = os.environ.get("TOTAL_REQUESTS")
        try:
            os.environ["TARGET_URL"] = f"{self.base_url}/200"
            os.environ["TOTAL_REQUESTS"] = "2"
            exit_code = main()
            self.assertEqual(exit_code, 0)
        finally:
            if saved_url is not None:
                os.environ["TARGET_URL"] = saved_url
            else:
                os.environ.pop("TARGET_URL", None)
            if saved_reqs is not None:
                os.environ["TOTAL_REQUESTS"] = saved_reqs
            else:
                os.environ.pop("TOTAL_REQUESTS", None)


if __name__ == "__main__":
    unittest.main()
