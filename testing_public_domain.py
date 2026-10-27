"""
Defensive, reliable HTTP client implementation with bounded concurrency,
thread-isolated sessions, strict input validation, comprehensive error classification,
robust task cancellation tracking, and authorized Webshare/standard proxy pool integration
with decoupled round-robin rotation, safe secret redaction, and bounded failover.

Security and Resilience Invariants:
1. TLS certificate verification is strictly enforced (session.verify = True).
2. Proxy passwords and credentials are never logged, printed, or exposed in exceptions.
3. Decoupled rotation: regular requests rotate round-robin; failover triggers only on proxy transport errors.
4. When require_proxy is True, requests will never fall back to direct connections.
5. In-flight requests run to completion bounded by socket request_timeout (Future.cancel() cancels queued tasks).
"""

from collections import Counter
import concurrent.futures
from dataclasses import dataclass, field
import logging
import os
import re
import sys
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse
from urllib3.util import Retry
import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)


def redact_credentials(text: Optional[str], secret: Optional[str] = None) -> str:
    """
    Sanitizes strings and exception messages to prevent credential leakage.
    Replaces embedded user:pass@ with user:***@ and redacts explicit secrets.
    """
    if not text:
        return ""
    s = str(text)
    if secret and secret in s:
        s = s.replace(secret, "***")
    pattern = r"([a-zA-Z0-9+.-]+://[^:/\s@]+:)(?:.+?)@([a-zA-Z0-9_.-]+(?::\d+)?)"
    return re.sub(pattern, r"\g<1>***@\2", s)


def mask_proxy_url(url: Optional[str]) -> Optional[str]:
    """Masks authentication credentials in proxy URLs for safe logging and reporting."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
        if parsed.username:
            return f"{parsed.scheme}://{parsed.username}:***@{parsed.hostname}:{parsed.port}"
        return url
    except Exception:
        return "http://***"


def format_proxy_url(
    raw_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> str:
    """
    Validates and formats a proxy URL, supporting standard URLs with or without credentials.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Proxy URL must be a non-empty string.")

    parsed = urlparse(raw_url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https", "socks5", "socks5h"):
        raise ValueError(
            f"Unsupported proxy scheme '{scheme}'. Supported schemes: http, https, socks5, socks5h."
        )

    if not parsed.hostname:
        raise ValueError(f"Proxy URL '{mask_proxy_url(raw_url)}' missing host.")

    if not parsed.port or not (1 <= parsed.port <= 65535):
        raise ValueError(f"Proxy URL '{mask_proxy_url(raw_url)}' must specify a valid port (1-65535).")

    if parsed.username:
        return raw_url.strip()

    if username is not None and password is not None:
        user_clean = quote(str(username), safe="")
        pass_clean = quote(str(password), safe="")
        return f"{scheme}://{user_clean}:{pass_clean}@{parsed.hostname}:{parsed.port}"

    return raw_url.strip()


def parse_proxy_entry(
    entry: str,
    default_user: Optional[str] = None,
    default_pass: Optional[str] = None,
) -> str:
    """
    Parses a proxy entry from either:
    - Webshare list export: 'IP:PORT:USERNAME:PASSWORD'
    - Host and port: 'IP:PORT'
    - Standard URL: 'http://user:pass@host:port' or 'http://host:port'
    """
    clean = entry.strip()
    if not clean:
        raise ValueError("Proxy entry must not be empty.")

    if "://" in clean:
        return format_proxy_url(clean, default_user, default_pass)

    parts = clean.split(":")
    if len(parts) == 4:
        host, port_str, user, password = parts
        if not user.strip() or not password.strip():
            raise ValueError("Proxy entry credentials (username/password) must not be empty.")
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port '{port_str}' in proxy entry.")
        return format_proxy_url(f"http://{host}:{port}", user.strip(), password.strip())

    if len(parts) == 2:
        host, port_str = parts
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port '{port_str}' in proxy entry.")
        return format_proxy_url(f"http://{host}:{port}", default_user, default_pass)

    raise ValueError(
        "Unrecognized proxy format. Expected 'host:port:user:pass', 'host:port', or 'http://...'"
    )


@dataclass
class ProxyEndpoint:
    """Encapsulates a proxy endpoint with index and masked identifier for safe logging."""
    index: int
    raw_url: str
    identifier: str

    @classmethod
    def create(cls, index: int, raw_url: str) -> "ProxyEndpoint":
        parsed = urlparse(raw_url)
        ident = f"Proxy #{index} ({parsed.hostname}:{parsed.port})"
        return cls(index=index, raw_url=raw_url, identifier=ident)


class ProxyPool:
    """
    Thread-safe proxy pool supporting:
    1. Round-robin proxy selection for new requests.
    2. Decoupled failure-based failover to alternate proxies.
    """
    def __init__(self, proxy_urls: List[str]):
        self._endpoints: List[ProxyEndpoint] = [
            ProxyEndpoint.create(idx + 1, url) for idx, url in enumerate(proxy_urls)
        ]
        self._lock = threading.Lock()
        self._rotation_index = 0

    def get_next(self) -> Optional[ProxyEndpoint]:
        """Round-robin proxy selection for regular request scheduling."""
        if not self._endpoints:
            return None
        with self._lock:
            ep = self._endpoints[self._rotation_index % len(self._endpoints)]
            self._rotation_index += 1
            return ep

    def get_fallback(self, exclude_index: Optional[int] = None) -> Optional[ProxyEndpoint]:
        """Selects an alternate proxy during failover, excluding the failed endpoint index."""
        if not self._endpoints:
            return None
        with self._lock:
            available = [ep for ep in self._endpoints if ep.index != exclude_index]
            if not available:
                return self._endpoints[0]
            fallback = available[self._rotation_index % len(available)]
            self._rotation_index += 1
            return fallback

    def __len__(self) -> int:
        return len(self._endpoints)


@dataclass
class ClientConfig:
    """Configuration settings with strict bounds for safety, stability, and proxy control."""
    target_url: str
    max_threads: int = 2
    total_requests: int = 10
    request_timeout: float = 10.0
    user_agent: str = "DefensiveHttpClient/1.0"
    max_retries: int = 0
    backoff_factor: float = 0.5
    # Authorized proxy settings
    proxy_urls: List[str] = field(default_factory=list)
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = field(default=None, repr=False)
    require_proxy: bool = False
    max_proxy_retries: int = 0

    def __repr__(self) -> str:
        """Custom string representation that guarantees credentials are never printed."""
        masked_urls = [mask_proxy_url(u) for u in self.proxy_urls]
        return (
            f"ClientConfig(target_url={self.target_url!r}, "
            f"max_threads={self.max_threads}, total_requests={self.total_requests}, "
            f"request_timeout={self.request_timeout}, user_agent={self.user_agent!r}, "
            f"max_retries={self.max_retries}, backoff_factor={self.backoff_factor}, "
            f"proxy_urls={masked_urls!r}, proxy_username={self.proxy_username!r}, "
            f"proxy_password={'***' if self.proxy_password else None!r}, "
            f"require_proxy={self.require_proxy}, max_proxy_retries={self.max_proxy_retries})"
        )


def validate_config(config: ClientConfig) -> None:
    """
    Validates all configuration parameters to prevent malformed requests,
    header injection, resource exhaustion, and invalid proxy settings.
    Raises ValueError with sanitized error messages on invalid input.
    """
    if not config.target_url or not isinstance(config.target_url, str):
        raise ValueError("TARGET_URL must be a non-empty string.")

    parsed = urlparse(config.target_url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are supported."
        )
    if not parsed.netloc:
        raise ValueError("Malformed URL: missing network location/host.")

    if not isinstance(config.max_threads, int) or isinstance(config.max_threads, bool):
        raise ValueError("MAX_THREADS must be an integer.")
    if not (1 <= config.max_threads <= 32):
        raise ValueError(
            f"MAX_THREADS must be between 1 and 32 to prevent resource exhaustion, got {config.max_threads}."
        )

    if not isinstance(config.total_requests, int) or isinstance(config.total_requests, bool):
        raise ValueError("TOTAL_REQUESTS must be an integer.")
    if not (1 <= config.total_requests <= 1000):
        raise ValueError(
            f"TOTAL_REQUESTS must be between 1 and 1000, got {config.total_requests}."
        )

    if not isinstance(config.request_timeout, (int, float)) or isinstance(config.request_timeout, bool):
        raise ValueError("REQUEST_TIMEOUT must be a number.")
    if not (0.1 <= float(config.request_timeout) <= 60.0):
        raise ValueError(
            f"REQUEST_TIMEOUT must be between 0.1 and 60.0 seconds, got {config.request_timeout}."
        )

    if not isinstance(config.max_retries, int) or isinstance(config.max_retries, bool):
        raise ValueError("MAX_RETRIES must be an integer.")
    if not (0 <= config.max_retries <= 5):
        raise ValueError(
            f"max_retries must be between 0 and 5, got {config.max_retries}."
        )

    if not isinstance(config.backoff_factor, (int, float)) or isinstance(config.backoff_factor, bool):
        raise ValueError("BACKOFF_FACTOR must be a number.")
    if not (0.0 <= float(config.backoff_factor) <= 10.0):
        raise ValueError(
            f"BACKOFF_FACTOR must be between 0.0 and 10.0, got {config.backoff_factor}."
        )

    if not config.user_agent or not isinstance(config.user_agent, str):
        raise ValueError("USER_AGENT must be a non-empty string.")
    if len(config.user_agent.strip()) == 0 or len(config.user_agent) > 256:
        raise ValueError("USER_AGENT length must be between 1 and 256 characters.")
    if any(c in config.user_agent for c in ("\r", "\n")):
        raise ValueError("USER_AGENT must not contain newline characters.")

    if not isinstance(config.require_proxy, bool):
        raise ValueError("require_proxy must be a boolean.")

    if config.require_proxy and not config.proxy_urls:
        raise ValueError("require_proxy is True but no proxy_urls were provided.")

    if config.proxy_urls:
        if not isinstance(config.proxy_urls, (list, tuple)):
            raise ValueError("proxy_urls must be a list or tuple.")
        if len(config.proxy_urls) > 50:
            raise ValueError("proxy_urls list exceeds maximum allowed size of 50.")
        for raw_p in config.proxy_urls:
            parse_proxy_entry(raw_p, config.proxy_username, config.proxy_password)

    if not isinstance(config.max_proxy_retries, int) or isinstance(config.max_proxy_retries, bool):
        raise ValueError("max_proxy_retries must be an integer.")
    if not (0 <= config.max_proxy_retries <= 5):
        raise ValueError(
            f"max_proxy_retries must be between 0 and 5, got {config.max_proxy_retries}."
        )


def create_resilient_session(config: ClientConfig) -> requests.Session:
    """Creates and configures an isolated requests.Session with standard TLS and retries."""
    session = requests.Session()

    retry_strategy = Retry(
        total=config.max_retries,
        backoff_factor=config.backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=1,
        pool_maxsize=1,
    )

    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.verify = True  # Strict HTTPS certificate verification enforced
    session.headers.update({"User-Agent": config.user_agent})

    return session


class ThreadLocalSessionManager:
    """
    Manages per-thread sessions and proxy pool distribution.
    Maintains thread isolation while ensuring all active sessions are cleanly closed.
    """
    def __init__(self, config: ClientConfig):
        self.config = config
        self._local = threading.local()
        self._sessions: List[requests.Session] = []
        self._lock = threading.Lock()

        parsed_proxies: List[str] = [
            parse_proxy_entry(p, config.proxy_username, config.proxy_password)
            for p in config.proxy_urls
        ]
        self.proxy_pool = ProxyPool(parsed_proxies) if parsed_proxies else None

    def get_session(self) -> requests.Session:
        if not hasattr(self._local, "session"):
            sess = create_resilient_session(self.config)
            self._local.session = sess
            with self._lock:
                self._sessions.append(sess)
        return self._local.session

    def close_all(self) -> int:
        """Safely closes all tracked sessions across all threads."""
        closed_count = 0
        with self._lock:
            for sess in self._sessions:
                try:
                    sess.close()
                    closed_count += 1
                except Exception as e:
                    logger.warning(f"Error closing session: {e}")
            self._sessions.clear()
        return closed_count


def classify_response_status(status_code: int) -> str:
    """Categorizes HTTP status codes into clear functional categories."""
    if 200 <= status_code < 300:
        return "http_success"
    if 300 <= status_code < 400:
        return "http_redirect"
    if 400 <= status_code < 500:
        return "http_client_error"
    if 500 <= status_code < 600:
        return "http_server_error"
    return "http_other"


def fetch_url(
    session: requests.Session,
    url: str,
    timeout: float,
    endpoint: Optional[ProxyEndpoint] = None,
    secret_to_redact: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a single GET request, accurately categorizing outcomes:
    - Distinguishes proxy transport failures from target server timeouts/responses.
    - Strictly redacts credentials from error messages.
    """
    proxy_ident = endpoint.identifier if endpoint else None
    proxies = {"http": endpoint.raw_url, "https": endpoint.raw_url} if endpoint else None

    try:
        response = session.get(url, timeout=timeout, proxies=proxies)
        status_category = classify_response_status(response.status_code)
        return {
            "status": status_category,
            "status_code": response.status_code,
            "error": None,
            "proxy_identifier": proxy_ident,
        }
    except requests.exceptions.ProxyError as e:
        return {
            "status": "proxy_error",
            "status_code": None,
            "error": redact_credentials(str(e), secret_to_redact),
            "proxy_identifier": proxy_ident,
        }
    except requests.exceptions.Timeout as e:
        return {
            "status": "timeout",
            "status_code": None,
            "error": redact_credentials(str(e), secret_to_redact),
            "proxy_identifier": proxy_ident,
        }
    except requests.exceptions.SSLError as e:
        return {
            "status": "tls_error",
            "status_code": None,
            "error": redact_credentials(str(e), secret_to_redact),
            "proxy_identifier": proxy_ident,
        }
    except requests.exceptions.ConnectionError as e:
        err_msg = str(e).lower()
        clean_err = redact_credentials(str(e), secret_to_redact)
        if "timed out" in err_msg or "timeout" in err_msg:
            return {
                "status": "timeout",
                "status_code": None,
                "error": clean_err,
                "proxy_identifier": proxy_ident,
            }
        if "proxy" in err_msg:
            return {
                "status": "proxy_error",
                "status_code": None,
                "error": clean_err,
                "proxy_identifier": proxy_ident,
            }
        return {
            "status": "connection_error",
            "status_code": None,
            "error": clean_err,
            "proxy_identifier": proxy_ident,
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "request_error",
            "status_code": None,
            "error": redact_credentials(str(e), secret_to_redact),
            "proxy_identifier": proxy_ident,
        }


def fetch_with_failover(
    session: requests.Session,
    url: str,
    timeout: float,
    session_manager: ThreadLocalSessionManager,
    config: ClientConfig,
) -> Dict[str, Any]:
    """
    Executes a request using round-robin proxy rotation, with decoupled
    failure-based failover. Only retries on proxy transport failures, never on
    target timeouts or HTTP responses. Never falls back to a direct connection
    if proxy mode is required.
    """
    pool = session_manager.proxy_pool
    if not pool:
        if config.require_proxy:
            return {
                "status": "proxy_error",
                "status_code": None,
                "error": "Proxy mode is required but no approved proxies are configured.",
                "proxy_identifier": None,
            }
        return fetch_url(session, url, timeout, endpoint=None, secret_to_redact=config.proxy_password)

    # 1. Round-robin proxy selection for this request
    primary_endpoint = pool.get_next()
    res = fetch_url(
        session,
        url,
        timeout,
        endpoint=primary_endpoint,
        secret_to_redact=config.proxy_password,
    )

    # Return immediately on success, target HTTP responses (4xx/5xx), or target timeouts.
    # Failover is strictly reserved for proxy transport failures (proxy_error).
    if res["status"] != "proxy_error":
        return res

    # 2. Failure-based failover (logged with proxy identifier only, credentials omitted)
    logger.warning(
        f"Primary {primary_endpoint.identifier} encountered proxy transport error. Initiating failover..."
    )

    max_failovers = min(len(pool) - 1, config.max_proxy_retries)
    last_res = res
    current_failed_index = primary_endpoint.index

    for attempt in range(max_failovers):
        fallback_endpoint = pool.get_fallback(exclude_index=current_failed_index)
        if not fallback_endpoint:
            break

        fb_res = fetch_url(
            session,
            url,
            timeout,
            endpoint=fallback_endpoint,
            secret_to_redact=config.proxy_password,
        )

        if fb_res["status"] != "proxy_error":
            logger.info(
                f"Failover attempt {attempt + 1} succeeded using {fallback_endpoint.identifier}"
            )
            return fb_res

        current_failed_index = fallback_endpoint.index
        last_res = fb_res
        logger.warning(
            f"Failover attempt {attempt + 1} failed on {fallback_endpoint.identifier}."
        )

    return last_res


def run_bounded_batch(
    config: ClientConfig,
    stop_event: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    """
    Executes a bounded batch of requests concurrently with decoupled proxy rotation,
    safe secret redaction, and reliable session lifecycle cleanup.
    """
    validate_config(config)

    session_manager = ThreadLocalSessionManager(config)
    results: List[Dict[str, Any]] = []
    status_counter = Counter()

    submitted_count = 0
    cancelled_count = 0
    unsubmitted_count = 0

    def worker_task(url: str, timeout: float) -> Dict[str, Any]:
        if stop_event and stop_event.is_set():
            return {
                "status": "cancelled",
                "status_code": None,
                "error": "Task cancelled before execution",
                "proxy_identifier": None,
            }
        sess = session_manager.get_session()
        return fetch_with_failover(sess, url, timeout, session_manager, config)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.max_threads) as executor:
            futures = []
            for _ in range(config.total_requests):
                if stop_event and stop_event.is_set():
                    unsubmitted_count = config.total_requests - len(futures)
                    break
                future = executor.submit(worker_task, config.target_url, config.request_timeout)
                futures.append(future)

            submitted_count = len(futures)

            for future in concurrent.futures.as_completed(futures):
                if stop_event and stop_event.is_set():
                    for f in futures:
                        if not f.done():
                            f.cancel()

                if future.cancelled():
                    cancelled_count += 1
                    continue

                try:
                    res = future.result()
                    if res.get("status") == "cancelled":
                        cancelled_count += 1
                        continue
                    results.append(res)
                    status_counter[res["status"]] += 1
                except concurrent.futures.CancelledError:
                    cancelled_count += 1
                except Exception as exc:
                    results.append({
                        "status": "task_execution_error",
                        "status_code": None,
                        "error": redact_credentials(str(exc), config.proxy_password),
                        "proxy_identifier": None,
                    })
                    status_counter["task_execution_error"] += 1

    finally:
        closed_sessions = session_manager.close_all()

    completed_count = len(results)
    total_cancelled = cancelled_count + unsubmitted_count

    successful_count = status_counter["http_success"]
    http_error_count = (
        status_counter["http_client_error"] + status_counter["http_server_error"]
    )
    failed_network_count = (
        status_counter["timeout"]
        + status_counter["tls_error"]
        + status_counter["proxy_error"]
        + status_counter["connection_error"]
        + status_counter["request_error"]
        + status_counter["task_execution_error"]
    )

    return {
        "tasks": {
            "configured": config.total_requests,
            "submitted": submitted_count,
            "completed": completed_count,
            "cancelled": total_cancelled,
            "successful": successful_count,
            "http_errors": http_error_count,
            "failed": failed_network_count,
        },
        "status_distribution": dict(status_counter),
        "closed_sessions": closed_sessions,
        "details": results,
    }


def load_env_file(env_path: str = ".env") -> None:
    """
    Loads environment variables from a local .env file, supporting multiline quoted strings.
    """
    if not os.path.isfile(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            content = f.read()

        lines = content.splitlines()
        in_multiline = False
        quote_char = None
        current_key = None
        current_val: List[str] = []

        for line in lines:
            stripped = line.strip()
            if not in_multiline:
                if not stripped or stripped.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if (v.startswith('"') and not (v.endswith('"') and len(v) > 1)) or (
                    v.startswith("'") and not (v.endswith("'") and len(v) > 1)
                ):
                    in_multiline = True
                    quote_char = v[0]
                    current_key = k
                    current_val = [v[1:]]
                else:
                    if (v.startswith('"') and v.endswith('"')) or (
                        v.startswith("'") and v.endswith("'")
                    ):
                        v = v[1:-1]
                    if k and k not in os.environ:
                        os.environ[k] = v
            else:
                if stripped.endswith(str(quote_char)):
                    end_idx = line.rfind(str(quote_char))
                    current_val.append(line[:end_idx])
                    if current_key and current_key not in os.environ:
                        os.environ[current_key] = "\n".join(current_val)
                    in_multiline = False
                    current_key = None
                    current_val = []
                    quote_char = None
                else:
                    current_val.append(line)
    except Exception as e:
        logger.warning(f"Could not load .env file from {env_path}: {e}")


def parse_env_int(key: str, default: int) -> int:
    """Safely parses an integer environment variable with descriptive errors."""
    val = os.getenv(key)
    if val is None or not val.strip():
        return default
    try:
        return int(val.strip())
    except ValueError:
        raise ValueError(f"Environment variable '{key}' must be an integer, got: {val.strip()!r}")


def parse_env_float(key: str, default: float) -> float:
    """Safely parses a floating-point environment variable with descriptive errors."""
    val = os.getenv(key)
    if val is None or not val.strip():
        return default
    try:
        return float(val.strip())
    except ValueError:
        raise ValueError(f"Environment variable '{key}' must be a number, got: {val.strip()!r}")


def parse_env_bool(key: str, default: bool) -> bool:
    """Safely parses a boolean environment variable with descriptive errors."""
    val = os.getenv(key)
    if val is None or not val.strip():
        return default
    clean = val.strip().lower()
    if clean in ("true", "1", "yes", "on"):
        return True
    if clean in ("false", "0", "no", "off"):
        return False
    raise ValueError(f"Environment variable '{key}' must be a boolean (true/false), got: {val.strip()!r}")


def load_config_from_env() -> ClientConfig:
    """Loads configuration with safe defaults from environment variables or .env file."""
    load_env_file(".env")

    raw_proxies = os.getenv("PROXY_LIST") or os.getenv("PROXY_URLS", "")
    proxy_urls = []
    if raw_proxies:
        normalized = raw_proxies.replace(";", "\n").replace(",", "\n")
        proxy_urls = [
            p.strip() for p in normalized.split("\n")
            if p.strip() and not p.strip().startswith("#")
        ]

    single_proxy = os.getenv("WEBSHARE_PROXY_URL") or os.getenv("PROXY_URL")
    if single_proxy and single_proxy.strip() not in proxy_urls:
        proxy_urls.insert(0, single_proxy.strip())

    return ClientConfig(
        target_url=os.getenv("TARGET_URL", "http://127.0.0.1:8000/"),
        max_threads=parse_env_int("MAX_THREADS", 2),
        total_requests=parse_env_int("TOTAL_REQUESTS", 10),
        request_timeout=parse_env_float("REQUEST_TIMEOUT", 10.0),
        user_agent=os.getenv("USER_AGENT", "DefensiveHttpClient/1.0"),
        max_retries=parse_env_int("MAX_RETRIES", 0),
        backoff_factor=parse_env_float("BACKOFF_FACTOR", 0.5),
        proxy_urls=proxy_urls,
        proxy_username=os.getenv("WEBSHARE_PROXY_USERNAME") or os.getenv("PROXY_USERNAME"),
        proxy_password=os.getenv("WEBSHARE_PROXY_PASSWORD") or os.getenv("PROXY_PASSWORD"),
        require_proxy=parse_env_bool("REQUIRE_PROXY", False),
        max_proxy_retries=parse_env_int("MAX_PROXY_RETRIES", 0),
    )


def main() -> int:
    """
    Main entry point for command-line and automated CI/CD execution.
    Returns:
        0: Batch execution succeeded without network errors.
        1: Execution encountered network errors, timeouts, or 0 successful requests.
        2: Configuration validation error.
        130: Process interrupted by user.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        app_config = load_config_from_env()
        logger.info(f"Starting execution with validated configuration: {app_config}")
        summary = run_bounded_batch(app_config)
        print("\n=== Batch Execution Summary ===")
        print(f"Task Accounting: {summary['tasks']}")
        print(f"Status Distribution: {summary['status_distribution']}")
        print(f"Sessions cleanly closed: {summary['closed_sessions']}")

        tasks = summary["tasks"]
        if tasks.get("failed", 0) > 0:
            logger.error(
                f"Execution finished with {tasks['failed']} failed network tasks."
            )
            return 1
        if tasks.get("successful", 0) == 0 and tasks.get("configured", 0) > 0:
            logger.error("Execution finished with 0 successful requests.")
            return 1
        return 0
    except ValueError as val_err:
        logger.error(f"Configuration Validation Error: {val_err}")
        return 2
    except KeyboardInterrupt:
        logger.warning("Execution interrupted by user.")
        return 130
    except Exception as exc:
        logger.error(f"Unexpected execution error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
