import concurrent.futures
import os
import random
import threading
import time
from collections import Counter, defaultdict
import urllib3
from urllib3.util.ssl_ import create_urllib3_context
import requests
from requests.adapters import HTTPAdapter

# Disable insecure request warnings when SSL verification is bypassed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_URL = os.getenv("TARGET_URL", "https://tracker.bepcssa.in")
TOTAL_REQUESTS = int(os.getenv("TOTAL_REQUESTS", "20000"))
MAX_THREADS = int(os.getenv("MAX_THREADS", "150"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))
PROGRESS_INTERVAL = int(os.getenv("PROGRESS_INTERVAL", "100"))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

# --- SSL / SNI Handling ---
# Bypass TLS handshake failure when public edge/WAF rejects mismatched SNI
orig_ssl_wrap = urllib3.util.ssl_._ssl_wrap_socket_impl


def no_sni_wrap(sock, ssl_context, tls_in_tls, server_hostname=None):
    # Suppress SNI header so edge server falls back to default cert
    return orig_ssl_wrap(sock, ssl_context, tls_in_tls, server_hostname=None)


urllib3.util.ssl_._ssl_wrap_socket_impl = no_sni_wrap


class ResilientSSLAdapter(HTTPAdapter):
    """HTTPAdapter with connection pooling and relaxed SSL validation."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = 0  # CERT_NONE
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(*args, **kwargs)


# Thread-local storage to give each worker thread its own Session (simulating real users with cookie persistence)
thread_local = threading.local()


def get_worker_session():
    if not hasattr(thread_local, "session"):
        session = requests.Session()
        adapter = ResilientSSLAdapter(pool_connections=1, pool_maxsize=2)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        thread_local.session = session
    return thread_local.session


stats_lock = threading.Lock()
stats = {
    "total": 0,
    "success": 0,
    "failed": 0,
    "status_codes": Counter(),
    "latencies": [],
    "errors": defaultdict(int),
}


def fetch_once():
    session = get_worker_session()
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    start = time.perf_counter()
    try:
        resp = session.get(TARGET_URL, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        elapsed = time.perf_counter() - start
        status = resp.status_code

        with stats_lock:
            stats["total"] += 1
            total_now = stats["total"]
            stats["status_codes"][status] += 1
            stats["latencies"].append(elapsed)
            if 200 <= status < 400:
                stats["success"] += 1
            else:
                stats["failed"] += 1
                stats["errors"][f"status_{status}"] += 1

        if total_now % PROGRESS_INTERVAL == 0:
            print(f"Progress: {total_now}/{TOTAL_REQUESTS} requests completed")
        return status, elapsed, None

    except requests.exceptions.RequestException as exc:
        elapsed = time.perf_counter() - start
        err_msg = type(exc).__name__
        with stats_lock:
            stats["total"] += 1
            total_now = stats["total"]
            stats["failed"] += 1
            stats["latencies"].append(elapsed)
            stats["errors"][err_msg] += 1

        if total_now % PROGRESS_INTERVAL == 0:
            print(f"Progress: {total_now}/{TOTAL_REQUESTS} requests completed")
        return None, elapsed, str(exc)


def print_summary(total_duration):
    total = stats["total"]
    success = stats["success"]
    failed = stats["failed"]
    latencies = stats["latencies"]
    avg = sum(latencies) / len(latencies) if latencies else 0
    p95_index = max(0, min(len(latencies) - 1, int(len(latencies) * 0.95)))
    p95 = sorted(latencies)[p95_index] if latencies else 0
    rps = total / total_duration if total_duration > 0 else 0

    print("\n=== Load Test Summary ===")
    print(f"Target: {TARGET_URL}")
    print(f"Threads: {MAX_THREADS}")
    print(f"Total requested: {TOTAL_REQUESTS}")
    print(f"Total completed: {total}")
    print(f"Successful: {success}")
    print(f"Failed: {failed}")
    print(f"Throughput: {rps:.2f} req/s")
    print(f"Average latency: {avg:.3f}s")
    print(f"P95 latency: {p95:.3f}s")
    print(f"Status codes: {dict(stats['status_codes'])}")
    if stats["errors"]:
        print("Errors:")
        for err, count in stats["errors"].items():
            print(f"  {err}: {count}")


def main():
    print(f"Starting {TOTAL_REQUESTS} requests against {TARGET_URL} using {MAX_THREADS} threads")
    start = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
        futures = [pool.submit(fetch_once) for _ in range(TOTAL_REQUESTS)]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                print(f"Unexpected worker exception: {exc}")

    elapsed = time.perf_counter() - start
    print(f"Run completed in {elapsed:.2f}s")
    print_summary(elapsed)


if __name__ == "__main__":
    main()
