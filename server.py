import json
import os
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from testing_public_domain import run_cycle, stats, stats_lock, TARGET_URL, TOTAL_REQUESTS, MAX_THREADS

# Automation settings
CYCLE_INTERVAL = int(os.getenv("CYCLE_INTERVAL", "60"))
PORT = int(os.getenv("PORT", 10000))

server_state = {
    "service": "Defensive Endpoint Continuous Tester (Render 24/7 Web Service)",
    "status": "starting",
    "total_cycles": 0,
    "last_cycle_timestamp": None,
    "last_cycle_duration_seconds": 0,
    "target_url": TARGET_URL,
    "requests_per_cycle": TOTAL_REQUESTS,
    "concurrency_threads": MAX_THREADS,
    "started_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
}
state_lock = threading.Lock()


def background_tester_worker():
    print(f"\n[Worker] Background 1-minute continuous tester started.")
    print(f"[Worker] Target: {TARGET_URL} | Interval: {CYCLE_INTERVAL}s")
    with state_lock:
        server_state["status"] = "running"

    cycle = 1
    while True:
        try:
            start_ts = time.time()
            elapsed = run_cycle(cycle)

            with state_lock:
                server_state["total_cycles"] = cycle
                server_state["last_cycle_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                server_state["last_cycle_duration_seconds"] = round(elapsed, 2)

            sleep_time = CYCLE_INTERVAL - (time.time() - start_ts)
            if sleep_time > 0:
                print(f"[Worker] Sleeping {sleep_time:.1f}s until next minute cycle...")
                time.sleep(sleep_time)
            cycle += 1
        except Exception as e:
            print(f"[Worker Error] Unexpected error in worker loop: {e}")
            time.sleep(10)


class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with state_lock:
            state_copy = dict(server_state)
        with stats_lock:
            latest_stats = {
                "total": stats["total"],
                "success": stats["success"],
                "failed": stats["failed"],
                "status_codes": dict(stats["status_codes"]),
            }

        response_data = {
            "service": "Defensive Endpoint Continuous Tester",
            "state": state_copy,
            "latest_cycle_metrics": latest_stats,
            "instructions": "Keep-alive ping received. Service is active and running 24/7."
        }

        body = json.dumps(response_data, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        sys.stderr.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Keep-Alive Ping: {format % args}\n")


def main():
    # Start background tester in a daemon thread
    worker_thread = threading.Thread(target=background_tester_worker, daemon=True)
    worker_thread.start()

    # Start HTTP server on PORT
    server_address = ("", PORT)
    httpd = HTTPServer(server_address, WebHandler)
    print(f"[Server] Web Service listening on port {PORT}...")
    print(f"[Server] Ready for Render deployment & keep-alive pings.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")


if __name__ == "__main__":
    main()
