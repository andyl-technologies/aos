"""Exercise the real Envoy chain and coordinate guest semantic boundaries."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request


ROUTER_A = "http://10.77.0.2:8080"
CONTROL = "http://10.77.0.2:9090"
REQUESTS_PER_BATCH = 4
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def guest(*arguments):
    subprocess.run(("crucible-guest", *arguments), check=True)


def request(sequence):
    try:
        with NO_PROXY.open(
            f"{ROUTER_A}/probe?seq={sequence}", timeout=4
        ) as response:
            return sequence, response.read(256).decode("ascii"), response.status
    except (OSError, UnicodeError, ValueError):
        return sequence, "", 0


def announce(boundary):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            request_body = urllib.request.Request(
                f"{CONTROL}/{boundary}", data=b"", method="POST"
            )
            with NO_PROXY.open(request_body, timeout=2) as response:
                if response.status == 204:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)
    raise RuntimeError(f"router A did not acknowledge {boundary}")


def transport_applied():
    try:
        with NO_PROXY.open(f"{CONTROL}/transport-applied", timeout=2) as response:
            return response.status == 204
    except (OSError, urllib.error.URLError):
        return False


def wait_for_convergence():
    for _attempt in range(90):
        _sequence, body, status = request(0)
        if status == 200 and body == "east:0:1:1:1":
            return
        time.sleep(1)
    raise RuntimeError("the initial A-B-C-east path did not converge")


def run_west():
    guest("setup-complete")
    wait_for_convergence()
    guest("semantic-marker", "network.converged", "instance-1")
    announce("converged")

    successful = 0
    lost = 0
    response_completion_inversions = 0
    sequence = 0
    window_requests = 0
    measurement_started = False
    failover_sequence = None
    with ThreadPoolExecutor(max_workers=REQUESTS_PER_BATCH) as workers:
        while True:
            if not measurement_started and transport_applied():
                guest("measurement-begin", "traffic-window", "instance-1")
                measurement_started = True

            batch = list(range(sequence + 1, sequence + REQUESTS_PER_BATCH + 1))
            futures = [workers.submit(request, number) for number in batch]
            arrival_order = []

            for future in as_completed(futures):
                number, body, status = future.result()
                arrival_order.append(number)

                if status != 200:
                    if measurement_started:
                        lost += 1
                    continue
                if body.startswith("UNSAFE:"):
                    guest(
                        "unreachable",
                        "forbidden-destination-delivery",
                        "Router A answered without delivering to traffic-east",
                    )
                    continue
                if body.count(":") != 4 or "," in body:
                    guest(
                        "unreachable",
                        "persistent-forwarding-loop",
                        "A routed request repeated a proxy hop",
                    )
                    continue
                if body not in (
                    f"east:{number}:1:1:1",
                    f"east:{number}:1::1",
                ):
                    guest(
                        "unreachable",
                        "forbidden-destination-delivery",
                        "A response lacked the required endpoint and route identity",
                    )
                    continue
                if measurement_started and body == f"east:{number}:1::1" and failover_sequence is None:
                    failover_sequence = number
                if measurement_started:
                    successful += 1

            if measurement_started:
                response_completion_inversions += sum(
                    left > right
                    for index, left in enumerate(arrival_order)
                    for right in arrival_order[index + 1 :]
                )
                window_requests += REQUESTS_PER_BATCH
            sequence += REQUESTS_PER_BATCH

            if window_requests == 120:
                guest(
                    "metric-sample", "traffic-window", "instance-1",
                    "traffic_success_packets", "u64", str(successful),
                )
                guest(
                    "metric-sample", "traffic-window", "instance-1",
                    "traffic_loss_packets", "u64", str(lost),
                )
                guest(
                    "metric-sample", "traffic-window", "instance-1",
                    "response_completion_inversions", "u64",
                    str(response_completion_inversions),
                )
                guest("measurement-end", "traffic-window", "instance-1")
                outcome = "converged" if successful > 0 else "bounded-failure"
                guest("event", "recovery.outcome", f"kind={outcome}")
                guest(
                    "sometimes", "bounded-recovery-outcome",
                    "The response converged or declared bounded failure", "1",
                )
                guest("semantic-marker", "recovery.measured", "instance-1")
                if failover_sequence is not None:
                    guest("event", "network.route", "path=a-c-east", f"sequence={failover_sequence}")
                    guest("semantic-marker", "network.failover.observed", "instance-1")
                announce("followup-ready")
            if window_requests == 240:
                guest("semantic-marker", "campaign.complete", "instance-1")

            time.sleep(0.1)


class ControlHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/transport-applied":
            self.send_error(404)
            return

        if not Path("/run/transport-applied").exists():
            self.send_error(425)
            return

        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        if self.path not in ("/converged", "/followup-ready"):
            self.send_error(404)
            return

        marker = self.path.removeprefix("/")
        Path(f"/run/{marker}").touch()
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format, *_arguments):
        pass


def run_control():
    HTTPServer(("10.77.0.2", 9090), ControlHandler).serve_forever()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: traffic.py west|control")
    if sys.argv[1] == "west":
        run_west()
    elif sys.argv[1] == "control":
        run_control()
    else:
        raise SystemExit(f"unknown traffic role: {sys.argv[1]}")
