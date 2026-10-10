# Production CLI selection over a closed Connect-JSON fixture. This verifies
# the transport and pinned request, independently of service IAM qualification.

import base64
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

root = Path(sys.argv[1])
binary = Path(sys.argv[2])
calls = []
scenario = "complete"
profiles = ["license-signals", "updates", "vulnerabilities"]


def digest(domain, value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(domain.encode() + bytes([0]) + encoded).hexdigest()


def status(position):
    subject = "a" if position is None else "b"
    page = {
        "schema": "aos.assessment-status/v1",
        "resourceScope": "fixture-registry-incarnation",
        "inventoryDigest": "sha256:" + "a" * 64,
        "inventoryRevision": 7,
        "policyDigest": "sha256:" + "b" * 64,
        "asOf": "2026-10-10T00:00:00Z",
        "subjects": [{
            "subjectRef": subject, "packageCoordinate": "fixture/example",
            "version": "1.2.0", "platform": "x86_64-linux", "output": "out",
            "profiles": [{
                "profile": profile, "desiredGeneration": 0, "committedGeneration": 0,
                "fresh": False, "pending": False,
            } for profile in profiles],
        }],
    }
    if position is None:
        page["nextSubject"] = subject
    elif scenario == "changed-inventory":
        page["inventoryRevision"] += 1
    elif scenario == "repeated-page":
        page["subjects"][0]["subjectRef"] = "a"
    elif scenario == "missing-profile":
        page["subjects"][0]["profiles"].pop()
    if scenario.startswith("source-"):
        availability = {
            "state": "waiting", "retryAt": "2026-10-10T00:03:20Z",
            "cause": "spacing-or-cooldown",
        }
        if scenario == "source-extra-field":
            availability = {"state": "eligible", "account": "private-account"}
        elif scenario == "source-expired-retry":
            availability["retryAt"] = page["asOf"]
        page["sourceStatus"] = [{"provider": "osv", "availability": availability}]
    return page


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        assert self.headers["Authorization"] == "Bearer public-fixture-token"
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert request["registrySlug"] == "fixture"
        field = "queryJson" if self.path.endswith("/GetStatus") else "documentJson"
        assert set(request) == {"registrySlug", field}, request
        document = json.loads(base64.b64decode(request[field]))
        calls.append((self.path, document))
        if self.path == "/aos.hub.v1.AssessmentService/ListEvents":
            assert document == {
                "schema": "aos.assessment-event-query/v1", "limit": 10,
                "afterSequence": 0,
            }, document
            failure = {
                "scanId": "fixture-durable-scan", "provider": "osv",
                "operationDigest": "sha256:" + "c" * 64,
                "planDigest": "sha256:" + "d" * 64, "attempt": 1,
                "receiptDigest": "sha256:" + "e" * 64,
                "code": "rate-limited", "status": 429,
                "retryAt": "2026-10-10T00:02:00Z",
            }
            if scenario == "source-event-private-field":
                failure["requestUrl"] = "https://example.org/private"
            elif scenario == "source-event-invalid-status":
                failure["status"] = 200
            response = {
                "schema": "aos.assessment-event-page/v1",
                "resourceScope": "fixture-registry-incarnation",
                "asOf": "2026-10-10T00:00:00Z", "nextSequence": 1,
                "events": [{
                    "schema": "aos.assessment-event/v1", "eventId": "fixture-source-failure",
                    "sequence": "1", "occurredAt": "2026-10-10T00:00:00Z",
                    "payload": {"kind": "source-failed", "failure": failure},
                }],
            }
        elif self.path == "/aos.hub.v1.AssessmentService/GetStatus":
            assert document["profiles"] == profiles
            assert document["limit"] == 100
            position = document.get("afterSubject")
            if position is not None:
                assert position == "a"
                assert document["inventoryDigest"] == "sha256:" + "a" * 64
                assert document["policyDigest"] == "sha256:" + "b" * 64
            response = status(position)
        else:
            assert self.path == "/aos.hub.v1.ScanService/RequestScan"
            assert document["subjects"] == ["a", "b"]
            assert document["profiles"] == profiles
            assert document["inventoryRevision"] == 7
            assert document["freshness"] == "offline"
            assert document["idempotencyKey"] == "fixture-selection"
            admitted = copy.deepcopy(document)
            admitted.update({
                "schema": "aos.scan-request/v1", "resourceScope": "fixture-registry-incarnation",
                "authorizationPartition": "fixture-authorization-partition",
                "actorRef": "fixture-authenticated-actor", "trigger": "manual",
            })
            if scenario == "changed-receipt":
                admitted["subjects"] = ["a"]
            response = {
                "schema": "aos.assessment-scan-receipt/v1", "scanId": "fixture-durable-scan",
                "request": admitted, "requestDigest": digest("aos.scan-request/v1", admitted),
                "generation": 1, "state": "queued", "admissionComplete": True,
                "usage": {"providerRequests": 0, "tasks": 0, "normalizedBytes": 0},
                "createdAt": "2026-10-10T00:00:00Z", "resourceVersion": 1,
            }
        encoded = json.dumps({
            "documentJson": base64.b64encode(json.dumps(response).encode()).decode(),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix="aos-assessment-selection-cli-") as directory:
        environment = os.environ.copy()
        environment.update({
            "XDG_CONFIG_HOME": str(Path(directory) / "config"),
            "XDG_STATE_HOME": str(Path(directory) / "state"), "AOS_ROOT": str(root),
        })

        def run(package="fixture/example", okay=True):
            result = subprocess.run([
                str(binary), "--json", "hub", "maintain", "scan", "--registry", "fixture",
                "--hub", f"http://127.0.0.1:{server.server_port}", "--token", "public-fixture-token",
                "--profile", "all,updates", "--package", package, "--freshness", "offline",
                "--idempotency-key", "fixture-selection",
            ], cwd=root, env=environment, capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == okay, (result.stdout, result.stderr)
            if okay:
                response = json.loads(result.stdout)
                assert response["data"]["request"]["subjects"] == ["a", "b"], response

        run()
        assert len(calls) == 3
        calls.clear()
        run("fixture/absent", okay=False)
        assert len(calls) == 2 and all(path.endswith("/GetStatus") for path, _ in calls)
        for scenario in ["changed-inventory", "repeated-page", "missing-profile"]:
            calls.clear()
            run(okay=False)
            assert len(calls) == 2 and all(path.endswith("/GetStatus") for path, _ in calls)
        scenario = "changed-receipt"
        calls.clear()
        run(okay=False)
        assert len(calls) == 3

        def run_status(as_json=True, okay=True):
            result = subprocess.run([
                str(binary), *(["--json"] if as_json else []),
                "hub", "maintain", "status", "--registry", "fixture", "--profile", "all",
                "--hub", f"http://127.0.0.1:{server.server_port}", "--token", "public-fixture-token",
            ], cwd=root, env=environment, capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == okay, (result.stdout, result.stderr)
            if okay and as_json:
                assert json.loads(result.stdout)["data"]["sourceStatus"][0]["availability"]["cause"] == "spacing-or-cooldown"
            elif okay:
                human = result.stdout + result.stderr
                assert "osv: Waiting until" in human and "provider spacing or cooldown" in human, (result.stdout, result.stderr)

        scenario = "source-status"
        run_status()
        run_status(as_json=False)
        for scenario in ["source-extra-field", "source-expired-retry"]:
            calls.clear()
            run_status(okay=False)
            assert len(calls) == 1 and calls[0][0].endswith("/GetStatus")

        def run_events(as_json=True, okay=True):
            result = subprocess.run([
                str(binary), *(["--json"] if as_json else []),
                "hub", "maintain", "events", "--registry", "fixture",
                "--hub", f"http://127.0.0.1:{server.server_port}", "--token", "public-fixture-token",
            ], cwd=root, env=environment, capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == okay, (result.stdout, result.stderr)
            if okay:
                if as_json:
                    failure = json.loads(result.stdout)["data"]["events"][0]["payload"]["failure"]
                    assert failure["code"] == "rate-limited" and failure["status"] == 429
                else:
                    assert "source-failed" in result.stdout + result.stderr
                assert "requestUrl" not in result.stdout + result.stderr

        scenario = "source-event"
        calls.clear()
        run_events()
        run_events(as_json=False)
        assert len(calls) == 2 and all(path.endswith("/ListEvents") for path, _ in calls)
        for scenario in ["source-event-private-field", "source-event-invalid-status"]:
            calls.clear()
            run_events(okay=False)
            assert len(calls) == 1 and calls[0][0].endswith("/ListEvents")
        print("PASS: actual CLI pinned selection, bounded pages and changed receipt refusal")
        print("PASS: actual CLI scoped source status and malformed availability refusal")
        print("PASS: actual CLI source failure events and malformed fact refusal")
finally:
    server.shutdown()
    server.server_close()
