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
        if self.path == "/aos.hub.v1.AssessmentService/GetStatus":
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
        print("PASS: actual CLI pinned selection, bounded pages and changed receipt refusal")
finally:
    server.shutdown()
    server.server_close()
