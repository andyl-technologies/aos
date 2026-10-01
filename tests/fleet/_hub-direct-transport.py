"""Observe bounded TLS responses from installed fixture services during startup.

An unsigned private-route refusal proves transport startup. The retained status,
headers and body do not establish a provider profile or authority admission.
"""

import hashlib
import json
from pathlib import Path
import shlex
import time


def wait_worker_transport(worker, curl, python, external_direct, timeout=180,
                          observation_label="worker"):
    """Retain each actual startup response and require the route's refusal."""
    route, expected = (
        ("credential-custody", "409") if external_direct else ("capabilities", "401")
    )
    return wait_fixture_tls_response(
        worker, curl, python,
        "https://aos.andyl.org/_internal/storage/v1/" + route,
        "POST", {expected}, observation_label, timeout,
    )


def wait_provider_transport(machine, curl, python, observation_label, timeout=180):
    """Observe the provider's unsigned TLS API response before privacy testing."""
    return wait_fixture_tls_response(
        machine, curl, python, "https://s3.fleet.test/fleet-s3/absent",
        "GET", {"403", "404", "409"}, observation_label, timeout,
    )


def wait_fixture_tls_response(machine, curl, python, url, method, expected_statuses,
                              observation_label, timeout):
    """Retain actual bounded transport results without inferring provider privacy."""
    if not observation_label or not all(character.isalnum() or character == "-"
                                        for character in observation_label):
        raise ValueError("invalid transport observation label")
    observations = Path(observation_label + "-transport-observations")
    observations.mkdir(mode=0o700)
    deadline = time.monotonic() + timeout
    attempt = 0

    while time.monotonic() < deadline:
        attempt += 1
        arguments = shlex.split(curl) + [
            "-sS", "--max-time", "10", "--max-filesize", "65536",
            "-X", method, "-D", "/tmp/fleet-startup-headers",
            "-o", "/tmp/fleet-startup-body", "-w", "%{http_code}", url,
        ]
        command = (
            f"{shlex.quote(python)} - <<'WORKER_TRANSPORT'\n"
            "import base64,json,subprocess\nfrom pathlib import Path\n"
            "headers=Path('/tmp/fleet-startup-headers')\n"
            "body=Path('/tmp/fleet-startup-body')\n"
            "headers.unlink(missing_ok=True);body.unlink(missing_ok=True)\n"
            f"result=subprocess.run({arguments!r},capture_output=True,text=True,timeout=15)\n"
            "header_bytes=headers.read_bytes() if headers.exists() else b''\n"
            "body_bytes=body.read_bytes() if body.exists() else b''\n"
            "assert len(header_bytes)<=16384 and len(body_bytes)<=65536\n"
            "print(json.dumps({'curl_exit':result.returncode,'http_status':result.stdout,"
            "'stderr':result.stderr,'headers_base64':base64.b64encode(header_bytes).decode(),"
            "'body_base64':base64.b64encode(body_bytes).decode()}))\n"
            "WORKER_TRANSPORT\n"
        )
        status, stdout, _ = machine.agent.request(command.encode(), timeout=20)
        if status != 0:
            raise RuntimeError("fixture startup observation command failed")
        value = json.loads(stdout)
        value.update({
            "version": 1, "attempt": attempt, "url": url, "method": method,
            "scope": "actual unsigned TLS response; transport startup only",
        })
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        path = observations / f"attempt-{attempt:04d}.json"
        path.write_bytes(body)
        path.chmod(0o600)

        if value["curl_exit"] == 0 and value["http_status"] in expected_statuses:
            print("Fixture TLS startup response:", observation_label,
                  value["http_status"], hashlib.sha256(body).hexdigest())
            return value
        time.sleep(1)

    raise RuntimeError("fixture TLS startup response unavailable; actual observations retained")
