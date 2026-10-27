"""Compares fresh native Hub state and authenticated HTTP behavior."""

import base64
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlencode


def request(port, method, path, body=None, headers=None):
    """Returns one bounded local HTTP response without following redirects."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        headers = {name.lower(): value for name, value in response.getheaders()}
        return response.status, headers, response.read()
    finally:
        connection.close()


def command(binary, root, arguments, environment, password=None):
    """Runs a native maintenance command against a private fresh instance."""
    result = subprocess.run(
        [str(binary), "--root", str(root), *arguments],
        input=password, capture_output=True, timeout=30, env=environment,
    )
    if result.returncode:
        raise ValueError(f"native Hub {arguments} failed: {result.stderr[-2000:]!r}")


def instance(binary, directory):
    """Exercises initialization, recovery, HTTP authentication and restart."""
    root = directory / "state"
    credentials = directory / "credentials"
    credentials.mkdir(mode=0o700)
    values = {
        "HUB_JWT_SECRET_FILE": "native-hub-bazel-conversion-jwt-secret-v1",
        "HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE": "[]",
        "HUB_ROUTE_RESERVATION_KEYS_FILE": json.dumps({
            "activeVersion": 1,
            "keys": [{"version": 1, "keyBase64": base64.b64encode(bytes(32)).decode()}],
        }),
        "HUB_SECRET_VERSION_MANIFEST_FILE": "{}",
    }
    environment = {"HOME": str(directory), "PATH": os.environ.get("PATH", ""), "TZ": "UTC"}
    # Keep the production URL policy enabled. This unseeded lifecycle issues no
    # domain probes; its Nix sandbox provides no external network access.
    environment["HUB_DNS_JSON_ENDPOINT"] = "https://8.8.8.8/resolve"
    for name, value in values.items():
        path = credentials / name
        path.write_text(value)
        path.chmod(0o600)
        environment[name] = str(path)

    email = "operator@example.test"
    command(binary, root, ["init", "--root-email", email, "--root-password-stdin"],
            environment, b"initial-password\n")
    if not (root / "hub.db").is_file() or (root / "seeded").exists():
        raise ValueError("native Hub did not initialize an unseeded database")
    command(binary, root, ["index"], environment)
    command(binary, root, ["reset-root", "--email", email, "--password-stdin"],
            environment, b"recovered-password\n")

    records = {"fresh_unseeded_database": True, "offline_index": True, "credential_reset": True}
    cookie = None
    for restart in range(2):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        with (directory / f"server-{restart}.log").open("wb") as log:
            process = subprocess.Popen(
                [str(binary), "--root", str(root), "serve", "--listen", f"127.0.0.1:{port}",
                 "--external-url", f"http://127.0.0.1:{port}", "--reindex-interval", "0"],
                env=environment, stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        raise ValueError("native Hub exited before becoming ready")
                    try:
                        status, _, body = request(port, "GET", "/healthz")
                        if status == 200 and body == b"ok (0 registries)\n":
                            break
                    except (OSError, http.client.HTTPException):
                        pass
                    if time.monotonic() >= deadline:
                        raise ValueError("native Hub did not become healthy within 30 seconds")
                    time.sleep(0.1)

                records["healthy_after_restart" if restart else "healthy_initial_server"] = True
                if restart == 0:
                    form_headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    status, headers, body = request(
                        port, "POST", "/login/password",
                        urlencode({"email": email, "password": "initial-password"}), form_headers,
                    )
                    if status != 200 or "set-cookie" in headers or b"Invalid email or password" not in body:
                        raise ValueError("native Hub accepted the credential replaced by reset-root")
                    status, headers, _ = request(
                        port, "POST", "/login/password",
                        urlencode({"email": email, "password": "recovered-password"}), form_headers,
                    )
                    cookies = SimpleCookie()
                    cookies.load(headers.get("set-cookie", ""))
                    if status != 303 or len(cookies) != 1:
                        raise ValueError("native Hub omitted the authenticated session redirect")
                    cookie = "; ".join(f"{name}={value.value}" for name, value in cookies.items())
                    records["old_password_rejected"] = True
                    records["recovered_password_authenticated"] = True

                status, _, page = request(port, "GET", "/-/instance", headers={"Cookie": cookie})
                if status != 200 or not re.search(rb'name="aos-session-csrf" content="[^"]+"', page):
                    raise ValueError("native Hub omitted authenticated instance access or its CSRF token")
                records["session_persists_after_restart" if restart else "authenticated_instance_page"] = True
            except Exception as error:
                log.flush()
                details = (directory / f"server-{restart}.log").read_bytes()[-4000:]
                raise ValueError(f"native Hub runtime check failed; server log: {details!r}") from error
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    return records


def qualify(packages):
    """Requires both installed drivers to preserve fresh native server behavior."""
    if set(packages) != {"ordinary", "bazel"}:
        raise ValueError("native Hub runtime comparison requires both package roots")
    records = {}
    for driver, outputs in packages.items():
        with tempfile.TemporaryDirectory(prefix="hub-bazel-native-runtime-") as temporary:
            records[driver] = instance(Path(outputs["out"]) / "bin/aos-hub", Path(temporary))
    if records["ordinary"] != records["bazel"]:
        raise ValueError("installed native Hub runtime behavior differs")
    return records
