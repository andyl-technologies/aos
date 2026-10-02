"""Exercise the actual Nginx format locally with controlled non-authority inputs."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


def run(nginx, format_file, root):
    root.mkdir(mode=0o700, exist_ok=False)
    directories = ("client", "proxy", "fastcgi", "uwsgi", "scgi")
    for name in directories:
        (root / name).mkdir(mode=0o700)
    raw_log = root / "protected-headers.jsonl"
    descriptor = os.open(raw_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    with socket.socket() as selected:
        selected.bind(("127.0.0.1", 0))
        port = selected.getsockname()[1]
    formatting = format_file.read_text()
    configuration = f"""pid {root}/nginx.pid;
error_log {root}/errors.log warn;
events {{ worker_connections 32; }}
http {{
client_body_temp_path {root}/client;
proxy_temp_path {root}/proxy;
fastcgi_temp_path {root}/fastcgi;
uwsgi_temp_path {root}/uwsgi;
scgi_temp_path {root}/scgi;
{formatting}
access_log {raw_log} controlled_headers;
server {{
listen 127.0.0.1:{port};
location / {{
default_type application/json;
add_header x-aos-storage-work-signature {'b' * 64};
return 200 '{{}}';
}}
}}
}}
"""
    path = root / "nginx.conf"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(configuration)
    arguments = [str(nginx), "-e", str(root / "bootstrap-errors.log"),
        "-p", str(root) + "/", "-c", str(path)]
    checked = subprocess.run(arguments + ["-t"], capture_output=True, check=False, timeout=20)
    (root / "validation.stdout").write_bytes(checked.stdout)
    (root / "validation.stderr").write_bytes(checked.stderr)
    if checked.returncode:
        raise RuntimeError("controlled Nginx configuration refused; diagnostics retained")
    with (root / "process.log").open("xb") as log:
        process = subprocess.Popen(arguments + ["-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            targets = [
                "/_internal/storage/external-copy/v1",
                "/v2/repo/manifests/latest?aos_hybrid_manifest_upload=" + "e" * 32,
                "/v2/token?access_token=controlled-private-query",
                "/v2/repo/blobs/uploads/fixture",
            ]
            for index, target in enumerate(targets):
                for _ in range(100):
                    try:
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        connection.connect()
                        break
                    except ConnectionRefusedError:
                        if process.poll() is not None:
                            raise RuntimeError("controlled Nginx process exited")
                        time.sleep(0.01)
                else:
                    raise RuntimeError("controlled Nginx did not listen")
                try:
                    connection.request("POST", target, b"{}", {
                        "x-aos-hybrid-ingress": "e30.controlledsignature",
                        "x-aos-hybrid-upload-phase": "authorize-final" if index == 3 else "",
                        "x-aos-storage-work-signature": "a" * 64,
                        "Authorization": "Bearer controlled-private-bearer",
                        "Cookie": "session=controlled-private-cookie",
                    })
                    response = connection.getresponse()
                    if response.status != 200 or response.read() != b"{}":
                        raise RuntimeError("controlled Nginx response differs")
                finally:
                    connection.close()
        finally:
            process.send_signal(signal.SIGQUIT)
            process.wait(timeout=10)
    raw = raw_log.read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    assert len(rows) == 4
    assert [row["query_class"] for row in rows] == ["absent", "retained", "unsupported", "absent"]
    assert rows[2]["path_and_query"] == rows[2]["ingress"] == ""
    assert rows[3]["phase"] == "authorize-final"
    assert raw_log.stat().st_mode & 0o777 == 0o600
    for secret in (b"controlled-private-bearer", b"controlled-private-cookie", b"controlled-private-query"):
        assert secret not in raw
    receipt = {"version": 1, "cases": len(rows), "exitCode": process.returncode,
        "configurationSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "formatSha256": hashlib.sha256(format_file.read_bytes()).hexdigest(),
        "nginxSha256": hashlib.sha256(nginx.read_bytes()).hexdigest(),
        "privateLogSha256": hashlib.sha256(raw).hexdigest(),
        "privateLogByteSize": len(raw), "logMode": "0600",
        "scope": "actual local Nginx capture format; controlled headers, no MAC, SQL, provider or VM acceptance"}
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx-bin", type=Path, required=True)
    parser.add_argument("--format-file", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.nginx_bin, args.format_file, args.output_root.resolve())))
