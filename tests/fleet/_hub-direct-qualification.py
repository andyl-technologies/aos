"""Retain actual protected prequalification dispatches on the Worker operator.

The existing source-built Node driver signs controls, streams real provider
uploads and observes genuine queue jobs. This wrapper supplies private fixture
files and retains its original evidence. It does not sign acceptance or settle
unknown effects, and its isolated jobs do not prove the final registry workload.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import textwrap


def prepare_direct_qualification_bulk(worker, python, directory):
    """Create three distinct disk-backed 2 GiB originals on Worker."""
    originals = json.loads(private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'QUALIFICATION_BULK_ORIGINALS'
        import hashlib, json, os
        from pathlib import Path

        root = Path({directory!r})
        if not root.is_absolute():
            raise ValueError('bulk originals require an absolute private directory')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        originals = []
        for number in range(3):
            path = root / ('bulk-' + str(number) + '.bin')
            block = bytes([number + 1]) * 1048576
            digest = hashlib.sha256()
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                for _ in range(2048):
                    output.write(block)
                    digest.update(block)
                output.flush()
                os.fsync(output.fileno())
            originals.append({{'file': str(path), 'metadata': False,
                'byte_size': path.stat().st_size, 'sha256': digest.hexdigest()}})
        print(json.dumps(originals))
        QUALIFICATION_BULK_ORIGINALS
    """), timeout=600))
    if (
        len(originals) != 3 or len({item["sha256"] for item in originals}) != 3
        or any(item["metadata"] is not False or item["byte_size"] != 2147483648
               or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
               for item in originals)
    ):
        raise ValueError("actual bulk originals differ from the selected qualification size")
    return originals


def retain_direct_qualification_files(worker, python, guest_directory, run_id, retention_label=None):
    """Copy the driver's committed observation files into private host custody."""
    if retention_label is not None and not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", retention_label):
        raise ValueError("qualification retention label is invalid")
    def read_guest_file(name, maximum):
        return private_guest_command(worker, textwrap.dedent(f"""
            {shlex.quote(python)} - <<'RETAIN_QUALIFICATION_FILE'
            import os, stat, sys
            from pathlib import Path

            path = Path({guest_directory!r}) / {name!r}
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() \\
                        or before.st_mode & 0o077 or before.st_size > {maximum}:
                    raise ValueError('qualification file custody or size refused')
                body = source.read({maximum + 1})
                after = os.fstat(source.fileno())
            if len(body) != before.st_size or any(getattr(before, field) != getattr(after, field)
                    for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                raise ValueError('qualification file changed during retention')
            sys.stdout.buffer.write(body)
            RETAIN_QUALIFICATION_FILE
        """), timeout=60).encode()

    inventory_body = private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'OBSERVE_QUALIFICATION_FILES'
        import hashlib, json, os, re, stat
        from pathlib import Path

        root = Path({guest_directory!r})
        files = []
        if root.exists():
            if not root.is_dir() or root.is_symlink():
                raise ValueError('qualification evidence directory refused')
            for path in sorted(root.iterdir()):
                if len(files) >= 50000 or not re.fullmatch(r'[a-z0-9][a-z0-9-]{{0,127}}\\.json', path.name):
                    raise ValueError('qualification evidence inventory exceeds bounds')
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as source:
                    metadata = os.fstat(source.fileno())
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() \\
                            or metadata.st_mode & 0o077 or metadata.st_size > 4194304:
                        raise ValueError('qualification evidence custody refused')
                    body = source.read(4194305)
                if len(body) != metadata.st_size:
                    raise ValueError('qualification evidence changed during inventory')
                files.append({{'name': path.name, 'sha256': hashlib.sha256(body).hexdigest()}})
        print(json.dumps({{'version': 1, 'runId': {run_id!r}, 'files': files,
            'scope': 'post-process filesystem observation; not a driver completion claim'}}))
        OBSERVE_QUALIFICATION_FILES
    """), timeout=60).encode()
    inventory = json.loads(inventory_body)
    manifest_present = any(item["name"] == "file-manifest.json" for item in inventory["files"])
    manifest_body = read_guest_file("file-manifest.json", 4 * 1024 * 1024) if manifest_present else None
    manifest = json.loads(manifest_body) if manifest_body is not None else inventory
    if (
        set(manifest) != ({"version", "runId", "files"} if manifest_present
                          else {"version", "runId", "files", "scope"})
        or manifest["version"] != 1
        or manifest["runId"] != run_id or not isinstance(manifest["files"], list)
        or not 0 <= len(manifest["files"]) <= 50000
    ):
        raise ValueError("actual qualification manifest differs from its original run")
    directory_name = run_id if retention_label is None else run_id + "-" + retention_label
    root = Path("external-direct-prequalification") / directory_name
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    names = set()
    retained = []
    for item in inventory["files"]:
        if item["name"] == "file-manifest.json":
            continue
        if (
            set(item) != {"name", "sha256"}
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}\.json", item["name"])
            or item["name"] in names
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
        ):
            raise ValueError("qualification manifest contains an invalid file original")
        names.add(item["name"])
        body = read_guest_file(item["name"], 4 * 1024 * 1024)
        if hashlib.sha256(body).hexdigest() != item["sha256"]:
            raise ValueError("retained qualification observation differs from the driver original")
        descriptor = os.open(root / item["name"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        retained.append({**item, "byteSize": len(body)})
    if manifest_present and any(item not in inventory["files"] for item in manifest["files"]):
        raise ValueError("driver's committed files differ from the post-process inventory")
    for name, body in (("observed-file-inventory.json", inventory_body),
                       ("file-manifest.json", manifest_body)):
        if body is None:
            continue
        descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    return {"directory": str(root), "driverManifestPresent": manifest_present,
            "manifestSha256": hashlib.sha256(manifest_body).hexdigest() if manifest_present else None,
            "observedInventorySha256": hashlib.sha256(inventory_body).hexdigest(),
            "files": retained}


def observe_direct_prequalification_phase(worker, tools, origin, control_key_file,
                                         identity_file, run_id, phase, label,
                                         wait_seconds=0):
    """Inspect or requeue the exact original into a new evidence directory.

    The source-built driver authenticates every selected control and retains its
    request/reply commitments. Requeue selects only positively closed unverified
    immutable sources; it does not repeat Create, Close or provider mutation.
    Earlier evidence remains in its original directory.
    """
    if phase not in {"status", "requeue"} or not re.fullmatch(r"[0-9a-f]{64}", run_id):
        raise ValueError("qualification recovery requires its exact retained original")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label):
        raise ValueError("qualification recovery evidence label is invalid")
    if type(wait_seconds) is not int or not 0 <= wait_seconds <= 3600:
        raise ValueError("qualification recovery wait exceeds the driver bound")
    root = "/var/lib/hybrid-worker/operator/prequalification-" + run_id + "-" + label
    arguments = [tools["node"], tools["qualificationDriver"], "--origin", origin,
        "--control-key-file", control_key_file, "--identity-file", identity_file,
        "--output-dir", root + "/evidence", "--run-id", run_id,
        "--phase", phase, "--wait-seconds", str(wait_seconds)]
    receipt = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path(selected['root'])
        root.mkdir(mode=0o700, exist_ok=False)
        environment = dict(os.environ)
        environment['NODE_EXTRA_CA_CERTS'] = '/etc/ssl/certs/ca-certificates.crt'
        os.umask(0o077)
        started = time.time_ns()
        with (root / 'stdout.log').open('xb') as stdout, (root / 'stderr.log').open('xb') as stderr:
            try:
                result = subprocess.run(selected['arguments'], env=environment,
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                    check=False, timeout=selected['waitSeconds'] + 300)
                exit_code, timed_out = result.returncode, False
            except subprocess.TimeoutExpired:
                exit_code, timed_out = None, True
        print(json.dumps({'version': 1, 'runId': selected['runId'], 'phase': selected['phase'],
            'exitCode': exit_code, 'timedOut': timed_out, 'guestDirectory': str(root),
            'startedUnixNs': str(started), 'finishedUnixNs': str(time.time_ns()),
            'driverSha256': hashlib.sha256(Path(selected['driver']).read_bytes()).hexdigest(),
            'stdoutSha256': hashlib.sha256((root / 'stdout.log').read_bytes()).hexdigest(),
            'stderrSha256': hashlib.sha256((root / 'stderr.log').read_bytes()).hexdigest(),
            'scope': 'same retained qualification original; new invocation evidence; no fresh provider mutation'}))
    """, {"root": root, "arguments": arguments, "driver": tools["qualificationDriver"],
            "runId": run_id, "phase": phase, "waitSeconds": wait_seconds},
        timeout=wait_seconds + 360))
    retained = retain_direct_qualification_files(worker, tools["python"], root + "/evidence", run_id, label)
    report = {"version": 1, "process": receipt, "retained": retained}
    path = Path(retained["directory"]) / "fleet-invocation.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(report, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    if receipt["exitCode"] != 0:
        raise RuntimeError("qualification recovery invocation failed; exact original evidence retained")
    statuses = []
    for item in retained["files"]:
        if not item["name"].endswith("-status-capture.json"):
            continue
        captured = _closed_review_json((Path(retained["directory"]) / item["name"]).read_bytes())
        result = captured["result"]
        if (result["original"]["runId"] != run_id
                or result["inspectionOnly"] is not False):
            raise ValueError("recovery inspection does not describe this installed original source")
        statuses.append({"replySha256": item["sha256"], "objects": result["objects"]})
    if not statuses:
        raise ValueError("authenticated original status was not retained by the recovery driver")
    report["authenticatedStatuses"] = statuses
    return report


def run_direct_prequalification(worker, python, node, driver_file, origin,
                                control_key_file, identity_file, selector,
                                bulk_originals, metadata_originals, wait_seconds=600):
    """Dispatch one fresh protected run and preserve terminal or incomplete facts."""
    if len(bulk_originals) != 3 or len(metadata_originals) != 4:
        raise ValueError("prequalification requires three bulk and four metadata originals")
    if type(wait_seconds) is not int or not 1 <= wait_seconds <= 3600:
        raise ValueError("qualification wait exceeds the existing driver's bound")
    originals = [*bulk_originals, *metadata_originals]
    if any(not isinstance(item["file"], str) or not item["file"].startswith("/")
           for item in originals):
        raise ValueError("qualification sources require explicit Worker file paths")
    run_id = os.urandom(32).hex()
    root = "/var/lib/hybrid-worker/operator/prequalification-" + run_id
    manifest = {"provider": {"kind": "external", "selector": selector},
                "objects": [{"file": item["file"], "metadata": item["metadata"]}
                            for item in originals]}
    encoded = base64.b64encode(json.dumps(manifest, separators=(",", ":")).encode()).decode()
    arguments = [node, driver_file, "--origin", origin, "--control-key-file", control_key_file,
                 "--identity-file", identity_file, "--manifest-file", root + "/manifest.json",
                 "--output-dir", root + "/evidence", "--run-id", run_id,
                 "--wait-seconds", str(wait_seconds)]
    receipt = json.loads(private_guest_command(worker, textwrap.dedent(f"""
        {shlex.quote(python)} - <<'ACTUAL_PROTECTED_QUALIFICATION'
        import base64, hashlib, json, os, subprocess
        from pathlib import Path

        root = Path({root!r})
        root.mkdir(mode=0o700, exist_ok=False)
        descriptor = os.open(root / 'manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(base64.b64decode({encoded!r}, validate=True))
            output.flush()
            os.fsync(output.fileno())
        environment = dict(os.environ)
        environment['NODE_EXTRA_CA_CERTS'] = '/etc/ssl/certs/ca-certificates.crt'
        os.umask(0o077)
        timed_out = False
        with (root / 'stdout.log').open('xb') as stdout, (root / 'stderr.log').open('xb') as stderr:
            try:
                result = subprocess.run({arguments!r}, env=environment, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, check=False, timeout={wait_seconds + 1500})
                exit_code = result.returncode
            except subprocess.TimeoutExpired:
                # subprocess.run kills only its child and waits. Pending original
                # intents remain unknown; no provider mutation is repeated.
                timed_out = True
                exit_code = None
        print(json.dumps({{'version': 1, 'runId': {run_id!r}, 'exitCode': exit_code,
            'timedOut': timed_out,
            'machineRole': 'worker_operator', 'guestDirectory': str(root),
            'driverSha256': hashlib.sha256(Path({driver_file!r}).read_bytes()).hexdigest(),
            'scope': 'isolated actual provider/queue prequalification; no acceptance'}}))
        ACTUAL_PROTECTED_QUALIFICATION
    """), timeout=wait_seconds + 1800))
    if receipt["runId"] != run_id or (
        type(receipt["exitCode"]) is not int
        and not (receipt["timedOut"] is True and receipt["exitCode"] is None)
    ):
        raise ValueError("qualification process receipt differs from its original")
    retained = retain_direct_qualification_files(worker, python, root + "/evidence", run_id)
    result = {"process": receipt, "retained": retained, "sourceOriginals": originals}
    descriptor = os.open(Path(retained["directory"]) / "fleet-invocation.json",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(result, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    if receipt["exitCode"] != 0:
        raise RuntimeError("actual protected prequalification failed; originals and evidence retained")
    return result
