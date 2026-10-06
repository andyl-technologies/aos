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
import stat
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


def qualification_retention_directory(run_id, retention_label=None):
    """Select only the existing private host directory for this exact original."""
    if (not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{64}", run_id) is None
            or retention_label is not None and (not isinstance(retention_label, str)
                or re.fullmatch(r"[a-z][a-z0-9-]{0,47}", retention_label) is None)):
        raise ValueError("qualification retention original or label differs")
    name = run_id if retention_label is None else run_id + "-" + retention_label
    return Path("external-direct-prequalification") / name


def retain_direct_qualification_process(receipt, retention_label=None):
    """Persist the actual child outcome before any potentially partial export."""
    root = qualification_retention_directory(receipt["runId"], retention_label)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    descriptor = os.open(root / "fleet-process.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(receipt, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    # The receipt and its directory entry must survive interrupted copying.
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return root


def retain_direct_qualification_output_report(directory, observation):
    """Make per-stream unknown outcomes durable before the larger JSON export."""
    descriptor = os.open(directory / "fleet-invocation-output.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(observation, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def qualification_guest_inventory(worker, python, guest_directory, run_id):
    """Observe all bounded JSON files through one stable private directory."""
    encoded = direct_guest_python(worker, python, r"""
        import hashlib, os, re, stat

        descriptor = os.open(selected['directory'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root = os.fstat(descriptor)
            if root.st_uid != os.geteuid() or stat.S_IMODE(root.st_mode) != 0o700:
                raise ValueError('qualification evidence directory custody refused')
            names = sorted(os.listdir(descriptor))
            if len(names) > 50000:
                raise ValueError('qualification evidence inventory exceeds bounds')
            files = []
            for name in names:
                if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,127}\.json', name) is None:
                    raise ValueError('qualification evidence filename refused')
                file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                with os.fdopen(file, 'rb') as source:
                    before = os.fstat(source.fileno())
                    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                            or before.st_size > 4194304):
                        raise ValueError('qualification evidence custody refused')
                    body = source.read(4194305)
                    after = os.fstat(source.fileno())
                path = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                if len(body) != before.st_size or any(getattr(before, field) != getattr(after, field)
                        or getattr(before, field) != getattr(path, field) for field in fields):
                    raise ValueError('qualification evidence changed during inventory')
                files.append({'name': name, 'sha256': hashlib.sha256(body).hexdigest(), 'byteSize': len(body)})
            after = os.fstat(descriptor)
            path = os.stat(selected['directory'], follow_symlinks=False)
            if (names != sorted(os.listdir(descriptor)) or (root.st_dev, root.st_ino) != (path.st_dev, path.st_ino)
                    or (root.st_mtime_ns, root.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError('qualification evidence directory changed during inventory')
            print(json.dumps({'version': 1, 'runId': selected['runId'], 'files': files,
                'rootIdentity': {'device': root.st_dev, 'inode': root.st_ino, 'ownerUid': root.st_uid},
                'scope': 'post-process filesystem observation; not a driver completion claim'}))
        finally:
            os.close(descriptor)
    """, {"directory": guest_directory, "runId": run_id}, timeout=60).encode()
    if len(encoded) > 14 * 1024 * 1024:
        raise ValueError("qualification inventory transport exceeds bound")
    inventory = json.loads(encoded)
    if (set(inventory) != {"version", "runId", "files", "rootIdentity", "scope"}
            or inventory["version"] != 1 or inventory["runId"] != run_id
            or not isinstance(inventory["files"], list) or len(inventory["files"]) > 50000
            or not isinstance(inventory["rootIdentity"], dict)
            or set(inventory["rootIdentity"]) != {"device", "inode", "ownerUid"}
            or any(type(value) is not int or value < 0 for value in inventory["rootIdentity"].values())):
        raise ValueError("qualification observed inventory differs")
    names = set()
    for item in inventory["files"]:
        if (not isinstance(item, dict) or set(item) != {"name", "sha256", "byteSize"}
                or not isinstance(item["name"], str)
                or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}\.json", item["name"]) is None
                or item["name"] in names or not isinstance(item["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
                or type(item["byteSize"]) is not int or not 0 <= item["byteSize"] <= 4194304):
            raise ValueError("qualification inventory contains an invalid file original")
        names.add(item["name"])
    return inventory, encoded


def qualification_file_batches(files):
    """Pack whole files within both transport and count ceilings."""
    batch = []
    size = 0
    for item in files:
        if batch and (len(batch) == 64 or size + item["byteSize"] > 8 * 1024 * 1024):
            yield batch
            batch, size = [], 0
        batch.append(item)
        size += item["byteSize"]
    if batch:
        yield batch


def qualification_read_batch(worker, python, guest_directory, inventory, files):
    """Export exact inventory-selected bytes with bounded private transport."""
    encoded = direct_guest_python(worker, python, r"""
        import base64, hashlib, os, re, stat

        files = selected['files']
        if (not isinstance(files, list) or not 1 <= len(files) <= 64
                or sum(item['byteSize'] for item in files) > 8388608):
            raise ValueError('qualification export batch exceeds bounds')
        descriptor = os.open(selected['directory'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root = os.fstat(descriptor)
            identity = {'device': root.st_dev, 'inode': root.st_ino, 'ownerUid': root.st_uid}
            if (identity != selected['rootIdentity'] or root.st_uid != os.geteuid()
                    or stat.S_IMODE(root.st_mode) != 0o700):
                raise ValueError('qualification export directory differs')
            exported = []
            names = set()
            for item in files:
                name = item['name']
                if (re.fullmatch(r'[a-z0-9][a-z0-9-]{0,127}\.json', name) is None
                        or name in names or not 0 <= item['byteSize'] <= 4194304):
                    raise ValueError('qualification export filename or bound refused')
                names.add(name)
                file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                with os.fdopen(file, 'rb') as source:
                    before = os.fstat(source.fileno())
                    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                            or before.st_size != item['byteSize']):
                        raise ValueError('qualification export custody or size refused')
                    body = source.read(4194305)
                    after = os.fstat(source.fileno())
                path = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                if (len(body) != item['byteSize'] or hashlib.sha256(body).hexdigest() != item['sha256']
                        or any(getattr(before, field) != getattr(after, field)
                            or getattr(before, field) != getattr(path, field) for field in fields)):
                    raise ValueError('qualification export differs from observed original')
                exported.append({**item, 'body': base64.b64encode(body).decode()})
            path = os.stat(selected['directory'], follow_symlinks=False)
            if (root.st_dev, root.st_ino) != (path.st_dev, path.st_ino):
                raise ValueError('qualification export directory changed')
            body = json.dumps({'files': exported})
            if len(body.encode()) > 12582912:
                raise ValueError('qualification export transport exceeds bound')
            print(body)
        finally:
            os.close(descriptor)
    """, {"directory": guest_directory, "rootIdentity": inventory["rootIdentity"], "files": files}, timeout=60)
    if len(encoded.encode()) > 12 * 1024 * 1024:
        raise ValueError("qualification export transport exceeds bound")
    result = json.loads(encoded)
    if set(result) != {"files"} or not isinstance(result["files"], list) or len(result["files"]) != len(files):
        raise ValueError("qualification exported batch shape differs")
    retained = []
    size = 0
    for expected, actual in zip(files, result["files"]):
        if (set(actual) != {"name", "sha256", "byteSize", "body"}
                or {key: actual[key] for key in expected} != expected):
            raise ValueError("qualification export selection differs")
        body = base64.b64decode(actual["body"], validate=True)
        size += len(body)
        if (len(body) != expected["byteSize"] or hashlib.sha256(body).hexdigest() != expected["sha256"]
                or size > 8 * 1024 * 1024):
            raise ValueError("qualification exported bytes differ")
        retained.append((expected, body))
    return retained


def retain_direct_qualification_files(worker, python, guest_directory, run_id, retention_label=None, *,
                                      host_directory=None):
    """Retain every observation in bounded batches without claiming completion."""
    root = qualification_retention_directory(run_id, retention_label)
    if host_directory is None:
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
    elif Path(host_directory) != root:
        raise ValueError("qualification host directory differs from its exact original")
    custody = root.lstat()
    if (not stat.S_ISDIR(custody.st_mode) or custody.st_uid != os.geteuid()
            or stat.S_IMODE(custody.st_mode) != 0o700):
        raise ValueError("qualification host directory custody refused")
    inventory, inventory_body = qualification_guest_inventory(worker, python, guest_directory, run_id)
    manifest_item = next((item for item in inventory["files"] if item["name"] == "file-manifest.json"), None)
    manifest_body = None
    selected = [item for item in inventory["files"] if item["name"] != "file-manifest.json"]
    if manifest_item is not None:
        manifest_body = qualification_read_batch(worker, python, guest_directory, inventory, [manifest_item])[0][1]
        manifest = json.loads(manifest_body)
        if (not isinstance(manifest, dict) or set(manifest) != {"version", "runId", "files"}
                or manifest["version"] != 1 or manifest["runId"] != run_id
                or not isinstance(manifest["files"], list) or len(manifest["files"]) != len(selected)):
            raise ValueError("driver committed manifest differs from its original")
        committed = {}
        for item in manifest["files"]:
            if (not isinstance(item, dict) or set(item) != {"name", "sha256"}
                    or not isinstance(item["name"], str) or item["name"] in committed
                    or not isinstance(item["sha256"], str)):
                raise ValueError("driver manifest contains an invalid file original")
            committed[item["name"]] = item["sha256"]
        if committed != {item["name"]: item["sha256"] for item in selected}:
            raise ValueError("driver committed files differ from the complete observed inventory")
    descriptor = os.open(root / "observed-file-inventory.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(inventory_body)
        output.flush()
        os.fsync(output.fileno())

    retained = []
    for batch in qualification_file_batches(selected):
        for item, body in qualification_read_batch(worker, python, guest_directory, inventory, batch):
            descriptor = os.open(root / item["name"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            retained.append(item)
    final_inventory, _ = qualification_guest_inventory(worker, python, guest_directory, run_id)
    if final_inventory != inventory:
        raise ValueError("qualification observed inventory changed during export")
    for name, body in (("file-manifest.json", manifest_body),):
        if body is None:
            continue
        descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    return {"directory": str(root), "driverManifestPresent": manifest_item is not None,
        "manifestSha256": hashlib.sha256(manifest_body).hexdigest() if manifest_item else None,
        "observedInventorySha256": hashlib.sha256(inventory_body).hexdigest(), "files": retained}


def retain_direct_qualification_output(worker, python, guest_directory, host_directory, receipt, *,
                                       operator_root="/var/lib/hybrid-worker/operator", retention_label=None):
    """Retain only this invocation's bounded output without printing child errors.

    Each file has its own explicit outcome: a failed or oversized stderr copy
    cannot erase retained stdout or turn an unsuccessful invocation into success.
    """
    if (operator_root != "/var/lib/hybrid-worker/operator" and re.fullmatch(
            r"/var/lib/hybrid-worker/external-oci/[0-9a-f]{32}/operator", operator_root) is None):
        raise ValueError("qualification output operator directory differs")
    qualification_retention_directory(receipt["runId"], retention_label)
    expected_directory = operator_root + "/prequalification-" + receipt["runId"]
    if retention_label is not None:
        expected_directory += "-" + retention_label
    if guest_directory != receipt["guestDirectory"] or guest_directory != expected_directory:
        raise ValueError("qualification output directory differs from the current invocation")
    destination = Path(host_directory)
    custody = destination.lstat()
    if (not stat.S_ISDIR(custody.st_mode) or custody.st_uid != os.geteuid()
            or custody.st_mode & 0o077):
        raise ValueError("qualification output destination custody refused")

    observations = []
    for name, digest_field in (("stdout.log", "stdoutSha256"), ("stderr.log", "stderrSha256")):
        record = {"name": name, "state": "refused_or_unknown"}
        try:
            encoded = direct_guest_python(worker, python, """
                import base64, hashlib, os, stat
                from pathlib import Path

                root = Path(selected['root'])
                custody = root.lstat()
                if not stat.S_ISDIR(custody.st_mode) or custody.st_uid != os.geteuid() \\
                        or custody.st_mode & 0o077:
                    raise ValueError('invocation output directory custody refused')
                descriptor = os.open(root / selected['name'],
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as source:
                    before = os.fstat(source.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() \\
                            or before.st_mode & 0o077 or before.st_nlink != 1 \\
                            or before.st_size > 65536:
                        raise ValueError('invocation output custody or bound refused')
                    body = source.read(65537)
                    after = os.fstat(source.fileno())
                if len(body) != before.st_size or any(
                        getattr(before, field) != getattr(after, field)
                        for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                    raise ValueError('invocation output changed during retention')
                print(json.dumps({'body': base64.b64encode(body).decode(),
                    'sha256': hashlib.sha256(body).hexdigest(), 'byteSize': len(body)}))
            """, {"root": guest_directory, "name": name}, timeout=60)
            if len(encoded) > 90000:
                raise ValueError("qualification output transport exceeds bound")
            captured = json.loads(encoded)
            if set(captured) != {"body", "sha256", "byteSize"}:
                raise ValueError("qualification output transport differs")
            body = base64.b64decode(captured["body"], validate=True)
            digest = hashlib.sha256(body).hexdigest()
            if (len(body) > 65536 or type(captured["byteSize"]) is not int
                    or captured["byteSize"] != len(body) or captured["sha256"] != digest
                    or receipt[digest_field] != digest):
                raise ValueError("qualification output differs from the current invocation")

            descriptor = os.open(destination / name,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            record = {"name": name, "state": "retained", "byteSize": len(body), "sha256": digest}
        except Exception:
            # Transfer and custody failures stay value-free. The caller still
            # raises its original invocation failure after this record is saved.
            pass
        observations.append(record)
    return {"maximumFileBytes": 65536, "files": observations}


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

        def bounded_output_sha256(path):
            with path.open('rb') as source:
                body = source.read(65537)
            return hashlib.sha256(body).hexdigest() if len(body) <= 65536 else None

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
            'stdoutSha256': bounded_output_sha256(root / 'stdout.log'),
            'stderrSha256': bounded_output_sha256(root / 'stderr.log'),
            'scope': 'same retained qualification original; new invocation evidence; no fresh provider mutation'}))
    """, {"root": root, "arguments": arguments, "driver": tools["qualificationDriver"],
            "runId": run_id, "phase": phase, "waitSeconds": wait_seconds},
        timeout=wait_seconds + 360))
    if (receipt["runId"] != run_id or receipt["phase"] != phase or receipt["guestDirectory"] != root
            or (type(receipt["exitCode"]) is not int
                and not (receipt["timedOut"] is True and receipt["exitCode"] is None))):
        raise ValueError("qualification recovery process receipt differs")
    destination = retain_direct_qualification_process(receipt, label)
    invocation_output = retain_direct_qualification_output(
        worker, tools["python"], root, str(destination), receipt, retention_label=label)
    retain_direct_qualification_output_report(destination, invocation_output)
    retained = retain_direct_qualification_files(worker, tools["python"], root + "/evidence", run_id, label,
        host_directory=destination)
    report = {"version": 1, "process": receipt, "retained": retained,
              "invocationOutput": invocation_output}
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
                                bulk_originals, metadata_originals, wait_seconds=600, *,
                                operator_root="/var/lib/hybrid-worker/operator"):
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
    if operator_root != "/var/lib/hybrid-worker/operator" and re.fullmatch(
            r"/var/lib/hybrid-worker/external-oci/[0-9a-f]{32}/operator", operator_root) is None:
        raise ValueError("External qualification custody root differs")
    root = operator_root + "/prequalification-" + run_id
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

        def bounded_output_sha256(path):
            with path.open('rb') as source:
                body = source.read(65537)
            return hashlib.sha256(body).hexdigest() if len(body) <= 65536 else None

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
            'stdoutSha256': bounded_output_sha256(root / 'stdout.log'),
            'stderrSha256': bounded_output_sha256(root / 'stderr.log'),
            'scope': 'isolated actual provider/queue prequalification; no acceptance'}}))
        ACTUAL_PROTECTED_QUALIFICATION
    """), timeout=wait_seconds + 1800))
    if receipt["runId"] != run_id or (
        type(receipt["exitCode"]) is not int
        and not (receipt["timedOut"] is True and receipt["exitCode"] is None)
    ):
        raise ValueError("qualification process receipt differs from its original")
    if receipt["guestDirectory"] != root:
        raise ValueError("qualification process output directory differs")
    destination = retain_direct_qualification_process(receipt)
    invocation_output = retain_direct_qualification_output(
        worker, python, root, str(destination), receipt, operator_root=operator_root)
    retain_direct_qualification_output_report(destination, invocation_output)
    retained = retain_direct_qualification_files(worker, python, root + "/evidence", run_id,
        host_directory=destination)
    result = {"process": receipt, "retained": retained, "sourceOriginals": originals,
              "invocationOutput": invocation_output}
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
