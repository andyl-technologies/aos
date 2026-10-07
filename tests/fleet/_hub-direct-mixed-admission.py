"""Join an owned held provider read to an authenticated unfinished bulk Begin.

The fixture barrier grants no runtime or provider authority. Final mixed rows
still come from the existing authenticated completion receipts and predicates.
"""

import hashlib
import json
import re
import os
import time
import textwrap


MIXED_READY_FIELDS = {
    "version", "cohortNonce", "jobProjectionSha256", "runId", "sourceDigest", "scriptVersion", "originalSha256",
    "objectId", "expectedSourceSha256", "expectedSourceBytes", "closedSha256",
    "attemptNonce", "attemptSha256", "inspectionSha256", "inspectionFile",
}


def mixed_document_digest(value):
    """Match the producer's existing sorted JSON commitment for this schema."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_mixed_ready(ready, capture, authentication, run_id, source, identity, *, arming=False):
    """Join a source-authenticated capture, exact first original and unfinished Begin."""
    if (not isinstance(ready, dict) or set(ready) != (MIXED_ARM_FIELDS if arming else MIXED_READY_FIELDS)
            or type(ready["version"]) is not int or ready["version"] != 1
            or ready["runId"] != run_id
            or ready["sourceDigest"] != identity["sourceDigest"]
            or ready["scriptVersion"] != identity["scriptVersion"]
            or not re.fullmatch(r"[0-9]{5}-inspect-capture\.json", ready["inspectionFile"])):
        raise ValueError("mixed readiness schema or installed source differs")
    commitments = ["cohortNonce", "jobProjectionSha256", "originalSha256", "closedSha256", "inspectionSha256"]
    if not arming:
        commitments += ["attemptNonce", "attemptSha256"]
    for name in commitments:
        if not isinstance(ready[name], str) or re.fullmatch(r"[0-9a-f]{64}", ready[name]) is None:
            raise ValueError("mixed readiness commitment differs")
    if (authentication["status"] != 200
            or authentication["responseSha256"] != ready["inspectionSha256"]
            or authentication["requestSha256"] != capture["requestSha256"]
            or capture["sourceDigest"] != identity["sourceDigest"]
            or capture["scriptVersion"] != identity["scriptVersion"]):
        raise ValueError("mixed readiness lacks its actual authenticated exchange")
    result = capture["result"]
    original = result["original"]
    if (original["runId"] != run_id or original["sourceDigest"] != identity["sourceDigest"]
            or original["scriptVersion"] != identity["scriptVersion"]
            or original["publicOrigin"] != identity["publicOrigin"]
            or mixed_document_digest(original) != ready["originalSha256"]):
        raise ValueError("mixed readiness original differs")
    first = original["objects"][0]
    if (first["metadata"] is not False or first["objectId"] != ready["objectId"]
            or result["objectId"] != first["objectId"]
            or first["byteSize"] != str(source["byte_size"])
            or ready["expectedSourceBytes"] != first["byteSize"]
            or first["expectedSha256"] != source["sha256"]
            or ready["expectedSourceSha256"] != first["expectedSha256"]
            or result["closed"] is None
            or mixed_document_digest(result["closed"]) != ready["closedSha256"]
            or mixed_document_digest(result["closed"]["job"]) != ready["jobProjectionSha256"]
            or len(result["attempts"]) != (0 if arming else 1)):
        raise ValueError("mixed readiness first closed source differs")
    if arming:
        if result["nextAttempt"] is not None:
            raise ValueError("mixed arm has historical attempts")
        return result
    record = result["attempts"][0]
    if (record["receipt"] is not None or record["attempt"]["nonce"] != ready["attemptNonce"]
            or mixed_document_digest(record["attempt"]) != ready["attemptSha256"]):
        raise ValueError("mixed readiness is not the exact unfinished Begin")
    # QueueAttempt precedes Capacity::acquire and has no object counters.
    # Admission is established separately by the exact held integrity GET;
    # the eventual metadata receipt must independently report bulkActive > 0.
    return result


def validate_mixed_held(held, read_selection, arm, owner):
    """Require the exact source-selected full conditional GET and held prefix."""
    if (held["state"] != "held" or held["endedAtUnixMillis"] is not None
            or held["terminalCause"] is not None or held["receipt"] is None):
        raise ValueError("mixed provider hold is terminal or unobserved")
    receipt = held["receipt"]
    expected_owner = {name: owner[name] for name in (
        "pid", "startTicks", "ownerUid", "configurationSha256", "listenerSourceSha256",
        "listenAddress", "upstreamAddress")}
    if receipt["owner"] != expected_owner:
        raise ValueError("mixed held read owner differs")
    if (receipt["selectionContextSha256"] != arm["selectionContextSha256"]
            or receipt["sourceSha256"] != arm["expectedSourceSha256"]
            or receipt["sourceBytes"] != arm["expectedSourceBytes"]
            or receipt["prefixFile"]["sha256"] != arm["expectedPrefixSha256"]
            or receipt["prefixFile"]["byteSize"] != "65536"
            or receipt["bindings"] != arm["bindings"]
            or receipt["cohortNonce"] != arm["cohortNonce"]):
        raise ValueError("mixed held source commitments differ")
    if (read_selection is None or read_selection["sourceSha256"] != arm["expectedSourceSha256"]
            or read_selection["sourceBytes"] != arm["expectedSourceBytes"]
            or receipt["identity"]["target"] != read_selection["target"]
            or receipt["identity"]["host"] != read_selection["host"]
            or receipt["identity"]["ifMatch"] != read_selection["etag"]
            or receipt["identity"]["method"] != "GET" or receipt["identity"]["range"] is not None
            or receipt["downstreamOfferedBytes"] != "0" or receipt["upstreamComplete"] is not False
            or receipt["remoteDrain"] is not None):
        raise ValueError("mixed held read differs from the actual closed verify job")
    if (any(type(receipt[name]) is not int for name in (
            "selectedAtUnixMillis", "heldAtUnixMillis", "cutoffUnixMillis"))
            or not receipt["selectedAtUnixMillis"] <= receipt["heldAtUnixMillis"] < receipt["cutoffUnixMillis"]
            or not 0 < receipt["cutoffUnixMillis"] - receipt["selectedAtUnixMillis"] <= 35000):
        raise ValueError("mixed held read was already at its owner cutoff")
    return held["receiptFile"]["sha256"]


def mixed_release_document(ready, held_receipt_sha256):
    """Project a one-use source-specific barrier after both joins succeeded."""
    if not re.fullmatch(r"[0-9a-f]{64}", held_receipt_sha256):
        raise ValueError("mixed held receipt commitment differs")
    return {"version": 1, "runId": ready["runId"],
            "readySha256": mixed_document_digest(ready),
            "heldReceiptSha256": held_receipt_sha256}


def validate_mixed_metadata_finish(value, ready, metadata_source):
    """Require actual fresh metadata completion and its admitted-under-bulk counters."""
    if (set(value) != {"version", "runId", "readySha256", "record"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["runId"] != ready["runId"]
            or value["readySha256"] != mixed_document_digest(ready)):
        raise ValueError("mixed metadata completion differs from this barrier")
    record = value["record"]
    receipt = record["receipt"]
    before, after = receipt["attempt"]["providerBefore"], receipt["providerAfter"]
    counts = [receipt["objects"]["bulkActive"], before["dispatches"], after["dispatches"],
              before["metadataAdmissionsDuringBulk"], after["metadataAdmissionsDuringBulk"]]
    if any(type(value) is not int or not 0 <= value <= 9007199254740991 for value in counts):
        raise ValueError("mixed metadata counters are not exact observed integers")
    if (record["object"]["metadata"] is not True or receipt["verificationReplayed"] is not False
            or receipt["proof"]["sha256"] != metadata_source["sha256"]
            or receipt["proof"]["byte_size"] != str(metadata_source["byte_size"])
            or receipt["objects"]["bulkActive"] <= 0
            or before["isolateId"] != after["isolateId"]
            or after["dispatches"] <= before["dispatches"]
            or after["metadataAdmissionsDuringBulk"] <= before["metadataAdmissionsDuringBulk"]):
        raise ValueError("mixed metadata lacks fresh source consumption and bulk admission")
    return record


MIXED_ARM_FIELDS = MIXED_READY_FIELDS - {"attemptNonce", "attemptSha256"}


def validate_mixed_arm(ready, capture, authentication, run_id, source, identity):
    """Arm only an authenticated, closed, never-enqueued first bulk object."""
    return validate_mixed_ready(ready, capture, authentication, run_id, source, identity, arming=True)


def mixed_bindings(ready):
    return {name: ready[name] for name in (
        "runId", "objectId", "originalSha256", "closedSha256", "jobProjectionSha256")}


def mixed_remaining(cutoff, maximum=10):
    """Allocate only time remaining inside the caller's original monotonic bound."""
    remaining = cutoff - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("original mixed owner cutoff exhausted")
    return min(maximum, remaining)


def mixed_owner_command(s3, tools, request, *, cutoff):
    """Exchange with the pinned peer inside the caller's existing absolute bound."""
    installation = tools["providerHoldInstallation"]
    if (installation["root"] != "/var/lib/hybrid-s3/read-timeout"
            or installation["ready"]["controlSocket"] != installation["root"] + "/control.sock"):
        raise ValueError("mixed response owner custody root differs")
    body = json.dumps(request, separators=(",", ":"), allow_nan=False).encode()
    if len(body) > 16384:
        raise ValueError("mixed control exceeds its bound")
    seconds = mixed_remaining(cutoff)
    # Same original owner/peer checks as _direct_provider_listener_exchange.
    # This copy additionally carries the finite caller budget into every recv;
    # individual partial socket reads cannot restart a fresh ten-second timer.
    return json.loads(direct_guest_python(s3, tools["python"], r"""
        import hashlib, os, socket, stat, struct, time
        from pathlib import Path
        deadline = time.monotonic() + selected['seconds']
        def remaining():
            value = deadline - time.monotonic()
            if value <= 0: raise TimeoutError('original mixed control cutoff exhausted')
            return value
        pin = selected['process']; proc = Path('/proc') / str(pin['pid'])
        before = (proc / 'stat').read_text().rpartition(') ')[2].split()
        if before[19] != pin['startTicks'] or before[0] == 'Z' or proc.stat().st_uid != pin['ownerUid']:
            raise ValueError('mixed response owner lifetime differs')
        remaining()
        with (proc / 'exe').open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != pin['executableSha256']:
                raise ValueError('mixed response owner executable differs')
        for name, expected in (('cmdline', pin['commandLineSha256']), ('environ', pin['environmentSha256'])):
            remaining()
            body = (proc / name).read_bytes()
            if len(body) > 65536 or hashlib.sha256(body).hexdigest() != expected:
                raise ValueError('mixed response owner inputs differ')
        path = Path(selected['socket']); metadata = path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != pin['ownerUid'] or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError('mixed response owner socket custody differs')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(remaining()); connection.connect(str(path))
            pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != pin['pid'] or uid != pin['ownerUid']: raise ValueError('mixed response owner peer differs')
            connection.settimeout(remaining()); connection.sendall(bytes.fromhex(selected['requestHex']))
            connection.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                connection.settimeout(remaining())
                chunk = connection.recv(16385 - len(response))
                if not chunk: break
                response.extend(chunk)
                if len(response) > 16384: raise ValueError('mixed response exceeds its bound')
        remaining()
        after = (proc / 'stat').read_text().rpartition(') ')[2].split()
        if after[19] != before[19] or after[0] == 'Z': raise ValueError('mixed response owner changed')
        print(response.decode())
    """, {"seconds": seconds, "process": installation["process"],
          "socket": installation["ready"]["controlSocket"], "requestHex": body.hex()}, timeout=seconds))


# The managed owner is a session leader; its Node child inherits that group.
# SIGTERM is cooperative, with a real child wait and a fixed cleanup reserve
# inside the original 2100s subprocess budget. No detached signing/driver child.
MIXED_SUPERVISOR = r"""
import hashlib, json, os, signal, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1])
arguments = json.loads(sys.argv[2])
budget = int(sys.argv[3])
os.umask(0o077)
started = time.monotonic()
original_cutoff = started + budget
work_cutoff = original_cutoff - 5
reap_cutoff = original_cutoff - 1
cancelled = False

def cancel(*_):
    global cancelled
    cancelled = True

signal.signal(signal.SIGTERM, cancel)
signal.signal(signal.SIGINT, cancel)

def save(name, value):
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, sort_keys=True, separators=(',', ':'))
        output.flush(); os.fsync(output.fileno())
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def bounded_hash(name):
    with (root / name).open('rb') as source:
        body = source.read(65537)
    return hashlib.sha256(body).hexdigest() if len(body) <= 65536 else None

with (root / 'stdout.log').open('xb') as stdout, (root / 'stderr.log').open('xb') as stderr:
    child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
    proc = Path('/proc') / str(child.pid)
    primary = None
    try:
        stat = (proc / 'stat').read_text().rpartition(') ')[2].split()
        save('mixed-child.json', {'version': 1, 'pid': child.pid, 'startTicks': stat[19],
            'ownerUid': proc.stat().st_uid, 'processGroup': os.getpgid(child.pid), 'arguments': arguments})
        while child.poll() is None and not cancelled and time.monotonic() < work_cutoff:
            time.sleep(min(0.025, max(0, work_cutoff - time.monotonic())))
    except BaseException as error:
        primary = error
    finally:
        # Even an exception arriving late cannot start a fresh TERM/reap timer.
        if child.poll() is None:
            child.terminate()
            remaining = max(0, reap_cutoff - time.monotonic())
            try: child.wait(timeout=remaining / 2)
            except subprocess.TimeoutExpired: pass
        if child.poll() is None:
            child.kill()
            remaining = max(0, reap_cutoff - time.monotonic())
            try: child.wait(timeout=remaining)
            except subprocess.TimeoutExpired: pass
        child_reaped = child.poll() is not None
    timed_out = not cancelled and time.monotonic() >= work_cutoff
    save('mixed-outcome.json', {'version': 1, 'runId': root.name.split('prequalification-', 1)[1],
        'exitCode': child.returncode, 'timedOut': timed_out, 'cancelled': cancelled,
        'machineRole': 'worker_operator', 'guestDirectory': str(root),
        'driverSha256': hashlib.sha256(Path(arguments[1]).read_bytes()).hexdigest(),
        'stdoutSha256': bounded_hash('stdout.log'), 'stderrSha256': bounded_hash('stderr.log'),
        'childReaped': child_reaped, 'supervisorFailure': None if primary is None else type(primary).__name__,
        'originalBudgetSeconds': budget, 'scope': 'isolated actual provider/queue prequalification; no acceptance'})
"""


def mixed_guest_snapshot(worker, tools, root, process, *, cutoff):
    """Read only fixed records and their exact authenticated capture references."""
    return json.loads(direct_guest_python(worker, tools["python"], r"""
        import hashlib, os, re, stat
        from pathlib import Path
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value: raise ValueError('duplicate mixed evidence field')
                value[key] = item
            return value
        def read_at(directory, name, maximum):
            try: fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError: return None
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > maximum):
                    raise ValueError('mixed evidence custody differs')
                body = os.read(fd, maximum + 1)
                after = os.fstat(fd)
                if len(body) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError('mixed evidence changed')
                return {'value': json.loads(body, object_pairs_hook=pairs), 'sha256': hashlib.sha256(body).hexdigest()}
            finally: os.close(fd)
        root_fd = os.open(selected['root'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            outcome = read_at(root_fd, 'mixed-outcome.json', 16384)
            pin = selected['process']; proc = Path('/proc') / str(pin['pid'])
            if outcome is None:
                before = (proc / 'stat').read_text().rpartition(') ')[2].split()
                if before[19] != pin['startTicks'] or before[0] == 'Z' or proc.stat().st_uid != pin['ownerUid']:
                    raise ValueError('mixed supervisor lifetime unavailable')
            child = read_at(root_fd, 'mixed-child.json', 65536)
            evidence_fd = os.open('evidence', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            try:
                result = {'outcome': outcome, 'child': child}
                for name in ('mixed-arm-ready.json', 'mixed-admission-ready.json', 'mixed-admission-metadata-finish.json'):
                    item = read_at(evidence_fd, name, 262144)
                    if item is not None and name != 'mixed-admission-metadata-finish.json':
                        filename = item['value']['inspectionFile']
                        if re.fullmatch(r'[0-9]{5}-inspect-capture\.json', filename) is None:
                            raise ValueError('mixed capture reference differs')
                        item['capture'] = read_at(evidence_fd, filename, 262144)
                        item['authentication'] = read_at(evidence_fd, filename.replace('-capture.json', '-authentication.json'), 16384)
                        if item['capture'] is None or item['authentication'] is None:
                            raise ValueError('mixed capture authentication absent')
                    result[name] = item
            finally: os.close(evidence_fd)
            if outcome is None:
                after = (proc / 'stat').read_text().rpartition(') ')[2].split()
                if before[19] != after[19]: raise ValueError('mixed supervisor identity changed')
            print(json.dumps(result))
        finally: os.close(root_fd)
    """, {"root": root, "process": process}, timeout=mixed_remaining(cutoff)))


def publish_mixed_barrier(worker, tools, root, filename, value, *, cutoff):
    """Create exactly one private canonical barrier; never rewrite a release."""
    if filename not in {"mixed-arm-release.json", "mixed-admission-release.json"}:
        raise ValueError("mixed barrier filename differs")
    direct_guest_python(worker, tools["python"], r"""
        import os, stat
        fd = os.open(selected['root'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError('mixed release directory custody differs')
            body = json.dumps(selected['value'], sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
            output_fd = os.open(selected['filename'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(output_fd, 'wb') as output:
                output.write(body); output.flush(); os.fsync(output.fileno())
            os.fsync(fd)
        finally: os.close(fd)
    """, {"root": root, "filename": filename, "value": value}, timeout=mixed_remaining(cutoff))


def stop_mixed_supervisor(worker, tools, process, *, cutoff):
    """Signal only the exact owned group and report uncertainty rather than adopt."""
    seconds = mixed_remaining(cutoff)
    return json.loads(direct_guest_python(worker, tools["python"], r"""
        import os, signal, time
        from pathlib import Path
        pin = selected['process']; proc = Path('/proc') / str(pin['pid'])
        original_cutoff = time.monotonic() + selected['seconds']
        def same():
            try: fields = (proc / 'stat').read_text().rpartition(') ')[2].split()
            except FileNotFoundError: return False
            if fields[19] != pin['startTicks'] or proc.stat().st_uid != pin['ownerUid']:
                raise ValueError('mixed cleanup owner changed')
            return fields[0] != 'Z'
        if same():
            if os.getpgid(pin['pid']) != pin['pid']: raise ValueError('mixed owner is not its selected group leader')
            descriptor = os.pidfd_open(pin['pid'])
            try:
                if same(): signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                work_cutoff = time.monotonic() + max(0, original_cutoff - time.monotonic()) / 2
                while same() and time.monotonic() < work_cutoff:
                    time.sleep(min(0.025, max(0, work_cutoff - time.monotonic())))
                if same():
                    # Node inherits this exact leader's group. Fail closed if
                    # identity is unavailable; never signal a reused group.
                    os.killpg(pin['pid'], signal.SIGKILL)
                while same() and time.monotonic() < original_cutoff:
                    time.sleep(min(0.025, max(0, original_cutoff - time.monotonic())))
            finally: os.close(descriptor)
        print(json.dumps({'version': 1, 'pid': pin['pid'], 'startTicks': pin['startTicks'],
            'ownerAbsentOrZombie': not same(), 'exitCode': None,
            'scope': 'owner cleanup observation; group drain unknown unless child receipt confirms'}))
    """, {"process": process, "seconds": seconds}, timeout=seconds))


def assert_mixed_supervisor_completion(receipt):
    """Refuse an exit-zero child unless its supervisor completed normally."""
    if receipt["exitCode"] == 0 and (
        receipt.get("childReaped") is not True
        or receipt.get("supervisorFailure") is not None
        or receipt.get("timedOut") is not False
        or receipt.get("cancelled") is not False
    ):
        raise ValueError("positive driver lacks completed supervisor custody")


def run_mixed_prequalification(worker, s3, tools, root, run_id, arguments, encoded_manifest,
                              sources, identity, worker_process, wait_seconds):
    """Own one serialized pump; actual holder and authenticated receipts release it."""
    if (worker_process is None or tools.get("providerHoldInstallation") is None
            or root != "/var/lib/hybrid-worker/operator/prequalification-" + run_id):
        raise ValueError("mixed qualification caller is not explicitly wired")
    original_cutoff = time.monotonic() + wait_seconds + 1800
    # All owner control, cooperative stop, final snapshot and local retention
    # consume the existing wrapper budget. Fifteen seconds are reserved inside
    # it, never appended when ordinary work reaches its cutoff.
    work_cutoff = original_cutoff - 15
    payload = {"root": root, "manifest": encoded_manifest,
               "supervisor": MIXED_SUPERVISOR, "arguments": arguments}
    direct_guest_python(worker, tools["python"], r"""
        import base64, os
        from pathlib import Path
        root = Path(selected['root']); root.mkdir(mode=0o700, exist_ok=False)
        (root / 'evidence').mkdir(mode=0o700)
        for name, body in (('manifest.json', base64.b64decode(selected['manifest'], validate=True)),
                           ('mixed-supervisor.py', selected['supervisor'].encode())):
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(body); output.flush(); os.fsync(output.fileno())
    """, payload, timeout=mixed_remaining(work_cutoff))
    mixed_remaining(work_cutoff, 30)
    if work_cutoff - time.monotonic() < 30:
        raise TimeoutError("original wrapper has no managed launch budget")
    process = launch_managed_process(worker, tools, root, "mixed-supervisor",
        [tools["python"], "-B", root + "/mixed-supervisor.py", root,
         json.dumps(arguments, separators=(",", ":")), str(wait_seconds + 1500)],
        {"NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/ca-certificates.crt"})
    arm = None
    ready = None
    resumed = False
    terminal = None
    owner_events = {"version": 1, "runId": run_id, "supervisor": process, "events": []}
    primary = None
    receipt = None
    try:
        while time.monotonic() < work_cutoff:
            snapshot = mixed_guest_snapshot(worker, tools, root, process, cutoff=work_cutoff)
            child = snapshot["child"]
            if child is not None and (child["value"]["arguments"] != arguments
                    or child["value"]["processGroup"] != process["pid"]
                    or child["value"]["ownerUid"] != process["ownerUid"]):
                raise ValueError("mixed child is outside its exact supervisor ownership")
            arming = snapshot["mixed-arm-ready.json"]
            if arming is not None and arm is None:
                value = arming["value"]
                capture, auth = arming["capture"], arming["authentication"]["value"]
                if capture["sha256"] != auth["responseSha256"]:
                    raise ValueError("mixed actual authenticated capture bytes differ")
                result = validate_mixed_arm(value, capture["value"], auth, run_id, sources[0], identity)
                selection = direct_restart_read_selection(result)
                if selection is None or selection["port"] != 443:
                    raise ValueError("mixed closed job lacks its actual selected TLS placement")
                prefix = json.loads(direct_guest_python(worker, tools["python"], r"""
                    import hashlib, os, stat
                    fd = os.open(selected['file'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        before = os.fstat(fd)
                        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                                or before.st_size != selected['byte_size']):
                            raise ValueError('mixed source custody differs')
                        body = os.read(fd, 65536); after = os.fstat(fd)
                        if len(body) != 65536 or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('mixed source prefix changed')
                        print(json.dumps({'sha256': hashlib.sha256(body).hexdigest()}))
                    finally: os.close(fd)
                """, sources[0], timeout=mixed_remaining(work_cutoff)))
                server_deadline = int(direct_guest_python(s3, tools["python"],
                    "import time; print(time.time_ns() // 1000000 + 1200000)", {}, timeout=mixed_remaining(work_cutoff)))
                arm = {"version": 1, "kind": "arm_mixed_read", "cohortNonce": value["cohortNonce"],
                    "bindings": mixed_bindings(value), "selection": {name: selection[name] for name in ("target", "host", "etag")},
                    "expectedSourceSha256": sources[0]["sha256"], "expectedSourceBytes": str(sources[0]["byte_size"]),
                    "expectedPrefixSha256": prefix["sha256"], "selectionContextSha256": mixed_document_digest(value),
                    "selectionDeadlineUnixMillis": server_deadline, "pauseMillis": 35000}
                reply = mixed_owner_command(s3, tools, arm, cutoff=work_cutoff)
                if reply != {"version": 1, "status": "armed", "cohortNonce": arm["cohortNonce"]}:
                    raise ValueError("mixed source owner did not arm exact cohort")
                owner_events["events"].append({"phase": "armed", "request": arm, "reply": reply})
                publish_mixed_barrier(worker, tools, root, "mixed-arm-release.json", mixed_release_document(value, mixed_document_digest(arm)), cutoff=work_cutoff)
            admission = snapshot["mixed-admission-ready.json"]
            command = None if arm is None else {"version": 1, "kind": "mixed_state",
                "cohortNonce": arm["cohortNonce"], "bindings": arm["bindings"]}
            if admission is not None and ready is None:
                value = admission["value"]
                if arm is None or mixed_bindings(value) != arm["bindings"] or value["cohortNonce"] != arm["cohortNonce"]:
                    raise ValueError("mixed Begin differs from armed closed job")
                capture, auth = admission["capture"], admission["authentication"]["value"]
                if capture["sha256"] != auth["responseSha256"]: raise ValueError("mixed Begin capture bytes differ")
                result = validate_mixed_ready(value, capture["value"], auth, run_id, sources[0], identity)
                held = mixed_owner_command(s3, tools, command, cutoff=work_cutoff)
                if held["state"] in {"cutoff", "disconnected", "refused", "cancelled", "eof"}:
                    raise ValueError("mixed owner ended before metadata admission")
                if held["state"] == "held":
                    digest = validate_mixed_held(held, direct_restart_read_selection(result), arm,
                                                tools["providerHoldInstallation"]["ready"])
                    reply = mixed_owner_command(s3, tools, {**command, "kind": "bind_mixed_begin", "beginNonce": value["attemptNonce"]}, cutoff=work_cutoff)
                    if reply != {"version": 1, "status": "bound", "cohortNonce": arm["cohortNonce"]}:
                        raise ValueError("mixed Begin owner binding was not acknowledged")
                    owner_events["events"].append({"phase": "held_and_bound", "held": held, "ready": value, "reply": reply})
                    publish_mixed_barrier(worker, tools, root, "mixed-admission-release.json", mixed_release_document(value, digest), cutoff=work_cutoff)
                    ready = value
            if ready is not None and not resumed:
                current = mixed_owner_command(s3, tools, command, cutoff=work_cutoff)
                if current["state"] != "held" or current["beginNonce"] != ready["attemptNonce"]:
                    raise ValueError("mixed original hold ended before actual metadata completion")
            finish = snapshot["mixed-admission-metadata-finish.json"]
            if finish is not None and not resumed:
                if ready is None: raise ValueError("metadata finished without this actual held Begin")
                validate_mixed_metadata_finish(finish["value"], ready, sources[3])
                held = mixed_owner_command(s3, tools, command, cutoff=work_cutoff)
                validate_mixed_held(held, arm["selection"] | {"sourceSha256": arm["expectedSourceSha256"],
                    "sourceBytes": arm["expectedSourceBytes"]}, arm, tools["providerHoldInstallation"]["ready"])
                reply = mixed_owner_command(s3, tools, {**command, "kind": "resume_mixed_read",
                    "beginNonce": ready["attemptNonce"], "heldReceiptSha256": held["receiptFile"]["sha256"],
                    "metadataReceiptSha256": mixed_document_digest(finish["value"]["record"]["receipt"])}, cutoff=work_cutoff)
                if reply != {"version": 1, "status": "resume_dispatched", "cohortNonce": arm["cohortNonce"], "remoteDrain": None}:
                    raise ValueError("mixed stream resume dispatch is unknown")
                owner_events["events"].append({"phase": "resume_dispatched", "reply": reply,
                    "metadataFinishSha256": finish["sha256"]})
                resumed = True
            if resumed and terminal is None:
                state = mixed_owner_command(s3, tools, command, cutoff=work_cutoff)
                if state["terminalFile"] is not None:
                    owner_events["events"].append({"phase": "terminal", "state": state})
                    terminal = state
                    if state["state"] != "eof": raise ValueError("mixed provider stream did not reach exact EOF")
            if snapshot["outcome"] is not None:
                receipt = snapshot["outcome"]["value"]
                assert_mixed_supervisor_completion(receipt)
                if receipt["exitCode"] == 0 and (not resumed or terminal is None):
                    raise ValueError("positive driver lacks same-stream terminal custody")
                break
            time.sleep(min(0.025, max(0, work_cutoff - time.monotonic())))
        else:
            raise TimeoutError("original mixed qualification supervisor deadline elapsed")
    except BaseException as error:
        primary = error
        owner_events["ownerFailure"] = type(error).__name__
    finally:
        errors = []
        if arm is not None and terminal is None:
            try:
                ended = mixed_owner_command(s3, tools, {"version": 1, "kind": "cancel_mixed_read",
                    "cohortNonce": arm["cohortNonce"], "bindings": arm["bindings"]}, cutoff=original_cutoff)
                owner_events["events"].append({"phase": "cleanup", "state": ended})
            except BaseException as error: errors.append(error)
        try: owner_events["cleanup"] = stop_mixed_supervisor(worker, tools, process, cutoff=original_cutoff)
        except BaseException as error: errors.append(error)
        try:
            snapshot = mixed_guest_snapshot(worker, tools, root, process, cutoff=original_cutoff)
            if snapshot["outcome"] is not None:
                receipt = snapshot["outcome"]["value"]
                if primary is not None: receipt["ownerFailure"] = type(primary).__name__
                owner_events["actualChildOutcome"] = receipt
        except BaseException as error: errors.append(error)
        # Receipt already observed before the predicate failed must still carry
        # that failure even if the final guest snapshot is unavailable.
        if receipt is not None and primary is not None:
            receipt["ownerFailure"] = type(primary).__name__
            owner_events["actualChildOutcome"] = receipt
        try:
            mixed_remaining(original_cutoff)
            retain_direct_flow("mixed-admission-" + run_id + ".json", owner_events)
        except BaseException as error: errors.append(error)
        if errors:
            if primary is not None:
                for error in errors: primary.add_note("mixed cleanup or retention failed: " + type(error).__name__)
            else: raise errors[0]
    if receipt is None:
        if primary is not None: raise primary
        raise RuntimeError("mixed child exit outcome is unavailable; effects remain unknown")
    if primary is not None:
        receipt["ownerFailure"] = type(primary).__name__
    return receipt
