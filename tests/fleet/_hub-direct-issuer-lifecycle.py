"""Observe real cohort issuance and cold reopening of the retained issuer.

Requests are prepared through the selected shared Rust codec on Native. Worker
transports their exact bytes without receiving the publisher or signing seed.
These observations prove neither provider settlement nor cache renewal ratios.
"""

import hashlib
import json
import re
import shlex


def exchange_direct_issuer(native, worker, tools, helper, bootstrap, operation,
                           label, previous_observed=0, role="renewal"):
    """Dispatch one original and verify its actual reply through shared codecs."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label) or role not in {"renewal", "publisher"}:
        raise ValueError("issuer observation label or key role is invalid")
    native_root = "/var/lib/hybrid-shared-controls/issuer-" + label
    prepared = run_direct_shared_control(native, tools, helper, {
        "kind": "issuer_prepare", "key_file": "/var/lib/hybrid-authority/" + role + ".key",
        "installation": bootstrap["issuer_installation"], "operation": operation,
        "output_directory": native_root,
    }, "issuer-prepare-" + label)
    worker_root = "/var/lib/hybrid-worker/issuer-observations/" + label
    request = read_direct_guest_file(native, tools["python"], native_root + "/request.json", 1048576)
    headers = read_direct_guest_file(native, tools["python"], native_root + "/headers.txt", 4096)
    if hashlib.sha256(request).hexdigest() != prepared["requestSha256"]:
        raise ValueError("prepared issuer original changed before transport")
    for name, body in (("request.json", request), ("headers.txt", headers)):
        install_direct_guest_file(worker, tools["python"], worker_root + "/" + name, body)
    transport = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path(selected['root'])
        reply = root / 'reply.json'
        descriptor = os.open(reply, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        arguments = selected['curl'] + ['--silent', '--show-error', '--max-time', '20',
            '--max-filesize', '1048576', '--connect-to', 'localhost:8443:native:8443',
            '--request', 'POST', '--header', '@' + str(root / 'headers.txt'),
            '--data-binary', '@' + str(root / 'request.json'), '--output', str(reply),
            '--write-out', '%{http_code}', 'https://localhost:8443/_aos/storage-authority/issuer/v1']
        started = time.time_ns()
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
            capture_output=True, check=False, timeout=25)
        body = reply.read_bytes()
        if len(body) > 1048576:
            raise ValueError('issuer response exceeds its retained body bound')
        status = int(result.stdout) if len(result.stdout) == 3 and result.stdout.isdigit() else None
        print(json.dumps({'version': 1, 'exitCode': result.returncode, 'status': status,
            'requestSha256': hashlib.sha256((root / 'request.json').read_bytes()).hexdigest(),
            'replySha256': hashlib.sha256(body).hexdigest(), 'replyBytes': len(body),
            'startedUnixNs': str(started), 'completedUnixNs': str(time.time_ns()),
            'stderrSha256': hashlib.sha256(result.stderr).hexdigest(),
            'stderrBytes': len(result.stderr), 'scope': 'actual Worker-to-Native metadata transport'}))
    """, {"root": worker_root, "curl": shlex.split(tools["curl"])}, timeout=35))
    retain_direct_flow("issuer-transport-" + label + ".json", transport)
    if (transport["exitCode"] != 0 or transport["status"] != 200
            or transport["stderrBytes"] or transport["requestSha256"] != prepared["requestSha256"]):
        raise RuntimeError("issuer original has no positive transport reply; retained without replay")
    reply = read_direct_guest_file(worker, tools["python"], worker_root + "/reply.json", 1048576)
    if hashlib.sha256(reply).hexdigest() != transport["replySha256"]:
        raise ValueError("actual issuer reply changed after transport observation")
    install_direct_guest_file(native, tools["python"], native_root + "/reply.json", reply)
    verified = run_direct_shared_control(native, tools, helper, {
        "kind": "issuer_verify", "request_file": native_root + "/request.json",
        "reply_file": native_root + "/reply.json", "issuer_key_id": bootstrap["issuer_key_id"],
        "issuer_public_key": bootstrap["issuer_public_key"],
        "uncertainty_seconds": int(bootstrap["clock_uncertainty"]),
        "previous_observed_seconds": previous_observed,
        "output_directory": native_root + "-verified",
    }, "issuer-verify-" + label)
    actual = json.loads(read_direct_guest_file(native, tools["python"],
        native_root + "-verified/verified-reply.json", 1048576))
    if verified["replySha256"] != transport["replySha256"]:
        raise ValueError("verified issuer reply differs from its actual transport")
    return {"prepared": prepared, "transport": transport, "verified": verified, "reply": actual}


def assert_direct_issuer_issue(exchange, cohort, timing_profile):
    """Check the actual verified token's cohort and bounded admission lifetime."""
    reply = exchange["reply"]
    if reply["lease"] is None:
        raise ValueError("actual issuer response contains no cohort lease")
    payload = json.loads(reply["lease"])["payload"]
    issued, expires = int(payload["issued_at"]), int(payload["not_after"])
    if (payload["cohort"] != cohort or payload["timing_profile"] != timing_profile
            or not 0 < expires - issued <= int(timing_profile["maximum_lifetime"])
            or expires > int(cohort["attestation_valid_until"])
            or expires > int(reply["current"]["journal"]["largest_issued_expiry"])):
        raise ValueError("actual verified lease differs from its cohort, TTL or durable expiry floor")
    return {"tokenSha256": exchange["verified"]["tokenSha256"],
        "cohortSha256": hashlib.sha256(json.dumps(cohort, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest(),
        "issuedAt": issued, "notAfter": expires, "lifetimeSeconds": expires - issued,
        "leaseSequence": payload["lease_sequence"]}


def assert_direct_issuer_cold_head(before, after):
    """Require exact authority epoch and nondecreasing retained issuance history."""
    first, second = before["reply"]["current"], after["reply"]["current"]
    if first["installation"] != second["installation"]:
        raise ValueError("cold issuer changed its permanent resource installation")
    for name in ("authority", "executor_identity", "generation", "admission_digest",
                 "publication_digest", "state", "policy"):
        if first["journal"][name] != second["journal"][name]:
            raise ValueError("cold issuer changed the actual current epoch")
    for name in ("last_sequence", "largest_issued_expiry", "clock_floor"):
        if int(second["journal"][name]) < int(first["journal"][name]):
            raise ValueError("cold issuer rolled back retained issuance history")
    return {"version": 1, "beforeJournalSha256": before["verified"]["journalSha256"],
        "afterJournalSha256": after["verified"]["journalSha256"],
        "largestIssuedExpiry": second["journal"]["largest_issued_expiry"],
        "lastSequence": second["journal"]["last_sequence"],
        "scope": "actual signed retained metadata head; not provider drain or unknown settlement"}


def cold_restart_direct_issuer(native, tools, original):
    """Reopen the same journal after stopping only its pinned issuer lifetime."""
    observed = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, signal, socket, stat, subprocess, time
        from pathlib import Path

        root = Path('/var/lib/hybrid-authority')
        expected = [selected['authority'], 'serve', '--configuration', str(root / 'configuration.json')]
        process_root = Path('/proc') / str(selected['original']['pid'])
        def pin():
            metadata = process_root.stat()
            lifetime = (process_root / 'stat').read_text().rpartition(') ')[2].split()[19]
            arguments = (process_root / 'cmdline').read_bytes().split(b'\\x00')[:-1]
            with (process_root / 'exe').open('rb') as source:
                executable_sha = hashlib.file_digest(source, 'sha256').hexdigest()
            if (metadata.st_uid != os.getuid() or lifetime != selected['original']['startTicks']
                    or arguments != [os.fsencode(value) for value in expected]
                    or executable_sha != selected['original']['executableSha256']):
                raise ValueError('issuer lifetime differs from its retained original')
        def resource():
            values = {}
            for name in ('configuration.json', 'signing-seed.key', 'publisher.key', 'renewal.key'):
                descriptor = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as source:
                    metadata = os.fstat(source.fileno())
                    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                            or metadata.st_mode & 0o077 or metadata.st_size > 1048576):
                        raise ValueError('retained issuer configuration/key custody differs')
                    values[name] = hashlib.file_digest(source, 'sha256').hexdigest()
            journal = (root / 'journal.sqlite').lstat()
            if not stat.S_ISREG(journal.st_mode) or journal.st_uid != os.getuid():
                raise ValueError('retained issuer journal is not the original regular resource')
            return {'files': values, 'journalDevice': journal.st_dev, 'journalInode': journal.st_ino}
        pin()
        retained = resource()
        descriptor = os.pidfd_open(selected['original']['pid'])
        try:
            pin()
            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        finally:
            os.close(descriptor)
        deadline = time.monotonic() + 20
        while process_root.exists():
            try:
                fields = (process_root / 'stat').read_text().rpartition(') ')[2].split()
            except FileNotFoundError:
                break
            if fields[0] == 'Z':
                break
            if fields[19] != selected['original']['startTicks']:
                raise ValueError('issuer PID lifetime changed while awaiting its stop')
            if time.monotonic() > deadline:
                raise ValueError('pinned issuer did not stop; no replacement launched')
            time.sleep(0.1)
        if resource() != retained:
            raise ValueError('issuer resource changed during its stop; no replacement launched')
        descriptor = os.open(root / 'cold-serve.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as log:
            replacement = subprocess.Popen(expected, stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True)
        time.sleep(0.2)
        if replacement.poll() is not None:
            raise ValueError('cold issuer exited; original resource retained')
        replacement_root = Path('/proc') / str(replacement.pid)
        replacement_ticks = (replacement_root / 'stat').read_text().rpartition(') ')[2].split()[19]
        with (replacement_root / 'exe').open('rb') as source:
            replacement_executable_sha = hashlib.file_digest(source, 'sha256').hexdigest()
        if ((replacement_root / 'cmdline').read_bytes().split(b'\\x00')[:-1]
                != [os.fsencode(value) for value in expected] or resource() != retained
                or replacement_root.stat().st_uid != os.getuid()
                or replacement_executable_sha != selected['original']['executableSha256']):
            raise ValueError('cold issuer does not use the same retained resource/configuration')
        deadline = time.monotonic() + 15
        while True:
            if replacement.poll() is not None:
                raise ValueError('cold issuer exited before listener observation')
            try:
                with socket.create_connection(('127.0.0.1', 8444), timeout=1):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise ValueError('cold issuer listener unavailable; no Initialize or reset attempted')
                time.sleep(0.1)
        print(json.dumps({'version': 1, 'oldPid': selected['original']['pid'],
            'oldStartTicks': selected['original']['startTicks'], 'pid': replacement.pid,
            'startTicks': replacement_ticks, 'ownerUid': replacement_root.stat().st_uid,
            'executable': os.readlink(replacement_root / 'exe'),
            'executableSha256': replacement_executable_sha, 'arguments': expected,
            'retainedResource': retained,
            'scope': 'actual pinned issuer stop and cold Serve; no Initialize or provider action'}))
    """, {"authority": tools["authority"], "original": original}, timeout=45))
    retain_direct_flow("actual-issuer-cold-process.json", observed)
    return observed


def run_direct_issuer_lifecycle(native, worker, tools, helper, authority):
    """Exercise the installed two cohorts and retain history across cold Serve."""
    bootstrap = authority["exported"]["bootstrap"]
    timing = bootstrap["timing_profile"]
    current = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {"kind": "current"}, "lifecycle-current")
    issued, previous = [], current["verified"]["observedAtSeconds"]
    for purpose in ("read", "write"):
        cohort = bootstrap[purpose + "_cohort"]
        exchange = exchange_direct_issuer(native, worker, tools, helper, bootstrap, {
            "kind": "issue", "input": {"cohort": cohort,
                "requested_not_after": str(previous + 2 * int(timing["maximum_lifetime"]))},
        }, "lifecycle-" + purpose, previous)
        issued.append(assert_direct_issuer_issue(exchange, cohort, timing))
        previous = exchange["verified"]["observedAtSeconds"]
        current = exchange
    process = cold_restart_direct_issuer(native, tools, authority["issuerProcess"])
    authority["issuerProcess"] = process
    cold = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {"kind": "current"}, "lifecycle-cold", previous)
    retained = assert_direct_issuer_cold_head(current, cold)
    result = {"version": 1, "configuredCohorts": 2, "issuedCohorts": issued,
        "coldProcess": process, "retainedHead": retained,
        "scope": "actual two-cohort TTL and cold metadata history; business renewal ratios and provider budget remain independent"}
    retain_direct_flow("actual-issuer-lifecycle.json", result)
    return result
