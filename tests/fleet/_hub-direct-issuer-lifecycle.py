"""Observe cohort issuance and terminal unresolved-clock-session refusal.

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


def observe_direct_issuer_cold_refusal(native, tools, original, signed_head, *,
                                       recovery_policy=None, issuer_public_key=None,
                                       require_unused_resolution=False, label="cold-refusal"):
    """Retain the real unresolved-session refusal on the same used resource."""
    if label not in {"cold-refusal", "cold-unreviewed"}:
        raise ValueError("cold refusal label differs from its two fixed observations")
    observed = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, signal, sqlite3, stat, subprocess, time
        from pathlib import Path

        root = Path('/var/lib/hybrid-authority')
        expected = [selected['authority'], 'serve', '--configuration', str(root / 'configuration.json')]
        if 'clockResolutionFile' in selected['original']:
            if selected['original']['clockResolutionFile'] != str(root / 'cold-recovery' / 'resolution.json'):
                raise ValueError('original recovered receipt coordinate differs')
            expected += ['--clock-resolution', selected['original']['clockResolutionFile']]
        process_root = Path('/proc') / str(selected['original']['pid'])
        def pin(directory):
            metadata = directory.stat()
            lifetime = (directory / 'stat').read_text().rpartition(') ')[2].split()[19]
            arguments = (directory / 'cmdline').read_bytes().split(b'\\x00')[:-1]
            with (directory / 'exe').open('rb') as source:
                executable_sha = hashlib.file_digest(source, 'sha256').hexdigest()
            if (metadata.st_uid != os.getuid() or arguments != [os.fsencode(value) for value in expected]
                    or executable_sha != selected['original']['executableSha256']):
                raise ValueError('issuer lifetime differs from its selected executable/arguments')
            return lifetime
        def resource():
            values = {}
            for name in ('signing-seed.key', 'publisher.key', 'renewal.key'):
                # Secret content never enters fixture memory, hashes or output.
                metadata = (root / name).lstat()
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                        or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
                        or not 0 < metadata.st_size <= 65536):
                    raise ValueError('retained issuer key custody differs')
                values[name] = {'device': metadata.st_dev, 'inode': metadata.st_ino,
                    'bytes': metadata.st_size, 'mtimeNs': str(metadata.st_mtime_ns),
                    'owner': metadata.st_uid, 'mode': stat.S_IMODE(metadata.st_mode), 'links': metadata.st_nlink}
            for name in ('configuration.json', 'issuer-public-key.hex'):
                descriptor = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as source:
                    metadata = os.fstat(source.fileno())
                    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
                            or metadata.st_size > 1048576):
                        raise ValueError('retained issuer configuration/key custody differs')
                    body = source.read(1048577)
                    values[name] = hashlib.sha256(body).hexdigest()
                    if name == 'configuration.json':
                        configuration = json.loads(body)
                        if configuration['format_version'] != (2 if selected['recoveryPolicy'] is not None else 1):
                            raise ValueError('configuration/journal format selection differs')
                        if selected['recoveryPolicy'] is not None and (
                                configuration['format_version'] != 2
                                or configuration.get('clock_recovery') != selected['recoveryPolicy']):
                            raise ValueError('actual fresh recovery policy differs from selected public pins')
                    elif selected['issuerPublicKey'] is not None and body != selected['issuerPublicKey'].encode():
                        raise ValueError('actual issuer public verifier changed')
            journal = (root / 'journal' / 'journal.sqlite').lstat()
            parent = (root / 'journal').lstat()
            if (not stat.S_ISREG(journal.st_mode) or journal.st_uid != os.getuid()
                    or stat.S_IMODE(journal.st_mode) != 0o600 or journal.st_nlink != 1
                    or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                    or stat.S_IMODE(parent.st_mode) != 0o700):
                raise ValueError('retained issuer journal is not the original regular resource')
            return {'files': values, 'journalDevice': journal.st_dev, 'journalInode': journal.st_ino,
                'journalParentDevice': parent.st_dev, 'journalParentInode': parent.st_ino}
        def history():
            # These are independent read-only bytes, not a permission clock or
            # an operator resolution. Serving retains its unresolved marker.
            connection = sqlite3.connect('file:' + str(root / 'journal' / 'journal.sqlite') + '?mode=ro',
                uri=True, timeout=2)
            try:
                connection.execute('BEGIN')
                application = connection.execute('PRAGMA application_id').fetchone()[0]
                version = connection.execute('PRAGMA user_version').fetchone()[0]
                if application != 0x414f534a or version != (3 if selected['recoveryPolicy'] is not None else 2):
                    raise ValueError('actual issuer SQL resource identity differs')
                marker_size = connection.execute('SELECT length(marker) FROM installation_marker WHERE singleton=1').fetchone()[0]
                sizes = connection.execute('SELECT length(publication),length(journal) FROM authority_state WHERE singleton=1').fetchone()
                history_sizes = connection.execute('SELECT length(publication),length(receipt),length(operation) '
                    'FROM publication_receipts LIMIT 1025').fetchall()
                if (marker_size > 4096 or sizes[0] > 1048576 or sizes[1] > 16384
                        or len(history_sizes) > 1024 or sum(sum(row) for row in history_sizes) > 16777216):
                    raise ValueError('issuer retained bytes exceed their observation bounds')
                marker = connection.execute('SELECT marker FROM installation_marker WHERE singleton=1').fetchone()[0]
                publication, journal = connection.execute(
                    'SELECT publication,journal FROM authority_state WHERE singleton=1').fetchone()
                floor, session = connection.execute('SELECT floor,session FROM authority_clock WHERE singleton=1').fetchone()
                ceiling = None
                if version == 3:
                    ceiling = connection.execute('SELECT ceiling FROM authority_clock WHERE singleton=1').fetchone()[0]
                    length = connection.execute('SELECT length(policy) FROM clock_recovery_policy WHERE singleton=1').fetchone()[0]
                    if length > 32768:
                        raise ValueError('retained recovery policy exceeds source bound')
                    policy = connection.execute('SELECT policy FROM clock_recovery_policy WHERE singleton=1').fetchone()[0]
                    if json.loads(policy) != selected['recoveryPolicy']:
                        raise ValueError('retained immutable recovery policy differs')
                    if selected['requireUnusedResolution'] and any(connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] != 0
                            for table in ('clock_resolutions', 'clock_resolution_consumptions')):
                        raise ValueError('positive cold scenario is not the first one-use resolution')
                rows = connection.execute('SELECT generation,publication,receipt,operation FROM publication_receipts '
                    'ORDER BY generation LIMIT 1025').fetchall()
                schema = connection.execute("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
                if (len(marker) > 4096 or len(publication) > 1048576 or len(journal) > 16384
                        or len(rows) > 1024 or not isinstance(session, str)
                        or len(session) != 64 or any(value not in '0123456789abcdef' for value in session)
                        or json.loads(journal) != selected['signedJournal']
                        or json.loads(marker) != selected['signedInstallation']
                        or int(floor) < int(selected['signedJournal']['clock_floor'])):
                    raise ValueError('actual retained issuer bytes differ from the signed live head')
                retained_bytes = sum(len(value) for row in rows for value in row[1:])
                if retained_bytes > 16777216:
                    raise ValueError('issuer retained history exceeds the observation bound')
                projected = [[row[0], *[hashlib.sha256(value).hexdigest() for value in row[1:]]] for row in rows]
                return {'markerSha256': hashlib.sha256(marker).hexdigest(),
                    'publicationSha256': hashlib.sha256(publication).hexdigest(),
                    'journalSha256': hashlib.sha256(journal).hexdigest(),
                    'historySha256': hashlib.sha256(json.dumps(projected, separators=(',', ':')).encode()).hexdigest(),
                    'schemaSha256': hashlib.sha256(json.dumps(schema, separators=(',', ':')).encode()).hexdigest(),
                    'historyRows': len(rows), 'historyBytes': retained_bytes, 'clockFloor': floor,
                    'clockCeiling': ceiling, 'journalFormat': version,
                    'clockSessionSha256': hashlib.sha256(session.encode()).hexdigest()}
            finally:
                connection.close()
        if pin(process_root) != selected['original']['startTicks']:
            raise ValueError('original issuer PID lifetime changed')
        retained, retained_history = resource(), history()
        descriptor = os.pidfd_open(selected['original']['pid'])
        try:
            if pin(process_root) != selected['original']['startTicks']:
                raise ValueError('original issuer lifetime changed before stop')
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
            if fields[19] != selected['original']['startTicks'] or time.monotonic() > deadline:
                raise ValueError('pinned issuer did not stop; no cold attempt launched')
            time.sleep(0.1)
        if resource() != retained or history() != retained_history:
            raise ValueError('issuer state changed during stop; no cold attempt launched')
        log_path = root / (selected['label'] + '.log')
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as log:
            replacement = subprocess.Popen(expected, stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True)
        replacement_root = Path('/proc') / str(replacement.pid)
        replacement_fields = (replacement_root / 'stat').read_text().rpartition(') ')[2].split()
        replacement_ticks = replacement_fields[19]
        if replacement_root.stat().st_uid != os.getuid():
            raise ValueError('cold startup child ownership differs')
        executable_observed_live = replacement_fields[0] != 'Z'
        if executable_observed_live:
            try:
                if pin(replacement_root) != replacement_ticks:
                    raise ValueError('cold startup PID lifetime changed')
            except (FileNotFoundError, ProcessLookupError):
                # This is our unreaped child, not an arbitrary reused PID. A
                # fast failed exec can lose /proc/exe before its wait receipt.
                fields = (replacement_root / 'stat').read_text().rpartition(') ')[2].split()
                if fields[0] != 'Z' or fields[19] != replacement_ticks:
                    raise
                executable_observed_live = False
        with Path(selected['authority']).open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != selected['original']['executableSha256']:
                raise ValueError('exact cold startup executable changed')
        try:
            exit_code = replacement.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise ValueError('cold startup remains live/unknown; no signal or automatic recovery')
        with log_path.open('rb') as log:
            body = log.read(65537)
        if (not exit_code or len(body) > 65536
                or b'unresolved clock session requires explicit reviewed operator resolution' not in body
                or resource() != retained or history() != retained_history):
            raise ValueError('cold startup has no exact unresolved-session refusal with retained history')
        print(json.dumps({'version': 1, 'oldPid': selected['original']['pid'],
            'oldStartTicks': selected['original']['startTicks'], 'attemptPid': replacement.pid,
            'attemptStartTicks': replacement_ticks, 'exitCode': exit_code,
            'executableObservedWhileLive': executable_observed_live,
            'executableSha256': selected['original']['executableSha256'],
            'logSha256': hashlib.sha256(body).hexdigest(), 'logBytes': len(body),
            'retainedResource': retained, 'retainedHistory': retained_history,
            'positiveColdRecovery': 'awaiting_independent_review' if selected['recoveryPolicy'] is not None else 'unsupported',
            'scope': 'actual unresolved-clock-session refusal; no clear, Initialize, recovery or provider settlement'}))
    """, {"authority": tools["authority"], "original": original,
            "signedJournal": signed_head["reply"]["current"]["journal"],
            "signedInstallation": signed_head["reply"]["current"]["installation"],
            "recoveryPolicy": recovery_policy, "issuerPublicKey": issuer_public_key,
            "requireUnusedResolution": require_unused_resolution, "label": label}, timeout=45))
    retain_direct_flow("actual-issuer-" + label + ".json", observed)
    return observed


def run_direct_issuer_terminal_refusal(native, worker, tools, helper, authority):
    """Stop the retained issuer only after the other runtime scenarios finish."""
    before = exchange_direct_issuer(native, worker, tools, helper,
        authority["exported"]["bootstrap"], {"kind": "current"}, "terminal-before-cold")
    observed = observe_direct_issuer_cold_refusal(native, tools, authority["issuerProcess"], before,
        recovery_policy=authority.get("clockRecoveryPolicy"),
        issuer_public_key=authority["exported"]["bootstrap"]["issuer_public_key"])
    authority["issuerProcessStopped"] = True
    return observed


def run_direct_issuer_lifecycle(native, worker, tools, helper, authority):
    """Exercise the installed two cohorts while retaining the live issuer."""
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
    result = {"version": 1, "configuredCohorts": 2, "issuedCohorts": issued,
        "positiveColdRecovery": "unsupported",
        "scope": "actual two-cohort TTL while issuer remains live; terminal cold refusal follows other scenarios"}
    retain_direct_flow("actual-issuer-lifecycle.json", result)
    return result


def _run_direct_clock_operator(native, tools, operation, *, expires_at=None,
                                uncertainty=None):
    """Retain one bounded source-CLI outcome; failures never authorize a retry."""
    root = "/var/lib/hybrid-authority/cold-recovery"
    if operation == "inspect":
        arguments = [tools["authority"], "inspect-clock-session", "--configuration",
            "/var/lib/hybrid-authority/configuration.json", "--output", root + "/plan.json"]
    elif operation == "resolve" and type(expires_at) is int and type(uncertainty) is int:
        arguments = [tools["authority"], "resolve-clock-session", "--configuration",
            "/var/lib/hybrid-authority/configuration.json", "--review", root + "/review.json",
            "--output", root + "/resolution.json"]
    else:
        raise ValueError("clock operator operation or original deadline differs")
    result = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path('/var/lib/hybrid-authority/cold-recovery')
        if selected['operation'] == 'inspect':
            root.mkdir(mode=0o700, exist_ok=False)
        descriptors = {}
        for name in ('stdout', 'stderr'):
            descriptors[name] = os.open(root / (selected['operation'] + '.' + name),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        process = None
        category, exit_code = 'launch_unknown', None
        started = time.time_ns()
        try:
            allowance = 5.0
            if selected['expiresAt'] is not None:
                allowance = min(allowance, selected['expiresAt'] - selected['uncertainty'] - time.time())
                if allowance <= 0:
                    raise ValueError('original review deadline elapsed')
            deadline = time.monotonic() + allowance
            with os.fdopen(descriptors.pop('stdout'), 'wb') as output, \
                    os.fdopen(descriptors.pop('stderr'), 'wb') as error:
                process = subprocess.Popen(selected['arguments'], stdin=subprocess.DEVNULL,
                    stdout=output, stderr=error, start_new_session=True)
                category = 'command_unknown'
                while process.poll() is None:
                    if (os.fstat(output.fileno()).st_size > 65536
                            or os.fstat(error.fileno()).st_size > 65536):
                        category = 'output_overflow_unknown'
                        break
                    if time.monotonic() >= deadline:
                        category = 'deadline_unknown'
                        break
                    time.sleep(0.01)
                if process.poll() is None:
                    # Only this owned short-lived operator child is stopped.
                    # A possible committed resolution remains unknown, never undone.
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1)
                else:
                    category = 'success' if process.returncode == 0 else 'refused_or_unknown'
                exit_code = process.returncode
                output.flush()
                error.flush()
                os.fsync(output.fileno())
                os.fsync(error.fileno())
        except (OSError, ValueError):
            pass
        finally:
            for descriptor in descriptors.values():
                os.close(descriptor)
        retained = {}
        for name in ('stdout', 'stderr'):
            with (root / (selected['operation'] + '.' + name)).open('rb') as source:
                size = os.fstat(source.fileno()).st_size
                body = source.read(65537)
            retained[name] = {'bytes': size, 'inspectedBytes': len(body),
                'sha256': hashlib.sha256(body).hexdigest() if size <= 65536 else None}
            if size > 65536:
                category = 'output_overflow_unknown'
        if category == 'success' and any(value['bytes'] != 0 for value in retained.values()):
            category = 'unexpected_output_unknown'
        summary = {'version': 1, 'operation': selected['operation'], 'category': category,
            'exitCode': exit_code, 'startedUnixNs': str(started),
            'completedUnixNs': str(time.time_ns()), 'outputs': retained,
            'scope': 'one source operator invocation; no retry or rollback on unknown'}
        descriptor = os.open(root / (selected['operation'] + '-result.json'),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(summary, output, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps(summary))
    """, {"operation": operation, "arguments": arguments,
            "expiresAt": expires_at, "uncertainty": uncertainty}, timeout=10))
    retain_direct_flow("issuer-clock-" + operation + ".json", result)
    if result["category"] != "success" or result["exitCode"] != 0:
        raise RuntimeError("clock operator has no positive acknowledgment; retained without retry")
    return result


def _assert_direct_clock_plan(plan, policy, before, refusal):
    """Join the actual source-encoded original to independent retained facts."""
    fields = {"version", "file", "expected_head", "expected_session", "expected_floor",
        "expected_ceiling", "policy_digest", "successor_session", "nonce", "issued_at", "expires_at"}
    history, resource = refusal["retainedHistory"], refusal["retainedResource"]
    policy_bytes = json.dumps(policy, ensure_ascii=False, separators=(",", ":")).encode()
    if (set(plan) != fields or type(plan["version"]) is not int or plan["version"] != 1
            or plan["expected_head"] != before["reply"]["current"]
            or plan["expected_floor"] != history["clockFloor"]
            or plan["expected_ceiling"] != history["clockCeiling"]
            or hashlib.sha256(plan["expected_session"].encode()).hexdigest() != history["clockSessionSha256"]
            or plan["policy_digest"] != hashlib.sha256(policy_bytes).hexdigest()
            or plan["file"] != {"device": str(resource["journalDevice"]),
                "inode": str(resource["journalInode"]),
                "parent_device": str(resource["journalParentDevice"]),
                "parent_inode": str(resource["journalParentInode"])}):
        raise ValueError("clock plan differs from the actual pinned inactive resource")
    for name in ("expected_session", "successor_session", "nonce", "policy_digest"):
        if not isinstance(plan[name], str) or not re.fullmatch(r"[0-9a-f]{64}", plan[name]):
            raise ValueError("clock plan commitment differs from its source schema")
    for name in ("expected_floor", "expected_ceiling", "issued_at", "expires_at"):
        if not isinstance(plan[name], str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", plan[name]):
            raise ValueError("clock plan time differs from its canonical source integer")
        if int(plan[name]) > 2**63 - 1:
            raise ValueError("clock plan time exceeds the shared signed integer range")
    if (plan["successor_session"] == plan["expected_session"]
            or not 0 < int(plan["expires_at"]) - int(plan["issued_at"]) <= int(policy["maximum_review_seconds"])
            or int(plan["expected_ceiling"]) < int(plan["expected_floor"])):
        raise ValueError("clock plan successor or finite lifetime differs")


def _assert_direct_clock_review_bytes(review_bytes, plan_bytes, policy):
    """Refuse changed/noncanonical signed wire bytes without rewriting them.

    The plan is exact bounded output of the source inspect encoder. Embedding
    those original bytes avoids reordering nested typed fields. Only the fixed
    ClockRecoveryReview fields are encoded here, in their declared serde order;
    the Rust resolver still authenticates signature and all semantic invariants.
    """
    review = json.loads(review_bytes)
    if (not isinstance(review, dict)
            or set(review) != {"version", "plan", "plan_digest", "reviewer_key_id", "signature"}
            or type(review["version"]) is not int or review["version"] != 1
            or review["plan"] != json.loads(plan_bytes)
            or review["plan_digest"] != hashlib.sha256(plan_bytes).hexdigest()
            or review["reviewer_key_id"] != policy["reviewer_key_id"]
            or not isinstance(review["signature"], str)
            or not re.fullmatch(r"[0-9a-f]{128}", review["signature"])):
        raise ValueError("independent clock review changed the original, reviewer or signature shape")
    def scalar(value):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    expected = (b'{"version":1,"plan":' + plan_bytes
        + b',"plan_digest":' + scalar(review["plan_digest"])
        + b',"reviewer_key_id":' + scalar(review["reviewer_key_id"])
        + b',"signature":' + scalar(review["signature"]) + b'}')
    if review_bytes != expected:
        raise ValueError("independent clock review is not the exact canonical source wire encoding")
    return review


def _observe_direct_clock_recovery(native, tools, process, refusal, plan, review_digest):
    """Read one positive consumption and original history under the live owner."""
    result = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, sqlite3, stat
        from pathlib import Path

        root = Path('/var/lib/hybrid-authority')
        process = selected['process']
        owner = Path('/proc') / str(process['pid'])
        def pin():
            fields = (owner / 'stat').read_text().rpartition(') ')[2].split()
            if (fields[0] == 'Z' or fields[19] != process['startTicks']
                    or owner.stat().st_uid != os.getuid()
                    or os.readlink(owner / 'exe') != process['executable']):
                raise ValueError('recovered issuer owner changed')
            return fields[19]
        pin()
        resource = selected['resource']
        for name, expected in resource['files'].items():
            metadata = (root / name).lstat()
            if isinstance(expected, dict):
                actual = {'device': metadata.st_dev, 'inode': metadata.st_ino,
                    'bytes': metadata.st_size, 'mtimeNs': str(metadata.st_mtime_ns),
                    'owner': metadata.st_uid, 'mode': stat.S_IMODE(metadata.st_mode), 'links': metadata.st_nlink}
                if not stat.S_ISREG(metadata.st_mode) or actual != expected:
                    raise ValueError('original secret custody changed')
            else:
                descriptor = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as source:
                    opened = os.fstat(source.fileno())
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                            or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                            or not 0 < opened.st_size <= 1048576
                            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)):
                        raise ValueError('original public file custody changed')
                    body = source.read(1048577)
                    finished = os.fstat(source.fileno())
                current = (root / name).lstat()
                if ((finished.st_size, finished.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns)
                        or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
                        or len(body) != opened.st_size or hashlib.sha256(body).hexdigest() != expected):
                    raise ValueError('original public configuration or verifier changed')
        journal = root / 'journal' / 'journal.sqlite'
        metadata, parent = journal.lstat(), journal.parent.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) != 0o700
                or metadata.st_dev != resource['journalDevice'] or metadata.st_ino != resource['journalInode']
                or parent.st_dev != resource['journalParentDevice'] or parent.st_ino != resource['journalParentInode']):
            raise ValueError('original journal resource was replaced')
        connection = sqlite3.connect('file:' + str(journal) + '?mode=ro', uri=True, timeout=2)
        try:
            connection.execute('BEGIN')
            if (connection.execute('PRAGMA application_id').fetchone()[0] != 0x414f534a
                    or connection.execute('PRAGMA user_version').fetchone()[0] != 3):
                raise ValueError('recovered resource is not freshly initialized format 3')
            floor, session, ceiling = connection.execute(
                'SELECT floor,session,ceiling FROM authority_clock WHERE singleton=1').fetchone()
            counts = [connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                for table in ('clock_resolutions', 'clock_resolution_consumptions')]
            review_length = connection.execute('SELECT length(review) FROM clock_resolutions WHERE plan_digest=?',
                (selected['reviewDigest'],)).fetchone()[0]
            if not 0 < review_length <= 32768:
                raise ValueError('actual retained review exceeds source bound')
            retained_review, previous, successor = connection.execute(
                'SELECT review,previous_session,successor_session FROM clock_resolutions WHERE plan_digest=?',
                (selected['reviewDigest'],)).fetchone()
            if (counts != [1, 1] or len(retained_review) > 32768
                    or json.loads(retained_review)['plan'] != selected['plan']
                    or previous != selected['plan']['expected_session']
                    or successor != session or successor != selected['plan']['successor_session']
                    or connection.execute('SELECT plan_digest FROM clock_resolution_consumptions').fetchone()[0]
                        != selected['reviewDigest']):
                raise ValueError('actual one-use resolution/consumption differs from independent original')
            sizes = connection.execute('SELECT length(publication),length(receipt),length(operation) '
                'FROM publication_receipts LIMIT 1025').fetchall()
            if len(sizes) > 1024 or sum(sum(row) for row in sizes) > 16777216:
                raise ValueError('retained issuance history exceeds observation bounds')
            rows = connection.execute('SELECT generation,publication,receipt,operation FROM publication_receipts '
                'ORDER BY generation LIMIT 1025').fetchall()
            projected = [[row[0], *[hashlib.sha256(value).hexdigest() for value in row[1:]]] for row in rows]
            history_digest = hashlib.sha256(json.dumps(projected, separators=(',', ':')).encode()).hexdigest()
            if (history_digest != selected['history']['historySha256']
                    or int(floor) < int(selected['history']['clockFloor'])
                    or int(ceiling) < int(selected['history']['clockCeiling'])):
                raise ValueError('recovered issuer rolled back retained history or clock bounds')
        finally:
            connection.close()
        pin()
        print(json.dumps({'version': 1, 'pid': process['pid'], 'startTicks': process['startTicks'],
            'journalDevice': metadata.st_dev, 'journalInode': metadata.st_ino,
            'historySha256': history_digest, 'historyRows': len(rows),
            'clockFloor': floor, 'clockCeiling': ceiling,
            'successorSessionSha256': hashlib.sha256(session.encode()).hexdigest(),
            'resolutionCount': counts[0], 'consumptionCount': counts[1],
            'scope': 'actual one-use consumption and original history; no provider settlement'}))
    """, {"process": process, "resource": refusal["retainedResource"],
            "history": refusal["retainedHistory"], "plan": plan,
            "reviewDigest": review_digest}, timeout=10))
    retain_direct_flow("actual-issuer-cold-consumption.json", result)
    return result


def run_direct_issuer_cold_recovery(native, worker, tools, helper, authority,
                                    recovery_policy, independent_review, *,
                                    maximum_wait_seconds):
    """Recover one fresh format-3 resource through an independent finite review.

    The reviewer receives the exact canonical source plan and public policy bytes,
    and returns canonical signed review bytes. It owns opaque source-CLI signing;
    this fixture has no reviewer seed coordinate or signing implementation. The
    callback must fail by its supplied monotonic deadline. No parent approval is
    inferred, no plan is refreshed, and a failed/unknown resolution is not retried.
    """
    import time

    bootstrap = authority["exported"]["bootstrap"]
    timing = bootstrap["timing_profile"]
    policy = validate_direct_clock_recovery_policy(recovery_policy, bootstrap["issuer_key_id"],
        int(bootstrap["clock_uncertainty"]), int(authority["issuer"]["configuration"]["clock_commit_latency"]), timing)
    uncertainty = int(policy["clock_uncertainty"]) + int(policy["clock_commit_latency"]) + 1
    if (not callable(independent_review) or type(maximum_wait_seconds) is not int
            or not 0 < maximum_wait_seconds <= int(timing["maximum_lifetime"]) + 2 * uncertainty + 1):
        raise ValueError("cold recovery requires an independent reviewer and finite existing-lifetime wait")
    before = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {"kind": "current"}, "cold-before")
    refusal = observe_direct_issuer_cold_refusal(native, tools, authority["issuerProcess"], before,
        recovery_policy=policy, issuer_public_key=bootstrap["issuer_public_key"],
        require_unused_resolution=True, label="cold-unreviewed")
    authority["issuerProcessStopped"] = True
    eligible = max(int(refusal["retainedHistory"]["clockCeiling"]),
        int(before["reply"]["current"]["journal"]["largest_issued_expiry"])) + uncertainty
    waiting = json.loads(direct_guest_python(native, tools["python"], """
        import time
        deadline = time.monotonic() + selected['maximumWait']
        while int(time.time()) < selected['eligibleAt']:
            if time.monotonic() >= deadline:
                raise ValueError('retained admission bounds outlive finite cold wait')
            time.sleep(0.05)
        print(json.dumps({'version': 1, 'observedAt': str(int(time.time())),
            'earliestRequired': str(selected['eligibleAt'] - selected['uncertainty']),
            'scope': 'actual Native clock; no manufactured future sample'}))
    """, {"eligibleAt": eligible, "maximumWait": maximum_wait_seconds,
            "uncertainty": uncertainty}, timeout=maximum_wait_seconds + 2))
    retain_direct_flow("issuer-clock-eligible.json", waiting)

    _run_direct_clock_operator(native, tools, "inspect")
    root = "/var/lib/hybrid-authority/cold-recovery"
    plan_bytes = read_direct_guest_file(native, tools["python"], root + "/plan.json", 32768)
    plan = json.loads(plan_bytes)
    _assert_direct_clock_plan(plan, policy, before, refusal)
    # Convert remaining Native time to a local monotonic deadline. Host UTC is
    # never compared with the VM clock, nor used as a fabricated permission sample.
    sample_started = time.monotonic()
    remaining = float(direct_guest_python(native, tools["python"], """
        import time
        print(max(0.0, selected['expiresAt'] - selected['uncertainty'] - time.time()))
    """, {"expiresAt": int(plan["expires_at"]), "uncertainty": uncertainty}, timeout=2))
    if remaining <= 0:
        raise ValueError("actual clock plan expired before independent review")
    review_deadline = sample_started + min(remaining, int(policy["maximum_review_seconds"]))
    policy_bytes = json.dumps(policy, ensure_ascii=False, separators=(",", ":")).encode()
    retain_direct_flow("issuer-clock-plan.json", plan)
    review_bytes = independent_review(plan_bytes, policy_bytes, review_deadline)
    if (time.monotonic() >= review_deadline or not isinstance(review_bytes, bytes)
            or not 0 < len(review_bytes) <= 32768):
        raise ValueError("independent clock review absent, expired or oversized")
    review = _assert_direct_clock_review_bytes(review_bytes, plan_bytes, policy)
    install_direct_guest_file(native, tools["python"], root + "/review.json", review_bytes)
    retain_direct_flow("issuer-clock-review.json", review)
    _run_direct_clock_operator(native, tools, "resolve", expires_at=int(plan["expires_at"]),
        uncertainty=uncertainty)
    resolution_bytes = read_direct_guest_file(native, tools["python"], root + "/resolution.json", 32768)
    resolution = json.loads(resolution_bytes)
    if (set(resolution) != {"version", "review", "observed_at", "uncertainty"}
            or resolution["version"] != 1 or resolution["review"] != review
            or resolution["uncertainty"] != str(uncertainty)
            or int(resolution["observed_at"]) - uncertainty < eligible - uncertainty
            or int(resolution["observed_at"]) + uncertainty >= int(plan["expires_at"])):
        raise ValueError("actual resolution has no positive exact original and qualified interval")
    retain_direct_flow("issuer-clock-resolution.json", resolution)
    process = start_external_issuer(native, tools["python"], tools["authority"],
        clock_resolution_file=root + "/resolution.json", startup_label="cold-recovered",
        recovery_expires_at=int(plan["expires_at"]), recovery_uncertainty=uncertainty)
    if (process["executableSha256"] != refusal["executableSha256"]
            or (process["pid"], process["startTicks"]) == (refusal["oldPid"], refusal["oldStartTicks"])):
        raise ValueError("recovered owner is not a fresh lifetime of the exact selected executable")
    authority["issuerProcess"] = process
    authority["issuerProcessStopped"] = False
    authority["clockRecoveryPolicy"] = policy
    consumption = _observe_direct_clock_recovery(native, tools, process, refusal, plan, review["plan_digest"])
    after = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {"kind": "current"}, "cold-after")
    continuity = assert_direct_issuer_cold_head(before, after)
    issued, previous = [], after["verified"]["observedAtSeconds"]
    for purpose in ("read", "write"):
        exchange = exchange_direct_issuer(native, worker, tools, helper, bootstrap, {
            "kind": "issue", "input": {"cohort": bootstrap[purpose + "_cohort"],
                "requested_not_after": str(previous + int(timing["maximum_lifetime"]))},
        }, "cold-recovered-" + purpose, previous)
        issued.append(assert_direct_issuer_issue(exchange, bootstrap[purpose + "_cohort"], timing))
        previous = exchange["verified"]["observedAtSeconds"]
    result = {"version": 1, "positiveColdRecovery": "observed",
        "oldProcess": {"pid": refusal["oldPid"], "startTicks": refusal["oldStartTicks"]},
        "newProcess": process, "continuity": continuity, "consumption": consumption,
        "issuedCohorts": issued, "planSha256": hashlib.sha256(plan_bytes).hexdigest(),
        "resolutionSha256": hashlib.sha256(resolution_bytes).hexdigest(),
        "scope": "one independently reviewed cold issuer recovery; no provider or full-fleet acceptance"}
    retain_direct_flow("actual-issuer-cold-recovery.json", result)
    return result
