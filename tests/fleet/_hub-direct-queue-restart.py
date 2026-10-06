"""Interrupt one retained isolated queue read without repeating its mutations.

The rendezvous is an authenticated durable Begin without Finish. It does not
claim that the read was active, that bytes had reached the provider, or that a
local ACK was settled. The ordinary mixed/pure qualification is a separate run.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import time


def start_direct_restart_original(worker, tools, origin, control_key_file,
                                  identity_file, selector, source):
    """Launch a single actual bulk original and retain its exact driver lifetime."""
    if (source["metadata"] is not False or source["byte_size"] != 2147483648
            or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"])):
        raise ValueError("queue restart requires the selected actual 2 GiB bulk file")
    run_id = os.urandom(32).hex()
    root = "/var/lib/hybrid-worker/operator/restart-" + run_id
    arguments = [tools["node"], tools["qualificationDriver"], "--origin", origin,
        "--control-key-file", control_key_file, "--identity-file", identity_file,
        "--manifest-file", root + "/manifest.json", "--output-dir", root + "/evidence",
        "--run-id", run_id, "--wait-seconds", "600"]
    manifest = {"provider": {"kind": "external", "selector": selector},
                "objects": [{"file": source["file"], "metadata": False}]}
    return json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path

        root = Path(selected['root'])
        root.mkdir(mode=0o700, exist_ok=False)
        os.umask(0o077)
        with (root / 'manifest.json').open('x') as output:
            json.dump(selected['manifest'], output, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        environment = dict(os.environ)
        environment['NODE_EXTRA_CA_CERTS'] = '/etc/ssl/certs/ca-certificates.crt'
        with (root / 'stdout.log').open('xb') as stdout, (root / 'stderr.log').open('xb') as stderr:
            process = subprocess.Popen(selected['arguments'], env=environment,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        directory = Path('/proc') / str(process.pid)
        fields = (directory / 'stat').read_text().rpartition(') ')[2].split()
        if (directory.stat().st_uid != os.getuid()
                or (directory / 'cmdline').read_bytes().split(b'\\x00')[:-1]
                    != [os.fsencode(value) for value in selected['arguments']]):
            raise ValueError('restart driver lifetime differs from selected process')
        print(json.dumps({'version': 1, 'runId': selected['runId'], 'root': str(root),
            'pid': process.pid, 'ownerUid': directory.stat().st_uid, 'startTicks': fields[19],
            'arguments': selected['arguments'], 'startedUnixNs': str(time.time_ns()),
            'driverSha256': hashlib.sha256(Path(selected['driver']).read_bytes()).hexdigest()}))
    """, {"root": root, "manifest": manifest, "arguments": arguments,
            "runId": run_id, "driver": tools["qualificationDriver"]}))


def observe_direct_restart_readiness(worker, tools, driver):
    """Observe exact child custody, reading only bounded stderr after an owned exit."""
    pin = {name: driver[name] for name in ("runId", "root", "pid", "ownerUid", "startTicks")}
    if (not re.fullmatch(r"[0-9a-f]{64}", pin["runId"])
            or Path(pin["root"]).name != "restart-" + pin["runId"]
            or not Path(pin["root"]).is_absolute()
            or type(pin["pid"]) is not int or pin["pid"] <= 0
            or type(pin["ownerUid"]) is not int or pin["ownerUid"] < 0
            or not re.fullmatch(r"[1-9][0-9]{0,19}", pin["startTicks"])):
        raise ValueError("restart readiness requires the recorded child identity")
    unknown = {"version": 1, "runId": pin["runId"], "pid": pin["pid"],
        "ownerUid": pin["ownerUid"], "startTicks": pin["startTicks"],
        "category": "readiness_unknown", "ready": False, "custody": False,
        "processState": None, "exitCode": None, "statBytes": None,
        "statBoundBytes": 4096, "statEof": None, "outputs": {},
        "originalBoundBytes": 524288,
        "stderrReadBytes": 0, "stderrBoundBytes": 65536, "stderrEof": None,
        "stderrCategory": "not_read"}
    try:
        body = direct_guest_python(worker, tools["python"], """
            import os, stat

            result = dict(selected['unknown'])
            pin = selected['pin']
            descriptors = []

            def private_directory(path, parent=None):
                descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent)
                descriptors.append(descriptor)
                facts = os.fstat(descriptor)
                if facts.st_uid != pin['ownerUid'] or stat.S_IMODE(facts.st_mode) != 0o700:
                    raise ValueError('output custody unknown')
                return descriptor

            def output_metadata(parent, name):
                try:
                    facts = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    return {'present': False, 'custody': None, 'byteSize': None}
                if (not stat.S_ISREG(facts.st_mode) or facts.st_uid != pin['ownerUid']
                        or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_nlink != 1):
                    raise ValueError('output custody unknown')
                return {'present': True, 'custody': True, 'byteSize': str(facts.st_size)}

            def process_identity():
                directory = '/proc/' + str(pin['pid'])
                try:
                    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                except FileNotFoundError:
                    return None
                try:
                    owner = os.fstat(descriptor).st_uid
                    if owner != pin['ownerUid'] or owner != os.getuid():
                        result['category'] = 'driver_owner_changed'
                        raise ValueError('process custody differs')
                    status = os.open('stat', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                    with os.fdopen(status, 'rb') as source:
                        raw = source.read(4097)
                    result['statBytes'] = len(raw)
                    result['statEof'] = len(raw) <= 4096
                    fields = raw.rpartition(b') ')[2].split()
                    if (len(raw) > 4096 or len(fields) < 50
                            or raw.split(b' ', 1)[0] != str(pin['pid']).encode()):
                        raise ValueError('bounded process status unavailable')
                    if fields[19].decode('ascii') != pin['startTicks']:
                        result['category'] = 'driver_reused'
                        raise ValueError('process lifetime differs')
                    state = fields[0].decode('ascii')
                    if state not in ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'x', 'K', 'W', 'P', 'I'):
                        raise ValueError('process state unknown')
                    return state, int(fields[49])
                except FileNotFoundError:
                    return None
                finally:
                    os.close(descriptor)

            def terminal_stderr(root):
                # Classify only known public driver errors, never return raw
                # bytes. An EOF here describes the private file, not a provider.
                try:
                    before = os.stat('stderr.log', dir_fd=root, follow_symlinks=False)
                    descriptor = os.open('stderr.log', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=root)
                    with os.fdopen(descriptor, 'rb') as source:
                        opened = os.fstat(source.fileno())
                        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != pin['ownerUid']
                                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                            raise ValueError('stderr custody changed')
                        raw = source.read(65537)
                        after = os.fstat(source.fileno())
                    result['stderrReadBytes'] = len(raw)
                    result['stderrEof'] = len(raw) <= 65536
                    if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        result['stderrCategory'] = 'stderr_changed'
                    elif len(raw) > 65536:
                        result['stderrCategory'] = 'stderr_bound_exceeded'
                    else:
                        categories = (
                            ('private_input_refused', b'Private inputs must be owner-only regular files within bounds.'),
                            ('control_key_refused', b'Malformed control key.'),
                            ('runtime_identity_refused', b'Actual inspected identity does not match origin.'),
                            ('source_refused', b'Payload must be an owned nonempty regular file.'),
                            ('source_changed', b'Payload changed during source inspection.'),
                            ('control_acknowledgement_unknown', b'Operation lacks an exact acknowledgement; evidence retained without replay.'),
                        )
                        matched = {category for category, message in categories if message in raw}
                        result['stderrCategory'] = (next(iter(matched)) if len(matched) == 1 else
                            'unclassified' if not matched else 'multiple_known_errors')
                except (OSError, ValueError):
                    result['stderrCategory'] = 'stderr_custody_unknown'

            try:
                if pin['ownerUid'] != os.getuid():
                    result['category'] = 'driver_owner_changed'
                    raise ValueError('recorded owner differs')
                process_identity()
                result['category'] = 'output_custody_unknown'
                root = private_directory(pin['root'])
                for name in ('stdout.log', 'stderr.log'):
                    result['outputs'][name] = output_metadata(root, name)
                    if not result['outputs'][name]['present']:
                        raise ValueError('recorded output missing')
                try:
                    evidence = private_directory('evidence', root)
                except FileNotFoundError:
                    original = {'present': False, 'custody': None, 'byteSize': None}
                else:
                    original = output_metadata(evidence, 'original.json')
                if (original['present'] and not
                        0 < int(original['byteSize']) <= result['originalBoundBytes']):
                    raise ValueError('original metadata outside bounds')
                result['outputs']['original.json'] = original

                # Recheck the exact lifetime after file metadata observation. A
                # completed child may still have a valid original to inspect.
                result['category'] = 'readiness_unknown'
                identity = process_identity()
                state, wait_status = identity if identity is not None else (None, None)
                result['custody'] = identity is not None
                result['processState'] = state
                if state == 'Z' and (os.WIFEXITED(wait_status) or os.WIFSIGNALED(wait_status)):
                    result['exitCode'] = os.waitstatus_to_exitcode(wait_status)
                result['ready'] = original['present']
                result['category'] = ('original_ready' if result['ready'] else
                    'driver_missing' if identity is None else
                    'driver_exited_before_original' if state in ('Z', 'X', 'x') else
                    'waiting_for_original')
                if (state == 'Z' or identity is None) and not result['ready']:
                    terminal_stderr(root)
            except FileNotFoundError:
                if result['category'] != 'output_custody_unknown':
                    result['category'] = 'driver_missing'
            except (OSError, ValueError, UnicodeError):
                pass
            finally:
                for descriptor in reversed(descriptors):
                    os.close(descriptor)
            print(json.dumps(result, separators=(',', ':')))
        """, {"pin": pin, "unknown": unknown}, timeout=10)
        if len(body.encode()) > 4096:
            return unknown
        return json.loads(body)
    except Exception:
        # A failed guest observation is not an observed child exit. Never relay
        # raw channel errors or private child output into the controller log.
        return unknown


def direct_restart_readiness(worker, tools, driver):
    """Retain safe failure facts before stopping the original readiness wait."""
    observation = observe_direct_restart_readiness(worker, tools, driver)
    if observation["category"] not in ("waiting_for_original", "original_ready"):
        retain_direct_flow("queue-restart-readiness-failure.json", observation)
        raise AssertionError("queue restart child readiness observation refused")
    return observation["ready"]


def direct_restart_records(observation, run_id, source, identity):
    """Select only actual authenticated Inspect records for the exact original."""
    records = []
    object_id = None
    for selected in observation["retained"]["files"]:
        if not selected["name"].endswith("-inspect-capture.json"):
            continue
        body = (Path(observation["retained"]["directory"]) / selected["name"]).read_bytes()
        if hashlib.sha256(body).hexdigest() != selected["sha256"]:
            raise ValueError("retained queue inspection changed")
        result = _closed_review_json(body)["result"]
        original = result["original"]
        if (original["runId"] != run_id
                or original["sourceDigest"] != identity["sourceDigest"]
                or original["scriptVersion"] != identity["scriptVersion"]
                or original["publicOrigin"] != identity["publicOrigin"]
                or len(original["objects"]) != 1):
            raise ValueError("queue inspection describes a different installed original")
        plan = original["objects"][0]
        if (plan["metadata"] is not False or int(plan["byteSize"]) != source["byte_size"]
                or plan["expectedSha256"] != source["sha256"]
                or result["objectId"] != plan["objectId"]
                or (object_id is not None and object_id != plan["objectId"])):
            raise ValueError("queue inspection does not match the actual selected source")
        object_id = plan["objectId"]
        if result["closed"] is None:
            continue
        for record in result["attempts"]:
            nonce = record["attempt"]["nonce"]
            if not re.fullmatch(r"[0-9a-f]{64}", nonce):
                raise ValueError("retained queue attempt identity is invalid")
            records.append({"objectId": object_id, "attemptNonce": nonce,
                "attempt": record["attempt"], "receipt": record["receipt"],
                "inspectionSha256": selected["sha256"]})
    return records


def crash_direct_recorded_runtime(worker, tools, process, counters):
    """Kill only the observed workerd child and dispose its recorded runner."""
    runtime = counters["processes"]["workerd"]
    return json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, signal, stat, time
        from pathlib import Path

        def identity(pid):
            directory = Path('/proc') / str(pid)
            try:
                fields = (directory / 'stat').read_text().rpartition(') ')[2].split()
                if fields[0] == 'Z':
                    return {'state': 'Z', 'ppid': int(fields[1]), 'start': fields[19]}
                return {'state': fields[0], 'ppid': int(fields[1]), 'start': fields[19],
                    'uid': directory.stat().st_uid, 'exe': os.readlink(directory / 'exe'),
                    'argv': (directory / 'cmdline').read_bytes().split(b'\\x00')[:-1]}
            except FileNotFoundError:
                return None

        runner, runtime = selected['runner'], selected['runtime']
        parent = identity(runner['pid'])
        child = identity(runtime['pid'])
        if (parent is None or child is None or parent['state'] == 'Z' or child['state'] == 'Z'
                or parent['start'] != runner['startTicks']
                or parent['uid'] != runner['ownerUid']
                or parent['argv'] != [os.fsencode(value) for value in runner['arguments']]
                or child['start'] != str(runtime['start_ticks'])
                or child['uid'] != runner['ownerUid'] or child['ppid'] != runner['pid']
                or child['exe'] != runtime['exe']
                or child['exe'] != str(Path(selected['workerd']).resolve(strict=True))
                or hashlib.sha256(Path(runner['configurationFile']).read_bytes()).hexdigest()
                    != runner['configurationSha256']):
            raise ValueError('recorded runtime or runner identity changed before crash')
        killed_at = time.time_ns()
        os.kill(runtime['pid'], signal.SIGKILL)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = identity(runtime['pid'])
            if current is None or current['start'] != str(runtime['start_ticks']) or current['state'] == 'Z':
                break
            time.sleep(0.1)
        else:
            raise ValueError('exact runtime crash did not complete')
        parent = identity(runner['pid'])
        if parent is not None and parent['state'] != 'Z':
            if (parent['start'] != runner['startTicks'] or parent['uid'] != runner['ownerUid']
                    or parent['argv'] != [os.fsencode(value) for value in runner['arguments']]):
                raise ValueError('runner changed after runtime crash; no signal issued')
            os.kill(runner['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            parent = identity(runner['pid'])
            if parent is None or parent['start'] != runner['startTicks'] or parent['state'] == 'Z':
                break
            time.sleep(0.1)
        else:
            raise ValueError('runner disposal failed; no broader kill issued')
        socket = Path('/var/lib/hybrid-worker/acceptance-control.sock')
        if socket.exists():
            metadata = socket.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ValueError('crashed runner socket custody changed')
            socket.unlink()
        print(json.dumps({'version': 1, 'runtimePid': runtime['pid'],
            'runtimeStartTicks': str(runtime['start_ticks']), 'runnerPid': runner['pid'],
            'runnerStartTicks': runner['startTicks'], 'runtimeSignal': 'SIGKILL',
            'killedAtUnixNs': str(killed_at), 'observedGoneAtUnixNs': str(time.time_ns()),
            'configurationSha256': runner['configurationSha256'], 'persistenceRemoved': False}))
    """, {"runner": process, "runtime": runtime, "workerd": tools["workerd"]}, timeout=75))


def finish_direct_restart_driver(worker, tools, driver):
    """Wait for or cancel only the original driver, retaining its existing evidence."""
    outcome = json.loads(direct_guest_python(worker, tools["python"], """
        import os, signal, time
        from pathlib import Path

        path = Path('/proc') / str(selected['pid'])
        def live():
            try:
                fields = (path / 'stat').read_text().rpartition(') ')[2].split()
            except FileNotFoundError:
                return False
            if fields[19] != selected['startTicks']:
                return False
            if fields[0] == 'Z':
                return False
            if (path.stat().st_uid != selected['ownerUid']
                    or (path / 'cmdline').read_bytes().split(b'\\x00')[:-1]
                        != [os.fsencode(value) for value in selected['arguments']]):
                raise ValueError('driver identity changed; no signal issued')
            return True
        deadline = time.monotonic() + 30
        while live() and time.monotonic() < deadline:
            time.sleep(0.1)
        signalled = live()
        if signalled:
            os.kill(selected['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 45
        while live() and time.monotonic() < deadline:
            time.sleep(0.1)
        if live():
            raise ValueError('original driver remains live; no broad kill issued')
        print(json.dumps({'version': 1, 'pid': selected['pid'], 'startTicks': selected['startTicks'],
            'signal': 'SIGTERM' if signalled else None, 'exitCode': None,
            'scope': 'original driver lifetime ended; orphan exit status unavailable'}))
    """, driver, timeout=90))
    retained = retain_direct_qualification_files(
        worker, tools["python"], driver["root"] + "/evidence", driver["runId"], "interrupted-driver",
    )
    return {"process": outcome, "retained": retained}


def run_direct_queue_restart(worker, tools, process, identity, control_key_file,
                             selector, source):
    """Recover a real closed bulk original across a consumer crash, preserving unknowns."""
    driver = start_direct_restart_original(worker, tools, tools["workerUrl"],
        control_key_file, identity["identityFile"], selector, source)
    retain_direct_flow("queue-restart-original-driver.json", driver)
    identity_body = read_direct_guest_file(worker, tools["python"], identity["identityFile"], 262144)
    selected_identity = _closed_review_json(identity_body)
    selected_identity = selected_identity.get("identity", selected_identity)
    pending = None
    inspections = []
    deadline = time.monotonic() + 1200
    index = 0
    # The authenticated Start creates original.json before any source mutation.
    # Until then a status request would describe an absent run rather than a
    # delivery; inspect only after that actual capture exists.
    while time.monotonic() < deadline:
        ready = direct_restart_readiness(worker, tools, driver)
        if not ready:
            time.sleep(1)
            continue
        observed = observe_direct_prequalification_phase(worker, tools, tools["workerUrl"],
            control_key_file, identity["identityFile"], driver["runId"], "status",
            "before-crash-" + str(index), wait_seconds=0)
        inspections.append(observed)
        records = direct_restart_records(observed, driver["runId"], source, selected_identity)
        if any(record["receipt"] is not None for record in records):
            terminal = finish_direct_restart_driver(worker, tools, driver)
            retain_direct_flow("queue-restart-rendezvous-failure.json", {
                "version": 1, "driver": terminal, "inspections": inspections,
                "reason": "read_finished_before_restart_rendezvous", "consumerCrash": False,
            })
            raise AssertionError("queue read finished before the actual restart rendezvous")
        pending = next((record for record in records if record["receipt"] is None), None)
        if pending is not None:
            break
        index += 1
        if index >= 256:
            break
        time.sleep(1)
    if pending is None:
        terminal = finish_direct_restart_driver(worker, tools, driver)
        retain_direct_flow("queue-restart-rendezvous-failure.json", {
            "version": 1, "driver": terminal, "inspections": inspections,
            "reason": "no_closed_begin_without_finish_before_deadline", "consumerCrash": False,
        })
        raise AssertionError("no retained closed Begin without Finish observed before crash deadline")
    counters, _ = observe_direct_runtime_process(worker, tools, "before-queue-crash")
    crash = crash_direct_recorded_runtime(worker, tools, process, counters)
    retain_direct_flow("queue-restart-crash.json", crash)
    resumed = start_direct_worker(worker, tools, process["configurationFile"], "queue-recovered")
    if resumed["configurationSha256"] != process["configurationSha256"]:
        raise ValueError("consumer restart changed the selected runtime configuration")
    retain_direct_flow("queue-restart-new-runner.json", resumed)
    wait_worker_transport(worker, tools["curl"], tools["python"], True,
                          observation_label="worker-queue-recovered")
    original_driver = finish_direct_restart_driver(worker, tools, driver)
    after = observe_direct_prequalification_phase(worker, tools, tools["workerUrl"],
        control_key_file, identity["identityFile"], driver["runId"], "status", "after-crash", 0)
    recovered = observe_direct_prequalification_phase(worker, tools, tools["workerUrl"],
        control_key_file, identity["identityFile"], driver["runId"], "requeue", "recovered", 600)
    records = direct_restart_records(recovered, driver["runId"], source, selected_identity)
    unfinished = [record for record in records if record["attemptNonce"] == pending["attemptNonce"]]
    positive = [record for record in records if record["receipt"] is not None
                and record["attemptNonce"] != pending["attemptNonce"]]
    if len(unfinished) != 1 or unfinished[0]["receipt"] is not None or not positive:
        raise AssertionError("consumer crash did not preserve unfinished original and a later positive attempt")
    for record in positive:
        receipt = record["receipt"]
        proof = receipt["proof"]
        before = record["attempt"]["providerBefore"]
        after_provider = receipt["providerAfter"]
        if (receipt["verificationReplayed"] is not False or int(proof["byte_size"]) != source["byte_size"]
                or proof["sha256"] != source["sha256"]
                or before["isolateId"] != after_provider["isolateId"]
                or int(after_provider["dispatches"]) <= int(before["dispatches"])
                or int(record["attempt"]["startedAtMillis"]) * 1000000 <= int(crash["killedAtUnixNs"])):
            raise AssertionError("later delivery lacks a fresh exact full-source positive proof")
    report = {"version": 1, "runId": driver["runId"], "sourceSha256": source["sha256"],
        "sourceBytes": source["byte_size"], "pending": pending, "before": inspections,
        "crash": crash, "resumed": resumed, "originalDriver": original_driver,
        "afterCrash": after, "recovery": recovered, "positiveAttempts": positive,
        "explicitClosedReadEnqueueObserved": any(item["name"].endswith("-enqueue-capture.json")
            for item in recovered["retained"]["files"]),
        "aboveMeasuredForegroundBudget": None, "serverAcknowledgment": None,
        "scope": "isolated retained Begin without Finish at consumer crash; actual same-source recovery; not production publication evidence"}
    retain_direct_flow("actual-queue-restart.json", report)
    return report, resumed
