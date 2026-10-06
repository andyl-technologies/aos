"""Interrupt one retained isolated queue read without repeating its mutations.

The rendezvous joins an independently held GET to an authenticated durable
Begin without Finish after the exact consumer crash. Neither the held GET nor
an ACK alone proves a queue attempt or remote drain. The ordinary mixed/pure
qualification is a separate run.
"""

import base64
import hashlib
import stat
import json
import os
from pathlib import Path
import re
import time


def start_direct_restart_original(worker, tools, origin, control_key_file,
                                  identity_file, selector, source, run_id=None):
    """Launch a single actual bulk original and retain its exact driver lifetime."""
    if (source["metadata"] is not False or source["byte_size"] != 2147483648
            or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"])):
        raise ValueError("queue restart requires the selected actual 2 GiB bulk file")
    run_id = os.urandom(32).hex() if run_id is None else run_id
    if re.fullmatch(r"[0-9a-f]{64}", run_id) is None:
        raise ValueError("queue restart run identity differs")
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
                terminal = state in ('Z', 'X', 'x')
                if terminal or identity is None:
                    terminal_stderr(root)

                # A retained Start original does not make a later failed driver
                # healthy. Missing/reaped status stays unknown; only its owned
                # stderr can supply a known failure category, never an exit code.
                known_error = result['stderrCategory'] in (
                    'private_input_refused', 'control_key_refused',
                    'runtime_identity_refused', 'source_refused', 'source_changed',
                    'control_acknowledgement_unknown', 'multiple_known_errors')
                if result['ready'] and terminal and result['exitCode'] != 0:
                    result['category'] = 'driver_exited_after_original'
                elif result['ready'] and identity is None and known_error:
                    result['category'] = 'driver_status_unknown_after_original'
                else:
                    result['category'] = ('original_ready' if result['ready'] else
                        'driver_missing' if identity is None else
                        'driver_exited_before_original' if terminal else
                        'waiting_for_original')
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


def retain_direct_restart_outputs(worker, tools, driver, observation):
    """Retain bounded original-child outputs without resolving unknown custody.

    This copies only the recorded restart directory's two private files. File
    custody never supplies a missing process exit status or authorizes a replay.
    """
    pin = {name: driver[name] for name in ("runId", "root", "pid", "ownerUid", "startTicks")}
    if (not re.fullmatch(r"[0-9a-f]{64}", pin["runId"])
            or pin["root"] != "/var/lib/hybrid-worker/operator/restart-" + pin["runId"]
            or type(pin["pid"]) is not int or pin["pid"] <= 0
            or type(pin["ownerUid"]) is not int or pin["ownerUid"] < 0
            or not re.fullmatch(r"[1-9][0-9]{0,19}", pin["startTicks"])
            or any(observation.get(name) != pin[name]
                   for name in ("runId", "pid", "ownerUid", "startTicks"))):
        raise ValueError("restart outputs require the recorded original child")

    parent = Path("external-direct-flow")
    parent.mkdir(mode=0o700, exist_ok=True)
    facts = parent.lstat()
    if (not stat.S_ISDIR(facts.st_mode) or facts.st_uid != os.geteuid()
            or facts.st_mode & 0o077):
        raise ValueError("restart output parent custody refused")
    destination = parent / ("restart-" + pin["runId"] + "-outputs")
    destination.mkdir(mode=0o700, exist_ok=False)
    records = []
    for name in ("stdout.log", "stderr.log"):
        record = {"name": name, "state": "refused_or_unknown"}
        expected = observation.get("outputs", {}).get(name)
        try:
            if (not isinstance(expected, dict) or expected.get("present") is not True
                    or expected.get("custody") is not True
                    or not isinstance(expected.get("byteSize"), str)
                    or not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", expected["byteSize"])):
                raise ValueError("restart observed output custody unavailable")
            encoded = direct_guest_python(worker, tools["python"], """
                import base64, hashlib, os, stat

                pin = selected['pin']
                if (pin['ownerUid'] != os.getuid()
                        or pin['root'] != '/var/lib/hybrid-worker/operator/restart-' + pin['runId']
                        or selected['name'] not in ('stdout.log', 'stderr.log')):
                    raise ValueError('restart output identity refused')
                parent = os.open('/var/lib/hybrid-worker/operator',
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                root = None
                try:
                    root = os.open('restart-' + pin['runId'],
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    custody = os.fstat(root)
                    if (custody.st_uid != pin['ownerUid']
                            or stat.S_IMODE(custody.st_mode) != 0o700):
                        raise ValueError('restart output directory custody refused')
                    prior = os.stat(selected['name'], dir_fd=root, follow_symlinks=False)
                    descriptor = os.open(selected['name'],
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
                    with os.fdopen(descriptor, 'rb') as source:
                        before = os.fstat(source.fileno())
                        if (not stat.S_ISREG(before.st_mode) or before.st_uid != pin['ownerUid']
                                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                                or (before.st_dev, before.st_ino) != (prior.st_dev, prior.st_ino)
                                or str(before.st_size) != selected['expected']['byteSize']):
                            raise ValueError('restart output file custody changed')
                        raw = source.read(65537)
                        after = os.fstat(source.fileno())
                    if (any(getattr(before, field) != getattr(after, field)
                            for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
                            or len(raw) != min(before.st_size, 65537)):
                        raise ValueError('restart output changed during bounded read')
                    body = raw[:65536]
                    print(json.dumps({'body': base64.b64encode(body).decode(),
                        'sha256': hashlib.sha256(body).hexdigest(),
                        'observedByteSize': str(before.st_size), 'byteSize': len(body),
                        'eof': before.st_size <= 65536, 'truncated': before.st_size > 65536}))
                finally:
                    if root is not None:
                        os.close(root)
                    os.close(parent)
            """, {"pin": pin, "name": name, "expected": expected}, timeout=10)
            if len(encoded.encode()) > 90000:
                raise ValueError("restart output transport exceeds bound")
            captured = json.loads(encoded)
            if set(captured) != {"body", "sha256", "observedByteSize", "byteSize", "eof", "truncated"}:
                raise ValueError("restart output transport schema differs")
            body = base64.b64decode(captured["body"], validate=True)
            digest = hashlib.sha256(body).hexdigest()
            size = int(expected["byteSize"])
            if (len(body) != min(size, 65536) or type(captured["byteSize"]) is not int
                    or captured["byteSize"] != len(body) or captured["sha256"] != digest
                    or captured["observedByteSize"] != expected["byteSize"]
                    or captured["eof"] is not (size <= 65536)
                    or captured["truncated"] is not (size > 65536)):
                raise ValueError("restart output differs from the observed private file")
            descriptor = os.open(destination / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            record = {"name": name, "state": "retained_prefix" if size > 65536 else "retained",
                "file": str(destination / name), "byteSize": len(body), "sha256": digest,
                "observedByteSize": expected["byteSize"], "eof": size <= 65536,
                "truncated": size > 65536}
        except Exception:
            # Missing, changing and inaccessible streams are independently
            # unknown; a partial retention must not erase the original refusal.
            pass
        records.append(record)
    return {"version": 1, "runId": pin["runId"], "pid": pin["pid"],
        "ownerUid": pin["ownerUid"], "startTicks": pin["startTicks"],
        "processCustody": observation.get("custody"), "exitCode": observation.get("exitCode"),
        "maximumFileBytes": 65536, "files": records}


def direct_restart_readiness(worker, tools, driver):
    """Retain safe failure facts before stopping the original readiness wait."""
    observation = observe_direct_restart_readiness(worker, tools, driver)
    if observation["category"] not in ("waiting_for_original", "original_ready"):
        try:
            outputs = retain_direct_restart_outputs(worker, tools, driver, observation)
        except Exception:
            outputs = {"version": 1, "maximumFileBytes": 65536, "state": "refused_or_unknown"}
        retain_direct_flow("queue-restart-readiness-failure.json", {**observation, "childOutputs": outputs})
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
        capture = _closed_review_json(body)
        authentication_name = selected["name"].removesuffix("-capture.json") + "-authentication.json"
        authentication_files = [item for item in observation["retained"]["files"]
                                if item["name"] == authentication_name]
        if len(authentication_files) != 1:
            raise ValueError("queue inspection lacks its retained authenticated exchange")
        authentication_body = (Path(observation["retained"]["directory"]) / authentication_name).read_bytes()
        if hashlib.sha256(authentication_body).hexdigest() != authentication_files[0]["sha256"]:
            raise ValueError("queue inspection authentication changed")
        authentication = _closed_review_json(authentication_body)
        # The selected driver verifies the reply MAC before writing a capture.
        # This links that actual exchange to these exact retained bytes; it
        # neither re-verifies a MAC without its key nor invents authentication.
        if (authentication["status"] != 200 or authentication["responseSha256"] != selected["sha256"]
                or authentication["requestSha256"] != capture["requestSha256"]
                or capture["sourceDigest"] != identity["sourceDigest"]
                or capture["scriptVersion"] != identity["scriptVersion"]):
            raise ValueError("queue inspection exchange or installed source differs")
        result = capture["result"]
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
                "inspectionSha256": selected["sha256"],
                "readSelection": direct_restart_read_selection(result)})
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


def direct_restart_read_selection(result):
    """Project authenticated closed stage coordinates without credential bytes."""
    job = result["closed"].get("job")
    if job is None:
        return None
    placements = [item for item in job["admission"]["placements"]
                  if item["placementId"] == job["placementId"]]
    if len(placements) != 1:
        raise ValueError("queue closed job lacks one selected placement")
    placement = placements[0]
    cohort = placement["physical"]["readCohort"]
    alias = cohort["alias"]["spec"]
    session = job["admission"]["sessionId"]
    stage_key = (placement["stagingPrefix"] + "/" + hashlib.sha256(session.encode()).hexdigest()
                 + "/" + placement["placementId"] + "/payload")
    return {"target": "/" + alias["bucket"] + "/" + stage_key,
        "host": alias["host"]["value"], "port": alias["port"],
        "etag": job["closed"]["result"]["outcome"]["etag"],
        "sourceBytes": job["admission"]["intent"]["byteSize"],
        "sourceSha256": job["admission"]["intent"]["expectedSha256"],
        "providerSelectorSha256": hashlib.sha256(json.dumps(
            result["original"]["provider"]["selector"], sort_keys=True).encode()).hexdigest()}


def prepare_direct_queue_pause(worker, s3, tools, process, selector, source, staging_prefix, run_id):
    """Bind a bounded prefix observation to the actual unchanged bulk source."""
    prefix = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, stat

        descriptor = os.open(selected['file'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_size != selected['byte_size']):
                raise ValueError('queue source custody or full length differs')
            body = stream.read(65536)
            after = os.fstat(stream.fileno())
            if (len(body) != 65536 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError('queue source prefix changed')
        print(json.dumps({'sha256': hashlib.sha256(body).hexdigest(), 'byteSize': '65536'}))
    """, source))
    # The selection deadline covers upload/settlement. The separate pause
    # ceiling begins only when the real GET is selected.
    deadline = int(direct_guest_python(s3, tools["python"],
        "import time; print(time.time_ns() // 1000000 + 1200000)", {}))
    selection = {"version": 1, "host": "s3.fleet.test",
        "targetPrefix": "/fleet-s3/" + staging_prefix + "/"}
    context = {"runId": run_id, "sourceSha256": source["sha256"],
        "sourceBytes": str(source["byte_size"]), "prefix": prefix,
        "selectorSha256": hashlib.sha256(json.dumps(selector, sort_keys=True).encode()).hexdigest(),
        "configurationSha256": process["configurationSha256"], "selection": selection}
    arm = {"version": 1, "kind": "arm_queue_read", "selection": selection,
        "expectedSourceSha256": source["sha256"], "expectedSourceBytes": str(source["byte_size"]),
        "expectedPrefixSha256": prefix["sha256"],
        "selectionContextSha256": hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest(),
        "selectionDeadlineUnixMillis": deadline, "pauseMillis": 35000}
    reply = direct_provider_hold_command(s3, tools, tools["providerHoldInstallation"], arm)
    if reply != {"version": 1, "status": "armed"}:
        raise AssertionError("queue provider pause was not armed")
    retain_direct_flow("queue-restart-pause-arm.json", {"context": context, "request": arm, "reply": reply,
        "owner": tools["providerHoldInstallation"]["ready"]})
    return arm


def direct_restart_pause_join(record, held, arm, selector, crash):
    """Require an authenticated unfinished Begin for the independently held GET."""
    selected = record["readSelection"]
    receipt = held["receipt"]
    identity = receipt["identity"]
    if (record["receipt"] is not None or selected is None
            or identity["method"] != "GET" or identity["range"] is not None
            or identity["target"] != selected["target"] or identity["host"] != selected["host"]
            or selected["port"] != 443 or identity["ifMatch"] != selected["etag"]
            or receipt["sourceSha256"] != arm["expectedSourceSha256"]
            or receipt["sourceBytes"] != arm["expectedSourceBytes"]
            or str(selected["sourceBytes"]) != receipt["sourceBytes"]
            or selected["sourceSha256"] != receipt["sourceSha256"]
            or receipt["prefixFile"]["sha256"] != arm["expectedPrefixSha256"]
            or receipt["prefixFile"]["byteSize"] != "65536"
            or receipt["selectionContextSha256"] != arm["selectionContextSha256"]
            or selected["providerSelectorSha256"] != hashlib.sha256(
                json.dumps(selector, sort_keys=True).encode()).hexdigest()
            or receipt["downstreamOfferedBytes"] != "0" or receipt["upstreamComplete"] is not False
            or not (int(record["attempt"]["startedAtMillis"]) <= receipt["selectedAtUnixMillis"]
                    <= receipt["heldAtUnixMillis"] <= int(crash["killedAtUnixNs"]) // 1000000
                    < receipt["cutoffUnixMillis"])
            or receipt["cutoffUnixMillis"] - receipt["selectedAtUnixMillis"] > 35000):
        raise AssertionError("held provider read lacks exact authenticated unfinished Begin correlation")
    return record


def direct_restart_positive(records, pending, source, crash):
    """Validate existing fresh recovery receipts before deciding whether to enqueue."""
    unfinished = [record for record in records if record["attemptNonce"] == pending["attemptNonce"]]
    if len(unfinished) != 1 or unfinished[0]["receipt"] is not None:
        raise AssertionError("consumer crash did not retain the original unfinished attempt")
    positive = [record for record in records if record["receipt"] is not None
                and record["attemptNonce"] != pending["attemptNonce"]]
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
    return positive


def run_direct_queue_restart(worker, s3, tools, process, identity, control_key_file,
                             selector, source, staging_prefix):
    """Crash a real held read, then prove its unfinished Begin and fresh recovery."""
    run_id = os.urandom(32).hex()
    counters, _ = observe_direct_runtime_process(worker, tools, "before-queue-crash")
    arm = prepare_direct_queue_pause(worker, s3, tools, process, selector, source, staging_prefix, run_id)
    driver = None
    held = None
    crash = None
    try:
        driver = start_direct_restart_original(worker, tools, tools["workerUrl"],
            control_key_file, identity["identityFile"], selector, source, run_id=run_id)
        retain_direct_flow("queue-restart-original-driver.json", driver)
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            direct_restart_readiness(worker, tools, driver)
            state = direct_provider_hold_command(s3, tools, tools["providerHoldInstallation"],
                {"version": 1, "kind": "queue_state"})
            if state["state"] == "held":
                held = state
                break
            if state["state"] not in {"armed", "selected", "receiving_prefix"}:
                raise AssertionError("queue provider pause ended before consumer crash")
            time.sleep(0.05)
        if held is None:
            raise AssertionError("actual queue read was not selected before original deadline")
        retain_direct_flow("queue-restart-held-read.json", held)
        owner = tools["providerHoldInstallation"]["ready"]
        if held["receipt"]["owner"] != {name: owner[name] for name in (
                "pid", "startTicks", "ownerUid", "configurationSha256", "listenerSourceSha256",
                "listenAddress", "upstreamAddress")}:
            raise AssertionError("queue held GET belongs to a different provider response owner")
        if (held["endedAtUnixMillis"] is not None
                or held["receipt"]["cutoffUnixMillis"] <= held["receipt"]["heldAtUnixMillis"]):
            raise AssertionError("queue provider pause was not live at selected observation")
        # No Status call precedes the crash: the prior control reply arrived
        # only after Finish. This independent hold proves no
        # Begin; the authenticated post-crash join below is mandatory.
        crash = crash_direct_recorded_runtime(worker, tools, process, counters)
        retain_direct_flow("queue-restart-crash.json", crash)
        ended = direct_provider_hold_command(s3, tools, tools["providerHoldInstallation"],
            {"version": 1, "kind": "queue_state"})
        retain_direct_flow("queue-restart-pause-after-crash.json", ended)
        if (ended["receipt"] != held["receipt"]
                or int(crash["killedAtUnixNs"]) // 1000000 >= held["receipt"]["cutoffUnixMillis"]
                or ended["endedAtUnixMillis"] is not None
                    and ended["endedAtUnixMillis"] < int(crash["killedAtUnixNs"]) // 1000000):
            raise AssertionError("queue provider pause ended before exact consumer crash")
    finally:
        try:
            released = direct_provider_hold_command(s3, tools, tools["providerHoldInstallation"],
                {"version": 1, "kind": "queue_release"})
            retain_direct_flow("queue-restart-pause-release.json", released)
        finally:
            if crash is None and driver is not None:
                terminal = finish_direct_restart_driver(worker, tools, driver)
                retain_direct_flow("queue-restart-rendezvous-failure.json", {
                    "version": 1, "driver": terminal, "heldRead": held,
                    "reason": "provider_pause_not_proven_at_crash", "consumerCrash": False})

    resumed = start_direct_worker(worker, tools, process["configurationFile"], "queue-recovered")
    if resumed["configurationSha256"] != process["configurationSha256"]:
        raise ValueError("consumer restart changed the selected runtime configuration")
    retain_direct_flow("queue-restart-new-runner.json", resumed)
    wait_worker_transport(worker, tools["curl"], tools["python"], True,
                          observation_label="worker-queue-recovered")
    identity_body = read_direct_guest_file(worker, tools["python"], identity["identityFile"], 262144)
    selected_identity = _closed_review_json(identity_body)
    selected_identity = selected_identity.get("identity", selected_identity)
    original_driver = finish_direct_restart_driver(worker, tools, driver)
    after = observe_direct_prequalification_phase(worker, tools, tools["workerUrl"],
        control_key_file, identity["identityFile"], driver["runId"], "status", "after-crash", 0)
    records = direct_restart_records(after, driver["runId"], source, selected_identity)
    matching = [record for record in records if record["receipt"] is None
                and record["attempt"]["startedAtMillis"] is not None
                and int(record["attempt"]["startedAtMillis"]) <= held["receipt"]["selectedAtUnixMillis"]]
    if len(matching) != 1:
        raise AssertionError("crashed held read lacks one authenticated unfinished attempt")
    pending = direct_restart_pause_join(matching[0], held, arm, selector, crash)
    positive = direct_restart_positive(records, pending, source, crash)
    # Automatic recovery can already have completed during startup/inspection.
    # Its exact fresh proof is acceptance; another Enqueue is not needed then.
    recovered = after
    if not positive:
        recovered = observe_direct_prequalification_phase(worker, tools, tools["workerUrl"],
            control_key_file, identity["identityFile"], driver["runId"], "requeue", "recovered", 600)
        records = direct_restart_records(recovered, driver["runId"], source, selected_identity)
        positive = direct_restart_positive(records, pending, source, crash)
    if not positive:
        raise AssertionError("consumer recovery lacks a fresh positive attempt")
    report = {"version": 1, "runId": driver["runId"], "sourceSha256": source["sha256"],
        "sourceBytes": source["byte_size"], "pending": pending, "heldRead": held, "pauseArm": arm,
        "crash": crash, "resumed": resumed, "originalDriver": original_driver,
        "afterCrash": after, "recovery": recovered, "positiveAttempts": positive,
        "explicitClosedReadEnqueueObserved": any(item["name"].endswith("-enqueue-capture.json")
            for item in recovered["retained"]["files"]),
        "aboveMeasuredForegroundBudget": None, "serverAcknowledgment": None,
        "scope": "isolated retained Begin without Finish at consumer crash; actual same-source recovery; not production publication evidence"}
    retain_direct_flow("actual-queue-restart.json", report)
    return report, resumed
