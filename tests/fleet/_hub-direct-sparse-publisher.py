"""Observe and interrupt one real publisher at a retained sparse part boundary.

The helpers read existing journals and signal only the recorded client child.
They create no publication, provider original, synthetic part or replacement
journal. A missing sparse rendezvous remains a failed scenario. Controlled
tests qualify these observation fences, not provider execution or VM custody.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import textwrap


SPARSE_GUEST_LIBRARY = r'''
import hashlib, json, os, re, sqlite3, stat
from pathlib import Path
MAX_SESSION_ROWS = 50_000
MAX_SELECTED_ROWS = 32_768
MAX_RECORD_BYTES = 262_144
MAX_ENVIRONMENT_BYTES = 65_536
CLIENT_COUNTERS = ('caps', 'begin', 'status', 'grant', 'report', 'complete', 'abort',
    'identity', 'manifest_begin', 'manifest_append', 'manifest_seal', 'commit', 'metadata_read',
    'provider_attempts', 'provider_successes', 'acknowledged_bytes', 'max_provider_active')
CLIENT_EFFECT_COUNTERS = ('begin', 'grant', 'report', 'complete', 'abort', 'manifest_begin',
    'manifest_append', 'manifest_seal', 'commit', 'provider_attempts', 'provider_successes',
    'acknowledged_bytes', 'max_provider_active')

def _closed_json(body):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError("checkpoint contains duplicate fields")
            result[name] = value
        return result

    return json.loads(body, object_pairs_hook=pairs)


def _commitment(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _record(body):
    if not isinstance(body, bytes) or len(body) > MAX_RECORD_BYTES:
        raise ValueError("checkpoint record exceeds its bound")
    record = _closed_json(body)
    if not isinstance(record, dict) or set(record) != {"version", "value"} or type(record["version"]) is not int or record["version"] != 1:
        raise ValueError("checkpoint record format changed")
    return record["value"]


def _private_path(path, regular=True):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("publisher custody path is not absolute")
    for ancestor in reversed(path.parents):
        metadata = ancestor.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o022):
            raise ValueError("publisher path ancestor custody changed")
    metadata = path.lstat()
    if (metadata.st_uid != os.getuid() or metadata.st_nlink != 1
            or regular and not stat.S_ISREG(metadata.st_mode)
            or regular and metadata.st_mode & 0o7777 != 0o600):
        raise ValueError("publisher private file custody changed")
    return metadata


def _pin(pid, arguments, executable, uid, start_ticks=None):
    directory = Path("/proc") / str(pid)
    fields = (directory / "stat").read_text().rsplit(")", 1)[1].split()
    actual_arguments = (directory / "cmdline").read_bytes().split(b"\x00")[:-1]
    actual = {"pid": pid, "startTicks": fields[19], "uid": directory.stat().st_uid,
        "executable": os.readlink(directory / "exe"),
        "argvSha256": _commitment([argument.decode() for argument in actual_arguments])}
    expected = {"pid": pid, "startTicks": start_ticks or actual["startTicks"], "uid": uid,
        "executable": executable, "argvSha256": _commitment(arguments)}
    _same_pin(actual, expected)
    if fields[0] == "Z":
        raise ValueError("publisher process is already dead")
    return actual


def _same_pin(actual, expected):
    if actual != expected:
        raise ValueError("publisher process lifetime or arguments changed")


def _inputs(root, signed, process):
    _private_path(root / "input.json")
    _private_path(root / "supervisor.py")
    body = (root / "input.json").read_bytes()
    if len(body) > 16 * 1024:
        raise ValueError("publisher original input exceeds its bound")
    value = _closed_json(body)
    if (value["publisherHome"] != signed["publisherHome"]
            or value["label"] != process["label"] or value["attempt"] != process["attempt"]
            or hashlib.sha256((root / "supervisor.py").read_bytes()).hexdigest() != process["supervisorSha256"]):
        raise ValueError("publisher original supervisor or source scope changed")
    arguments = value["arguments"]
    expected = {"--root": signed["surfaceRoot"],
        "--direct-upload-journal": signed["publisherHome"] + "/direct-upload.sqlite"}
    for flag, path in expected.items():
        if arguments.count(flag) != 1 or arguments[arguments.index(flag) + 1] != path:
            raise ValueError("publisher original source root or journal selector changed")
    return value


def _decode_environment(body):
    if not body or len(body) > MAX_ENVIRONMENT_BYTES or not body.endswith(b'\x00'):
        raise ValueError('publisher environment exceeds its bound or is incomplete')
    environment = {}
    for entry in body.split(b'\x00')[:-1]:
        name, separator, value = entry.partition(b'=')
        if not separator or not name or name in environment:
            raise ValueError('publisher environment has ambiguous entries')
        environment[name] = value
    return environment


def _retain_environment(root, publisher, arguments):
    """Keep the actual pinned child's environment only in private guest custody."""
    _same_pin(_pin(publisher['pid'], arguments, publisher['executable'],
        publisher['uid'], publisher['startTicks']), publisher)
    with open(Path('/proc', str(publisher['pid']), 'environ'), 'rb') as environment:
        body = environment.read(MAX_ENVIRONMENT_BYTES + 1)
    _decode_environment(body)
    _same_pin(_pin(publisher['pid'], arguments, publisher['executable'],
        publisher['uid'], publisher['startTicks']), publisher)
    receipt = {'version': 1, 'publisher': publisher, 'bytes': len(body),
        'sha256': hashlib.sha256(body).hexdigest()}
    for name, content in (('sparse-child.environment', body),
            ('sparse-child.environment.json', json.dumps(receipt).encode())):
        with os.fdopen(os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as retained:
            retained.write(content)
            retained.flush()
            os.fsync(retained.fileno())
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return receipt


def _original_environment(root, arguments, uid):
    receipt_path = root / 'sparse-child.environment.json'
    _private_path(receipt_path)
    receipt_body = receipt_path.read_bytes()
    if len(receipt_body) > 4096:
        raise ValueError('publisher environment receipt exceeds its bound')
    receipt = _closed_json(receipt_body)
    if (set(receipt) != {'version', 'publisher', 'bytes', 'sha256'} or receipt['version'] != 1
            or receipt['publisher']['argvSha256'] != _commitment(arguments)
            or receipt['publisher']['executable'] != os.path.realpath(arguments[0])
            or receipt['publisher']['uid'] != uid):
        raise ValueError('publisher environment original process changed')
    path = root / 'sparse-child.environment'
    before = _private_path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as retained:
        opened = os.fstat(retained.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('publisher environment custody changed while opening')
        body = retained.read(MAX_ENVIRONMENT_BYTES + 1)
        after = os.fstat(retained.fileno())
    if (any(getattr(before, name) != getattr(after, name) for name in
            ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
            or len(body) != receipt['bytes'] or hashlib.sha256(body).hexdigest() != receipt['sha256']):
        raise ValueError('publisher retained environment changed')
    return _decode_environment(body), receipt


def _client_writes_zero(text):
    lines = [line.removeprefix('Direct upload client: ') for line in text.splitlines()
        if line.startswith('Direct upload client: ')]
    if len(lines) != 1:
        raise ValueError('changed source lacks one complete actual counter report')
    fields = lines[0].split()
    if len(fields) != len(CLIENT_COUNTERS):
        raise ValueError('changed source counter schema changed')
    values = {}
    for name, field in zip(CLIENT_COUNTERS, fields):
        match = re.fullmatch(r'([a-z_]+)=([0-9]+)', field)
        if match is None or match.group(1) != name:
            raise ValueError('changed source counter name or numeric value changed')
        values[name] = int(match.group(2))
    if any(values[name] != 0 for name in CLIENT_EFFECT_COUNTERS):
        raise ValueError('changed source invocation may have attempted an effect')
    return values


def _preserve_originals(previous, current):
    if (previous['namespace'], previous['runId']) != (current['namespace'], current['runId']):
        raise ValueError('publisher original journal namespace changed')
    selected = {item['session']['sessionId']: item for item in current['sessions']}
    for original in previous['sessions']:
        retained = selected.get(original['session']['sessionId'])
        if (retained is None or retained['session'] != original['session']
                or retained['originalSha256'] != original['originalSha256']):
            raise ValueError('publisher original session changed across observations')
        for kind in ('receipts', 'observed'):
            if any(retained[kind].get(key) != digest for key, digest in original[kind].items()):
                raise ValueError('publisher positive part changed across observations')


def _read_checkpoint(connection, sources):
    """Project actual selected originals; no lease or bearer value is returned."""
    identities = connection.execute("SELECT namespace,run_id,schema_version FROM direct_identity WHERE id=1").fetchall()
    if len(identities) != 1 or identities[0][2] != 1:
        raise ValueError("checkpoint identity changed")
    namespace, run_id, _ = identities[0]
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in (namespace, run_id)):
        raise ValueError("checkpoint namespace is malformed")
    selected = {source["path"]: source for source in sources}
    if not 1 <= len(selected) <= 2 or len(selected) != len(sources):
        raise ValueError("sparse observation needs the existing one or two large originals")
    sessions, cursor, visited = [], "", 0
    while True:
        page = connection.execute("SELECT owner,body FROM direct_records WHERE kind='session' AND owner LIKE 'session-%' AND owner>? ORDER BY owner LIMIT 128", (cursor,)).fetchall()
        if not page:
            break
        visited += len(page)
        if visited > MAX_SESSION_ROWS:
            raise ValueError("checkpoint session scan exceeds publication bounds")
        for owner, body in page:
            value = _record(body)
            if set(value) != {"session", "intent", "placements"}:
                raise ValueError("checkpoint session shape changed")
            intent, session = value["intent"], value["session"]
            target = intent["target"]
            if target.get("kind") != "publication_object" or target.get("path") not in selected:
                continue
            source = selected[target["path"]]
            size, part_size = int(intent["byteSize"]), int(intent["partSize"])
            if (size != source["byte_size"] or intent["expectedSha256"] != source["sha256"]
                    or part_size <= 0 or owner != "session-" + session["sessionId"]):
                raise ValueError("selected original source or session changed")
            original = connection.execute("SELECT body FROM direct_records WHERE kind='intent' AND owner=? AND placement='0' AND part=0", (intent["clientOperationId"],)).fetchone()
            if original is None or _record(original[0]) != intent:
                raise ValueError("session lacks its exact retained original")
            count = (size + part_size - 1) // part_size
            if not 2 <= count <= 10_000 or not 1 <= len(value["placements"]) <= 64:
                raise ValueError("selected source has no bounded multipart geometry")
            placements = {str(placement["placementId"]): placement for placement in value["placements"]}
            if len(placements) != len(value["placements"]):
                raise ValueError("selected original has duplicate placements")
            receipts, observed, grants = {}, {}, {}
            rows = connection.execute("SELECT kind,placement,part,body FROM direct_records WHERE owner=? AND kind IN ('receipt','observed','grant') ORDER BY kind,placement,part LIMIT ?", (session["sessionId"], MAX_SELECTED_ROWS + 1)).fetchall()
            if len(rows) > MAX_SELECTED_ROWS:
                raise ValueError("selected part projection exceeds its total bound")
            for kind, placement_id, number, raw in rows:
                if placement_id not in placements or not 1 <= number <= count:
                    raise ValueError("part row differs from original placement or geometry")
                part_value = _record(raw)
                key = placement_id + ":" + str(number)
                if kind == "grant":
                    if type(part_value) is not int or part_value <= 0:
                        raise ValueError("retained grant ordinal is invalid")
                    grants[key] = part_value
                    continue
                manifest = part_value["observed"] if kind == "receipt" else part_value
                part = manifest["part"]
                if (part["partNumber"] != number or int(part["offset"]) != (number - 1) * part_size
                        or int(part["byteSize"]) != min(part_size, size - (number - 1) * part_size)
                        or not isinstance(manifest["etag"], str) or not manifest["etag"].startswith('"')
                        or not manifest["etag"].endswith('"')):
                    raise ValueError("positive part does not bind exact original geometry")
                if kind == "receipt" and (part_value["session"] != session
                        or part_value["placement"] != placements[placement_id]
                        or not re.fullmatch(r"[0-9a-f]{64}", part_value["grant_id"])
                        or int(part_value["grant_revision"]) <= 0):
                    raise ValueError("receipt changed original session or placement")
                (receipts if kind == "receipt" else observed)[key] = hashlib.sha256(raw).hexdigest()
            if not set(receipts).issubset(grants):
                raise ValueError("positive receipt lacks its retained before-effect grant")
            complete = connection.execute("SELECT body FROM direct_records WHERE kind='complete' AND owner=? AND placement='0' AND part=0", (session["sessionId"],)).fetchone()
            gaps = []
            for placement_id in placements:
                positive = {int(key.split(":")[1]) for key in receipts if key.startswith(placement_id + ":")}
                if positive:
                    known = positive | {int(key.split(":")[1]) for key in observed if key.startswith(placement_id + ":")}
                    missing = next((number for number in range(1, max(positive)) if number not in known), None)
                    if missing is not None:
                        gaps.append({"placementId": placement_id, "lowerMissingPart": missing,
                            "higherPositivePart": max(positive)})
            sessions.append({"path": target["path"], "publicationId": target["publicationId"],
                "session": session, "originalSha256": hashlib.sha256(body).hexdigest(),
                "expectedSha256": intent["expectedSha256"], "byteSize": size,
                "partCount": count, "receipts": receipts, "observed": observed, "grants": grants,
                "unacknowledgedGrantKeys": sorted(set(grants) - set(receipts) - set(observed)),
                "completeSha256": hashlib.sha256(complete[0]).hexdigest() if complete else None,
                "sparseGaps": gaps})
        cursor = page[-1][0]
    if len({session["path"] for session in sessions}) != len(sessions):
        raise ValueError("one selected original acquired multiple sessions")
    metadata = {}
    for kind in ("publication_header", "publication_admission"):
        row = connection.execute("SELECT body FROM direct_records WHERE kind=? AND owner='publication' AND placement='0' AND part=0", (kind,)).fetchone()
        if row is not None:
            value = _record(row[0])
            if kind == "publication_header":
                metadata["headerSha256"] = hashlib.sha256(row[0]).hexdigest()
                metadata["header"] = value
            else:
                # The actual retained lease stays in the raw private journal.
                metadata["admission"] = {name: value[name] for name in
                    ("publicationId", "manifestDigest", "objectCount", "admittedObjectCount", "nextChunkIndex", "state")}
    return {"namespace": namespace, "runId": run_id, "sessions": sessions, "publication": metadata}


def _snapshot(path, sources, retain_file=None):
    """Read one SQLite snapshot under a shared lock and retain exact raw bytes."""
    metadata = _private_path(path)
    connection = sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True, timeout=0.2)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        document = _read_checkpoint(connection, sources)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            digest = hashlib.sha256()
            output = None
            if retain_file:
                output = os.fdopen(os.open(retain_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
            try:
                while block := source.read(1024 * 1024):
                    digest.update(block)
                    if output:
                        output.write(block)
                if output:
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                if output:
                    output.close()
            after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(before, field) != getattr(after, field) for field in fields)
                or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)):
            raise ValueError("checkpoint changed while its read lock was held")
        document.update(journalSha256=digest.hexdigest(), journalBytes=before.st_size,
            journalFile=str(path), retainedFile=retain_file)
        return document
    finally:
        connection.close()


'''

# Controlled source tests execute exactly the library sent to the guest.
exec(SPARSE_GUEST_LIBRARY, globals())


def _guest_definitions():
    return SPARSE_GUEST_LIBRARY


def _selection(process, signed, corpus):
    if process["label"] not in {"a", "b"} or process["attempt"] not in {1, 2, 3}:
        raise ValueError("publisher invocation label changed")
    return {"process": process, "signed": signed, "sources": corpus["large_objects"]}


def observe_direct_sparse_publisher(client, tools, process, signed, corpus):
    """Observe an existing exact live CLI child and its genuinely sparse receipts."""
    selected = _selection(process, signed, corpus)
    program = _guest_definitions() + textwrap.dedent("""
        process = selected['process']
        root = Path(process['directory'])
        if (root / 'result.json').exists():
            print(json.dumps({'version': 1, 'state': 'terminal', 'sparse': False}))
        else:
            inputs = _inputs(root, selected['signed'], process)
            supervisor = _pin(process['supervisorPid'], process['supervisorArguments'],
                process['supervisorExecutable'], process['supervisorUid'], process['supervisorStartTicks'])
            children = (Path('/proc') / str(supervisor['pid']) / 'task' / str(supervisor['pid']) / 'children').read_text().split()
            if len(children) != 1:
                raise ValueError('recorded publisher supervisor has no unique CLI child')
            publisher = _pin(int(children[0]), inputs['arguments'], os.path.realpath(inputs['arguments'][0]), os.getuid())
            journal = Path(selected['signed']['publisherHome']) / 'direct-upload.sqlite'
            try:
                snapshot = _snapshot(journal, selected['sources'])
                admission = _snapshot(Path(str(journal) + '.admission'), selected['sources'])
            except (FileNotFoundError, sqlite3.OperationalError):
                snapshot, admission = None, None
            sparse = snapshot is not None and any(item['sparseGaps'] and item['completeSha256'] is None for item in snapshot['sessions'])
            print(json.dumps({'version': 1, 'state': 'live', 'sparse': sparse,
                'publisher': publisher, 'supervisor': supervisor, 'checkpoint': snapshot, 'admission': admission,
                'scope': 'actual higher positive part with a lower receipt hole; unknown grant outcomes retained'}))
    """)
    return json.loads(direct_guest_python(client, tools["python"], program, selected))


def interrupt_direct_sparse_publisher(client, tools, process, signed, corpus, observation):
    """Signal only the pinned guest CLI after re-observing a real sparse boundary."""
    if not observation.get("sparse") or observation.get("state") != "live":
        raise ValueError("no actual sparse publisher rendezvous was observed")
    selected = {**_selection(process, signed, corpus), "observed": observation}
    program = _guest_definitions() + textwrap.dedent("""
        import signal, time

        process, observed = selected['process'], selected['observed']
        root = Path(process['directory'])
        if (root / 'result.json').exists():
            raise ValueError('publisher reached terminal result before sparse interruption')
        inputs = _inputs(root, selected['signed'], process)
        _pin(process['supervisorPid'], process['supervisorArguments'], process['supervisorExecutable'],
            process['supervisorUid'], process['supervisorStartTicks'])
        publisher = observed['publisher']
        descriptor = os.pidfd_open(publisher['pid'], 0)
        try:
            current = _pin(publisher['pid'], inputs['arguments'], os.path.realpath(inputs['arguments'][0]),
                publisher['uid'], publisher['startTicks'])
            _same_pin(current, publisher)
            saved = root / 'sparse-before.sqlite'
            checkpoint = _snapshot(Path(selected['signed']['publisherHome']) / 'direct-upload.sqlite', selected['sources'], str(saved))
            admission = _snapshot(Path(selected['signed']['publisherHome']) / 'direct-upload.sqlite.admission',
                selected['sources'], str(root / 'sparse-before.admission.sqlite'))
            previous = observed['checkpoint']
            _preserve_originals(previous, checkpoint)
            if admission['publication'].get('headerSha256') != observed['admission']['publication'].get('headerSha256'):
                raise ValueError('publisher original manifest/root changed before signal')
            if not any(item['sparseGaps'] and item['completeSha256'] is None for item in checkpoint['sessions']):
                raise ValueError('actual sparse gap closed before interruption; no synthetic replacement')
            environment = _retain_environment(root, publisher, inputs['arguments'])
            started = time.time_ns()
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            deadline = time.monotonic() + 10
            while not (root / 'result.json').exists():
                if time.monotonic() >= deadline:
                    raise ValueError('owned supervisor has not retained interrupted outcome')
                time.sleep(0.05)
            result = _closed_json((root / 'result.json').read_bytes())
            if result['exitCode'] != -signal.SIGKILL or result['timedOut']:
                raise ValueError('publisher exit differs from exact owned interruption')
            if Path('/proc', str(publisher['pid'])).exists():
                raise ValueError('interrupted child has not been reaped; no restart admitted')
            print(json.dumps({'version': 1, 'publisher': publisher, 'checkpoint': checkpoint, 'admission': admission,
                'environment': environment,
                'result': result, 'signal': 'SIGKILL', 'observedSignalUnixNs': str(started),
                'journalsEdited': False, 'providerSettlementInferred': False,
                'scope': 'same recorded guest client only; supervisor logs and unknown originals preserved'}))
        finally:
            os.close(descriptor)
    """)
    outcome = json.loads(direct_guest_python(client, tools["python"], program, selected, timeout=30))
    prefix = "publisher-" + process["label"] + "-sparse"
    artifacts = {}
    for name, maximum in (("stdout", 8 * 1024 * 1024), ("stderr", 1024 * 1024)):
        body = read_direct_guest_file(client, tools["python"], process["directory"] + "/" + name, maximum)
        artifacts[name] = retain_direct_flow(prefix + ".partial." + name, body)
    for name in ("checkpoint", "admission"):
        record = outcome[name]
        body = read_direct_guest_file(client, tools["python"], record["retainedFile"], 64 * 1024 * 1024)
        if hashlib.sha256(body).hexdigest() != record["journalSha256"]:
            raise ValueError("retained interrupted checkpoint bytes changed")
        artifacts[name] = retain_direct_flow(prefix + "." + name + ".sqlite", body)
    outcome["retainedArtifacts"] = artifacts
    retain_direct_flow("publisher-" + process["label"] + "-sparse-interruption.json", outcome)
    return outcome


def observe_direct_sparse_completion(client, tools, signed, corpus):
    """Read the same journal after the resumed invocation has genuinely exited."""
    program = _guest_definitions() + textwrap.dedent("""
        journal = Path(selected['signed']['publisherHome']) / 'direct-upload.sqlite'
        checkpoint = _snapshot(journal, selected['sources'])
        checkpoint['admission'] = _snapshot(Path(str(journal) + '.admission'), selected['sources'])
        print(json.dumps(checkpoint))
    """)
    return json.loads(direct_guest_python(client, tools["python"], program,
        {"signed": signed, "sources": corpus["large_objects"]}))


def assert_direct_sparse_resume(interrupted, completed, publication):
    """Require exact old sessions and receipts plus actual eventual publication."""
    before = interrupted["checkpoint"]
    if ((before["namespace"], before["runId"]) != (completed["namespace"], completed["runId"])
            or publication["state"] != "ready"):
        raise ValueError("sparse resume changed journal owner or lacks actual commit")
    original_header = interrupted["admission"]["publication"]
    current_header = completed["admission"]["publication"]
    if (original_header.get("headerSha256") is None
            or original_header.get("headerSha256") != current_header.get("headerSha256")
            or original_header["admission"]["publicationId"] != publication["publication_id"]
            or current_header["admission"]["publicationId"] != publication["publication_id"]):
        raise ValueError("sparse resume replaced original manifest/root/publication")
    after = {item["session"]["sessionId"]: item for item in completed["sessions"]}
    objects = {item["path"]: item for item in publication["objects"]}
    if not any(item["sparseGaps"] and item["completeSha256"] is None for item in before["sessions"]):
        raise ValueError("interrupted observation contains no genuine sparse boundary")
    for original in before["sessions"]:
        current = after.get(original["session"]["sessionId"])
        if (current is None or current["session"] != original["session"]
                or current["originalSha256"] != original["originalSha256"]
                or current["publicationId"] != publication["publication_id"]
                or original["publicationId"] != publication["publication_id"]
                or current["completeSha256"] is None):
            raise ValueError("resumed publication replaced an admitted original")
        for key, digest in original["receipts"].items():
            if current["receipts"].get(key) != digest:
                raise ValueError("resumed publisher replaced a retained positive part")
        if (original["path"] not in objects or not objects[original["path"]]["verified"]
                or objects[original["path"]]["sha256"] != original["expectedSha256"]
                or int(objects[original["path"]]["byte_size"]) != original["byteSize"]):
            raise ValueError("selected original lacks actual publication verification")
    return {"version": 1, "publicationId": publication["publication_id"],
        "retainedSessionCount": len(before["sessions"]),
        "preservedPositiveParts": sum(len(item["receipts"]) for item in before["sessions"]),
        "unacknowledgedGrantKeysAtInterruption": sum(len(item["unacknowledgedGrantKeys"]) for item in before["sessions"]),
        "scope": "same source journal/session and exact positive receipts; actual ready publication required"}


def probe_direct_changed_source(client, tools, process, signed, source, token):
    """Run the actual CLI against one changed local size using its original journal.

    This runs only after the interrupted child was reaped. It removes the last
    byte from an existing owned source, retains the failed invocation, then
    restores that exact byte to its independently checked original inode.
    It never selects a new journal, publication or provider original.
    """
    program = _guest_definitions() + textwrap.dedent("""
        import subprocess, time

        process = selected['process']
        root = Path(process['directory'])
        result = _closed_json((root / 'result.json').read_bytes())
        if result['exitCode'] != -9 or result['timedOut']:
            raise ValueError('changed source probe requires the recorded interrupted invocation')
        children = (Path('/proc') / str(process['supervisorPid']) / 'task' / str(process['supervisorPid']) / 'children')
        if children.exists() and children.read_text().split():
            raise ValueError('a live publisher child can still read the original source')
        inputs = _inputs(root, selected['signed'], process)
        environment, environment_receipt = _original_environment(root, inputs['arguments'], process['supervisorUid'])
        arguments = inputs['arguments'][:]
        if arguments.count('--token') != 1:
            raise ValueError('actual publisher token selector is ambiguous')
        arguments[arguments.index('--token') + 1] = selected['token']
        source = selected['source']
        path = Path(selected['signed']['surfaceRoot']) / source['path']
        if path.resolve() != path or not path.is_relative_to(Path(selected['signed']['surfaceRoot'])):
            raise ValueError('changed source path escaped the retained surface')
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        output_root = root / 'changed-source'
        output_root.mkdir(mode=0o700, exist_ok=False)
        journal = Path(selected['signed']['publisherHome']) / 'direct-upload.sqlite'
        before = [_snapshot(path, [source]) for path in (journal, Path(str(journal) + '.admission'))]
        started = time.time_ns()
        with os.fdopen(descriptor, 'r+b') as original:
            metadata = os.fstat(original.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1 or metadata.st_size != source['byte_size']
                    or hashlib.file_digest(original, 'sha256').hexdigest() != source['sha256']):
                raise ValueError('original source custody or digest changed before refusal probe')
            if metadata.st_size < 2:
                raise ValueError('changed-length probe needs an existing multipart source')
            original.seek(-1, os.SEEK_END)
            retained_last_byte = original.read(1)
            tail_file = output_root / 'original-last-byte'
            with os.fdopen(os.open(tail_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as tail:
                tail.write(retained_last_byte)
                tail.flush()
                os.fsync(tail.fileno())
            for directory in (output_root, root):
                directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
            original.truncate(metadata.st_size - 1)
            original.flush()
            os.fsync(original.fileno())
            changed = os.fstat(original.fileno())
            mutation_free_refusal = False
            try:
                with open(output_root / 'stdout', 'xb') as stdout, open(output_root / 'stderr', 'xb') as stderr:
                    os.chmod(output_root / 'stdout', 0o600)
                    os.chmod(output_root / 'stderr', 0o600)
                    try:
                        reply = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                            env=environment, check=False, timeout=180)
                        outcome = {'exitCode': reply.returncode, 'timedOut': False}
                    except subprocess.TimeoutExpired:
                        outcome = {'exitCode': None, 'timedOut': True}
                if outcome['exitCode'] in (None, 0) or outcome['timedOut']:
                    raise ValueError('changed source lacks actual non-success counter evidence; source remains retained')
                if (output_root / 'stderr').stat().st_size > 1048576:
                    raise ValueError('changed source counter output exceeds its bound')
                _client_writes_zero((output_root / 'stderr').read_text())
                mutation_free_refusal = True
            finally:
                current, pathname = os.fstat(original.fileno()), path.stat()
                if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
                        current.st_uid, current.st_mode, current.st_nlink) != (changed.st_dev, changed.st_ino,
                        changed.st_size, changed.st_mtime_ns, changed.st_uid, changed.st_mode, changed.st_nlink) or (pathname.st_dev, pathname.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise ValueError('changed source was concurrently edited; original remains retained without guessed restoration')
                if not mutation_free_refusal:
                    raise ValueError('changed source outcome is unresolved; no automatic restoration or retry')
                original.seek(0, os.SEEK_END)
                original.write(retained_last_byte)
                original.flush()
                os.fsync(original.fileno())
                original.seek(0)
                restored_digest = hashlib.file_digest(original, 'sha256').hexdigest()
                if restored_digest != source['sha256']:
                    raise ValueError('exact source restoration failed')
                restored = os.fstat(original.fileno())
        after = [_snapshot(path, [source]) for path in (journal, Path(str(journal) + '.admission'))]
        outcome.update(version=1, startedUnixNs=str(started), finishedUnixNs=str(time.time_ns()),
            sourcePath=source['path'], originalBytes=metadata.st_size, changedBytes=changed.st_size,
            retainedOriginalTailFile=str(tail_file), retainedOriginalTailSha256=hashlib.sha256(retained_last_byte).hexdigest(),
            restoredSha256=restored_digest, journalsUnchanged=[item['journalSha256'] for item in before] == [item['journalSha256'] for item in after],
            sourceCustody={'device': str(metadata.st_dev), 'inode': str(metadata.st_ino),
                'ownerUid': metadata.st_uid, 'mode': stat.S_IMODE(metadata.st_mode), 'linkCount': metadata.st_nlink,
                'originalMtimeNs': str(metadata.st_mtime_ns), 'restoredMtimeNs': str(restored.st_mtime_ns)},
            directory=str(output_root), scope='actual supported same-root CLI changed-length refusal; no geometry override or journal edit')
        outcome['originalEnvironment'] = environment_receipt
        print(json.dumps(outcome))
    """)
    outcome = json.loads(direct_guest_python(client, tools["python"], program,
        {"process": process, "signed": signed, "source": source, "token": token}, timeout=300))
    stdout = read_direct_guest_file(client, tools["python"], outcome["directory"] + "/stdout", 1024 * 1024)
    stderr = read_direct_guest_file(client, tools["python"], outcome["directory"] + "/stderr", 1024 * 1024)
    prefix = "publisher-" + process["label"] + "-changed-source"
    retain_direct_flow(prefix + ".result.json", outcome)
    retain_direct_flow(prefix + ".stdout.json", stdout)
    retain_direct_flow(prefix + ".stderr.log", stderr)
    tail = read_direct_guest_file(client, tools["python"], outcome["retainedOriginalTailFile"], 1)
    if len(tail) != 1 or hashlib.sha256(tail).hexdigest() != outcome["retainedOriginalTailSha256"]:
        raise ValueError("retained original source tail changed")
    retain_direct_flow(prefix + ".original-last-byte", tail)
    counters = direct_client_observations(stderr.decode())
    assert_direct_changed_source_refusal(outcome, json.loads(stdout), counters, source)
    return outcome


def assert_direct_changed_source_refusal(outcome, reply, counters, source):
    """Require retained non-success, original custody and actual zero client writes."""
    if (outcome["exitCode"] in {None, 0} or outcome["timedOut"]
            or not outcome["journalsUnchanged"] or outcome["restoredSha256"] != source["sha256"]
            or outcome["originalBytes"] != source["byte_size"]
            or outcome["changedBytes"] != source["byte_size"] - 1
            or not isinstance(reply.get("error"), str) or not reply["error"]
            or len(counters) != 1):
        raise ValueError("changed source lacks actual bounded original-preserving refusal")
    actual = counters[0]
    if any(actual[name] != 0 for name in CLIENT_EFFECT_COUNTERS):
        raise ValueError("changed source invocation attempted a new effect")
