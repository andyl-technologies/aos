"""Join actual cleanup helper lifetimes to the complete Native body inventory.

The helper's private stdout and result must describe the same bounded subscriber
rows. Upstream reply authentication is a separate invocation and cannot stand
for Native consumption. These observations grant no SQL or storage permission.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat


HELPER_TEST = "storage_work::oci_cleanup::controlled::actual_managed_terminal_cleanup_pair"
HELPER_PREFIX = "managed_cleanup_helper_observation "
NUMERIC_FIELDS = frozenset((
    "message", "transport_call_id", "offered_request_sha256", "plan_id", "operation",
    "exchange_attempts", "offered_plan_bytes", "observed_body_bytes",
    "discarded_status_responses", "outcome", "exchange_elapsed_ms",
))
INVOCATION_FIELDS = frozenset((
    "pid", "startTicks", "ownerUid", "executableSha256", "commandLineSha256",
    "environmentSha256", "commandLine", "environment", "version", "scope", "arguments",
    "started", "finished", "stdout", "stderr", "exitCode", "commonSourceStorePath",
    "workerFilteredSourceStorePath", "provenanceSha256",
))
TRANSPORT_PHASES = {"dispatch_unknown", "replay_positive", "settle"}
READONLY_PHASES = {"observe", "select_original", "authenticate_lost_reply"}


def cleanup_accounting_require(condition, message):
    if not condition:
        raise ValueError(message)


def cleanup_accounting_json(body):
    def closed(pairs):
        result = {}
        for key, value in pairs:
            cleanup_accounting_require(key not in result, "cleanup retained JSON has duplicate fields")
            result[key] = value
        return result

    return json.loads(body, object_pairs_hook=closed,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite cleanup JSON")))


def cleanup_accounting_encoded(value):
    # The Rust subscriber serializes a sorted BTreeMap with compact UTF-8 JSON.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode()


def cleanup_private_reference(reference, expected_path, maximum):
    """Reopen the exact bounded private file without following a replacement."""
    cleanup_accounting_require(isinstance(reference, dict)
        and set(reference) == {"path", "sha256", "byteSize"}
        and reference["path"] == str(expected_path)
        and isinstance(reference["sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])
        and type(reference["byteSize"]) is int and 0 <= reference["byteSize"] <= maximum,
        "cleanup private reference differs")
    descriptor = os.open(expected_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        cleanup_accounting_require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
            and before.st_size == reference["byteSize"], "cleanup private file custody differs")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    identity = lambda row: tuple(getattr(row, field) for field in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))
    cleanup_accounting_require(len(body) == reference["byteSize"] and len(body) <= maximum
        and identity(before) == identity(after) == identity(Path(expected_path).lstat())
        and hashlib.sha256(body).hexdigest() == reference["sha256"],
        "cleanup private retained bytes changed")
    return body


def verify_cleanup_retained_window(reference, maximum):
    """Hash a complete retained proxy row file with a fixed 64 KiB buffer."""
    cleanup_accounting_require(set(reference) == {"path", "sha256", "byteSize"}
        and re.fullmatch(r"[0-9a-f]{64}", reference['sha256'])
        and type(reference['byteSize']) is int and 0 <= reference['byteSize'] <= maximum,
        'cleanup retained window reference differs')
    descriptor = os.open(reference['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest, count = hashlib.sha256(), 0
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        cleanup_accounting_require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
            and before.st_size == reference['byteSize'], 'cleanup retained window custody differs')
        while block := stream.read(65536):
            count += len(block)
            cleanup_accounting_require(count <= reference['byteSize'], 'cleanup retained window grew')
            digest.update(block)
        after = os.fstat(stream.fileno())
    identity = lambda row: tuple(getattr(row, field) for field in (
        'st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    cleanup_accounting_require(count == reference['byteSize'] and digest.hexdigest() == reference['sha256']
        and identity(before) == identity(after) == identity(Path(reference['path']).lstat()),
        'cleanup retained window changed')


def read_managed_cleanup_invocation(helper, selected):
    """Project actual private helper files, excluding raw environment and input."""
    cleanup_accounting_require(set(selected) == {"root", "label", "phase", "commonSourceStorePath",
        "workerFilteredSourceStorePath", "testExecutableSha256", "provenanceSha256", "servicePid"}
        and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", selected["label"])
        and selected["phase"] in TRANSPORT_PHASES | READONLY_PHASES,
        "cleanup invocation selection differs")
    root = Path(selected["root"]) / "cleanup-helper" / selected["label"]
    for directory in (root.parent, root):
        metadata = directory.lstat()
        cleanup_accounting_require(stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
            "cleanup invocation directory custody differs")
    receipt = helper["receipt"]
    cleanup_accounting_require(set(receipt) == {"path", "sha256", "byteSize",
        "testExecutableSha256", "provenanceSha256", "exitCode", "invocation", "helperProcess"}
        and receipt["testExecutableSha256"] == selected["testExecutableSha256"]
        and receipt["provenanceSha256"] == selected["provenanceSha256"]
        and type(receipt["exitCode"]) is int and receipt["exitCode"] == 0,
        "cleanup helper executable/source receipt differs")
    invocation = cleanup_accounting_json(cleanup_private_reference(
        receipt["invocation"], root / "invocation.private.json", 65536))
    cleanup_accounting_require(isinstance(invocation, dict) and set(invocation) == INVOCATION_FIELDS
        and invocation == receipt["helperProcess"] and type(invocation["version"]) is int
        and invocation["version"] == 1 and invocation["scope"] == "actual_managed_cleanup_native_helper"
        and type(invocation["pid"]) is int and invocation["pid"] > 0
        and invocation["pid"] != selected["servicePid"]
        and invocation["ownerUid"] == os.getuid() and type(invocation["ownerUid"]) is int
        and re.fullmatch(r"[1-9][0-9]{0,19}", invocation["startTicks"])
        and type(invocation["exitCode"]) is int and invocation["exitCode"] == 0
        and invocation["executableSha256"] == selected["testExecutableSha256"]
        and invocation["provenanceSha256"] == selected["provenanceSha256"]
        and invocation["commonSourceStorePath"] == selected["commonSourceStorePath"]
        and invocation["workerFilteredSourceStorePath"] == selected["workerFilteredSourceStorePath"],
        "cleanup helper is not the selected distinct process/source")
    for field in ("started", "finished"):
        clock = invocation[field]
        cleanup_accounting_require(isinstance(clock, dict) and set(clock) == {"unixNs", "monotonicNs"}
            and all(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value)
                for value in clock.values()), "cleanup invocation clock shape differs")
    cleanup_accounting_require(all(int(invocation["finished"][clock]) >= int(invocation["started"][clock])
        for clock in ("unixNs", "monotonicNs")), "cleanup invocation brackets reversed")

    command = cleanup_private_reference(invocation["commandLine"], root / "command-line.private", 65536)
    environment = cleanup_private_reference(invocation["environment"], root / "environment.private", 65536)
    arguments = invocation["arguments"]
    cleanup_accounting_require(isinstance(arguments, list) and len(arguments) == 5
        and arguments[1:] == [HELPER_TEST, "--exact", "--ignored", "--nocapture"]
        and isinstance(arguments[0], str) and arguments[0].startswith("/nix/store/")
        and command == b"".join(value.encode() + b"\0" for value in arguments)
        and hashlib.sha256(command).hexdigest() == invocation["commandLineSha256"]
        and hashlib.sha256(environment).hexdigest() == invocation["environmentSha256"],
        "cleanup actual invocation or environment differs")
    input_path = root / "input.private.json"
    environment_rows = [row.split(b"=", 1) for row in environment.split(b"\0") if row]
    selected_inputs = [value for name, value in environment_rows
        if name == b"AOS_MANAGED_CLEANUP_CONTROLLED_INPUT"]
    cleanup_accounting_require(selected_inputs == [str(input_path).encode()],
        "cleanup actual helper selected a different private input")
    parameters = helper["input"]
    input_reference = {"path": str(input_path), "sha256": hashlib.sha256(
        json.dumps(parameters, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest(),
        "byteSize": len(json.dumps(parameters, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode())}
    original = cleanup_accounting_json(cleanup_private_reference(input_reference, input_path, 65536))
    cleanup_accounting_require(original == parameters and original["phase"] == selected["phase"]
        and original["outputFile"] == str(root / "result.private.json"),
        "cleanup actual input phase or output differs")
    result_reference = {field: receipt[field] for field in ("path", "sha256", "byteSize")}
    result = cleanup_accounting_json(cleanup_private_reference(result_reference, root / "result.private.json", 65536))
    cleanup_accounting_require(result == helper["value"] and result['inputSha256'] == input_reference['sha256']
        and all(isinstance(result[field], str) and re.fullmatch(r'[0-9a-f]{64}', result[field])
            for field in ('originalSha256', 'originalFingerprint', 'protectedProfileDigest'))
        and (original.get('expectedOriginalSha256') is None
            or original['expectedOriginalSha256'] == result['originalSha256']),
        "cleanup actual helper output or selected original substituted")
    stdout = cleanup_private_reference(invocation["stdout"], root / "stdout", 128 * 1024)
    cleanup_private_reference(invocation["stderr"], root / "stderr", 65536)
    cleanup_accounting_require(b'1 passed;' in stdout and b'0 failed;' in stdout,
        'cleanup actual ignored helper did not complete successfully')
    rows = []
    for line in stdout.splitlines():
        _, marker, encoded = line.partition(HELPER_PREFIX.encode())
        if marker:
            rows.append(cleanup_accounting_json(encoded))
    observations = result["nativeExchangeObservations"]
    if selected["phase"] in READONLY_PHASES:
        cleanup_accounting_require(observations is None and not rows,
            "upstream/readonly helper claimed Native consumption")
    else:
        cleanup_accounting_require(isinstance(observations, dict)
            and set(observations) == {"version", "scope", "complete", "events"}
            and type(observations["version"]) is int and observations["version"] == 1
            and observations["scope"] == "actual_native_managed_cleanup_transport"
            and observations["complete"] is True and observations["events"] == rows
            and len(rows) <= 64 and all(isinstance(row, dict)
                and all(isinstance(key, str) and isinstance(value, str) for key, value in row.items())
                for row in rows) and sum(len(cleanup_accounting_encoded(row)) for row in rows) <= 32768,
            "cleanup subscriber output is incomplete or differs from actual stdout")
    return {"version": 1, "phase": selected["phase"], "invocation": receipt["invocation"],
        "result": result_reference, "inputSha256": input_reference["sha256"],
        "process": {field: invocation[field] for field in ("pid", "startTicks", "ownerUid",
            "executableSha256", "commandLineSha256", "environmentSha256", "started", "finished")},
        "commonSourceStorePath": invocation["commonSourceStorePath"],
        "workerFilteredSourceStorePath": invocation["workerFilteredSourceStorePath"],
        "provenanceSha256": invocation['provenanceSha256'],
        "originalSha256": result['originalSha256'], "originalFingerprint": result['originalFingerprint'],
        "protectedProfileDigest": result['protectedProfileDigest'],
        "events": rows, "nativeBulkBytes": None}


def cleanup_invocation_events(projected, validate_authenticated, validate_final_sql):
    """Validate actual rows with the existing shared observation predicates."""
    numeric, authenticated, contexts = {}, {}, {}
    for row in projected["events"]:
        message = row.get("message", "")
        if message == "hybrid storage exchange accounting":
            cleanup_accounting_require(set(row) == NUMERIC_FIELDS
                and row["operation"] == "managed_oci_cleanup"
                and re.fullmatch(r"[0-9a-f]{32}", row["transport_call_id"])
                and re.fullmatch(r"[0-9a-f]{64}", row["plan_id"])
                and re.fullmatch(r"[0-9a-f]{64}", row["offered_request_sha256"])
                and all(re.fullmatch(r"0|[1-9][0-9]{0,19}", row[field]) for field in (
                    "exchange_attempts", "offered_plan_bytes", "observed_body_bytes",
                    "discarded_status_responses", "exchange_elapsed_ms"))
                and row["outcome"] in {"cancelled", "transport_failed", "http_rejected",
                    "invalid_result", "response_read_failed", "success"},
                "cleanup numeric observation differs")
            call_id = row["transport_call_id"]
            cleanup_accounting_require(call_id not in numeric, "cleanup numeric call ownership reused")
            numeric[call_id] = row
        elif set(row) == {"message"} and message.startswith("managed_oci_cleanup_authenticated "):
            value = cleanup_accounting_json(message.removeprefix("managed_oci_cleanup_authenticated "))
            validate_authenticated(value, {"/_internal/storage/managed-oci-cleanup/v1": "managed_oci_cleanup"})
            cleanup_accounting_require(value["transportCallId"] not in authenticated,
                "cleanup authenticated call ownership reused")
            authenticated[value["transportCallId"]] = value
        elif set(row) == {"message"} and message.startswith("storage_final_sql_checked "):
            encoded = message.removeprefix("storage_final_sql_checked ")
            value = cleanup_accounting_json(encoded)
            validate_final_sql(value)
            cleanup_accounting_require(value["contextKind"] == "managed_oci_cleanup_delete_checked"
                and value["exchange"]["transportCallId"] not in contexts,
                "cleanup final context ownership or scope differs")
            started, finished = (int(projected["process"][field]["unixNs"]) // 1000
                for field in ("started", "finished"))
            cleanup_accounting_require(started <= int(value["completedAtUnixMicros"]) <= finished,
                "cleanup final context is outside its actual helper lifetime")
            contexts[value["exchange"]["transportCallId"]] = {**value,
                "receiptSha256": hashlib.sha256(encoded.encode()).hexdigest(), "journalAtUnixMicros": None}
        else:
            raise ValueError("unsupported cleanup subscriber row")
    for call_id, value in authenticated.items():
        row = numeric.get(call_id)
        cleanup_accounting_require(row is not None and row["outcome"] == "success"
            and row["plan_id"] == value["planId"] and row["offered_request_sha256"] == value["requestSha256"]
            and int(row["exchange_attempts"]) == 1 and int(row["discarded_status_responses"]) == 0
            and int(row["offered_plan_bytes"]) == value["requestBytes"]
            and int(row["observed_body_bytes"]) == value["replyBytes"],
            "cleanup authentication lacks matching actual exposed counters")
    for call_id, value in contexts.items():
        cleanup_accounting_require(value["exchange"] == authenticated.get(call_id)
            and value["commitments"]["requestSha256"] == value["exchange"]["requestSha256"]
            and value["commitments"]["replySha256"] == value["exchange"]["replySha256"],
            "cleanup final SQL context lacks this exact authenticated call")
    return {"numeric": list(numeric.values()),
        "authenticated": [{**row, "nativeCompletedAtUnixMicros": None} for row in authenticated.values()],
        "contexts": list(contexts.values()), "nativeBulkBytes": None}


def read_managed_cleanup_upstream_invocation(authentication, selected):
    """Inventory a distinct read-only authenticator with startup/output custody.

    This reopens the actual child references. It returns no Native transport
    observations: a completed signed upstream reply is not a consumed reply of
    the original dispatch that intentionally lost its downstream response.
    """
    reference = authentication['invocation']
    root = Path(reference['path']).parent
    selected_root = Path(selected['root']) / 'cleanup-loss'
    cleanup_accounting_require(root.is_relative_to(selected_root)
        and Path(reference['path']).name == 'authentication-invocation.private.json',
        'upstream helper invocation escaped the actual confined listener')
    invocation = cleanup_accounting_json(cleanup_private_reference(reference,
        root / 'authentication-invocation.private.json', 65536))
    fields = {'version', 'scope', 'phase', 'transportScope', 'nativeTransportObservation',
        'helperProcess', 'arguments', 'input', 'output', 'outputErrorKind', 'started', 'finished',
        'stdout', 'stderr', 'exitCode', 'failureKind', 'completeProcessCustody',
        'startupReady', 'startupRelease', 'outputBound', 'outputOverflow',
        'completeOutputCollection', 'listenerSourceSha256', 'runtimeSourceSha256'}
    cleanup_accounting_require(isinstance(invocation, dict) and set(invocation) == fields
        and invocation == authentication['helperProcess'] and type(invocation['version']) is int
        and invocation['version'] == 1 and invocation['scope'] == 'managed_cleanup_upstream_authentication_helper'
        and invocation['phase'] == 'authenticate_lost_reply'
        and invocation['transportScope'] == 'read_only_upstream_validation'
        and invocation['nativeTransportObservation'] is None
        and invocation['completeProcessCustody'] is True and invocation['failureKind'] is None
        and type(invocation['exitCode']) is int and invocation['exitCode'] == 0
        and invocation['completeOutputCollection'] is True
        and type(invocation['outputBound']) is int and invocation['outputBound'] == 65536
        and invocation['outputOverflow'] == {'stdout': False, 'stderr': False}
        and invocation['outputErrorKind'] is None
        and invocation['listenerSourceSha256'] == selected['listenerSourceSha256']
        and invocation['runtimeSourceSha256'] == selected['runtimeSourceSha256'],
        'upstream helper source, mode, custody or bounded collection differs')
    pin = invocation['helperProcess']
    cleanup_accounting_require(isinstance(pin, dict) and set(pin) == {'pid', 'startTicks', 'ownerUid',
        'executableSha256', 'commandLineSha256', 'environmentSha256', 'commandLine', 'environment'}
        and type(pin['pid']) is int and pin['pid'] > 0 and pin['pid'] != selected['servicePid']
        and type(pin['ownerUid']) is int and pin['ownerUid'] == os.getuid()
        and re.fullmatch(r'[1-9][0-9]{0,19}', pin['startTicks'])
        and pin['executableSha256'] == selected['testExecutableSha256'],
        'upstream helper is not its distinct selected real process')
    command = cleanup_private_reference(pin['commandLine'], root / 'command-line.private', 65536)
    environment = cleanup_private_reference(pin['environment'], root / 'environment.private', 65536)
    cleanup_accounting_require(invocation['arguments'] == [selected['testExecutable'], HELPER_TEST,
        '--exact', '--ignored', '--nocapture']
        and command == b''.join(argument.encode() + b'\0' for argument in invocation['arguments'])
        and hashlib.sha256(command).hexdigest() == pin['commandLineSha256']
        and hashlib.sha256(environment).hexdigest() == pin['environmentSha256'],
        'upstream helper actual invocation substituted')
    variables = {}
    cleanup_accounting_require(environment.endswith(b'\0'), 'upstream process environment is truncated')
    for item in environment[:-1].split(b'\0'):
        name, separator, value = item.partition(b'=')
        cleanup_accounting_require(separator and name and name not in variables,
                                    'upstream process environment is malformed or ambiguous')
        variables[name] = value
    ready = cleanup_accounting_json(cleanup_private_reference(invocation['startupReady'],
        root / 'authentication-ready.private.json', 1024))
    release = cleanup_accounting_json(cleanup_private_reference(invocation['startupRelease'],
        root / 'authentication-release.private.json', 1024))
    cleanup_accounting_require(set(ready) == {'version', 'nonce', 'pid', 'scope'}
        and type(ready['version']) is int and ready['version'] == 1 and ready['pid'] == pin['pid']
        and ready['scope'] == 'managed_cleanup_before_input' and re.fullmatch(r'[0-9a-f]{32}', ready['nonce'])
        and set(release) == {'version', 'nonce'} and type(release['version']) is int
        and release == {'version': 1, 'nonce': ready['nonce']}
        and variables.get(b'AOS_MANAGED_CLEANUP_STARTUP_NONCE') == ready['nonce'].encode()
        and variables.get(b'AOS_MANAGED_CLEANUP_STARTUP_ROOT') == str(root).encode(),
        'upstream child startup nonce/PID/live pin/release differs')
    parameters = cleanup_accounting_json(cleanup_private_reference(invocation['input'],
        root / 'authentication-input.json', 16384))
    output = cleanup_accounting_json(cleanup_private_reference(invocation['output'],
        root / 'authenticated.json', 65536))
    cleanup_accounting_require(parameters['phase'] == 'authenticate_lost_reply'
        and parameters['outputFile'] == str(root / 'authenticated.json')
        and parameters['expectedOriginalSha256'] == selected['originalSha256']
        and variables.get(b'AOS_MANAGED_CLEANUP_CONTROLLED_INPUT')
            == str(root / 'authentication-input.json').encode()
        and output == authentication['proof'] and output['outcome'] == 'authenticated_completed_response'
        and output['inputSha256'] == invocation['input']['sha256']
        and output['originalSha256'] == selected['originalSha256']
        and output['protectedProfileDigest'] == selected['protectedProfileDigest']
        and output['nativeExchangeObservations'] is None,
        'upstream-only typed authentication input/output/source original differs')
    for field, parameter in [('request', 'lostRequestFile'), ('request-signature', 'lostRequestSignatureFile'),
            ('reply', 'lostReplyFile'), ('reply-signature', 'lostReplySignatureFile')]:
        ref = authentication['files'][field]
        cleanup_accounting_require(parameters[parameter] == ref['path'],
                                    'upstream authenticator substituted a signed body file')
        cleanup_private_reference(ref, root / (field + '.private'), 16384)
    cleanup_accounting_require(output['authenticatedRequestSha256'] == authentication['files']['request']['sha256'],
                                'upstream authenticator verified another exact request')
    for field in ('stdout', 'stderr'):
        cleanup_private_reference(invocation[field], root / ('authentication.' + field), 65536)
    for clock in ('unixNs', 'monotonicNs'):
        cleanup_accounting_require(all(isinstance(invocation[point][clock], str)
            and re.fullmatch(r'[1-9][0-9]{0,19}', invocation[point][clock]) for point in ('started', 'finished'))
            and int(invocation['started'][clock]) <= int(invocation['finished'][clock]),
            'upstream helper lifetime clock differs')
    return {'invocation': reference, 'process': pin,
        'started': invocation['started'], 'finished': invocation['finished'],
        'startupReady': invocation['startupReady'], 'startupRelease': invocation['startupRelease'],
        'input': invocation['input'], 'output': invocation['output'],
        'nativeTransportObservation': None, 'scope': 'independently inventoried read-only upstream child'}
