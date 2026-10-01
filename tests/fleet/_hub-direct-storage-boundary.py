"""Retain independent original and received storage bodies in fresh fleet VMs.

Native keeps the configured Worker origin. Its fixture-only DNS override sends
that origin through a local TLS observation proxy before reaching Worker. The
Worker proxy independently captures protected storage traffic; public object
responses are streamed without observer spooling. No historical VM is changed.
"""

import json
import hashlib
from pathlib import Path
import re
from decimal import Decimal, ROUND_CEILING


def start_direct_boundary_proxy(machine, tools, root, configuration, body_roots):
    """Start the exact source-built TLS proxy and retain its actual lifetime."""
    observed = json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib, os, stat, subprocess, time
        from pathlib import Path

        root = Path(selected['root'])
        for directory in [root, *[Path(value) for value in selected['bodyRoots']]]:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ValueError('observation directory custody differs')
            for name in ('client-body', 'proxy-temp', 'response-bodies',
                         'fastcgi-temp', 'uwsgi-temp', 'scgi-temp'):
                (directory / name).mkdir(mode=0o700, exist_ok=False)
        body = Path(selected['configuration']).read_bytes()
        target = root / 'nginx.conf'
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(body)
        base = [selected['nginx'], '-e', str(root / 'bootstrap-error.log'),
            '-c', str(target), '-p', str(root) + '/']
        checked = subprocess.run(base + ['-t'], stdin=subprocess.DEVNULL,
            capture_output=True, check=False, timeout=20)
        for name, contents in (('validation.stdout', checked.stdout), ('validation.stderr', checked.stderr)):
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(contents)
        if checked.returncode:
            raise ValueError('actual observation proxy rejected its configuration; diagnostics retained')
        arguments = base + ['-g', 'daemon off;']
        descriptor = os.open(root / 'process.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                stdout=output, stderr=output, start_new_session=True)
        time.sleep(0.2)
        if process.poll() is not None:
            raise ValueError('actual observation proxy exited at startup')
        directory = Path('/proc') / str(process.pid)
        command = (directory / 'cmdline').read_bytes().split(b'\\x00')[:-1]
        if directory.stat().st_uid != os.getuid() or command != [os.fsencode(value) for value in arguments]:
            raise ValueError('observation proxy owner or argv differs')
        with (directory / 'exe').open('rb') as executable:
            executable_sha = hashlib.file_digest(executable, 'sha256').hexdigest()
        receipt = {'version': 1, 'pid': process.pid, 'ownerUid': os.getuid(),
            'startTicks': (directory / 'stat').read_text().rpartition(') ')[2].split()[19],
            'executableSha256': executable_sha, 'arguments': arguments,
            'configurationSha256': hashlib.sha256(body).hexdigest(),
            'root': str(root), 'bodyRoots': selected['bodyRoots'],
            'scope': 'actual fixture TLS proxy lifetime; no protocol or provider acceptance'}
        descriptor = os.open(root / 'process.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(receipt, output, sort_keys=True)
        print(json.dumps(receipt))
    """, {"root": root, "configuration": configuration, "bodyRoots": body_roots,
            "nginx": tools["nginx"]}, timeout=45))
    return observed


def install_direct_storage_boundaries(native, worker, tools):
    """Install unchanged-origin observation routing only in these fresh VMs."""
    routing = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, ipaddress, os, socket
        from pathlib import Path

        root = Path('/var/lib/hybrid-native-outbound')
        root.mkdir(mode=0o700, exist_ok=False)
        native = socket.gethostbyname('native')
        worker = socket.gethostbyname('worker')
        before_worker = socket.gethostbyname('aos.andyl.org')
        if native == worker or before_worker != worker or any(
                not ipaddress.ip_address(value).is_private for value in (native, worker)):
            raise ValueError('fresh fixture Worker/Native routing differs')
        path = Path('/etc/hosts')
        before = path.read_bytes()
        lines = []
        for line in before.decode().splitlines():
            content, separator, comment = line.partition('#')
            fields = content.split()
            if len(fields) > 1:
                fields = [fields[0], *[value for value in fields[1:] if value != 'aos.andyl.org']]
                content = ' '.join(fields) if len(fields) > 1 else ''
            lines.append(content + (separator + comment if separator else ''))
        after = ('\\n'.join(lines) + '\\n' + native + ' aos.andyl.org\\n').encode()
        for name, body in (('hosts.before', before), ('hosts.selected', after)):
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
        temporary = Path('/etc/fleet-storage-observation-hosts')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(after)
        os.replace(temporary, path)
        if socket.gethostbyname('aos.andyl.org') != native or socket.gethostbyname('worker') != worker:
            raise ValueError('fixture routing did not preserve the actual Worker upstream')
        print(json.dumps({'version': 1, 'nativeAddress': native, 'workerAddress': worker,
            'configuredOrigin': 'https://aos.andyl.org',
            'hostsBeforeSha256': hashlib.sha256(before).hexdigest(),
            'hostsSelectedSha256': hashlib.sha256(after).hexdigest(),
            'scope': 'fresh Native VM only; actual Worker and client resolution unchanged'}))
    """, {}, timeout=30))
    worker_proxy = start_direct_boundary_proxy(worker, tools,
        "/var/lib/hybrid-worker-boundary", tools["workerObservationProxyConfiguration"], [])
    native_proxy = start_direct_boundary_proxy(native, tools,
        "/var/lib/hybrid-native-observations", tools["nativeObservationProxyConfiguration"],
        ["/var/lib/hybrid-native-outbound"])
    observed = {"version": 1, "routing": routing, "nativeProxy": native_proxy,
        "workerProxy": worker_proxy,
        "observerOverhead": "identical strict TLS, private request buffering and response storage for baseline and loaded runs"}
    retain_direct_flow("actual-storage-observation-installation.json", observed)
    return observed


def observe_direct_boundary_lifetimes(native, worker, tools, stage):
    """Check both actual proxy lifetimes and unchanged configurations at a boundary."""
    if stage not in {"baseline-start", "loaded-start", "loaded-finish"}:
        raise ValueError("proxy observation stage differs")
    observed = {}
    for role, machine in (("native", native), ("worker", worker)):
        selected = tools["storageBoundaryInstallation"][role + "Proxy"]
        receipt = json.loads(direct_guest_python(machine, tools["python"], """
            import hashlib, os
            from pathlib import Path

            root = Path('/proc') / str(selected['pid'])
            before = (root / 'stat').read_text().rpartition(') ')[2].split()[19]
            argv = (root / 'cmdline').read_bytes().split(b'\\x00')[:-1]
            with (root / 'exe').open('rb') as source:
                executable = hashlib.file_digest(source, 'sha256').hexdigest()
            configuration = Path(selected['root']) / 'nginx.conf'
            config_sha = hashlib.sha256(configuration.read_bytes()).hexdigest()
            after = (root / 'stat').read_text().rpartition(') ')[2].split()[19]
            if (before != after or before != selected['startTicks']
                    or root.stat().st_uid != selected['ownerUid']
                    or argv != [os.fsencode(value) for value in selected['arguments']]
                    or executable != selected['executableSha256']
                    or config_sha != selected['configurationSha256']):
                raise ValueError('actual proxy lifetime or configuration changed')
            print(json.dumps({'pid': selected['pid'], 'startTicks': before,
                'ownerUid': root.stat().st_uid, 'executableSha256': executable,
                'configurationSha256': config_sha}))
        """, selected, timeout=30))
        observed[role] = receipt
    retain_direct_flow("actual-proxy-lifetimes-" + stage + ".json", observed)
    return observed


def direct_storage_completion_receipts(text, worker_received=False):
    """Retain actual proxy completion UTC independently of a plan's claimed time.

    The access-log observation follows proxy response completion. It is not an
    exact in-handler authorization clock and cannot supply current permission.
    """
    normalized, completed = [], {}
    extra = {"origin_request_id", "caller"} if worker_received else set()
    for line in text.splitlines():
        raw = _closed_review_json(line)
        if set(raw) != NATIVE_OBSERVATION_FIELDS | extra | {"completed_unix_seconds"}:
            raise ValueError("storage completion receipt differs from its closed schema")
        observed = raw.pop("completed_unix_seconds")
        if not isinstance(observed, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,12})\.[0-9]{3}", observed):
            raise ValueError("actual proxy completion UTC is missing or malformed")
        seconds, milliseconds = observed.split(".")
        identifier = raw["request_id"]
        if identifier in completed:
            raise ValueError("proxy completion request identity is ambiguous")
        completed[identifier] = str(int(seconds) * 1000 + int(milliseconds))
        normalized.append(raw)
    return normalized, completed


DIRECT_CONTROL_RECEIPT_FIELDS = frozenset((
    "version", "route", "compiledSource", "requestBodySha256", "replyBodySha256",
    "requestBytes", "replyBytes", "completedAtUnixMillis",
))

DIRECT_CONTROL_RECEIPT_LIMITS = {
    "/_internal/storage/v1/capabilities": 64 * 1024,
    "/_internal/storage/v1/binding-adoption": 64 * 1024,
    "/_internal/storage/v1/bindings": 64 * 1024,
    "/_internal/storage/direct-upload-authority": 256 * 1024,
    "/_internal/storage/direct-upload-final-guard": 256 * 1024,
    "/_internal/storage/mirror-final-guard": 256 * 1024,
    "/_internal/storage/mirror-final-guard-batch": 256 * 1024,
}

DIRECT_CONTROL_METADATA_ROUTES = frozenset((
    "/_internal/storage/v1/capabilities", "/_internal/storage/v1/binding-adoption",
    "/_internal/storage/direct-upload-authority", "/_internal/storage/direct-upload-final-guard",
))


def direct_control_completion_receipts(text):
    """Parse the committed successful-handler schema without inferring permission.

    Identical replay receipts remain one semantic original with all observed
    completion times. A route with protected material still needs its own codec.
    """
    receipts = {}
    for line in text.splitlines():
        if "storage_control_complete " not in line:
            continue
        encoded = line.split("storage_control_complete ", 1)[1]
        if len(encoded.encode()) > 4096:
            raise ValueError("Worker control receipt exceeds its bounded schema")
        value = _closed_review_json(encoded)
        if (not isinstance(value, dict) or set(value) != DIRECT_CONTROL_RECEIPT_FIELDS
                or type(value["version"]) is not int or value["version"] != 1
                or not isinstance(value["route"], str)
                or value["route"] not in DIRECT_CONTROL_RECEIPT_LIMITS):
            raise ValueError("actual successful control receipt schema differs")
        for name in ("compiledSource", "requestBodySha256", "replyBodySha256"):
            if not isinstance(value[name], str) or not re.fullmatch(r"[0-9a-f]{64}", value[name]):
                raise ValueError("actual control receipt digest is malformed")
        for name in ("requestBytes", "replyBytes", "completedAtUnixMillis"):
            if not isinstance(value[name], str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,15})", value[name]):
                raise ValueError("actual control receipt count or time is noncanonical")
        if (int(value["completedAtUnixMillis"]) == 0
                or max(int(value["requestBytes"]), int(value["replyBytes"])) > DIRECT_CONTROL_RECEIPT_LIMITS[value["route"]]):
            raise ValueError("actual control receipt bound or clock is invalid")
        identity = tuple(value[name] for name in (
            "route", "compiledSource", "requestBodySha256", "replyBodySha256", "requestBytes", "replyBytes"))
        record = receipts.setdefault(identity, {**value, "completionObservations": set()})
        record["completionObservations"].add(value["completedAtUnixMillis"])
    return receipts


def direct_control_completion_join(receipts, body, source_digest, proxy_completed, elapsed_seconds):
    """Match actual source, bytes and handler time to the independent Worker proxy.

    Both clocks belong to the receiving Worker VM. Their completed-request
    interval is observational correlation, never an authorization clock.
    """
    if body["procedure"] not in DIRECT_CONTROL_METADATA_ROUTES or body["status"] != 200:
        return None
    identity = (body["procedure"], source_digest, body["bodies"]["request"]["sha256"],
        body["bodies"]["response"]["sha256"], str(body["bodies"]["request"]["byteSize"]),
        str(body["bodies"]["response"]["byteSize"]))
    record = receipts.get(identity)
    if record is None:
        return None
    if (not isinstance(proxy_completed, str) or not re.fullmatch(r"[1-9][0-9]{0,15}", proxy_completed)
            or not isinstance(elapsed_seconds, str)
            or not re.fullmatch(r"(?:0|[1-9][0-9]{0,12})\.[0-9]{3}", elapsed_seconds)):
        raise ValueError("actual control proxy interval is missing or malformed")
    finished = int(proxy_completed)
    elapsed = int((Decimal(elapsed_seconds) * 1000).to_integral_value(rounding=ROUND_CEILING))
    matching = sorted(value for value in record["completionObservations"]
        if finished - elapsed - 1 <= int(value) <= finished + 1)
    if not matching:
        return None
    return {"route": identity[0], "compiledSource": source_digest,
        "requestSha256": identity[2], "replySha256": identity[3],
        "requestBytes": int(identity[4]), "replyBytes": int(identity[5]),
        "handlerCompletedAtUnixMillis": matching,
        "workerProxyCompletedAtUnixMillis": proxy_completed,
        "handlerReceiptSemanticSha256": hashlib.sha256(json.dumps({name: record[name]
            for name in DIRECT_CONTROL_RECEIPT_FIELDS if name != "completedAtUnixMillis"},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "scope": "actual successful authenticated handler construction and independent transported byte equality; no permission, positive per-item result or settlement inference"}


def capture_direct_storage_boundary(native, worker, tools, native_text, worker_text,
                                    runtime_text, source_digest, native_address):
    """Join every actual Native request to its independently received bytes."""
    native_raw, native_completed = direct_storage_completion_receipts(native_text)
    worker_raw, worker_completed = direct_storage_completion_receipts(worker_text, True)
    originals = native_control_observations(
        "\n".join(json.dumps(row) for row in native_raw), "/var/lib/hybrid-native-outbound",
    )
    original_observations, original_bodies = capture_direct_native_bodies(
        native, tools, originals, "/var/lib/hybrid-native-outbound", "native-original",
    )
    received, correlations, unrelated = [], {}, []
    for raw in worker_raw:
        if set(raw) != NATIVE_OBSERVATION_FIELDS | {"origin_request_id", "caller"}:
            raise ValueError("Worker storage receipt schema differs")
        origin, caller = raw.pop("origin_request_id"), raw.pop("caller")
        parsed = native_control_observations(json.dumps(raw), "/var/lib/hybrid-worker-boundary")
        if caller != native_address:
            unrelated.append({"requestId": raw["request_id"],
                "callerSha256": hashlib.sha256(caller.encode()).hexdigest(),
                "workerProxyCompletedAtUnixMillis": worker_completed[raw["request_id"]],
                "scope": "outside selected Native-origin boundary"})
            continue
        if not re.fullmatch(r"[0-9a-f]{32}", origin):
            raise ValueError("actual Native storage request lacks its original correlation")
        received.extend(parsed)
        correlations[raw["request_id"]] = origin
    received_observations, received_bodies = capture_direct_native_bodies(
        worker, tools, received, "/var/lib/hybrid-worker-boundary", "worker-received",
    )
    by_origin = {}
    for body in received_bodies["bodies"]:
        origin = correlations[body["requestId"]]
        if origin in by_origin:
            raise ValueError("received storage request has ambiguous Native ownership")
        by_origin[origin] = body
    completions = {}
    for line in runtime_text.splitlines():
        if "storage_work_complete " not in line:
            continue
        matched = re.search(r"storage_work_complete plan=([0-9a-f]{32}) operation=([a-z][a-z0-9_]{0,63}) "
            r"plan_bytes=([0-9]+) source_bytes=([0-9]+) result_bytes=([0-9]+)$", line)
        if matched is None:
            raise ValueError("actual Worker storage completion schema differs")
        plan, operation, request, source, response = matched.groups()
        completions.setdefault(plan, set()).add((operation, int(request), int(source), int(response)))
    control_completions = direct_control_completion_receipts(runtime_text)
    received_elapsed = {row["request_id"]: row["elapsed_seconds"] for row in worker_raw}
    captures, authenticated, unresolved, accounted = [], [], [], set()
    for original in original_bodies["bodies"]:
        identifier = original["requestId"]
        body = by_origin.get(identifier)
        if body is None or any(original["bodies"][name] is None for name in ("request", "response")):
            unresolved.append(identifier)
            continue
        accounted.add(identifier)
        if (body["procedure"] != original["procedure"] or body["method"] != original["method"]
                or body["status"] != original["status"]
                or any(body["bodies"][name] is None or (
                    body["bodies"][name]["sha256"], body["bodies"][name]["byteSize"]) != (
                    original["bodies"][name]["sha256"], original["bodies"][name]["byteSize"])
                    for name in ("request", "response"))):
            unresolved.append(identifier)
            continue
        if body["procedure"] != "/_internal/storage/v1/execute":
            positive = direct_control_completion_join(control_completions, body, source_digest,
                worker_completed[body["requestId"]], received_elapsed[body["requestId"]])
            if positive is None:
                # Protected-material controls, unsupported routes and missing
                # actual handler receipts stay unresolved even after HTTP200.
                unresolved.append(identifier)
                continue
            captures.append({**body, "controlSelection": {"sourceDigest": source_digest,
                "deploymentId": tools["deploymentId"],
                "originalRequest": dict(original["bodies"]["request"])}})
            authenticated.append({**positive, "requestId": body["requestId"],
                "nativeRequestId": identifier,
                "nativeProxyCompletedAtUnixMillis": native_completed[identifier]})
            continue
        if body["status"] != 200:
            unresolved.append(identifier)
            continue
        request = _closed_review_json(Path(body["bodies"]["request"]["file"]).read_bytes())
        plan = request.get("plan_id")
        matches = completions.get(plan, set())
        if len(matches) != 1:
            unresolved.append(identifier)
            continue
        operation, request_bytes, source_bytes, response_bytes = next(iter(matches))
        wire_operation = request.get("operation", {}).get("kind")
        # The wire enum and its measured kind may differ (for example the
        # versioned tree query). The compiled observer must correlate them.
        if (not isinstance(wire_operation, str)
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", wire_operation)
                or request_bytes != body["bodies"]["request"]["byteSize"]
                or response_bytes != body["bodies"]["response"]["byteSize"]):
            unresolved.append(identifier)
            continue
        captures.append({**body, "storageWorkSelection": {"sourceDigest": source_digest,
            "originalPlan": dict(original["bodies"]["request"]),
            "completionObservedAtUnixMillis": worker_completed[body["requestId"]]}})
        authenticated.append({"requestId": body["requestId"],
            "nativeRequestId": identifier, "planIdSha256": hashlib.sha256(plan.encode()).hexdigest(),
            "operation": operation, "requestSha256": body["bodies"]["request"]["sha256"],
            "wireOperation": wire_operation,
            "replySha256": body["bodies"]["response"]["sha256"],
            "requestBytes": request_bytes, "replyBytes": response_bytes,
            "executorSourceBytes": source_bytes,
            "nativeProxyCompletedAtUnixMillis": native_completed[identifier],
            "workerProxyCompletedAtUnixMillis": worker_completed[body["requestId"]],
            "completionClockScope": "actual proxy response completion; not exact handler authorization time",
            "scope": "actual protected production handler completion plus independent original/received bytes; no fresh authority inference"})
    missing_originals = sorted(set(by_origin) - accounted)
    report = {"version": 1, "captures": captures, "authenticatedCompletions": authenticated,
        "nativeOriginalBodies": original_bodies, "workerReceivedBodies": received_bodies,
        "unresolvedNativeRequestIds": unresolved, "receivedWithoutOriginal": missing_originals,
        "nonNativeWorkerRequests": unrelated, "nativeBulkBytes": None,
        "actualNativeRequests": len(originals), "capturedWorkerRequests": len(received),
        "scope": "independent original/received byte equality and actual authenticated Worker completions; typed projection classification pending"}
    retain_direct_flow("actual-native-storage-boundary.json", report)
    return report
