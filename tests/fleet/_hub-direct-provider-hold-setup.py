"""Start the confined Garage response owner before provider observations.

The response owner forwards ordinary traffic unchanged. Its private calibration
and hold controls grant no provider or Hub permission. Readiness is joined to
the independently captured child executable, argv, environment and lifetime.
"""

import hashlib
import json
import re
import time


PROVIDER_HOLD_READY_FIELDS = {
    "version", "scope", "pid", "startTicks", "ownerUid", "configurationSha256",
    "executableSha256", "commandLine", "environment", "listenAddress",
    "upstreamAddress", "listenerSourceSha256", "controlSocket", "bodyBound",
}

COPY_PARTIAL_READY_FIELDS = (PROVIDER_HOLD_READY_FIELDS - {"bodyBound"}) | {
    "prefixBytes", "bodyBlockBound", "selectedPrefixes",
}


def validate_direct_provider_hold_ready(ready, prepared, process):
    """Join the bounded post-bind record to the actual selected child."""
    partial = "partialPrefixes" in prepared
    fields = COPY_PARTIAL_READY_FIELDS if partial else PROVIDER_HOLD_READY_FIELDS
    if not isinstance(ready, dict) or set(ready) != fields:
        raise ValueError("Provider response owner readiness schema differs")
    expected = {
        "version": 1, "scope": "copy_partial_response_listener" if partial else "garage_response_hold_listener",
        "pid": process["pid"], "startTicks": process["startTicks"],
        "ownerUid": process["ownerUid"],
        "configurationSha256": prepared["configurationSha256"],
        "executableSha256": process["executableSha256"],
        "listenerSourceSha256": prepared["listenerSourceSha256"],
        "listenAddress": "127.0.0.1:3903" if partial else "127.0.0.1:3902",
        "upstreamAddress": "127.0.0.1:3902" if partial else "127.0.0.1:3900",
        "controlSocket": prepared["root"] + "/control.sock",
    }
    expected.update({"prefixBytes": "65536", "bodyBlockBound": "65536",
        "selectedPrefixes": prepared["partialPrefixes"]} if partial else {"bodyBound": "65536"})
    if (any(type(ready[name]) is not int for name in ("version", "pid", "ownerUid"))
            or any(ready[name] != value
                for name, value in expected.items())):
        raise ValueError("Provider response owner post-bind identity differs")
    for name, digest, count, filename in (
            ("commandLine", process["commandLineSha256"], process["commandLineBytes"], "command-line.private"),
            ("environment", process["environmentSha256"], None, "environment.private")):
        row = ready[name]
        if (not isinstance(row, dict) or set(row) != {"path", "sha256", "byteSize"}
                or row["path"] != prepared["root"] + "/" + filename
                or row["sha256"] != digest or not isinstance(row["byteSize"], str)
                or not row["byteSize"].isdecimal() or str(int(row["byteSize"])) != row["byteSize"]
                or not 0 < int(row["byteSize"]) <= 65536
                or count is not None and row["byteSize"] != count):
            raise ValueError("Provider response owner private process commitment differs")
    return ready


def install_direct_provider_hold(s3, tools, *, partial_prefixes=None):
    """Launch the source-built one-shot owner and require actual listener readiness."""
    partial = partial_prefixes is not None
    if partial and (not isinstance(partial_prefixes, list) or not 1 <= len(partial_prefixes) <= 2
            or len(set(partial_prefixes)) != len(partial_prefixes)
            or any(not isinstance(prefix, str) or re.fullmatch(
                r"/fleet-s3/(\.aos-direct-qualification/external-oci/([0-9a-f]{32}))/\1/registry/", prefix) is None
                for prefix in partial_prefixes)):
        raise ValueError("Copy partial response prefixes differ from the planned fresh pairs")
    root = "/var/lib/hybrid-s3/copy-partial" if partial else "/var/lib/hybrid-s3/read-timeout"
    listener = tools["externalCopyPartialHold"] if partial else tools["providerHoldListener"]
    fields = COPY_PARTIAL_READY_FIELDS if partial else PROVIDER_HOLD_READY_FIELDS
    configuration = {"version": 1, "root": root}
    if partial:
        configuration.update(host="s3.fleet.test", targetPrefixes=partial_prefixes)
    configuration = json.dumps(configuration, sort_keys=True).encode()
    prepared = json.loads(direct_guest_python(s3, tools["python"], """
        import hashlib, os
        from pathlib import Path

        root=Path(selected['root'])
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        body=bytes.fromhex(selected['configurationHex'])
        fd=os.open(root/'configuration.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output:
            output.write(body); output.flush(); os.fsync(output.fileno())
        source=Path(selected['listener']).read_bytes()
        print(json.dumps({'root':str(root),'configurationFile':str(root/'configuration.json'),
            'configurationSha256':hashlib.sha256(body).hexdigest(),
            'listenerSourceSha256':hashlib.sha256(source).hexdigest()}))
    """, {"root": root, "configurationHex": configuration.hex(),
        "listener": listener}))
    if partial:
        prepared["partialPrefixes"] = partial_prefixes
    process = launch_managed_process(s3, tools, root, "response-owner", [
        tools["node"], listener, "--config", prepared["configurationFile"],
    ], {})
    stop = time.monotonic() + 30
    while time.monotonic() < stop:
        observation = json.loads(direct_guest_python(s3, tools["python"], """
            import hashlib, os, stat
            from pathlib import Path

            def closed_pairs(values):
                result={}
                for key,value in values:
                    if key in result:
                        raise ValueError('Provider response owner receipt has duplicate fields')
                    result[key]=value
                return result

            pin=selected['process']; proc=Path('/proc')/str(pin['pid'])
            before=(proc/'stat').read_text().rpartition(') ')[2].split()
            if before[19]!=pin['startTicks'] or before[0]=='Z' or proc.stat().st_uid!=pin['ownerUid']:
                raise ValueError('Provider response owner lifetime changed before readiness')
            with (proc/'exe').open('rb') as source:
                executable=hashlib.file_digest(source,'sha256').hexdigest()
            if executable!=pin['executableSha256']:
                raise ValueError('Provider response owner executable changed')
            for name,expected in (('cmdline',pin['commandLineSha256']),('environ',pin['environmentSha256'])):
                body=(proc/name).read_bytes()
                if len(body)>65536 or hashlib.sha256(body).hexdigest()!=expected:
                    raise ValueError('Provider response owner process inputs changed')
            for path,expected in ((selected['configurationFile'],selected['configurationSha256']),
                    (selected['listenerFile'],selected['listenerSourceSha256'])):
                body=Path(path).read_bytes()
                if len(body)>1048576 or hashlib.sha256(body).hexdigest()!=expected:
                    raise ValueError('Provider response owner selected source or configuration changed')
            path=Path(selected['root'])/'ready.json'
            ready=None
            if path.exists():
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as source:
                    metadata=os.fstat(source.fileno())
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=pin['ownerUid'] or stat.S_IMODE(metadata.st_mode)!=0o600 or not 0<metadata.st_size<=16384:
                        raise ValueError('Provider response owner readiness custody differs')
                    body=source.read(16385)
                    if len(body)!=metadata.st_size:
                        raise ValueError('Provider response owner readiness changed')
                ready=json.loads(body,object_pairs_hook=closed_pairs)
                if not isinstance(ready,dict) or set(ready)!=set(selected['readyFields']):
                    raise ValueError('Provider response owner readiness schema differs')
                for name,filename in (('commandLine','command-line.private'),('environment','environment.private')):
                    row=ready[name]; path=Path(selected['root'])/filename
                    if not isinstance(row,dict) or set(row)!={'path','sha256','byteSize'} or row['path']!=str(path):
                        raise ValueError('Provider response owner private path differs')
                    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                    with os.fdopen(fd,'rb') as source:
                        metadata=os.fstat(source.fileno())
                        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=pin['ownerUid'] or stat.S_IMODE(metadata.st_mode)!=0o600 or not 0<metadata.st_size<=65536:
                            raise ValueError('Provider response owner private receipt custody differs')
                        content=source.read(65537)
                    if len(content)>65536 or str(len(content))!=row['byteSize'] or hashlib.sha256(content).hexdigest()!=row['sha256']:
                        raise ValueError('Provider response owner private receipt differs')
            after=(proc/'stat').read_text().rpartition(') ')[2].split()
            if after[19]!=before[19] or after[0]=='Z':
                raise ValueError('Provider response owner lifetime changed during readiness')
            print(json.dumps({'ready':ready}))
        """, {"process": process, "root": root, **prepared,
            "listenerFile": listener,
            "readyFields": sorted(fields)}))
        if observation["ready"] is not None:
            ready = validate_direct_provider_hold_ready(observation["ready"], prepared, process)
            return {**prepared, "process": process, "ready": ready}
        time.sleep(0.1)
    raise RuntimeError("Provider response owner did not retain a matching post-bind receipt")


def direct_provider_hold_command(s3, tools, installation, request):
    """Use only the selected listener's private first-response or state control."""
    if not isinstance(request, dict) or type(request.get("version")) is not int or request["version"] != 1:
        raise ValueError("Provider response owner control version differs")
    if (installation.get("root") != "/var/lib/hybrid-s3/read-timeout"
            or installation.get("ready", {}).get("controlSocket") != installation["root"] + "/control.sock"):
        raise ValueError("Provider response owner control selection differs")
    fields = {
        "state": {"version", "kind"},
        "queue_state": {"version", "kind"},
        "queue_release": {"version", "kind"},
        "arm_queue_read": {"version", "kind", "selection", "expectedSourceSha256",
            "expectedSourceBytes", "expectedPrefixSha256", "selectionContextSha256",
            "selectionDeadlineUnixMillis", "pauseMillis"},
        "arm_first_response": {"version", "kind", "selection", "expectedSourceBodySha256",
            "expectedSourceBodyBytes", "selectionContextSha256", "holdUntilUnixMillis"},
    }
    kind = request.get("kind")
    if kind not in fields or set(request) != fields[kind]:
        raise ValueError("Provider response owner control field set differs")
    if kind == "arm_first_response" and (any(not isinstance(request[name], str)
            or re.fullmatch(r"[0-9a-f]{64}", request[name]) is None for name in (
                "expectedSourceBodySha256", "selectionContextSha256"))
            or not isinstance(request["expectedSourceBodyBytes"], str)
            or re.fullmatch(r"[1-9][0-9]{0,4}", request["expectedSourceBodyBytes"]) is None
            or int(request["expectedSourceBodyBytes"]) > 65536
            or type(request["holdUntilUnixMillis"]) is not int):
        raise ValueError("Provider response owner first-response commitment differs")
    if kind == "arm_queue_read" and (
            any(not isinstance(request[name], str) or re.fullmatch(r"[0-9a-f]{64}", request[name]) is None
                for name in ("expectedSourceSha256", "expectedPrefixSha256", "selectionContextSha256"))
            or request["expectedSourceBytes"] != "2147483648"
            or type(request["selectionDeadlineUnixMillis"]) is not int
            or type(request["pauseMillis"]) is not int or not 1 <= request["pauseMillis"] <= 35000):
        raise ValueError("Provider queue pause source or timing commitment differs")
    if kind in {"arm_first_response", "arm_queue_read"}:
        selection = request["selection"]
        if (not isinstance(selection, dict) or set(selection) != {"version", "host", "targetPrefix"}
                or type(selection["version"]) is not int or selection["version"] != 1
                or selection["host"] != "s3.fleet.test"
                or not isinstance(selection["targetPrefix"], str)
                or len(selection["targetPrefix"].encode()) > 2048
                or not selection["targetPrefix"].startswith("/")
                or not selection["targetPrefix"].endswith("/.aos-direct-upload/")
                or ".aos-direct-qualification" not in selection["targetPrefix"].split("/")
                or any(part in {"", ".", ".."}
                    for part in selection["targetPrefix"].split("/")[1:-1])
                or re.search(r"[%?#\\\s]", selection["targetPrefix"])):
            raise ValueError("Provider response owner staging prefix differs")
    body = json.dumps(request, sort_keys=True).encode()
    if len(body) > 16384:
        raise ValueError("Provider response owner control exceeds its bound")
    return _direct_provider_listener_exchange(s3, tools, installation, body)


def direct_copy_partial_command(s3, tools, installation, request):
    """Control only one initially selected partial-response case."""
    fields = {"version", "kind", "targetPrefix"}
    if isinstance(request, dict) and request.get("kind") in {"arm", "arm_inventory", "arm_inventory_after_first_range"}:
        fields.add("fixtureCutoffUnixMillis" if request["kind"] == "arm_inventory_after_first_range" else "holdUntilUnixMillis")
        if request["kind"] != "arm":
            fields.update({"sourceKey", "rangeStart"})
    if (not isinstance(request, dict) or set(request) != fields
            or type(request.get("version")) is not int or request["version"] != 1
            or request.get("kind") not in {"arm", "state", "release",
                "arm_inventory", "arm_inventory_after_first_range", "state_inventory", "release_inventory"}
            or installation.get("root") != "/var/lib/hybrid-s3/copy-partial"
            or request.get("targetPrefix") not in installation.get("partialPrefixes", [])
            or installation.get("ready", {}).get("controlSocket") != installation["root"] + "/control.sock"
            or request["kind"] in {"arm", "arm_inventory"} and type(request["holdUntilUnixMillis"]) is not int
            or request["kind"] == "arm_inventory_after_first_range" and type(request["fixtureCutoffUnixMillis"]) is not int
            or request["kind"] in {"arm_inventory", "arm_inventory_after_first_range"} and (type(request["rangeStart"]) is not int
                or request["rangeStart"] != 8388608 or not isinstance(request["sourceKey"], str)
                or re.fullmatch(re.escape(request["targetPrefix"] + "oci/blobs/sha256/")
                    + r"[0-9a-f]{64}", request["sourceKey"]) is None)):
        raise ValueError("Copy partial control differs from its initial selected listener")
    return _direct_provider_listener_exchange(s3, tools, installation,
        json.dumps(request, sort_keys=True).encode())


def _direct_provider_listener_exchange(s3, tools, installation, body):
    """Recheck actual lifetime and Unix peer before one bounded exchange."""
    return json.loads(direct_guest_python(s3, tools["python"], """
        import hashlib, os, socket, stat, struct, time
        from pathlib import Path

        pin=selected['process']; proc=Path('/proc')/str(pin['pid'])
        before=(proc/'stat').read_text().rpartition(') ')[2].split()
        if before[19]!=pin['startTicks'] or before[0]=='Z' or proc.stat().st_uid!=pin['ownerUid']:
            raise ValueError('Provider response owner no longer has the selected lifetime')
        with (proc/'exe').open('rb') as source:
            if hashlib.file_digest(source,'sha256').hexdigest()!=pin['executableSha256']:
                raise ValueError('Provider response owner executable differs')
        for name,expected in (('cmdline',pin['commandLineSha256']),('environ',pin['environmentSha256'])):
            body=(proc/name).read_bytes()
            if len(body)>65536 or hashlib.sha256(body).hexdigest()!=expected:
                raise ValueError('Provider response owner live inputs differ')
        path=Path(selected['socket'])
        metadata=path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid!=pin['ownerUid'] or stat.S_IMODE(metadata.st_mode)!=0o600:
            raise ValueError('Provider response owner control custody differs')
        request=bytes.fromhex(selected['requestHex'])
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(10)
            connection.connect(str(path))
            pid,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if pid!=pin['pid'] or uid!=pin['ownerUid']:
                raise ValueError('Provider response owner control peer differs')
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response=bytearray()
            while chunk:=connection.recv(16385-len(response)):
                response.extend(chunk)
                if len(response)>16384:
                    raise ValueError('Provider response owner control reply exceeds its bound')
        after=(proc/'stat').read_text().rpartition(') ')[2].split()
        if after[19]!=before[19] or after[0]=='Z':
            raise ValueError('Provider response owner lifetime changed during control')
        print(response.decode())
    """, {"process": installation["process"], "socket": installation["ready"]["controlSocket"],
        "requestHex": body.hex()}))


def stop_direct_provider_listeners(s3, tools, installations, producer_error=None):
    """Retain both exact owned exits without inferring provider settlement."""
    exits, failures = {}, []
    for label, installation in installations.items():
        try:
            exits[label] = stop_external_oci_process(s3, tools, installation["root"],
                installation["process"], "final-response-owner")
        except Exception as error:
            failures.append({"listener": label, "failureClass": type(error).__name__})
    try:
        retain_direct_flow("provider-response-owned-exits.json", {"version": 1,
            "exits": exits, "unresolvedExits": failures, "providerSettlement": None, "remoteDrain": None})
    except Exception as error:
        failures.append({"listener": "exit-receipt", "failureClass": type(error).__name__})
    if failures:
        if producer_error is not None:
            producer_error.add_note("Provider response owner exit evidence is incomplete")
        else:
            raise RuntimeError("Provider response owner exit evidence is incomplete")
    return exits
