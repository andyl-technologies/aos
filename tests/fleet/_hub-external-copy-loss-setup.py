"""Install the one-shot Closed reply owner before the fresh pair is observed.

The public Worker origin remains HTTPS. Only its captured Copy control route
passes through the private listener, which authenticates a retained reply before
losing it. Its local action grants no SQL or provider settlement verdict.
"""

import base64
import hashlib
import json
import time


def validate_external_copy_loss_ready(ready, installation, process):
    """Match the exact post-bind receipt to the independently captured child."""
    expected = {
        "version": 1, "scope": "copy_closed_reply_loss_listener",
        "pid": process["pid"], "startTicks": process["startTicks"],
        "ownerUid": process["ownerUid"], "executableSha256": process["executableSha256"],
        "configurationSha256": installation["configurationSha256"],
        "listenerSourceSha256": installation["listenerSourceSha256"],
        "listenAddress": "127.0.0.1:4678", "upstreamAddress": "127.0.0.1:4675",
        "upstreamScheme": "https", "tlsServerName": "localhost",
        "controlSocket": installation["root"] + "/control.sock",
        "bodyBytesMaximum": "65536", "attemptsMaximum": 64,
    }
    if (not isinstance(ready, dict) or set(ready) != set(expected) | {"commandLine", "environment"}
            or any(ready[name] != value for name, value in expected.items())
            or any(type(ready[name]) is not int for name in ("version", "pid", "ownerUid", "attemptsMaximum"))):
        raise ValueError("Copy loss owner post-bind identity differs")
    for name, digest, count in (
            ("commandLine", process["commandLineSha256"], process["commandLineBytes"]),
            ("environment", process["environmentSha256"], None)):
        raw = base64.b64decode(ready[name], validate=True)
        if (not 0 < len(raw) <= 65536 or hashlib.sha256(raw).hexdigest() != digest
                or count is not None and str(len(raw)) != count):
            raise ValueError("Copy loss owner live input commitment differs")
    return ready


def install_external_copy_closed_loss(worker, tools, prepared, *, ownership):
    """Launch the selected immutable module with the real private literal key."""
    root = prepared["coordinates"]["workerRoot"] + "/copy-closed-loss"
    key_file = tools["storageWorkKeyFile"]
    codec = tools["storageCodecExecutable"]
    selected = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, stat
        from pathlib import Path

        key=Path(selected['key']); metadata=key.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid()
                or stat.S_IMODE(metadata.st_mode)!=0o600 or metadata.st_nlink!=1):
            raise ValueError('Copy loss selected key custody differs')
        fd=os.open(key,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as source: raw=source.read(65)
        if len(raw)!=64 or any(value not in b'0123456789abcdef' for value in raw):
            raise ValueError('Copy loss selected key is not literal lowercase hex')
        codec=Path(selected['codec']); listener=Path(selected['listener'])
        with codec.open('rb') as source: codec_sha=hashlib.file_digest(source,'sha256').hexdigest()
        if codec_sha!=selected['codecSha256']: raise ValueError('Copy loss codec selection differs')
        root=Path(selected['root']); root.mkdir(mode=0o700,parents=True,exist_ok=False)
        print(json.dumps({'keySha256':hashlib.sha256(raw).hexdigest(),
            'listenerSourceSha256':hashlib.sha256(listener.read_bytes()).hexdigest()}))
    """, {"root": root, "key": key_file, "codec": codec["path"],
        "codecSha256": codec["sha256"], "listener": tools["externalCopyClosedLoss"]}))
    configuration = {"version": 1, "root": root, "deploymentId": tools["deploymentId"],
        "sourceDigest": hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest(),
        "codecFile": codec["path"], "codecSha256": codec["sha256"],
        "codecSourceSha256": tools["storageCodecSourceSha256"], "keyFile": key_file,
        "keySha256": selected["keySha256"]}
    body = json.dumps(configuration, separators=(",", ":")).encode()
    path = root + "/configuration.json"
    install_direct_guest_file(worker, tools["python"], path, body)
    process = launch_managed_process(worker, tools, root, "closed-owner", [tools["node"],
        tools["externalCopyClosedLoss"], "--config", path], {
            "NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/ca-certificates.crt",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"})
    installation = {"root": root, "configurationFile": path,
        "configurationSha256": hashlib.sha256(body).hexdigest(), **selected, "process": process}
    if ownership is not None:
        ownership["copyClosedLoss"] = installation
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready = json.loads(direct_guest_python(worker, tools["python"], """
            import hashlib, os, stat
            from pathlib import Path

            pin=selected['process']; proc=Path('/proc')/str(pin['pid'])
            before=(proc/'stat').read_text().rpartition(') ')[2].split()
            if before[19]!=pin['startTicks'] or before[0]=='Z' or proc.stat().st_uid!=pin['ownerUid']:
                raise ValueError('Copy loss owner exited before readiness')
            with (proc/'exe').open('rb') as source:
                if hashlib.file_digest(source,'sha256').hexdigest()!=pin['executableSha256']:
                    raise ValueError('Copy loss owner executable differs')
            for name,digest in (('cmdline',pin['commandLineSha256']),('environ',pin['environmentSha256'])):
                if hashlib.sha256((proc/name).read_bytes()).hexdigest()!=digest:
                    raise ValueError('Copy loss owner live inputs differ')
            path=Path(selected['root'])/'ready.json'; value=None
            if path.exists():
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as source:
                    metadata=os.fstat(source.fileno()); body=source.read(196609)
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=pin['ownerUid']
                        or stat.S_IMODE(metadata.st_mode)!=0o600 or metadata.st_nlink!=1
                        or not 0<len(body)<=196608 or len(body)!=metadata.st_size):
                    raise ValueError('Copy loss readiness custody differs')
                def pairs(rows):
                    result={}
                    for key,value in rows:
                        if key in result: raise ValueError('Duplicate readiness field')
                        result[key]=value
                    return result
                value=json.loads(body,object_pairs_hook=pairs)
            after=(proc/'stat').read_text().rpartition(') ')[2].split()
            if before[19]!=after[19] or after[0]=='Z': raise ValueError('Copy loss owner lifetime changed')
            print(json.dumps(value))
        """, installation))
        if ready is not None:
            installation["ready"] = validate_external_copy_loss_ready(ready, installation, process)
            retain_direct_flow("external-copy-" + prepared["coordinates"]["runId"] + "-loss-owner.json", installation)
            return installation
        time.sleep(0.1)
    raise RuntimeError("Copy loss owner did not retain matching readiness")


def external_copy_loss_command(worker, tools, installation, request):
    """Exchange a closed one-use command with the actual pinned Unix peer."""
    fields = {"version", "kind"}
    if request.get("kind") == "arm":
        fields |= {"captureId", "originalSha256", "lossUntilUnixMillis"}
    if (set(request) != fields or type(request.get("version")) is not int or request["version"] != 1
            or request["kind"] not in {"state", "arm"}):
        raise ValueError("Copy loss private command fields differ")
    return _direct_provider_listener_exchange(worker, tools, installation,
        json.dumps(request, separators=(",", ":")).encode() + b"\n")
