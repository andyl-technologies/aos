"""Admit fresh real publication owners for a separate production queue window.

These metadata calls do not publish a registry or stand in for Direct admission.
The ordinary staged driver subsequently performs Begin, Grant, PUT and Report.
Unknown mutations retain their original request and are never repeated here.
"""

import hashlib
import json
import re
import time


PAYLOAD_BYTES = 8 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST_FIELDS = {"path", "sha256", "byteSize", "kind", "mediaType"}


def source_declaration(run_digest):
    """Declare the actual deterministic original used by the staged driver."""
    if not isinstance(run_digest, str) or not DIGEST.fullmatch(run_digest):
        raise ValueError("queue source has no distinct controlled window")
    block = hashlib.sha256(b"aos.staged-race.v1:external_s3:complete").digest()
    source_sha = hashlib.sha256(block * (PAYLOAD_BYTES // len(block))).hexdigest()
    pointer = json.dumps({"queueFaultWindow": run_digest}, separators=(",", ":")).encode()
    objects = [
        {"path": "objects/queue-faults/" + run_digest + "/payload.bin",
         "sha256": source_sha, "byteSize": str(PAYLOAD_BYTES), "kind": "immutable",
         "mediaType": "application/octet-stream"},
        {"path": "web/config.json", "sha256": hashlib.sha256(pointer).hexdigest(),
         "byteSize": str(len(pointer)), "kind": "mutable_pointer", "mediaType": "application/json"},
    ]
    return sorted(objects, key=lambda item: item["path"])


def manifest_digest(objects):
    """Encode the production manifest tuples with integer sizes, not wire strings."""
    if (not isinstance(objects, list) or not 1 <= len(objects) <= 64
            or any(set(item) != MANIFEST_FIELDS for item in objects)
            or len({item["path"] for item in objects}) != len(objects)):
        raise ValueError("publication declarations are not one bounded exact manifest")
    tuples = []
    for item in objects:
        if (not DIGEST.fullmatch(item["sha256"])
                or not re.fullmatch(r"0|[1-9][0-9]{0,18}", item["byteSize"])
                or item["kind"] not in {"immutable", "mutable_pointer"}):
            raise ValueError("publication declaration differs from its closed wire original")
        tuples.append([item["path"], item["sha256"], int(item["byteSize"]),
                       item["kind"], item["mediaType"]])
    encoded = json.dumps(sorted(tuples), ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def prepare_publication(call, retain, registry, run_digest):
    """Call genuine Begin/Append/Seal once and select a server-emitted object ID.

    The unuploaded pointer keeps this separate diagnostic publication preparing;
    no Commit or visibility operation is dispatched by this fixture.
    """
    if not isinstance(registry, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_/-]{0,159}", registry):
        raise ValueError("publication requires one actual selected registry")
    objects = source_declaration(run_digest)
    digest = manifest_digest(objects)
    sequence = 0

    def once(method, request):
        nonlocal sequence
        sequence += 1
        raw = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode()
        retain("%02d-%s-request.json" % (sequence, method), raw)
        # A lost reply does not authorize replay, new generation or new owner.
        response = call("PublishService/" + method, request)
        retain("%02d-%s-response.json" % (sequence, method),
               json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode())
        return response

    begun = once("BeginRegistryPublicationManifest", {
        "registry": registry, "generation": "queue-fault-" + run_digest,
        "refsDigest": run_digest, "defaultCommit": "", "parentPublicationId": "",
        "manifestDigest": digest, "objectCount": len(objects)})
    if (begun.get("manifestDigest") != digest or begun.get("objectCount") != len(objects)
            or begun.get("admittedObjectCount") != 0 or begun.get("nextChunkIndex") != 0
            or begun.get("state") != "accepting"
            or not re.fullmatch(r"[0-9a-f]{32}", begun.get("publicationId", ""))
            or not re.fullmatch(r"[0-9a-f]{32}", begun.get("leaseToken", ""))):
        raise ValueError("fresh publication Begin returned a substituted or resumed owner")
    appended = once("AppendRegistryPublicationManifest", {
        "publicationId": begun["publicationId"], "leaseToken": begun["leaseToken"],
        "chunkIndex": 0, "chunkDigest": digest, "objects": objects})
    for name in ("publicationId", "leaseToken", "manifestDigest", "objectCount"):
        if appended.get(name) != begun[name]:
            raise ValueError("manifest append changed the original owner or declaration")
    if appended.get("admittedObjectCount") != len(objects) or appended.get("nextChunkIndex") != 1:
        raise ValueError("manifest append did not acknowledge the exact full page")
    sealed = once("SealRegistryPublicationManifest", {
        "publicationId": begun["publicationId"], "leaseToken": begun["leaseToken"]})
    if (sealed.get("publicationId") != begun["publicationId"] or sealed.get("registry") != registry
            or sealed.get("generation") != "queue-fault-" + run_digest
            or sealed.get("manifestDigest") != digest or sealed.get("refsDigest") != run_digest
            or sealed.get("state") != "preparing" or len(sealed.get("objects", [])) != len(objects)
            or len(sealed.get("placements", [])) != 1
            or sealed["placements"][0].get("required") is not True):
        raise ValueError("sealed publication inventory or required placement differs")
    selected = []
    for original in objects:
        matched = [item for item in sealed["objects"] if item.get("path") == original["path"]]
        if (len(matched) != 1 or any(matched[0].get(name) != value for name, value in original.items())
                or not re.fullmatch(r"[1-9][0-9]{0,18}", matched[0].get("objectId", ""))
                or matched[0].get("verified") is not False):
            raise ValueError("sealed object is substituted or already verified")
        if original["kind"] == "immutable":
            selected.append(matched[0])
    if len(selected) != 1:
        raise ValueError("fault window did not select exactly one fresh immutable original")
    target = {"kind": "publication_object", "publicationId": sealed["publicationId"],
              "surfaceObjectId": selected[0]["objectId"], "path": selected[0]["path"]}
    return {"publication": sealed, "target": target, "declared": objects,
            "sourceSha256": selected[0]["sha256"], "byteSize": selected[0]["byteSize"],
            "manifestDigest": digest, "qualification": None}


def install_get_owner(s3, tools, owners):
    """Start a separate source-built pre-forward owner, with actual process pins."""
    root = "/var/lib/hybrid-s3/queue-fault-get"
    prepared = json.loads(owners["direct_guest_python"](s3, tools["python"], """
        import hashlib, os
        from pathlib import Path
        root = Path(selected['root'])
        root.mkdir(mode=0o700, exist_ok=False)
        raw = json.dumps({'version': 1, 'root': str(root)}, separators=(',', ':')).encode()
        fd = os.open(root/'configuration.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        listener = Path(selected['listener']).read_bytes()
        if not 0 < len(listener) <= 65536:
            raise ValueError('GET listener selected source exceeds bound')
        print(json.dumps({'root':str(root),'configurationFile':str(root/'configuration.json'),
            'configurationSha256':hashlib.sha256(raw).hexdigest(),
            'listenerFile':selected['listener'],'listenerSourceSha256':hashlib.sha256(listener).hexdigest()}))
    """, {"root": root, "listener": tools["queueFaultGetListener"]}))
    process = owners["launch_managed_process"](s3, tools, root, "get-owner", [
        tools["node"], prepared["listenerFile"], "--config", prepared["configurationFile"]], {})
    installation = {**prepared, "process": process}
    deadline = time.monotonic() + 10
    while True:
        ready = get_owner_command(s3, tools, owners, installation, None)
        if ready.get("status") != "pending":
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("selected GET owner did not become observable")
        time.sleep(0.05)
    if (ready["listenAddress"] != "127.0.0.1:3904" or ready["upstreamAddress"] != "127.0.0.1:3903"
            or ready["controlSocket"] != root + "/control.sock"):
        raise ValueError("GET owner selected the wrong unchanged upstream chain")
    return {**installation, "ready": ready}


def get_owner_command(s3, tools, owners, installation, request):
    """Use only the recorded owner's private control socket and verify its lifetime."""
    if request is not None:
        if (not isinstance(request, dict) or request.get("kind") not in {"observe", "arm", "release"}
                or len(json.dumps(request).encode()) > 16384):
            raise ValueError("GET owner command is outside its bounded interface")
    raw = owners["direct_guest_python"](s3, tools["python"], """
        import hashlib, os, socket, stat, struct
        from pathlib import Path

        pin = selected['installation']['process']
        proc = Path('/proc')/str(pin['pid'])
        def lifetime():
            fields = (proc/'stat').read_text().rpartition(') ')[2].split()
            if fields[0] == 'Z' or fields[19] != pin['startTicks'] or proc.stat().st_uid != pin['ownerUid']:
                raise ValueError('selected GET owner lifetime differs')
            for name, expected in [('cmdline',pin['commandLineSha256']),('environ',pin['environmentSha256'])]:
                value = (proc/name).read_bytes()
                if len(value)>65536 or hashlib.sha256(value).hexdigest()!=expected:
                    raise ValueError('selected GET owner process inputs differ')
            with (proc/'exe').open('rb') as executable:
                if hashlib.file_digest(executable,'sha256').hexdigest()!=pin['executableSha256']:
                    raise ValueError('selected GET owner executable differs')
        lifetime()
        root = Path(selected['installation']['root'])
        for name, expected in [('configurationFile','configurationSha256'),('listenerFile','listenerSourceSha256')]:
            value = Path(selected['installation'][name]).read_bytes()
            if len(value)>65536 or hashlib.sha256(value).hexdigest()!=selected['installation'][expected]:
                raise ValueError('selected GET owner source or configuration differs')
        ready_path = root/'ready.json'
        if not ready_path.exists():
            lifetime()
            print(json.dumps({'status':'pending'}))
            raise SystemExit(0)
        fd = os.open(ready_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as file:
            metadata=os.fstat(file.fileno())
            if metadata.st_nlink==2:
                try:
                    pending=(root/'ready.pending').lstat()
                except FileNotFoundError:
                    after=os.fstat(file.fileno())
                    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns')
                    if (after.st_nlink!=1 or not stat.S_ISREG(after.st_mode)
                            or after.st_uid!=pin['ownerUid'] or stat.S_IMODE(after.st_mode)!=0o600
                            or not 0<after.st_size<=16384
                            or any(getattr(metadata,key)!=getattr(after,key) for key in fields)):
                        raise ValueError('GET ready publication transition differs')
                    lifetime()
                    print(json.dumps({'status':'pending'}))
                    raise SystemExit(0)
                if (not stat.S_ISREG(pending.st_mode) or pending.st_uid!=pin['ownerUid']
                        or stat.S_IMODE(pending.st_mode)!=0o600 or pending.st_nlink!=2
                        or (pending.st_dev,pending.st_ino)!=(metadata.st_dev,metadata.st_ino)
                        or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=pin['ownerUid']
                        or stat.S_IMODE(metadata.st_mode)!=0o600 or not 0<metadata.st_size<=16384):
                    raise ValueError('GET ready publication aliases differ')
                lifetime()
                print(json.dumps({'status':'pending'}))
                raise SystemExit(0)
            value=file.read(16385)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=pin['ownerUid'] or metadata.st_nlink!=1 or stat.S_IMODE(metadata.st_mode)!=0o600 or not 0<len(value)<=16384 or len(value)!=metadata.st_size:
                raise ValueError('selected GET ready record custody differs')
        ready=json.loads(value)
        fields={'version','pid','ownerUid','startTicks','listenerSourceSha256','listenAddress','upstreamAddress','controlSocket'}
        if set(ready)!=fields or ready['version']!=1 or any(ready[name]!=pin[name] for name in ('pid','ownerUid','startTicks')) or ready['listenerSourceSha256']!=selected['installation']['listenerSourceSha256']:
            raise ValueError('GET ready record does not select the actual receiver')
        if selected['request'] is None:
            reply=ready
        else:
            path=root/'control.sock'; metadata=path.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid!=pin['ownerUid'] or stat.S_IMODE(metadata.st_mode)!=0o600:
                raise ValueError('GET control socket custody differs')
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sock.settimeout(2)
            try:
                sock.connect(str(path))
                peer_pid,peer_uid,_=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if peer_pid!=pin['pid'] or peer_uid!=pin['ownerUid']:
                    raise ValueError('GET control peer differs from selected owner')
                sock.sendall(json.dumps(selected['request'],separators=(',',':')).encode()); sock.shutdown(socket.SHUT_WR)
                parts=[]; size=0
                while True:
                    part=sock.recv(4096)
                    if not part: break
                    parts.append(part); size+=len(part)
                    if size>16384: raise ValueError('GET control response exceeds bound')
                reply=json.loads(b''.join(parts))
            finally: sock.close()
        lifetime()
        print(json.dumps(reply))
    """, {"installation": installation, "request": request}, timeout=5)
    return json.loads(raw)
