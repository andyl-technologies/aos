"""Retain one bounded Managed runner control on its exact live private peer.

Only the published GC snapshot and retained-positive replay variants are selected.
Their factory validates physical keys and retained claims. This transport keeps
the original before dispatch and never retries an unknown exchange. Snapshot
metadata does not measure business SDK calls or grant deletion authority.
"""

import json
import re


def require_managed_runner_request(request):
    """Constrain the two actual runner factory request shapes."""
    require_managed_pair(isinstance(request, dict) and type(request.get("version")) is int
            and request["version"] == 1, "Managed runner request version differs")
    kind = request.get("kind")
    if kind == "managed-gc-snapshot":
        require_managed_pair(set(request) == {"version", "kind", "keys", "claimIds"},
                "Managed snapshot fields differ")
        for field in ("keys", "claimIds"):
            values = request[field]
            require_managed_pair(isinstance(values, list) and 0 < len(values) <= 32
                    and all(isinstance(value, str) and 0 < len(value.encode()) <= 512
                        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
                        for value in values)
                    and len(values) == len(set(values)), "Managed snapshot selectors differ")
    elif kind == "managed-gc-positive-replay":
        require_managed_pair(set(request) == {"version", "kind", "key", "claimId", "receiptSha256"}
                and isinstance(request["key"], str) and 0 < len(request["key"].encode()) <= 512
                and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request["claimId"])
                and re.fullmatch(r"[0-9a-f]{64}", request["receiptSha256"]),
                "Managed replay selectors differ")
    else:
        raise ValueError("Managed runner control variant is unsupported")
    require_managed_pair(len(json.dumps(request, separators=(",", ":")).encode()) <= 32768,
            "Managed control request exceeds its bound")


def read_managed_runner_command(worker, tools, prepared, processes, request, label):
    """Dispatch once after retaining the original and checking the actual peer."""
    require_managed_runner_request(request)
    require_managed_pair(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label),
            "Managed control evidence label differs")
    process = processes["worker"]
    return json.loads(direct_guest_python(worker, tools["python"], """
        import base64, hashlib, importlib.util, os, socket, stat, struct, time
        from pathlib import Path

        specification = importlib.util.spec_from_file_location('managed_namespace', selected['observer'])
        namespace = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(namespace)
        root = Path(selected['root']) / 'gc-controls' / selected['label']
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        def retain(name, body):
            descriptor = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            return {'path':str(root/name),'sha256':hashlib.sha256(body).hexdigest(),
                'byteSize':str(len(body))}
        def identity():
            actual = namespace.process_identity(selected['process']['pid'], Path(selected['node']))
            if (actual['startTicks'] != selected['process']['startTicks']
                    or actual['ownerUid'] != selected['process']['ownerUid']):
                raise ValueError('Managed control process lifetime changed')
            actual_sha, _ = namespace.hash_file('/proc/'+str(actual['pid'])+'/exe', 512*1024*1024, follow_link=True)
            if actual_sha != selected['process']['executableSha256']:
                raise ValueError('Managed control process executable changed')
            directory = Path('/proc') / str(actual['pid'])
            for name, expected in (('cmdline', selected['process']['commandLineSha256']),
                    ('environ', selected['process']['environmentSha256'])):
                body = (directory/name).read_bytes()
                if len(body)>65536 or hashlib.sha256(body).hexdigest()!=expected:
                    raise ValueError('Managed control process original changed')
            if hashlib.sha256(Path(selected['configuration']).read_bytes()).hexdigest()!=selected['configurationSha256']:
                raise ValueError('Managed control configuration changed')
            return actual
        before = identity()
        original = json.dumps(selected['request'], separators=(',', ':')).encode()+b'\\n'
        original_ref = retain('original.json', original)
        directory = os.open(root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        socket_path = Path(selected['socket'])
        observed = socket_path.lstat()
        if not stat.S_ISSOCK(observed.st_mode) or observed.st_uid!=os.getuid() or stat.S_IMODE(observed.st_mode)!=0o600:
            raise ValueError('Managed control socket custody differs')
        response = bytearray()
        started = time.time_ns()
        outcome = 'unknown'
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(20)
                peer.connect(str(socket_path))
                pid, uid, _ = struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if pid!=before['pid'] or uid!=before['ownerUid']:
                    raise ValueError('Managed control peer differs')
                identity()
                peer.sendall(original)
                peer.shutdown(socket.SHUT_WR)
                while block := peer.recv(4096):
                    response.extend(block)
                    if len(response)>1024*1024:
                        raise ValueError('Managed control response exceeds bound')
            after = identity()
            value = namespace.closed_json(bytes(response))
            if value.get('version')!=1 or value.get('kind')!=selected['request']['kind']:
                raise ValueError('Managed control response refused or changed variant')
            outcome = 'received'
        finally:
            reply_ref = retain('reply.private.json', bytes(response))
            receipt = {'version':1,'outcome':outcome,'request':original_ref,'reply':reply_ref,
                'sentAtUnixNanos':str(started),'finishedAtUnixNanos':str(time.time_ns()),
                'before':before,'scope':'actual private control exchange; no SDK completeness or authority'}
            retain('exchange.json',json.dumps(receipt,sort_keys=True).encode())
        print(json.dumps({'value':value,'receipt':receipt,'after':after}))
    """, {"root": prepared["coordinates"]["workerRoot"], "label": label,
        "observer": tools["ociNamespaceObserver"], "node": tools["node"], "process": process,
        "socket": prepared["coordinates"]["workerRoot"] + "/control.sock",
        "configuration": prepared["configurationFile"],
        "configurationSha256": prepared["configurationSha256"], "request": request}, timeout=35))
