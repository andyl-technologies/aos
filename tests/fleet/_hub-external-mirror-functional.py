"""Explicit Native review commands and byte-only Worker functional installation.

Native observes its own original serving helper. The Worker socket stores exact
signed bytes only; its response is not business acceptance or Hosted evidence.
The caller supplies the existing guest transport globals in the selected bundle.
"""

import base64
import hashlib
import json
import re


MIRROR_FUNCTIONAL_ARTIFACT_LIMIT = 32 * 1024


def _run_mirror_functional(machine, tools, arguments, output_file, expected_kind="sha"):
    """Retain one actual offline tool invocation without printing private inputs."""
    result = json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib, json, os, selectors, subprocess, time
        from pathlib import Path

        os.umask(0o077)
        executable=Path(selected['executable'])
        with executable.open('rb') as source:
            before=hashlib.file_digest(source,'sha256').hexdigest()
        output=Path(selected['output'])
        stdout=output.with_name(output.name+'.review.stdout')
        stderr=output.with_name(output.name+'.review.stderr')
        arguments=[str(executable)]+selected['arguments']
        with stdout.open('xb') as out,stderr.open('xb') as err:
            process=subprocess.Popen(arguments,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            deadline=time.monotonic()+180
            counts={'stdout':0,'stderr':0}
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout,selectors.EVENT_READ,('stdout',out))
                    selector.register(process.stderr,selectors.EVENT_READ,('stderr',err))
                    while selector.get_map():
                        remaining=deadline-time.monotonic()
                        if remaining<=0:
                            raise ValueError('Mirror reviewer invocation exceeded lifetime bound')
                        for ready,_ in selector.select(min(remaining,0.25)):
                            name,destination=ready.data
                            chunk=os.read(ready.fd,4096)
                            if not chunk:
                                selector.unregister(ready.fileobj)
                                continue
                            if counts[name]+len(chunk)>65536:
                                raise ValueError('Mirror reviewer retained output exceeds its bounded envelope')
                            destination.write(chunk)
                            counts[name]+=len(chunk)
                    returncode=process.wait(timeout=max(0.001,deadline-time.monotonic()))
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdout.close();process.stderr.close()
                out.flush();os.fsync(out.fileno());err.flush();os.fsync(err.fileno())
        with executable.open('rb') as source:
            after=hashlib.file_digest(source,'sha256').hexdigest()
        if before!=after or returncode:
            raise ValueError('Mirror reviewer refused; actual private invocation outputs retained')
        raw=stdout.read_bytes()
        if not 0<len(raw)<=4096:
            raise ValueError('Mirror reviewer stdout exceeds its closed result bound')
        references={}
        for name,path in [('stdout',stdout),('stderr',stderr)]:
            size=path.stat().st_size
            if size>65536:
                raise ValueError('Mirror reviewer retained output exceeds its bounded envelope')
            with path.open('rb') as source: digest=hashlib.file_digest(source,'sha256').hexdigest()
            references[name]={'file':str(path),'sha256':digest,'byteSize':size}
        print(json.dumps({'version':1,'arguments':arguments,'executableSha256':before,
            'exitCode':returncode,'value':raw.decode().strip(),'outputs':references}))
    """, {"executable": tools["reviewer"], "arguments": arguments, "output": output_file}, timeout=190))
    pattern = r"[0-9a-f]{64}" if expected_kind == "sha" else r"controlled-external-mirror-v1:[0-9a-f]{64}"
    if re.fullmatch(pattern, result.get("value", "")) is None:
        raise ValueError("Mirror reviewer returned an unsupported result")
    return result


def _mirror_file(machine, tools, file_name, maximum):
    raw = read_direct_guest_file(machine, tools["python"], file_name, maximum)
    return raw, {"file": file_name, "sha256": hashlib.sha256(raw).hexdigest(), "byteSize": len(raw)}


def prepare_mirror_functional(machine, tools, selection_file, output_file):
    """Prepare only; return exact candidate SHA for a separate review checkpoint."""
    invocation = _run_mirror_functional(machine, tools,
        ["mirror-functional-prepare", "--selection-file", selection_file, "--output", output_file], output_file)
    _, candidate = _mirror_file(machine, tools, output_file, 64 * 1024)
    _, selection = _mirror_file(machine, tools, selection_file, 256 * 1024)
    if candidate["sha256"] != invocation["value"]:
        raise ValueError("Mirror prepared candidate changed from the actual Rust output")
    return {"version": 1, "candidate": candidate, "selection": selection, "invocation": invocation,
        "scope": "unsigned actual-input candidate; independent review and signing remain required"}


def sign_mirror_functional(machine, tools, selection_file, candidate_file, reviewed_candidate_sha256,
                          reviewer_key_file, reviewer_public_key_file, output_file):
    """Sign only the independently selected explicit reviewed candidate SHA."""
    if re.fullmatch(r"[0-9a-f]{64}", reviewed_candidate_sha256) is None:
        raise ValueError("Mirror independent candidate review SHA is absent")
    invocation = _run_mirror_functional(machine, tools, ["mirror-functional-sign",
        "--selection-file", selection_file, "--candidate-file", candidate_file,
        "--candidate-sha256", reviewed_candidate_sha256, "--reviewer-key-file", reviewer_key_file,
        "--reviewer-public-key-file", reviewer_public_key_file, "--output", output_file], output_file)
    _, artifact = _mirror_file(machine, tools, output_file, MIRROR_FUNCTIONAL_ARTIFACT_LIMIT)
    if artifact["sha256"] != invocation["value"]:
        raise ValueError("Mirror signed artifact changed from the actual Rust output")
    return {"version": 1, "artifact": artifact, "reviewedCandidateSha256": reviewed_candidate_sha256,
        "invocation": invocation, "scope": "signed finite functional statement; no Hosted or business acceptance"}


MIRROR_FUNCTIONAL_STORE_PROGRAM = """
        import base64,hashlib,json,os,socket
        from pathlib import Path

        os.umask(0o077)
        expected=selected['process'];root=Path('/proc')/str(expected['pid'])
        def pin():
            fields=(root/'stat').read_text().rsplit(')',1)[1].split()
            with (root/'exe').open('rb') as source: executable=hashlib.file_digest(source,'sha256').hexdigest()
            command=(root/'cmdline').read_bytes()
            if (fields[0]=='Z' or fields[19]!=expected['startTicks']
                    or root.stat().st_uid!=expected['ownerUid']
                    or executable!=expected['executableSha256']
                    or hashlib.sha256(command).hexdigest()!=expected['commandLineSha256']):
                raise ValueError('Mirror Worker process changed around stored-byte install')
            return [fields[19],root.stat().st_uid,executable,hashlib.sha256(command).hexdigest()]
        original=pin()
        body=base64.b64decode(selected['artifactBase64'],validate=True)
        if not 0<len(body)<=32768 or hashlib.sha256(body).hexdigest()!=selected['artifactSha256']:
            raise ValueError('Mirror installer received changed functional bytes')
        request={'version':1,'kind':'external-mirror-functional-install',
            'artifactBase64':selected['artifactBase64'],'artifactSha256':selected['artifactSha256'],'key':selected['key']}
        wire=json.dumps(request,separators=(',',':')).encode()+b'\\n'
        path=Path(selected['socket']);metadata=path.lstat()
        import stat
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid!=expected['ownerUid']:
            raise ValueError('Mirror installer socket custody differs')
        retained=path.parent/('mirror-functional-'+selected['artifactSha256'])
        request_file=retained.with_suffix('.request.json')
        response_file=retained.with_suffix('.response.json')
        with request_file.open('xb') as output:
            output.write(wire);output.flush();os.fsync(output.fileno())
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(30);connection.connect(str(path));connection.sendall(wire)
            # The selected runner dispatches only after the request writer finishes.
            connection.shutdown(socket.SHUT_WR)
            response=bytearray()
            while True:
                chunk=connection.recv(4096)
                if not chunk:
                    break
                if len(response)+len(chunk)>65536:
                    raise ValueError('Mirror installer response excessive')
                response.extend(chunk)
        if not response.endswith(b'\\n'):
            raise ValueError('Mirror installer response incomplete')
        with response_file.open('xb') as output:
            output.write(response);output.flush();os.fsync(output.fileno())
        value=json.loads(response)
        if (set(value)!={'version','status','key','artifactSha256','byteSize','runnerPid','runnerStartTicks','artifactBase64'}
                or value['version']!=1 or value['status']!='stored' or value['key']!=selected['key']
                or value['artifactSha256']!=selected['artifactSha256'] or value['byteSize']!=str(len(body))
                or value['runnerPid']!=expected['pid'] or value['runnerStartTicks']!=expected['startTicks']
                or base64.b64decode(value['artifactBase64'],validate=True)!=body or pin()!=original):
            raise ValueError('Mirror actual stored-byte readback or lifetime differs')
        def reference(path):
            body=path.read_bytes()
            return {'file':str(path),'sha256':hashlib.sha256(body).hexdigest(),'byteSize':len(body)}
        print(json.dumps({'storedBytes':value,'request':reference(request_file),'response':reference(response_file)}))
    """


def _store_mirror_functional_bytes(worker, tools, socket_file, worker_process, raw, artifact_sha256, key):
    return json.loads(direct_guest_python(worker, tools["python"], MIRROR_FUNCTIONAL_STORE_PROGRAM,
        {"process": worker_process, "socket": socket_file, "artifactBase64": base64.b64encode(raw).decode(),
            "artifactSha256": artifact_sha256, "key": key}, timeout=40))


def install_mirror_functional(native, worker, tools, selection_file, artifact_file, socket_file, worker_process):
    """Verify on Native, store/read back on Worker, and reverify on the same Native epoch."""
    before = _run_mirror_functional(native, tools, ["mirror-functional-verify",
        "--selection-file", selection_file, "--artifact-file", artifact_file], artifact_file + ".before")
    key_receipt = _run_mirror_functional(native, tools, ["mirror-functional-registry-key",
        "--selection-file", selection_file, "--artifact-file", artifact_file], artifact_file + ".key", "key")
    raw, artifact = _mirror_file(native, tools, artifact_file, MIRROR_FUNCTIONAL_ARTIFACT_LIMIT)
    if artifact["sha256"] != before["value"]:
        raise ValueError("Mirror artifact changed before Worker byte installation")
    namespace_before = direct_namespace_readback(worker, tools["python"], worker_process,
        socket_file=socket_file, namespace_kind="external_copy")
    installed = _store_mirror_functional_bytes(worker, tools, socket_file, worker_process,
        raw, artifact["sha256"], key_receipt["value"])
    namespace_after = direct_namespace_readback(worker, tools["python"], worker_process,
        socket_file=socket_file, namespace_kind="external_copy")
    for field in ("runnerPid", "runnerStartTicks", "configurationSha256", "scriptSha256", "namespaces"):
        if namespace_before[field] != namespace_after[field]:
            raise ValueError("Mirror installation changed the selected actual Worker namespace")
    if namespace_after["configurationSha256"] != json.loads(raw)["installation"]["configurationSha256"]:
        raise ValueError("Mirror stored-byte installation belongs to another Worker configuration")
    after = _run_mirror_functional(native, tools, ["mirror-functional-verify",
        "--selection-file", selection_file, "--artifact-file", artifact_file], artifact_file + ".after")
    if after["value"] != artifact["sha256"]:
        raise ValueError("Mirror artifact changed after Worker byte installation")
    return {"version": 1, "artifact": artifact, "key": key_receipt, "nativeBefore": before, "nativeAfter": after,
        "storedBytes": installed["storedBytes"], "installRequest": installed["request"],
        "installResponse": installed["response"], "namespaceBefore": namespace_before, "namespaceAfter": namespace_after,
        "businessAcceptance": None, "scope": "typed stored/readback bytes in original producer epoch; successor runtime stays separate"}
