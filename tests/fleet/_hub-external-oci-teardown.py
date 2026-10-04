"""Retain owner-bound helper shutdown and every dedicated process exit.

A helper terminal file proves its own original-bound serving lifetime ended.
It does not establish that provider promises drained or that effects settled.
"""

import json
import re


def shutdown_external_oci_helper(native, tools, prepared, helper):
    """Stop the selected candidate through its private owner shutdown file."""
    root = prepared["coordinates"]["nativeRoot"]
    identity = helper["readiness"]["identity"]
    if (identity["inputSha256"] != helper["input"]["sha256"]
            or identity["pid"] != helper["process"]["pid"]
            or str(identity["startTicks"]) != helper["process"]["startTicks"]):
        raise ValueError("External helper shutdown changed its selected original")
    offered = {"version": 1, "inputSha256": identity["inputSha256"],
        "candidateSha256": identity["candidateSha256"]}
    paths = helper.get("inputValue", {"shutdownFile": root + "/helper-shutdown.json",
        "terminalFile": root + "/helper-terminal.json"})
    if (paths["shutdownFile"], paths["terminalFile"]) not in {
            (root + "/helper-shutdown.json", root + "/helper-terminal.json"),
            (root + "/inventory-restart-shutdown.json", root + "/inventory-restart-terminal.json")}:
        raise ValueError("External helper shutdown leaves its selected actual epoch")
    request = install_direct_guest_file(native, tools["python"], paths["shutdownFile"],
        json.dumps(offered, separators=(",", ":")).encode())
    result = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, select, time
        from pathlib import Path

        process=selected['process']
        proc=Path('/proc')/str(process['pid'])
        fd=None
        if proc.exists():
            fd=os.pidfd_open(process['pid'])
            fields=(proc/'stat').read_text().rpartition(') ')[2].split()
            if fields[19]!=process['startTicks'] or proc.stat().st_uid!=process['ownerUid']:
                raise ValueError('External helper PID was reused')
            if fields[0]!='Z':
                with (proc/'exe').open('rb') as stream:
                    actual=hashlib.file_digest(stream,'sha256').hexdigest()
                if actual!=process['executableSha256']:
                    raise ValueError('External helper executable changed before shutdown')
            poll=select.poll(); poll.register(fd,select.POLLIN)
            if not poll.poll(40000): raise ValueError('Owner-bound helper exit remains unknown')
        try:
            path=Path(selected['terminal'])
            metadata=path.lstat()
            if (path.is_symlink() or not path.is_file() or metadata.st_uid!=os.getuid()
                    or metadata.st_mode&0o077 or metadata.st_nlink!=1 or metadata.st_size>65536):
                raise ValueError('External helper terminal custody differs')
            raw=path.read_bytes(); value=json.loads(raw)
            if (value['version']!=1 or value['scope']!='controlled_external_oci_native_origin'
                    or value['identity']!=selected['identity']):
                raise ValueError('External helper terminal names another original')
            print(json.dumps({'terminal':value,'terminalReference':{'file':str(path),
                'sha256':hashlib.sha256(raw).hexdigest(),'byteSize':str(len(raw))},
                'process':process,'processExitObserved':True,'providerEffectsSettled':None,
                'remoteDrain':None}))
        finally:
            if fd is not None: os.close(fd)
    """, {"process": helper["process"], "identity": identity,
        "terminal": paths["terminalFile"]}, timeout=50))
    return {"shutdownOriginal": request, **result}


def teardown_external_oci_pair(client, native, worker, tools, ownership, producer_error=None):
    """Observe all owned exits while preserving an active producer exception."""
    prepared = ownership["prepared"]
    coordinates = prepared["coordinates"]
    processes = ownership.get("processes", {})
    results, failures = {}, []
    helper = ownership.get("helper")
    if helper is not None:
        try:
            results["controlledNative"] = shutdown_external_oci_helper(native, tools, prepared, helper)
        except Exception as error:
            failures.append({"role": "controlledNative", "failureClass": type(error).__name__})
    selected = []
    if ownership.get("copyClosedLoss") is not None:
        listener = ownership["copyClosedLoss"]
        selected.append(("copyClosedLoss", worker, listener["root"], listener["process"]))
    if helper is None and processes.get("native") is not None:
        selected.append(("native", native, coordinates["nativeRoot"], processes["native"]))
    for role, machine in (("worker", worker), ("nativeProxy", native), ("workerProxy", worker)):
        if processes.get(role) is not None:
            root = coordinates["nativeRoot" if machine is native else "workerRoot"]
            selected.append((role, machine, root, processes[role]))
    if ownership.get("issuer") is not None:
        selected.append(("issuer", native, coordinates["nativeRoot"], ownership["issuer"]))
    for index, forward in enumerate(ownership.get("forwards", [])):
        selected.append(("forward-" + str(index), client, coordinates["clientRoot"], forward))
    for role, machine, root, process in selected:
        try:
            label = re.sub(r"([A-Z])", lambda match: "-" + match[1].lower(), role)
            results[role] = stop_external_oci_process(machine, tools, root, process, "final-" + label)
        except Exception as error:
            failures.append({"role": role, "failureClass": type(error).__name__})
    report = {"version": 1, "exits": results, "unresolvedExits": failures,
        "persistenceRemoved": False, "providerEffectsSettled": None}
    try:
        retain_direct_flow("external-oci-" + coordinates["runId"] + "-owned-exits.json", report)
    except Exception as error:
        failures.append({"role": "exit-receipt", "failureClass": type(error).__name__})
    if failures:
        if producer_error is not None:
            producer_error.add_note("External process exit observation incomplete; private receipt retained")
        else:
            raise RuntimeError("External process exit observation is incomplete")
    return report
