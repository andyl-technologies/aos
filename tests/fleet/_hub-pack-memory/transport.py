"""Expose fixed serialized guest actions for the private memory owner.

The host supplies no shell program. Every command surface, child module and
mailbox filename is selected here. A pidfd becoming readable records observed
exit; it does not manufacture a parent wait/reap or provider drain receipt.
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import time

from bridge import checked_request, encoded, private_directory, read_private, write_private
from worker_owner import process_pin


def checked_root(root):
    if not re.fullmatch(r"/var/lib/hybrid-(?:native|worker)/external-oci/[a-f0-9]{32}/"
            r"pack-memory/(?:semantic32|live36|replacement-overflow)", root):
        raise ValueError("selected memory root differs")
    return Path(root)


def checked_owner(selected):
    if set(selected) != {"root", "process"}:
        raise ValueError("selected owner coordinate schema differs")
    root = private_directory(checked_root(selected["root"]))
    expected = selected["process"]
    descriptor = os.pidfd_open(expected["pid"])
    try:
        poll = select.poll()
        poll.register(descriptor, select.POLLIN)
        if poll.poll(0):
            return root, descriptor, True
        if process_pin(expected["pid"]) != expected:
            raise ValueError("selected memory owner lifetime changed")
        return root, descriptor, False
    except BaseException:
        os.close(descriptor)
        raise


def publish(selected):
    if set(selected) != {"action", "root", "leaf", "value"}:
        raise ValueError("memory publication selection differs")
    root = private_directory(checked_root(selected["root"]))
    if selected["leaf"] not in {"owner-selection.json", "source-selection.json", "native-selection.json",
            "admission-selection.json", "admission-template.json", "pack-template.json",
            "metadata-template-0.json", "metadata-template-1.json",
            "metadata-original-0.json", "metadata-original-1.json", "fixture-manifest.json"}:
        raise ValueError("memory publication is outside fixed controls")
    return write_private(root / selected["leaf"], selected["value"], 65536)


def launch(selected):
    if set(selected) != {"action", "root", "python", "moduleDirectory", "kind", "selection"}:
        raise ValueError("memory launch selection differs")
    root = private_directory(checked_root(selected["root"]))
    modules = Path(selected["moduleDirectory"])
    if not str(modules).startswith("/nix/store/") or not selected["python"].startswith("/nix/store/"):
        raise ValueError("memory owner is not source-built")
    leaf = {"source": "worker_owner.py", "native": "guest.py", "admission": "admission.py"}.get(selected["kind"])
    selection_leaf = {"source": "owner-selection.json", "native": "native-selection.json",
        "admission": "admission-selection.json"}.get(selected["kind"])
    if leaf is None or selected["selection"]["file"] != str(root / selection_leaf):
        raise ValueError("memory owner selection path differs")
    raw = read_private(root / selection_leaf, 65536)
    if (len(raw) != selected["selection"]["bytes"]
            or hashlib.sha256(raw).hexdigest() != selected["selection"]["sha256"]):
        raise ValueError("memory owner controls changed before launch")
    controls = json.loads(raw)
    if not 3 < controls["cutoffUptimeSeconds"] - time.monotonic() <= 120:
        raise ValueError("memory owner original cutoff is expired")
    arguments = [selected["python"], "-B", str(modules / leaf), "--selection", str(root / selection_leaf)]
    with (root / (selected["kind"] + "-owner.stdout")).open("xb") as stdout, \
            (root / (selected["kind"] + "-owner.stderr")).open("xb") as stderr:
        os.fchmod(stdout.fileno(), 0o600)
        os.fchmod(stderr.fileno(), 0o600)
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=stdout,
            stderr=stderr, start_new_session=True)
    identity = process_pin(process.pid)
    record = {"root": str(root), "process": identity, "kind": selected["kind"]}
    write_private(root / (selected["kind"] + "-owner-process.json"), {"version": 1, **record,
        "arguments": arguments, "cutoffUptimeSeconds": controls["cutoffUptimeSeconds"]}, 8192)
    return record


def terminal_leaf(kind):
    leaf = {"source": "owner-terminal.json", "native": "terminal.json",
        "admission": "admission-terminal.json"}.get(kind)
    if leaf is None:
        raise ValueError("memory owner kind differs")
    return leaf


def poll_owner(selected):
    try:
        root, descriptor, exited = checked_owner({key: selected[key] for key in ("root", "process")})
    except ProcessLookupError:
        root = private_directory(checked_root(selected["root"]))
        descriptor, exited = None, True
    try:
        terminal = None
        if exited:
            path = root / terminal_leaf(selected["kind"])
            try:
                raw = read_private(path, 4 * 1024 * 1024)
                if json.loads(raw)["ownerProcess"] != selected["process"]:
                    raise ValueError("actual terminal record belongs to another owner lifetime")
                terminal = {"file": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            except FileNotFoundError:
                pass
        return {"pidfdReadable": exited if descriptor is not None else None,
            "recordedTerminalProcessAbsent": descriptor is None and terminal is not None,
            "process": selected["process"],
            "terminalReference": terminal, "providerDrain": None}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def mailbox(selected):
    if set(selected) != {"action", "root", "sequence", "runId", "case"}:
        raise ValueError("memory mailbox selection differs")
    root = private_directory(checked_root(selected["root"])) / "bridge"
    if type(selected["sequence"]) is not int or not 0 <= selected["sequence"] < 512:
        raise ValueError("memory mailbox sequence differs")
    path = root / f"request-{selected['sequence']:04d}.json"
    try:
        raw = read_private(path, 1024)
    except FileNotFoundError:
        return None
    request = checked_request(json.loads(raw), selected["runId"], selected["case"], selected["sequence"])
    if raw != encoded(request):
        raise ValueError("memory request canonical bytes differ")
    return {"request": request, "reference": {"file": str(path), "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest()}}


def respond(selected):
    if set(selected) != {"action", "root", "sequence", "requestSha256", "reply"}:
        raise ValueError("memory response selection differs")
    root = private_directory(checked_root(selected["root"])) / "bridge"
    sequence = selected["sequence"]
    if type(sequence) is not int or not 0 <= sequence < 512:
        raise ValueError("memory reply sequence differs")
    request = read_private(root / f"request-{sequence:04d}.json", 1024)
    if (hashlib.sha256(request).hexdigest() != selected["requestSha256"]
            or selected["reply"]["requestSha256"] != selected["requestSha256"]):
        raise ValueError("memory reply belongs to another original request")
    return write_private(root / f"response-{sequence:04d}.json", selected["reply"])


def run_action(selected):
    action = selected.get("action")
    if action == "prepare":
        if set(selected) != {"action", "root"}:
            raise ValueError("memory root selection differs")
        root = checked_root(selected["root"])
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name in ("bridge", "capture", "source"):
            (root / name).mkdir(mode=0o700)
        return {"root": str(private_directory(root)), "uptimeSeconds": time.monotonic(),
            "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    if action == "publish":
        return publish(selected)
    if action == "launch":
        return launch(selected)
    if action == "poll":
        if set(selected) != {"action", "root", "process", "kind"}:
            raise ValueError("memory owner poll fields differ")
        return poll_owner(selected)
    if action == "mailbox":
        return mailbox(selected)
    if action == "respond":
        return respond(selected)
    if action == "dispatch":
        if set(selected) != {"action", "root", "moduleDirectory", "selection"}:
            raise ValueError("memory dispatch fields differ")
        if (Path(selected["moduleDirectory"]) != Path(__file__).parent
                or selected["selection"]["root"] != str(private_directory(checked_root(selected["root"])))):
            raise ValueError("memory dispatch selected another source root")
        from bridge import worker_dispatch
        return asyncio.run(worker_dispatch(selected["selection"]))
    if action == "read_fixed":
        if set(selected) != {"action", "root", "leaf"}:
            raise ValueError("memory fixed read selection differs")
        limits = {"ready.json": 8192, "owner-terminal.json": 65536,
            "admission-terminal.json": 256 * 1024, "terminal.json": 4 * 1024 * 1024}
        maximum = limits.get(selected["leaf"])
        if maximum is None:
            raise ValueError("memory read leaves the closed output list")
        path = private_directory(checked_root(selected["root"])) / selected["leaf"]
        try:
            raw = read_private(path, maximum)
        except FileNotFoundError:
            return None
        return {"value": json.loads(raw), "reference": {"file": str(path),
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}
    if action == "source_chunk":
        if set(selected) != {"action", "root", "chunk"}:
            raise ValueError("memory source chunk selection differs")
        from files import transfer_chunk
        return transfer_chunk(private_directory(checked_root(selected["root"])), selected["chunk"])
    if action == "terminate":
        if set(selected) != {"action", "root", "process", "kind", "cutoffUptimeSeconds"}:
            raise ValueError("memory owner cleanup fields differ")
        try:
            _, descriptor, exited = checked_owner({key: selected[key] for key in ("root", "process")})
        except ProcessLookupError:
            observed = poll_owner(selected)
            return {**observed, "signalSent": False}
        try:
            remaining = selected["cutoffUptimeSeconds"] - time.monotonic()
            sent = False
            if remaining > 0 and not exited:
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                sent = True
            poll = select.poll()
            poll.register(descriptor, select.POLLIN)
            exited = exited or (remaining > 0 and bool(poll.poll(int(remaining * 1000))))
            return {"pidfdReadable": exited, "recordedTerminalProcessAbsent": False,
                "signalSent": sent, "providerDrain": None}
        finally:
            os.close(descriptor)
    raise ValueError("memory guest action is not selected")
