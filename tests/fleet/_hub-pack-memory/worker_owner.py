"""Own the selected source child within one original Worker uptime window."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import time

from bridge import private_directory, read_private, write_private


def process_pin(pid):
    directory = Path("/proc") / str(pid)
    fields = (directory / "stat").read_text().rpartition(") ")[2].split()
    if fields[0] == "Z" or directory.stat().st_uid != os.getuid():
        raise ValueError("owned source child is not live")
    return {"pid": pid, "startTicks": int(fields[19]), "ownerUid": os.getuid(),
        "executable": str((directory / "exe").resolve(strict=True))}


def peer_pin(path, expected):
    metadata = Path(path).lstat()
    if (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077):
        raise ValueError("source socket custody differs")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(0.5)
        peer.connect(path)
        pid, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if pid != expected["pid"] or uid != expected["ownerUid"] or process_pin(pid) != expected:
        raise ValueError("source socket names another actual child")


async def run_owner(selected):
    if (set(selected) != {"version", "root", "node", "launcher", "configurationFile",
            "cutoffUptimeSeconds"} or type(selected["version"]) is not int
            or selected["version"] != 1):
        raise ValueError("source owner selection differs")
    root = private_directory(selected["root"])
    cutoff = selected["cutoffUptimeSeconds"]
    if type(cutoff) not in {int, float} or not 3 < cutoff - time.monotonic() <= 120:
        raise ValueError("original source owner cutoff differs")
    configuration = json.loads(read_private(selected["configurationFile"], 65536))
    if (configuration["privateRoot"] != str(root)
            or configuration["controlSocket"] != str(root / "source.sock")
            or configuration["cutoffUptimeMillis"] != cutoff * 1000):
        raise ValueError("source owner and selected source cutoffs differ")
    for field in ("node", "launcher"):
        if not selected[field].startswith("/nix/store/"):
            raise ValueError("source-built launcher is not selected")
    logs = [open(root / name, "xb") for name in ("stdout.log", "stderr.log")]
    for stream in logs:
        os.fchmod(stream.fileno(), 0o600)
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(name, stopped.set)
    process = None
    waiter = None
    receipt = {"version": 1, "startedMonotonic": time.monotonic(),
        "originalCutoffMonotonic": cutoff, "ready": None, "exit": None,
        "reaped": None, "failureClass": None, "providerDrain": None}
    receipt["ownerProcess"] = process_pin(os.getpid())
    primary = None
    try:
        process = await asyncio.create_subprocess_exec(selected["node"], selected["launcher"],
            selected["configurationFile"], stdin=asyncio.subprocess.DEVNULL,
            stdout=logs[0], stderr=logs[1])
        identity = process_pin(process.pid)
        while True:
            if process.returncode is not None or time.monotonic() >= cutoff - 3 or stopped.is_set():
                raise RuntimeError("source child unavailable before readiness")
            try:
                peer_pin(str(root / "source.sock"), identity)
                break
            except FileNotFoundError:
                await asyncio.sleep(min(0.05, cutoff - 3 - time.monotonic()))
        receipt["ready"] = {"version": 1, "process": identity,
            "socket": str(root / "source.sock"), "originalCutoffMonotonic": cutoff}
        write_private(root / "ready.json", receipt["ready"], 8192)
        waiter = asyncio.create_task(process.wait())
        cancellation = asyncio.create_task(stopped.wait())
        await asyncio.wait({waiter, cancellation}, timeout=max(0, cutoff - 3 - time.monotonic()),
            return_when=asyncio.FIRST_COMPLETED)
        cancellation.cancel()
    except BaseException as error:
        primary = error
        receipt["failureClass"] = type(error).__name__
    finally:
        if process is not None:
            if waiter is None:
                waiter = asyncio.create_task(process.wait())
            remaining = cutoff - time.monotonic()
            if remaining > 0 and process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
            done, _ = await asyncio.wait({waiter}, timeout=max(0, remaining / 2))
            if not done and cutoff - time.monotonic() > 0:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                done, _ = await asyncio.wait({waiter}, timeout=max(0, cutoff - time.monotonic()))
            receipt["exit"] = waiter.result() if done else process.returncode
            receipt["reaped"] = True if done and time.monotonic() < cutoff else None
            if not done:
                waiter.cancel()
        for stream in logs:
            for action in (stream.flush, lambda: os.fsync(stream.fileno()), stream.close):
                try:
                    action()
                except Exception as error:
                    if primary is None:
                        primary = error
                        receipt["failureClass"] = type(error).__name__
                    else:
                        primary.add_note("source output retention failed: " + type(error).__name__)
        receipt["finishedMonotonic"] = time.monotonic()
        try:
            write_private(root / "owner-terminal.json", receipt, 65536)
        except Exception as error:
            if primary is None:
                raise
            primary.add_note("source owner retention failed: " + type(error).__name__)
    if primary is not None:
        raise primary
    if receipt["reaped"] is not True:
        raise RuntimeError("source child reap remains unknown")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True)
    arguments = parser.parse_args()
    os.umask(0o077)
    asyncio.run(run_owner(json.loads(read_private(arguments.selection, 65536))))
