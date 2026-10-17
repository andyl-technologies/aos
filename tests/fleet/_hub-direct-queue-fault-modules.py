"""Prepare an explicit fixture wrapper around a reviewed installed Worker tuple.

The original registered module files remain unchanged. Named Durable Object
exports are re-exported from their original shim; only its default callbacks are
wrapped. The resulting module graph is a new fixture input, never an ordinary
deployment artifact or a provider acceptance record.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path


def _digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def prepare_queue_fault_modules(installed, expected, selection, destination):
    """Copy only exact reviewed modules and write a source-bound fixture entry.

    The caller must independently review the installed receipt. Matching hashes
    here protects against drift during preparation and does not create authority.
    Files remain retained on any failure, with no automatic cleanup or overwrite.
    """
    installed, destination = Path(installed), Path(destination)
    if (not str(installed).startswith("/nix/store/") or not installed.is_dir()
            or installed.resolve() != installed or destination.exists()
            or set(expected) != {"compiledSourceDigest", "modules"}
            or set(expected["modules"]) != {"shim.mjs", "index.wasm"}):
        raise ValueError("queue fault modules need the exact reviewed installed tuple and a fresh root")
    worker = Path(__file__).with_name("_hub-direct-queue-fault-worker.mjs")
    helper = Path(__file__).with_name("_hub-direct-queue-faults.py")
    spec = importlib.util.spec_from_file_location("queue_faults", helper)
    faults = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(faults)
    if (not isinstance(expected["compiledSourceDigest"], str)
            or not faults.DIGEST.fullmatch(expected["compiledSourceDigest"])
            or selection.get("sourceDigest") != expected["compiledSourceDigest"]):
        raise ValueError("queue fault selected source differs from the installed receipt")
    destination.mkdir(mode=0o700)
    records = {}
    for name, target in [("shim.mjs", "installed-shim.mjs"), ("index.wasm", "index.wasm")]:
        path = installed / name
        selected = expected["modules"][name]
        maximum = 2 * 1024 * 1024 if name == "shim.mjs" else 64 * 1024 * 1024
        if (path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum
                or set(selected) != {"bytes", "sha256"}
                or type(selected["bytes"]) is not int or path.stat().st_size != selected["bytes"]
                or _digest(path) != selected["sha256"]):
            raise ValueError("installed queue fault module differs from the reviewed bytes")
        body = path.read_bytes()
        if name == "index.wasm" and (not body.startswith(b"\0asm\1\0\0\0")
                or expected["compiledSourceDigest"].encode() not in body):
            raise ValueError("selected compiled source is absent from the actual Wasm")
        output = destination / target
        with output.open("xb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        output.chmod(0o444)
        records[target] = {"bytes": len(body), "sha256": _digest(output)}
    wrapper = destination / "queue-fault-worker.mjs"
    wrapper.write_bytes(worker.read_bytes())
    wrapper.chmod(0o444)
    entry = destination / "queue-fault-entry.mjs"
    entry.write_text(
        "import installed from './installed-shim.mjs';\n"
        "export * from './installed-shim.mjs';\n"
        "import { wrapDirectQueueFaults } from './queue-fault-worker.mjs';\n"
        "const selection = " + json.dumps(selection, ensure_ascii=True, separators=(",", ":")) + ";\n"
        "export default wrapDirectQueueFaults(installed, selection);\n"
    )
    entry.chmod(0o444)
    for path in (wrapper, entry):
        records[path.name] = {"bytes": path.stat().st_size, "sha256": _digest(path)}
    return {"version": 1, "installed": str(installed), "scriptPath": str(entry),
            "compiledSourceDigest": expected["compiledSourceDigest"], "modules": records,
            "scope": "fixture wrapper graph around unchanged registered modules; no ordinary artifact relabel"}
