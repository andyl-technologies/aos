"""Run the genuine selected Native callbacks with a serialized Worker bridge.

This owner never derives an expected source identity from a runtime log. The
tuple, source descriptor, genuine admitted originals and publisher manifest are
separate pinned inputs. Its private result is workload evidence, not a claim of
whole-Worker or hosted memory qualification.
"""

import argparse
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import signal
import time

from bridge import GuestPackHold, private_directory, read_private, write_private
from callbacks import FreshNativeCallbacks


def load_sibling(name):
    path = Path(__file__).with_name(name + ".py")
    specification = importlib.util.spec_from_file_location("pack_guest_" + name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def original_child_cutoff(caller, process):
    """Read the actual pre-launch25s cutoff, never construct a replacement."""
    matches = []
    for row in getattr(caller, "process_cutoffs", {}).values():
        if not isinstance(row, dict) or set(row) != {"pid", "cutoffMonotonic"}:
            raise ValueError("actual child original-cutoff record differs")
        if type(row["pid"]) is int and row["pid"] == process.pid:
            matches.append(row)
    if len(matches) != 1:
        raise RuntimeError("actual child original cutoff is missing or ambiguous")
    cutoff = matches[0]["cutoffMonotonic"]
    if type(cutoff) not in {int, float} or not 0 < cutoff <= caller.cutoff:
        raise ValueError("actual child original cutoff exceeds its original owner")
    return cutoff


async def run_selected(selected):
    if (set(selected) != {"version", "runId", "case", "root", "bridgeRoot",
            "captureRoot", "currentTupleReference", "sourceDescriptorReference",
            "prepared", "cutoffUptimeSeconds"}
            or type(selected["version"]) is not int or selected["version"] != 1):
        raise ValueError("Native memory owner selection differs")
    root = private_directory(selected["root"])
    bridge_root = private_directory(selected["bridgeRoot"])
    cutoff = selected["cutoffUptimeSeconds"]
    remaining = cutoff - time.monotonic()
    if type(cutoff) not in {int, float} or not 3 < remaining <= 120:
        raise ValueError("original Native owner cutoff differs")
    operation_cutoff = cutoff - 2
    native_module = load_sibling("native")
    window_module = load_sibling("window")
    # The independent descriptor is supplied by the final common-source
    # artifact producer, never constructed from the selected caller output.
    native = native_module.NativeCaller(selected["currentTupleReference"],
        root / "native-originals", operation_cutoff, selected["captureRoot"],
        source_descriptor_reference=selected["sourceDescriptorReference"])
    callbacks = FreshNativeCallbacks(native, root, operation_cutoff)
    hold = GuestPackHold(bridge_root, selected["runId"], selected["case"], operation_cutoff)
    prepared = dict(selected["prepared"])
    if "originalCutoffMonotonic" in prepared:
        raise ValueError("foreign clock cannot supply the Native owner cutoff")
    prepared["originalCutoffMonotonic"] = operation_cutoff
    retained = []

    async def retain(name, value):
        if name not in {"conclusion.json", "failure.json", "pending-cancellation.json"}:
            raise ValueError("memory owner retained an unselected output")
        retained.append(write_private(root / name, value, 1024 * 1024))

    receipt = {"version": 1, "runId": selected["runId"], "case": selected["case"],
        "startedMonotonic": time.monotonic(), "originalCutoffMonotonic": cutoff,
        "terminal": "unknown", "failureClass": None, "result": None,
        "wholeIsolateBytes": None, "linearWasmBytes": None, "jsSdkBytes": None,
        "nativeBulkBytes": None, "platformCpuMillis": None, "providerDrain": None,
        "memory128PredicateQualified": False,
        "unresolved": ["whole_worker_isolate_allocation", "workerd_linear_memory_not_exposed"],
        "sourceDescriptorReference": selected["sourceDescriptorReference"],
        "currentTupleReference": selected["currentTupleReference"]}
    from worker_owner import process_pin
    receipt["ownerProcess"] = process_pin(os.getpid())
    primary = None
    try:
        result = await window_module.run_case(selected["case"], prepared, callbacks, hold, retain)
        # The pure exporter manifest describes the source pair. It cannot
        # stand in for captured production request/reply frames. This owner
        # retains actual callback references; the strict captured-frame codec
        # join remains unresolved and is never inferred from that manifest.
        receipt.update(terminal="callbacks_completed", result=result,
            actualPackCodec=None, codecJoinRequired=True)
    except BaseException as error:
        primary = error
        receipt.update(terminal="refused_or_unknown", failureClass=type(error).__name__,
            refusalEvidence=getattr(error, "evidence", None), intendedOverflowFence=None)
    finally:
        # NativeCaller owns the actual subprocess objects. Retirement uses
        # their original deadline and records actual wait completion only.
        child_outcomes = []
        # Prefer the SDK's create-only receipt: a known earlier original is
        # not made unknown just because another callback finished later. A
        # still-running child is retired only inside its actual original25s
        # cutoff, never the later parent120s window.
        for child in native.processes:
            outcome = {"pid": child.pid, "exit": child.returncode, "reaped": None,
                "reapedWithinOriginal": None}
            try:
                actual = None
                for reference in callbacks.references:
                    path = root / "native-originals" / reference["actualSelection"]["sha256"] / "receipt.json"
                    try:
                        candidate = json.loads(read_private(path, 65536))
                    except FileNotFoundError:
                        continue
                    if candidate.get("process", {}).get("pid") == child.pid:
                        actual = candidate
                        break
                if actual is not None:
                    outcome.update(reaped=actual.get("reaped"),
                        reapedWithinOriginal=actual.get("reapedWithinOriginal"),
                        originalCutoffMonotonic=actual["nativeSubwindowCutoffMonotonic"])
                else:
                    original = original_child_cutoff(native, child)
                    await native_module.retire_native_process(child, outcome, original)
                    # Missing SDK disposition remains unknown even after an
                    # observed parent wait. It cannot clear a poisoned caller.
                    outcome["sdkDispositionMissing"] = True
                if (outcome.get("reaped") is not True
                        or outcome.get("reapedWithinOriginal") is not True
                        or outcome.get("sdkDispositionMissing") is True):
                    raise RuntimeError("actual child original retirement is unknown")
            except BaseException as error:
                outcome["cleanupFailureClass"] = type(error).__name__
                if primary is None:
                    primary = error
                else:
                    primary.add_note("memory child cleanup failed: " + type(error).__name__)
            child_outcomes.append(outcome)
        receipt.update(childOutcomes=child_outcomes,
            ownedChildrenReaped=all(row.get("reaped") is True
                and row.get("reapedWithinOriginal") is True
                and row.get("cleanupFailureClass") is None for row in child_outcomes)
                and getattr(native, "_retirement_unknown", None) is None,
            retirementPoisoned=getattr(native, "_retirement_unknown", None) is not None,
            holdReplies=hold.receipts, retained=retained,
            actualSelections=callbacks.references,
            finishedMonotonic=time.monotonic())
        # Preservation is class-only; arbitrary helper failures remain in the
        # already private child logs, and never enter the control channel.
        try:
            write_private(root / "terminal.json", receipt, 4 * 1024 * 1024)
        except Exception as error:
            if primary is not None:
                primary.add_note("memory terminal retention failed: " + type(error).__name__)
            else:
                raise
    if not receipt["ownedChildrenReaped"]:
        raise RuntimeError("Native memory child retirement remains unknown") from primary
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True)
    arguments = parser.parse_args()
    selected = json.loads(read_private(arguments.selection, 65536))
    async def own():
        operation = asyncio.create_task(run_selected(selected))
        loop = asyncio.get_running_loop()
        for name in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(name, operation.cancel)
        return await operation

    receipt = asyncio.run(own())
    # Fixed status only. Original SQL, URLs and private child output stay in
    # their create-only files; the host separately retains explicit references.
    print(json.dumps({"version": 1, "terminal": receipt["terminal"],
        "ownedChildrenReaped": receipt["ownedChildrenReaped"]}, separators=(",", ":")))


if __name__ == "__main__":
    main()
