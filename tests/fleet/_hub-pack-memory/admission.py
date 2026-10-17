"""Run only the genuine SQL-backed Status/Begin preparation before holding reads."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import signal
import time

from bridge import private_directory, read_private, write_private
from callbacks import FreshNativeCallbacks
from guest import load_sibling, original_child_cutoff
from worker_owner import process_pin


async def run(selected):
    if set(selected) != {"version", "root", "currentTupleReference", "sourceDescriptorReference",
            "templateReference", "cutoffUptimeSeconds"} or type(selected["version"]) is not int \
            or selected["version"] != 1:
        raise ValueError("Native admission owner selection differs")
    root = private_directory(selected["root"])
    cutoff = selected["cutoffUptimeSeconds"]
    if type(cutoff) not in {int, float} or not 3 < cutoff - time.monotonic() <= 30:
        raise ValueError("Native admission original cutoff differs")
    native_module = load_sibling("native")
    caller = native_module.NativeCaller(selected["currentTupleReference"], root / "admission-originals",
        cutoff - 2, root / "capture", source_descriptor_reference=selected["sourceDescriptorReference"])
    callbacks = FreshNativeCallbacks(caller, root, cutoff - 2)
    receipt = {"version": 1, "ownerProcess": process_pin(os.getpid()), "result": None,
        "failureClass": None, "reaped": None, "providerDrain": None}
    primary = None
    try:
        actual = callbacks.selection(selected["templateReference"])
        template = json.loads(read_private(actual["file"], 65536))
        if template["phase"]["kind"] != "prepare_metadata":
            raise ValueError("Native admission phase differs")
        receipt["result"] = await caller._run(actual)
    except BaseException as error:
        primary = error
        receipt["failureClass"] = type(error).__name__
        receipt["refusalEvidence"] = getattr(error, "evidence", None)
    finally:
        outcomes = []
        # Prefer the SDK's create-only receipt: a known earlier original is
        # not made unknown just because another callback finished later. A
        # still-running child is retired only inside its actual original25s
        # cutoff, never the later parent120s window.
        for child in caller.processes:
            outcome = {"pid": child.pid, "exit": child.returncode, "reaped": None,
                "reapedWithinOriginal": None}
            try:
                actual = None
                for reference in callbacks.references:
                    path = root / "admission-originals" / reference["actualSelection"]["sha256"] / "receipt.json"
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
                    original = original_child_cutoff(caller, child)
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
            outcomes.append(outcome)
        receipt.update(childOutcomes=outcomes, reaped=all(row.get("reaped") is True and row.get("reapedWithinOriginal") is True
                and row.get("cleanupFailureClass") is None for row in outcomes)
                and getattr(caller, "_retirement_unknown", None) is None,
            retirementPoisoned=getattr(caller, "_retirement_unknown", None) is not None,
            actualSelections=callbacks.references, finishedMonotonic=time.monotonic())
        try:
            write_private(root / "admission-terminal.json", receipt, 256 * 1024)
        except Exception as error:
            if primary is None:
                raise
            primary.add_note("admission retention failed: " + type(error).__name__)
    if primary is not None:
        raise primary
    if not receipt["reaped"]:
        raise RuntimeError("Native admission reap remains unknown")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True)
    selected = json.loads(read_private(parser.parse_args().selection, 65536))

    async def own():
        task = asyncio.create_task(run(selected))
        for name in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(name, task.cancel)
        return await task

    result = asyncio.run(own())
    print(json.dumps({"version": 1, "actualPreparationReturned": result["result"] is not None,
        "ownedChildrenReaped": result["reaped"]}, separators=(",", ":")))
