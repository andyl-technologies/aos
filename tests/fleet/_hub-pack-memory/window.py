"""Run one fixed pack/metadata overlap through genuine selected Native callbacks.

Callbacks must bind the existing Native client and owned source hold. This
adapter creates no plans, profiles, signatures, provider effects or authority.
An absent actual callback is an integration prerequisite, never a passed case.
"""

import asyncio
import time

CASES = {"semantic32", "live36", "replacement-overflow"}


def observed_capacity(rows):
    """Assess actual candidate interval headers without inferring whole memory."""
    if len(rows) != 2:
        raise ValueError("two actual metadata observations required")
    bulk, metadata, overlap = 0, 0, 0
    for row in rows:
        if set(row) != {"peakBulk", "peakMetadata", "peakMetadataWhileBulk", "admissions"}:
            raise ValueError("actual candidate buffer interval schema differs")
        if any(type(value) is not int or value < 0 for value in row.values()):
            raise ValueError("observed capacity counters differ")
        bulk = max(bulk, row["peakBulk"])
        metadata = max(metadata, row["peakMetadata"])
        overlap = max(overlap, row["peakMetadataWhileBulk"])
    if bulk != 1 or metadata != 2 or overlap != 2:
        raise ValueError("actual one-bulk/two-metadata overlap is absent or exceeded")
    return {"peakBulk": bulk, "peakMetadata": metadata, "peakMetadataWhileBulk": overlap}


async def run_case(case, prepared, native, hold, retain, *, monotonic=time.monotonic):
    """Execute one original once; cancellation retains unknown and never retries.

    native.inspect_pack(prepared['queryReference']) must call the actual current
    Native consumer and return its already checked result/proof references.
    native.metadata(originalReference) must drive the normal Native Mirror
    producer and return actual candidate buffer interval headers. Both callbacks
    are async and preserve original auth/SQL and unknown outcomes.
    The fixed holder methods belong to the independently
    selected one-pack source holder, not a fabricated provider-start dictionary.
    retain(name, observation) must be owner-private/create-only and bounded.
    """
    if case not in CASES or set(prepared) != {
            "queryReference", "metadataOriginalReferences", "originalCutoffMonotonic",
            "fixtureManifestReference", "currentTupleReference"}:
        raise ValueError("fixed case selection differs")
    if len(prepared["metadataOriginalReferences"]) != 2:
        raise ValueError("exactly two distinct metadata originals required")
    if prepared["metadataOriginalReferences"][0] == prepared["metadataOriginalReferences"][1]:
        raise ValueError("metadata original reused")
    cutoff = prepared["originalCutoffMonotonic"]
    if type(cutoff) not in {int, float} or not 0 < cutoff - monotonic() <= 120:
        raise ValueError("original cutoff absent, expired or outside fixed bound")
    # Leave retirement inside the original cutoff, never a replacement lease.
    operation_cutoff = cutoff - min(2.0, (cutoff - monotonic()) / 4)
    tasks = []
    released = False
    original_failure = None
    conclusion = {"version": 1, "case": case, "terminal": "unknown",
        "wholeIsolateBytes": None, "jsSdkBytes": None, "nativeBulkBytes": None,
        "hostedAdmission": None, "platformCpuMillis": None}

    async def original_wait(awaitable):
        remaining = operation_cutoff - monotonic()
        if remaining <= 0:
            if hasattr(awaitable, "close"):
                awaitable.close()
            raise TimeoutError("original operation cutoff reached")
        task = asyncio.ensure_future(awaitable)
        done, _ = await asyncio.wait({task}, timeout=remaining)
        if not done or monotonic() >= operation_cutoff:
            task.cancel()
            if task not in tasks:
                tasks.append(task)
            raise TimeoutError("original operation cutoff reached")
        return task.result()

    async def cleanup_wait(awaitable):
        remaining = cutoff - monotonic()
        if remaining <= 0:
            if hasattr(awaitable, "close"):
                awaitable.close()
            return False
        task = asyncio.ensure_future(awaitable)
        done, _ = await asyncio.wait({task}, timeout=remaining)
        if task not in done:
            task.cancel()
            return False
        task.result()
        return True

    try:
        tasks.append(asyncio.create_task(native.inspect_pack(prepared["queryReference"])))
        await original_wait(hold.wait_received())
        if monotonic() >= operation_cutoff:
            raise TimeoutError("original cutoff reached before metadata")
        for reference in prepared["metadataOriginalReferences"]:
            tasks.append(asyncio.create_task(native.metadata(reference)))
        await original_wait(hold.wait_metadata_received())
        await original_wait(hold.release_metadata_once())
        metadata = await original_wait(asyncio.gather(*tasks[1:]))
        # Bulk remains held until both normal metadata callbacks settle.
        if tasks[0].done():
            raise ValueError("pack completed before the held-read release")
        capacity = observed_capacity([row["bufferInterval"] for row in metadata])
        await original_wait(hold.release_once())
        released = True
        pack = await original_wait(tasks[0])
        conclusion.update({"terminal": "callbacks_completed", "capacity": capacity,
            "pack": pack, "metadata": metadata,
            "scope": "selected Native callbacks and observed interval only; qualification unknown"})
        await original_wait(retain("conclusion.json", conclusion))
        return conclusion
    except BaseException as original:
        original_failure = original
        try:
            await cleanup_wait(retain("failure.json", {**conclusion, "failureClass": type(original).__name__}))
        except BaseException:
            pass
        raise
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        # Retire the owned source even after a normal release. A released source
        # is not a drained source, and Python cancellation proves no provider EOF.
        remaining = max(0.0, cutoff - monotonic())
        retirement = asyncio.create_task(hold.cancel()) if remaining > 0 else None
        waiting = set(tasks) | ({retirement} if retirement is not None else set())
        done, pending = await asyncio.wait(waiting, timeout=remaining) if waiting else (set(), set())
        retirement_error = None
        for task in done:
            if not task.cancelled():
                error = task.exception()
                if task is retirement:
                    retirement_error = error
        for task in pending:
            task.cancel()
        incomplete = bool(pending) or retirement is None
        if incomplete:
            try:
                await cleanup_wait(retain("pending-cancellation.json", {
                    "pendingCallbacks": len(pending), "providerDrain": None,
                    "holdRetired": retirement is not None and retirement in done,
                    "qualification": None}))
            except BaseException:
                pass
        if original_failure is None and (incomplete or retirement_error is not None):
            raise TimeoutError("owned retirement incomplete within original cutoff") from retirement_error
