"""Controlled adapter tests; no Native/Worker/provider/memory qualification."""

import asyncio
import time
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("window", Path(__file__).with_name("window.py"))
window = importlib.util.module_from_spec(spec)
spec.loader.exec_module(window)
native_spec = importlib.util.spec_from_file_location("native_owner", Path(__file__).with_name("native.py"))
native_owner = importlib.util.module_from_spec(native_spec)
native_spec.loader.exec_module(native_owner)


class WindowTests(unittest.IsolatedAsyncioTestCase):
    def selection(self):
        return {"queryReference": "actual-query-ref", "metadataOriginalReferences": ["first", "second"],
            "originalCutoffMonotonic": 30, "fixtureManifestReference": "fixture-ref",
            "currentTupleReference": "tuple-ref"}

    async def test_positive_overlap_releases_once_after_both_metadata(self):
        events = []
        release = asyncio.Event()
        holder_entered = asyncio.Event()
        class Native:
            async def inspect_pack(self, reference):
                events.append("pack_started")
                holder_entered.set()
                await release.wait()
                return {"scope": "controlled mock result"}
            async def metadata(self, reference):
                events.append(reference)
                await asyncio.sleep(0)
                return {"bufferInterval": {"peakBulk":1,"peakMetadata":2,
                    "peakMetadataWhileBulk":2,"admissions":2}}
        class Hold:
            async def wait_received(self): await holder_entered.wait()
            async def wait_metadata_received(self): await asyncio.sleep(0)
            async def release_metadata_once(self): events.append("metadata_release")
            async def release_once(self):
                self.releases += 1
                events.append("release")
                release.set()
            async def cancel(self): events.append("cancel")
            releases = 0
        hold = Hold()
        rows = []
        async def retain(name, row): rows.append((name, row))
        result = await window.run_case("live36", self.selection(), Native(), hold, retain, monotonic=lambda:1)
        self.assertEqual(hold.releases, 1)
        self.assertLess(events.index("metadata_release"), events.index("release"))
        self.assertLess(events.index("first"), events.index("release"))
        self.assertLess(events.index("second"), events.index("release"))
        self.assertIsNone(result["wholeIsolateBytes"])
        self.assertIsNone(result["nativeBulkBytes"])

    async def test_expired_original_has_no_dispatch(self):
        class Never:
            def __getattr__(self, name): self.fail(name)
        with self.assertRaisesRegex(ValueError, "cutoff"):
            await window.run_case("live36", self.selection(), Never(), Never(), Never(), monotonic=lambda:31)

    async def test_cutoff_during_hold_cancels_without_release_or_metadata(self):
        values = iter([1, 1, 1, 31])
        events = []
        class Native:
            async def inspect_pack(self, reference):
                events.append("pack")
                await asyncio.Event().wait()
            async def metadata(self, reference): events.append("forbidden_metadata")
        class Hold:
            async def wait_received(self): return None
            async def release_once(self): events.append("forbidden_release")
            async def cancel(self): events.append("cancel")
        async def retain(name, row): events.append(name)
        with self.assertRaises(TimeoutError):
            await window.run_case("live36", self.selection(), Native(), Hold(), retain,
                monotonic=lambda:next(values, 31))
        self.assertNotIn("forbidden_metadata",events)
        self.assertNotIn("forbidden_release",events)
        self.assertNotIn("cancel", events)
        self.assertNotIn("conclusion.json", events)

        # A cancellation-resistant hold must not get another five seconds after
        # the original expires, even when all controlled operations succeeded.
        release = asyncio.Event()
        entered = asyncio.Event()
        class ImmediateNative:
            async def inspect_pack(self, reference):
                entered.set()
                await release.wait()
                return {"scope": "controlled"}
            async def metadata(self, reference):
                return {"bufferInterval": {"peakBulk": 1, "peakMetadata": 2,
                    "peakMetadataWhileBulk": 2, "admissions": 2}}
        class SlowRetirement:
            async def wait_received(self): await entered.wait()
            async def wait_metadata_received(self): return None
            async def release_metadata_once(self): return None
            async def release_once(self): release.set()
            async def cancel(self): await asyncio.Event().wait()
        selected = self.selection()
        started = time.monotonic()
        selected["originalCutoffMonotonic"] = started + 0.04
        with self.assertRaisesRegex(TimeoutError, "retirement"):
            await window.run_case("live36", selected, ImmediateNative(), SlowRetirement(), retain)
        self.assertLess(time.monotonic() - started, 0.2)

        # TERM-resistant children get KILL and an actual wait inside the second
        # half. An owner with no remaining original reserve issues no signal.
        class Child:
            returncode = None
            def __init__(self, kill_settles=True):
                self.calls = []
                self.exited = asyncio.Event()
                self.kill_settles = kill_settles
            def terminate(self): self.calls.append("term")
            def kill(self):
                self.calls.append("kill")
                if self.kill_settles:
                    self.returncode = -9
                    self.exited.set()
            async def wait(self):
                await self.exited.wait()
                self.calls.append("reap")
                return self.returncode
        for kill_settles in (True, False):
            child = Child(kill_settles)
            receipt = {}
            started = time.monotonic()
            await native_owner.retire_native_process(child, receipt, started + 0.04)
            self.assertEqual(child.calls[:2], ["term", "kill"])
            self.assertLess(time.monotonic() - started, 0.2)
            self.assertEqual(receipt["reaped"], True if kill_settles else None)
            self.assertEqual(receipt["exit"], -9 if kill_settles else None)
            if kill_settles:
                self.assertTrue(receipt["reapedWithinOriginal"])
                self.assertIn("reap", child.calls)
        expired = Child()
        await native_owner.retire_native_process(expired, {}, time.monotonic() - 1)
        self.assertEqual(expired.calls, [])

    def test_configured_or_excessive_capacity_does_not_pass(self):
        for bulk, metadata, overlap in [(0,2,2),(1,1,1),(2,2,2),(1,3,3)]:
            row={"peakBulk":bulk,"peakMetadata":metadata,"peakMetadataWhileBulk":overlap,"admissions":2}
            with self.assertRaises(ValueError): window.observed_capacity([row,row])

        # Exact current-source tuple pins refuse arbitrary files/modules before
        # any dynamic execution; fixture artifact hashes here are structural only.
        source = "/nix/store/" + "a" * 32 + "-selected-current-source"
        selected = {"version": 1, "runtimeParentCommit": native_owner.COMMIT,
            "runtimeSourceStorePath": source}
        for role, (relative, count, digest) in native_owner.MODULES.items():
            selected[role] = {"file": source + "/" + relative, "bytes": count, "sha256": digest}
        for role in ("nativeExecutable", "codecExecutable"):
            selected[role] = {"file": "/nix/store/" + "b" * 32 + "-fixture/bin/" + role,
                "bytes": 1, "sha256": "c" * 64}
        self.assertEqual(native_owner.validate_current_tuple(selected), selected)
        for role in native_owner.MODULES:
            for field, wrong in (("file", "/tmp/unreviewed.py"), ("bytes", 1), ("sha256", "d" * 64)):
                changed = {**selected, role: {**selected[role], field: wrong}}
                with self.assertRaises(ValueError): native_owner.validate_current_tuple(changed)


if __name__ == "__main__":
    unittest.main()
