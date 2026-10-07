"""Controlled source/correlation fences, without process or provider effects."""

import asyncio
import copy
import hashlib
import importlib.util
import json
import tempfile
import time
from unittest import mock
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("native_owner", Path(__file__).with_name("native.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeInputs(unittest.TestCase):
    def final_inputs(self):
        source = "/nix/store/" + "a" * 32 + "-final-common-source"
        descriptor = {"version": 1, "sourceCommit": "1" * 40, "sourceTree": "2" * 40,
            "commonSourceStorePath": source, "modules": {}, "artifacts": {}}
        value = {"version": 2, "runtimeParentCommit": descriptor["sourceCommit"],
            "runtimeSourceStorePath": source}
        for role, (path, _, _) in native.MODULES.items():
            descriptor["modules"][role] = {"relativePath": path, "bytes": 200, "sha256": "3" * 64}
            value[role] = {"file": source + "/" + path, "bytes": 200, "sha256": "3" * 64}
        for role in ("nativeExecutable", "codecExecutable"):
            descriptor["artifacts"][role] = {"file": "/nix/store/" + "b" * 32 + "-fixture/bin/" + role,
                "bytes": 100, "sha256": "4" * 64}
            value[role] = dict(descriptor["artifacts"][role])
        return value, descriptor

    def test_final_descriptor_required_and_cannot_relabel_historical_tuple(self):
        value, descriptor = self.final_inputs()
        self.assertEqual(native.validate_current_tuple(value, descriptor), value)
        with self.assertRaises(ValueError):
            native.validate_current_tuple(value)
        value["version"] = 1
        value["runtimeParentCommit"] = native.COMMIT
        with self.assertRaises(ValueError):
            native.validate_current_tuple(value, descriptor)

    def test_crossed_source_modules_and_artifacts_refuse_before_loading(self):
        value, descriptor = self.final_inputs()
        for role, field, changed in (("resources", "sha256", "5" * 64),
                ("executeParser", "file", "/tmp/arbitrary.py"),
                ("nativeExecutable", "sha256", "5" * 64)):
            wrong = copy.deepcopy(value)
            wrong[role][field] = changed
            with self.assertRaises(ValueError):
                native.validate_current_tuple(wrong, descriptor)
        for key, changed in (("sourceCommit", "bad"), ("sourceTree", "bad")):
            wrong = copy.deepcopy(descriptor)
            wrong[key] = changed
            with self.assertRaises(ValueError):
                native.validate_current_tuple(value, wrong)
        descriptor["modules"]["resources"]["bytes"] = 256 * 1024 + 1
        with self.assertRaises(ValueError):
            native.validate_current_tuple(value, descriptor)

    def capture(self):
        header = '{"peakBulk":1,"peakMetadata":2,"peakMetadataWhileBulk":2,"admissions":2}'
        observation = {"version": 1, "planId": "5" * 32, "transportCallId": "6" * 32, "jobId": "7" * 64,
            **{key: "3" * 64 for key in ("originalDigest", "stepDigest", "protectedProfileDigest",
                "requestSha256", "replySha256")}, "requestBytes": "200", "replyBytes": "100",
            "responseHeaderName": "x-aos-mirror-candidate-buffers", "responseHeaderValue": header,
            "responseHeaderSha256": hashlib.sha256(header.encode()).hexdigest(),
            "bufferInterval": json.loads(header), "replyMacAuthentication": None}
        captured = {"version": 1, "selectionSha256": "1" * 64,
            "nativeExecutableSha256": "2" * 64, "candidateObservation": observation}
        result = {"selectionSha256": "1" * 64, "nativeExecutableSha256": "2" * 64,
            "result": {"kind": "metadata", "progress": {"original_digest": "3" * 64}}}
        return captured, result

    def test_actual_header_commitment_and_native_original_correlation(self):
        captured, result = self.capture()
        self.assertEqual(native.validate_candidate_capture(captured, result, "1" * 64, "2" * 64),
            captured["candidateObservation"]["bufferInterval"])
        for field, wrong in (("originalDigest", "4" * 64), ("responseHeaderValue", "{}"),
                ("requestBytes", 200), ("replyMacAuthentication", True)):
            changed = copy.deepcopy(captured)
            changed["candidateObservation"][field] = wrong
            with self.assertRaises(ValueError):
                native.validate_candidate_capture(changed, result, "1" * 64, "2" * 64)

    def test_unknown_header_counts_and_crossed_native_selection_do_not_pass(self):
        captured, result = self.capture()
        for interval in ({"peakBulk": 1, "peakMetadata": 2},
                {"peakBulk": True, "peakMetadata": 2, "peakMetadataWhileBulk": 2, "admissions": 2}):
            changed = copy.deepcopy(captured)
            changed["candidateObservation"]["bufferInterval"] = interval
            raw = json.dumps(interval)
            changed["candidateObservation"]["responseHeaderValue"] = raw
            changed["candidateObservation"]["responseHeaderSha256"] = hashlib.sha256(raw.encode()).hexdigest()
            with self.assertRaises(ValueError):
                native.validate_candidate_capture(changed, result, "1" * 64, "2" * 64)
        result["selectionSha256"] = "4" * 64
        with self.assertRaises(ValueError):
            native.validate_candidate_capture(captured, result, "1" * 64, "2" * 64)


    def test_unknown_retirement_blocks_different_later_selection(self):
        class Process:
            def __init__(self, outcome):
                self.pid = 123
                self.outcome = outcome

            async def wait(self):
                if self.outcome == "timeout":
                    await asyncio.Future()
                return 1

        async def exercise(outcome, retirement):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                selection = root / "selection.json"
                selection.write_text(json.dumps({"outputFile": str(root / "output.json")}))
                selection.chmod(0o600)
                reference = native.measured_reference(selection, 65536)
                caller = native.NativeCaller.__new__(native.NativeCaller)
                caller.root = root / "calls"
                caller.root.mkdir(mode=0o700)
                caller.current_tuple_reference = {}
                caller.source_descriptor_reference = None
                caller.current_tuple = {"resources": {}, "nativeExecutable": {}}
                caller.executable = Path("/fixture/native")
                caller.cutoff = time.monotonic() + 2.5
                caller.started = set()
                caller.processes = []
                caller.process_cutoffs = {}
                caller._retirement_unknown = None
                caller.resources = mock.Mock()
                caller.resources.process_identity.return_value = {"pid": 123}
                caller.resources.process_sample.return_value = {"observed": "controlled"}

                async def retire(process, receipt, cutoff):
                    receipt.update({"reaped": retirement == "known",
                        "reapedWithinOriginal": retirement == "known"})
                    if retirement == "error":
                        raise RuntimeError("controlled retirement failure")

                selected_before_launch = None

                async def spawn(*arguments, **keywords):
                    nonlocal selected_before_launch
                    selected_before_launch = dict(caller.process_cutoffs[reference["sha256"]])
                    self.assertIsNone(selected_before_launch["pid"])
                    self.assertLessEqual(selected_before_launch["cutoffMonotonic"], caller.cutoff)
                    self.assertLessEqual(selected_before_launch["cutoffMonotonic"], time.monotonic() + 25)
                    return Process(outcome)

                launch = mock.AsyncMock(side_effect=spawn)
                expected_error = TimeoutError if outcome == "timeout" else native.NativeRefusal
                with mock.patch.object(native, "selected_tuple", return_value=caller.current_tuple), \
                        mock.patch.object(native.asyncio, "create_subprocess_exec", launch), \
                        mock.patch.object(native, "retire_native_process", retire):
                    with self.assertRaises(expected_error) as retained:
                        await caller._run(reference)
                    if outcome == "refusal":
                        evidence = retained.exception.evidence
                        self.assertIsNotNone(evidence["receiptReference"])
                        actual = json.loads(native.retained_bytes(evidence["receiptReference"], 65536))
                        self.assertEqual(actual["reaped"], retirement == "known")
                        self.assertIsNone(evidence["refusalCategory"])
                        self.assertEqual(actual["nativeSubwindowCutoffMonotonic"],
                            selected_before_launch["cutoffMonotonic"])
                    if retirement == "known":
                        caller._require_known_retirement()
                    else:
                        with self.assertRaisesRegex(TimeoutError, "prior Native retirement remains unknown"):
                            await caller._run({"file": "/different/original.json"})
                        caller._retain_retirement_state({"reaped": True, "reapedWithinOriginal": True}, root)
                        with self.assertRaises(TimeoutError):
                            caller._require_known_retirement()
                    self.assertEqual(launch.await_count, 1)
                    self.assertEqual(caller.process_cutoffs[reference["sha256"]],
                        {"pid": 123, "cutoffMonotonic": selected_before_launch["cutoffMonotonic"]})

        for outcome, retirement in (("refusal", "unknown"), ("timeout", "unknown"),
                ("refusal", "error"), ("refusal", "known")):
            with self.subTest(outcome=outcome, retirement=retirement):
                asyncio.run(exercise(outcome, retirement))


if __name__ == "__main__":
    unittest.main()
