"""Synthetic source-shaped context joins, with no real authentication claim."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("context_wrapper", ROOT / "native_auth.py")
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)
SUPPORT = __import__("runpy").run_path(str(ROOT / "test_support.py"))
OBSERVER = SUPPORT["fixtures"](ROOT)


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = json.loads((OBSERVER / "cli-proof/positive-manifest.json").read_bytes())
        source = wrapper.SOURCE
        self.sources = {
            "nativeHandlerSourceSha256": wrapper.native_handler_source_sha256(source),
            "checkedContextSourceSha256": wrapper.digest((source / "crates/aos-hub-core/src/hybrid_ingress/observation.rs").read_bytes()),
        }
        build_record = json.loads(wrapper.PACKAGE_READER["installed_bytes"](
            ROOT.parent.parent / "helper-build-provenance.json"))
        self.process = {"pid": 321, "ownerUid": os.geteuid(), "startTicks": "123",
                        "executableSha256": wrapper.PACKAGE["runtime"]["nativeExecutableSha256"],
                        "executablePath": build_record["runtimeInputs"]["nativeExecutable"]}
        self.compacts, self.events = {}, []
        for index, row in enumerate(self.manifest["captures"]):
            # The production event requires the actual32-hex capture ID.
            row["requestId"] = str(index + 1) * 32
            if row.get("storageWorkSelection") is not None:
                continue
            compact = b"synthetic-private-compact-" + str(index).encode()
            self.compacts[row["requestId"]] = self.private("compact-" + str(index), compact)
            def frames(direction):
                body = row["bodies"][direction]
                return {"exposedBytes": body["byteSize"], "exposedSha256": body["sha256"],
                        "eof": True, "failed": False, "overflow": False}
            self.events.append({"version": 1, "requestId": row["requestId"], "method": row["method"],
                "pathSha256": wrapper.digest(row["procedure"].encode()),
                "compactSha256": wrapper.digest(compact), "originalSha256": "1" * 64,
                "phase": None, **self.sources, "envelopeAuthenticated": True, "bodyAuthenticated": True,
                "stage": "handler_completed", "status": 200,
                "checkedContexts": {"checks": [], "incomplete": False},
                "requestConsumed": frames("request"), "replyOffered": frames("response"),
                "completedAtUnixMicros": "100"})
        self.selected = {"version": 1, "runtimeCodecRevision": self.manifest["codecRevision"],
            "sourceDigest": self.manifest["sourceDigest"], "nativeExecutableSha256": self.process["executableSha256"],
            "nativeSources": self.sources, "nativeProcess": self.process, "nativeLog": None,
            "ingressCompacts": self.compacts,
            "observerExecutable": self.reference(Path(wrapper.PACKAGE["observerExecutable"]["file"])),
            "runtimeProvenance": self.reference(OBSERVER / "runtime-provenance.json"),
            "outputDirectory": str(self.root / "results")}
        Path(self.selected["outputDirectory"]).mkdir(mode=0o700)
        self.log()

    def reference(self, path):
        raw = path.read_bytes()
        return {"file": str(path), "sha256": wrapper.digest(raw), "byteSize": str(len(raw))}

    def private(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return self.reference(path)

    def log(self):
        raw = b"".join(json.dumps({"_PID": str(self.process["pid"]),
            "_EXE": self.process["executablePath"], "_SYSTEMD_UNIT": "aos-hub.service",
            "__REALTIME_TIMESTAMP": "100", "MESSAGE": "[INFO] message=native_ingress_application_body_observation "
            + json.dumps(row, separators=(",", ":"))}).encode() + b"\n" for row in self.events)
        self.selected["nativeLog"] = {"reference": self.private("native-log", raw), "format": "journal",
            "provenance": None, "epoch": {"beforeProcess": dict(self.process), "afterProcess": dict(self.process),
                                           "firstUnixMicros": "90", "lastUnixMicros": "110"}}

    def test_source_consistent_but_other_runtime_provenance_refuses(self):
        changed = json.loads((OBSERVER / "runtime-provenance.json").read_bytes())
        changed["sourceArchiveSha256"] = "f" * 64
        self.selected["runtimeProvenance"] = self.private("wrong-runtime-provenance", json.dumps(changed).encode())
        with self.assertRaisesRegex(ValueError, "six-field runtime"):
            wrapper.assess(self.selected, self.manifest)

    def test_installed_reader_rejects_private_or_noncanonical_code_paths(self):
        private_code = self.private("substituted-code", b"pass\n")
        with self.assertRaises(ValueError):
            wrapper.PACKAGE_READER["installed_bytes"](private_code["file"])
        executable = Path(wrapper.PACKAGE["observerExecutable"]["file"])
        traversed = executable.parent / ".." / "bin" / executable.name
        with self.assertRaises(ValueError):
            wrapper.PACKAGE_READER["installed_bytes"](traversed)

    def test_actual_source_reader_and_exact_frame_join(self):
        result = wrapper.assess(self.selected, self.manifest)
        self.assertTrue(result["wholeIngressContextComplete"])
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertEqual(len(result["captures"]), 2)
        self.assertEqual(len(result["externalJoinRequirements"]), 1)
        browser = result["captures"][-1]
        self.assertFalse(browser["independentMacVerification"])
        self.assertEqual(browser["sourceContractInference"], "current_management_handler_require_session_and_200")

    def test_missing_compact_does_not_erase_source_checked_event_or_fill_custody(self):
        self.selected["ingressCompacts"] = {}
        result = wrapper.assess(self.selected, self.manifest)
        self.assertFalse(result["wholeIngressContextComplete"])
        self.assertEqual(result["captures"][0]["sourceCheckedAuthentication"], "observed_native_checked_envelope_and_body")
        self.assertEqual(result["captures"][0]["compactCustody"], "unknown")

    def test_duplicate_partial_and_body_mismatch_stay_unknown(self):
        for mutate in (lambda: self.events.append(dict(self.events[0])),
                       lambda: self.events[0]["requestConsumed"].update(eof=False),
                       lambda: self.events[0]["replyOffered"].update(exposedSha256="2" * 64),
                       lambda: self.events[0]["checkedContexts"].update(incomplete=True)):
            original = copy.deepcopy(self.events)
            mutate()
            self.log()
            self.assertFalse(wrapper.assess(self.selected, self.manifest)["wholeIngressContextComplete"])
            self.events = original

    def test_source_process_and_epoch_substitution_refuse(self):
        self.selected["nativeSources"] = {**self.sources, "checkedContextSourceSha256": "3" * 64}
        with self.assertRaises(ValueError):
            wrapper.assess(self.selected, self.manifest)

    def test_plain_log_path_replacement_cannot_supply_the_second_read(self):
        raw = b"".join(("[INFO] message=native_ingress_application_body_observation "
            + json.dumps(row, separators=(",", ":")) + "\n").encode() for row in self.events)
        reference = self.private("plain-log", raw)
        path = Path(reference["file"])
        info = path.stat()
        self.process.update(logFile=str(path), commandLineSha256="4" * 64,
                            commandLineBytes=12, environmentSha256="5" * 64)
        position = {"path": str(path), "device": str(info.st_dev), "inode": str(info.st_ino)}
        provenance = {"beforeProcess": dict(self.process), "afterProcess": dict(self.process),
            "window": {"file": str(path), "before": {**position, "byteSize": 0},
                       "after": {**position, "byteSize": len(raw)},
                       "capturedBytes": len(raw), "sha256": wrapper.digest(raw)}}
        self.selected["nativeLog"].update(reference=reference, format="plain", provenance=provenance)
        self.selected["nativeLog"]["epoch"].update(beforeProcess=dict(self.process), afterProcess=dict(self.process))
        self.assertTrue(wrapper.assess(self.selected, self.manifest)["wholeIngressContextComplete"])
        original_reader = wrapper.source_readers

        def replaced(held_log=None):
            self.assertIsNotNone(held_log)
            path.rename(self.root / "old-plain-log")
            self.private("plain-log", b"substituted log\n")
            return original_reader(held_log)

        with patch.object(wrapper, "source_readers", side_effect=replaced):
            with self.assertRaisesRegex(ValueError, "Held Native log changed"):
                wrapper.assess(self.selected, self.manifest)

    def test_manifest_replacement_between_auth_and_codec_is_refused(self):
        selection = self.private("manifest-race-selection", json.dumps(self.selected).encode())
        manifest = self.private("manifest-race-input", json.dumps(self.manifest).encode())
        original = wrapper.observe

        def replaced(executable, path):
            with Path(path).open("ab") as output:
                output.write(b" ")
            return original(executable, path)

        with patch.object(wrapper, "observe", side_effect=replaced):
            with self.assertRaisesRegex(ValueError, "different manifest"):
                wrapper.execute(selection["file"], selection["sha256"], manifest["file"])
        self.assertEqual(list(Path(self.selected["outputDirectory"]).iterdir()), [])
        self.selected["nativeSources"] = self.sources
        self.selected["nativeLog"]["epoch"]["afterProcess"]["startTicks"] = "456"
        with self.assertRaises(ValueError):
            wrapper.assess(self.selected, self.manifest)

    def test_actual_cli_report_preserved_and_missing_context_exits_nonzero(self):
        for label, missing in (("positive", False), ("unknown", True)):
            if missing:
                self.selected["nativeLog"] = None
            self.selected["outputDirectory"] = str(self.root / (label + "-results"))
            Path(self.selected["outputDirectory"]).mkdir(mode=0o700)
            selection = self.private(label + "-selection", json.dumps(self.selected).encode())
            manifest = self.private(label + "-manifest", json.dumps(self.manifest).encode())
            command = [sys.executable, "-B", "-E", str(ROOT / "native_auth.py"),
                       selection["file"], selection["sha256"], manifest["file"]]
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 1 if missing else 0)
            actual = json.loads(result.stdout)
            self.assertEqual(len(actual), 8)
            self.assertTrue(all(row["authentication"].startswith("not_checked_") for row in actual["captures"]))
            assessment = json.loads((Path(self.selected["outputDirectory"]) / (manifest["sha256"] + ".json")).read_bytes())
            self.assertEqual(assessment["wholeIngressContextComplete"], not missing)
            self.assertEqual(assessment["reportSha256"], wrapper.digest(result.stdout))
            Path(selection["file"]).write_bytes(b"{}")
            refused = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(refused.stdout, b"")


if __name__ == "__main__":
    unittest.main()
