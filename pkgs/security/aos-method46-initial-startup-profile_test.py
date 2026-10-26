"""Checks profile producer boundaries without claiming native startup authority."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("aos-method46-initial-startup-profile.py")
SPEC = importlib.util.spec_from_file_location("initial_profile", SOURCE)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class ProducerTests(unittest.TestCase):
    def parameters(self, purpose):
        initial, _, normal = PROFILE.PURPOSES[purpose]
        return [purpose, Path("/package/bin") / initial, Path("/package/bin") / normal,
                811, 812, [99] * 32, [f"/package/bin/{normal}", "811", "812"]]

    def test_purposes_keep_distinct_commands_and_exact_non_mls_subjects(self):
        self.assertEqual(set(PROFILE.PURPOSES), {"controller", "storage"})
        self.assertEqual(len(set(PROFILE.PURPOSES.values())), 2)
        for purpose, (_, context, _) in PROFILE.PURPOSES.items():
            self.assertEqual(len(context.split(":")), 3)
            parameters = self.parameters(purpose)
            PROFILE.require_parameters(*parameters)

            for index in (1, 2):
                wrong = copy.deepcopy(parameters)
                wrong[index] = Path("/package/bin/foreign")
                with self.subTest(purpose=purpose, field=index), self.assertRaises(ValueError):
                    PROFILE.require_parameters(*wrong)

    def test_identifiers_and_public_key_are_exact_bounded_public_data(self):
        for purpose in PROFILE.PURPOSES:
            for index in (3, 4):
                for value in (0, -1, True, "811", 1 << 32):
                    wrong = self.parameters(purpose)
                    wrong[index] = value
                    with self.subTest(purpose=purpose, field=index, value=value), self.assertRaises(ValueError):
                        PROFILE.require_parameters(*wrong)
            for public in (None, "99" * 32, [0] * 32, [99] * 31, [99] * 33,
                           [True] * 32, [-1] * 32, [256] * 32):
                wrong = self.parameters(purpose)
                wrong[5] = public
                with self.subTest(purpose=purpose, public=public), self.assertRaises(ValueError):
                    PROFILE.require_parameters(*wrong)

    def test_command_bounds_count_utf8_bytes_and_retain_exact_argument_zero(self):
        for purpose in PROFILE.PURPOSES:
            parameters = self.parameters(purpose)
            argv0 = parameters[-1][0]
            for argv in ([], "not-a-list", [None], ["/foreign"], [argv0, "x\0y"],
                         [argv0] + [""] * 128, [argv0, "x" * 1025],
                         [argv0, "é" * 513], [argv0] + ["x" * 1024] * 32):
                wrong = copy.deepcopy(parameters)
                wrong[-1] = argv
                with self.subTest(purpose=purpose, argv=argv), self.assertRaises(ValueError):
                    PROFILE.require_parameters(*wrong)
            parameters[-1] = [argv0, "é" * 512, ""]
            PROFILE.require_parameters(*parameters)

    def test_normalized_unit_keeps_every_other_byte_in_the_commitment(self):
        entry = f"OpenFile={PROFILE.PROFILE_PLACEHOLDER}:{PROFILE.PROFILE_FD}:read-only\n".encode()
        unit = b"[Service]\nExecStart=selected\n" + entry
        PROFILE.require_unit_contract(unit)
        changed = unit + b"Environment=LD_PRELOAD=/foreign.so\n"
        PROFILE.require_unit_contract(changed)
        self.assertNotEqual(hashlib.sha256(unit).digest(), hashlib.sha256(changed).digest())

        for bad in (b"", unit * 2, b"# " + entry, entry[:-1], unit + b"\0",
                    unit + b"\xff", unit + b"x" * (64 * 1024),
                    entry.replace(b"read-only", b"graceful")):
            with self.subTest(unit=bad[:100]), self.assertRaises(ValueError):
                PROFILE.require_unit_contract(bad)

    def test_policy_provenance_requires_both_actual_digests_without_duplicates(self):
        with tempfile.TemporaryDirectory(prefix="aos-method46-profile-") as temporary:
            root = Path(temporary)
            canonical = root / "policy.33"
            canonical.write_bytes(b"actual canonical policy bytes")
            source = {"sha256": list(hashlib.sha256(b"source bytes").digest())}
            readback = {"sha256": list(hashlib.sha256(canonical.read_bytes()).digest())}
            evidence = (f"source_policy_sha256={bytes(source['sha256']).hex()}\n"
                        f"readback_sha256={bytes(readback['sha256']).hex()}\n")
            provenance = root / "provenance"
            provenance.write_text(evidence)
            PROFILE.require_policy_provenance(canonical, source, readback)

            for changed in ("", evidence.replace("source_policy_sha256=", "foreign="),
                            evidence.replace("readback_sha256=", "foreign="),
                            evidence + evidence.splitlines()[0] + "\n",
                            evidence.replace(bytes(source["sha256"]).hex(), "00" * 32)):
                provenance.write_text(changed)
                with self.subTest(provenance=changed), self.assertRaises(ValueError):
                    PROFILE.require_policy_provenance(canonical, source, readback)

    def test_oversized_or_foreign_closure_refuses_before_elf_resolution(self):
        runtime = mock.Mock()
        helpers = mock.Mock()
        helpers.graph_paths.return_value = [Path("/root")] * 513
        with self.assertRaises(ValueError):
            PROFILE.image_inventory(runtime, helpers, None, "initialRuntimeClosure",
                                    Path("/foreign/bin/selected"), None, None)
        runtime.runtime_files.assert_not_called()

        helpers.graph_paths.return_value = [Path("/root")]
        helpers.closure_owner.return_value = None
        with self.assertRaises(ValueError):
            PROFILE.image_inventory(runtime, helpers, None, "normalRuntimeClosure",
                                    Path("/foreign/bin/selected"), None, None)
        runtime.runtime_files.assert_not_called()

    def test_both_generated_profiles_join_actual_pins_and_complete_contract_bytes(self):
        # Only ELF resolution is replaced here. The test owns ordinary scratch
        # files, not immutable store images or genuine Source/TPM authority.
        runtime = PROFILE.load_helpers(SOURCE.with_name("aos-normal-root-profile.py"))
        for purpose in PROFILE.PURPOSES:
            with tempfile.TemporaryDirectory(prefix="aos-method46-profile-") as temporary:
                root = Path(temporary)
                initial_name, context, normal_name = PROFILE.PURPOSES[purpose]
                values = {}
                for name, filename in {
                    "executable": initial_name, "normal-executable": normal_name,
                    "normal-unit": f"{normal_name}.service", "pid1": "systemd",
                    "canonical-policy": "policy.33", "source-policy": "source-policy.33",
                    "effective-matrix": "effective-policy.tsv", "unit-contract": "unit-contract",
                    "normal-argv": "argv.json", "approval-public-key": "public.json",
                }.items():
                    values[name] = root / filename
                    values[name].write_text(f"actual selected {name} bytes\n")
                unit = (b"[Service]\nExecStart=selected\n" +
                        f"OpenFile={PROFILE.PROFILE_PLACEHOLDER}:{PROFILE.PROFILE_FD}:read-only\n".encode())
                values["unit-contract"].write_bytes(unit)
                argv = [str(values["normal-executable"]), "811", "812"]
                values["normal-argv"].write_text(json.dumps(argv))
                public = [99] * 32
                values["approval-public-key"].write_text(json.dumps(public))
                source_digest = bytes(runtime.pin(values["source-policy"])["sha256"]).hex()
                canonical_digest = bytes(runtime.pin(values["canonical-policy"])["sha256"]).hex()
                (root / "provenance").write_text(
                    f"source_policy_sha256={source_digest}\nreadback_sha256={canonical_digest}\n")
                output = root / "profile.json"
                command = ["profile", "--purpose", purpose, "--controller-uid", "811",
                           "--controller-gid", "812", "--output", str(output)]
                for name, value in values.items():
                    command.extend([f"--{name}", str(value)])
                for name in ("attrs", "runtime-profile-helpers", "elf-helpers", "patchelf", "readelf"):
                    command.extend([f"--{name}", str(root / name)])

                def inventory(runtime_helpers, elf_helpers, attrs, graph, executable, patchelf, readelf):
                    pin = runtime.pin(executable)
                    return {"executable": pin, "loader": runtime.pin(values["pid1"]),
                            "runtime_files": [pin], "closure_roots": [str(root)]}

                with mock.patch.object(PROFILE, "load_helpers", return_value=runtime), \
                        mock.patch.object(PROFILE, "image_inventory", side_effect=inventory), \
                        mock.patch.object(sys, "argv", command):
                    PROFILE.main()
                document = json.loads(output.read_bytes())
                self.assertEqual(document["format"], "AOS_METHOD46_INITIAL_STARTUP_3")
                self.assertEqual(document["unit"], f"{initial_name}.service")
                self.assertEqual(document["owner_context"], context)
                self.assertEqual(document["normal_image"]["argv"], argv)
                self.assertEqual(document["normal_unit_fragment"], runtime.pin(values["normal-unit"]))
                self.assertEqual(document["unit_sha256"], list(hashlib.sha256(unit).digest()))
                self.assertEqual(document["canonical_policy"], runtime.pin(values["canonical-policy"]))
                self.assertEqual(document["approval_public_key"], public)
                self.assertEqual((document["controller_uid"], document["controller_gid"]), (811, 812))

                # A conflicting actual provenance must not produce a new file.
                output.unlink()
                (root / "provenance").write_text("source_policy_sha256=foreign\n")
                with mock.patch.object(PROFILE, "load_helpers", return_value=runtime), \
                        mock.patch.object(PROFILE, "image_inventory", side_effect=inventory), \
                        mock.patch.object(sys, "argv", command), self.assertRaises(ValueError):
                    PROFILE.main()
                self.assertFalse(output.exists())

if __name__ == "__main__":
    unittest.main()
