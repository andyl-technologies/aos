"""Checks exact source derivation; these controls do not execute a guest."""

import argparse
import importlib.util
from pathlib import Path
import unittest


def load(path):
    specification = importlib.util.spec_from_file_location("oracle_transform", path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class SourceControls(unittest.TestCase):
    def test_omission_reconstructs_every_precursor_byte(self):
        changed = tool.transform(physical).decode()
        restored = changed.replace(tool.OMISSION, "", 1).replace(tool.HEADER_WITH_CLOCK, tool.HEADER, 1)
        self.assertEqual(restored.encode(), physical)
        self.assertEqual(changed.count(tool.OMISSION), 1)

    def test_first_horizon_and_other_clients_are_preserved(self):
        changed = tool.transform(physical).decode()
        self.assertIn("icount_get_raw_observed() >= 700000", changed)
        self.assertIn(tool.ANCHOR, changed)
        for client in ["CRUCIBLE_CHECKPOINT", "MIGRATION", "VGA", "CODE"]:
            self.assertEqual(changed.count("DIRTY_MEMORY_" + client), physical.decode().count("DIRTY_MEMORY_" + client))
        self.assertEqual(changed.count("qemu_crucible_ram_dirty_generation_advance();"), physical.decode().count("qemu_crucible_ram_dirty_generation_advance();"))

    def test_already_changed_source_is_refused(self):
        with self.assertRaises(ValueError):
            tool.transform(tool.transform(physical))

    def test_unknown_source_is_refused_without_anchor_search(self):
        for changed in [physical + b"\n", physical.replace(b"CRUCIBLE_CHECKPOINT", b"CRUCIBLE_CHECKPOINX", 1)]:
            with self.subTest(source=tool.digest(changed)):
                with self.assertRaises(ValueError):
                    tool.transform(changed)

    def test_paged_token_noack_and_containment_contract_is_exact(self):
        tool.verify_paged(paged)
        self.assertEqual(tool.digest(paged), tool.PAGED_SHA256)

    def test_paged_drift_cannot_turn_into_positive_evidence(self):
        for changed in [paged + b"\n", paged.replace(b"result->capture_close.attempted != 1", b"false", 1), paged.replace(b"qemu_crucible_ram_diagnostic_fail(result->first_status);", b";", 1)]:
            with self.subTest(source=tool.digest(changed)):
                with self.assertRaises(ValueError):
                    tool.verify_paged(changed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--physical-source", type=Path, required=True)
    parser.add_argument("--paged-source", type=Path, required=True)
    parser.add_argument("--transform-tool", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    tool = load(args.transform_tool)
    physical = args.physical_source.read_bytes()
    paged = args.paged_source.read_bytes()
    unittest.main(argv=[__file__, *remaining])
