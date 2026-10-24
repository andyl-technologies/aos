# SPDX-License-Identifier: MIT
"""Validates native memory diagnostics; it never certifies complete model state."""

import re
import sys
import unittest


HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _integer(fields, name, limit=1 << 64):
    value = fields.get(name)
    if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
        raise ValueError(f"missing native memory integer: {name}")
    result = int(value)
    if result >= limit:
        raise ValueError(f"native memory value exceeds its ceiling: {name}")
    return result


def _digest(fields, prefix, expected_bytes):
    if _integer(fields, prefix + ".bytes") != expected_bytes:
        raise ValueError(f"modeled byte extent differs: {prefix}")
    value = fields.get(prefix + ".sha256", "")
    if not isinstance(value, str) or HEX_DIGEST.fullmatch(value) is None:
        raise ValueError(f"modeled byte digest is missing: {prefix}")



def inspect_packet_payloads(inventory):
    """Rejects hashes of allocated, undefined native read-request storage."""
    packets = 0
    for item in inventory.get("objects", []):
        fields = item.get("modeled_fields", {})
        for key in fields:
            if not key.endswith(".has_storage"):
                continue
            prefix = key.removesuffix(".has_storage")
            if prefix + ".command" not in fields:
                continue
            packets += 1
            storage = _integer(fields, key, 2)
            defined = _integer(fields, prefix + ".data_defined", 2)
            if defined:
                if not storage:
                    raise ValueError("defined packet data lacks storage")
                _digest(fields, prefix + ".data", _integer(fields, prefix + ".size", 1048577))
            elif prefix + ".data.sha256" in fields or prefix + ".data.bytes" in fields:
                raise ValueError("undefined read-request storage was hashed")
            count = _integer(fields, prefix + ".functional_bytes", 1048577)
            for index in range(count):
                valid = _integer(fields, f"{prefix}.functional_byte[{index}]", 2)
                value_key = f"{prefix}.functional_value[{index}]"
                if valid:
                    if not storage:
                        raise ValueError("valid functional byte lacks storage")
                    _integer(fields, value_key, 256)
                elif value_key in fields:
                    raise ValueError("undefined functional packet byte was observed")
    return packets

def inspect_inventory(inventory, expected_ram_bytes):
    """Requires genuine selected-profile fields and returns explicit omissions."""
    if inventory.get("schema") != "crucible.gem5.modeled-state.v1":
        raise ValueError("unknown modeled memory schema")
    if inventory.get("complete") is not False:
        raise ValueError("partial modeled memory cannot claim complete state")

    found = set()
    omissions = []
    valid_blocks = 0
    for item in inventory.get("objects", []):
        fields = item.get("modeled_fields", {})
        if not fields:
            continue
        if not isinstance(fields, dict):
            raise ValueError("native object field map is malformed")
        memory_anchors = {"memory.total_bytes", "tags.num_blocks",
                          "controller.read_priorities", "dram.ranks"}
        if not memory_anchors.intersection(fields):
            continue
        # CPU vector-element banks have a separate explicitly bounded budget;
        # this checker only owns the selected memory/cache/controller visitors.
        if len(fields) > 131072:
            raise ValueError("native memory field map is unbounded")
        if item.get("state_complete") is not False:
            raise ValueError("partial native object claims complete state")
        if "memory.total_bytes" in fields:
            if "physical-memory" in found:
                raise ValueError("selected profile has duplicate physical-memory owners")
            found.add("physical-memory")
            if _integer(fields, "memory.total_bytes") != expected_ram_bytes:
                raise ValueError("selected profile RAM size differs")
            count = _integer(fields, "memory.backing_count", 1025)
            ranges = []
            for index in range(count):
                prefix = f"memory.backing[{index}]"
                start = _integer(fields, prefix + ".guest_start")
                end = _integer(fields, prefix + ".guest_end")
                if end <= start:
                    raise ValueError("modeled backing range is empty or reversed")
                extent = end - start
                _digest(fields, prefix + ".data", extent)
                ranges.append((start, end))
            # This selected O3 fixture admits RAM at [0, expected_ram_bytes).
            # Native AddrRange.end() is exclusive. Equal summed extents cannot
            # establish coverage because overlap may hide an omitted region.
            covered_end = 0
            for start, end in sorted(ranges):
                if start != covered_end or end > expected_ram_bytes:
                    raise ValueError("private RAM inventory has missing or duplicate bytes")
                covered_end = end
            if covered_end != expected_ram_bytes:
                raise ValueError("private RAM inventory has missing or duplicate bytes")
        if "tags.num_blocks" in fields:
            found.add("cache-tags")
            count = _integer(fields, "tags.num_blocks", 16385)
            block_size = _integer(fields, "tags.block_size", 4097)
            if count != _integer(fields, "tags.visited_blocks"):
                raise ValueError("native cache visitor missed block storage")
            for index in range(count):
                prefix = f"tags.block[{index}]"
                valid = _integer(fields, prefix + ".valid", 2)
                if valid:
                    valid_blocks += 1
                    _digest(fields, prefix + ".data", block_size)
        if "controller.read_priorities" in fields:
            found.add("memory-controller")
            for kind in ("read", "write"):
                count = _integer(fields, f"controller.{kind}_priorities", 65)
                for index in range(count):
                    _integer(fields, f"controller.{kind}[{index}].size", 65537)
            _integer(fields, "controller.response.size", 65537)
        if "dram.ranks" in fields:
            found.add("dram")
            count = _integer(fields, "dram.ranks", 65)
            if count == 0:
                raise ValueError("native DRAM rank inventory is empty")
            for index in range(count):
                prefix = f"dram.rank[{index}]"
                _integer(fields, prefix + ".refresh_due_at")
                _integer(fields, prefix + ".power_state_tick")
                _integer(fields, prefix + ".banks", 65)
        if any(key.startswith(("memory.", "tags.", "controller.", "dram."))
               for key in fields):
            unsupported = fields.get("coverage.unsupported")
            if not unsupported:
                raise ValueError("native memory visitor lost its omission ledger")
            omissions.append((item.get("name"), unsupported))

    required = {"physical-memory", "cache-tags", "memory-controller", "dram"}
    if found != required or valid_blocks == 0:
        raise ValueError("selected native workload lacks required memory witnesses")
    return omissions


def require_complete_inventory(inventory, expected_ram_bytes):
    """Refuses incomplete RAM/cache/controller/transient state closure."""
    omissions = inspect_inventory(inventory, expected_ram_bytes)
    raise ValueError(f"complete memory model refused: {len(omissions)} unvisited domains")


class CoverageTests(unittest.TestCase):
    def setUp(self):
        fields = [
            {"memory.total_bytes": "1024", "memory.backing_count": "1",
             "memory.backing[0].guest_start": "0", "memory.backing[0].guest_end": "1024",
             "memory.backing[0].data.bytes": "1024", "memory.backing[0].data.sha256": "a" * 64},
            {"tags.num_blocks": "1", "tags.visited_blocks": "1", "tags.block_size": "64",
             "tags.block[0].valid": "1", "tags.block[0].data.bytes": "64",
             "tags.block[0].data.sha256": "b" * 64},
            {"controller.read_priorities": "1", "controller.read[0].size": "1",
             "controller.write_priorities": "1", "controller.write[0].size": "0",
             "controller.response.size": "0"},
            {"dram.ranks": "1", "dram.rank[0].refresh_due_at": "100",
             "dram.rank[0].power_state_tick": "0", "dram.rank[0].banks": "8"},
        ]
        for item in fields:
            item["coverage.unsupported"] = "unvisited-fields"
        self.inventory = {
            "schema": "crucible.gem5.modeled-state.v1", "complete": False,
            "objects": [{"name": str(index), "state_complete": False, "modeled_fields": item}
                        for index, item in enumerate(fields)],
        }

    def test_partial_inventory_cannot_be_promoted(self):
        self.assertEqual(len(inspect_inventory(self.inventory, 1024)), 4)
        with self.assertRaises(ValueError):
            require_complete_inventory(self.inventory, 1024)

    def test_missing_ram_digest_is_detected(self):
        del self.inventory["objects"][0]["modeled_fields"]["memory.backing[0].data.sha256"]
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def test_dirty_cache_content_loss_is_detected(self):
        del self.inventory["objects"][1]["modeled_fields"]["tags.block[0].data.sha256"]
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def test_ram_extent_mismatch_is_detected(self):
        self.inventory["objects"][0]["modeled_fields"]["memory.backing[0].data.bytes"] = "1023"
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def test_missing_dram_refresh_state_is_detected(self):
        del self.inventory["objects"][3]["modeled_fields"]["dram.rank[0].refresh_due_at"]
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def set_backing_ranges(self, ranges):
        fields = self.inventory["objects"][0]["modeled_fields"]
        fields["memory.backing_count"] = str(len(ranges))
        for index, (start, end) in enumerate(ranges):
            prefix = f"memory.backing[{index}]"
            fields[prefix + ".guest_start"] = str(start)
            fields[prefix + ".guest_end"] = str(end)
            fields[prefix + ".data.bytes"] = str(end - start)
            fields[prefix + ".data.sha256"] = "a" * 64

    def test_equal_sum_overlapping_ram_omission_is_detected(self):
        self.set_backing_ranges([(0, 512), (256, 768)])
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def test_shifted_equal_size_ram_is_detected(self):
        self.set_backing_ranges([(512, 1536)])
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def test_reordered_adjacent_backings_cover_admitted_ram(self):
        self.set_backing_ranges([(512, 1024), (0, 512)])
        self.assertEqual(len(inspect_inventory(self.inventory, 1024)), 4)

    def test_duplicate_physical_memory_owner_is_detected(self):
        self.inventory["objects"].append(self.inventory["objects"][0])
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def test_unknown_complete_claim_is_rejected(self):
        self.inventory["complete"] = True
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def test_omission_loss_is_detected(self):
        del self.inventory["objects"][2]["modeled_fields"]["coverage.unsupported"]
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)

    def test_cpu_field_budget_is_owned_by_cpu_checker(self):
        fields = {f"cpu.register[{index}]": "0" for index in range(131073)}
        self.inventory["objects"].append({"name": "cpu", "state_complete": False,
                                          "modeled_fields": fields})
        self.assertEqual(len(inspect_inventory(self.inventory, 1024)), 4)

    def packet_inventory(self, fields):
        return {"objects": [{"modeled_fields": {"packet.command": "1", **fields}}]}

    def test_pending_read_storage_has_no_payload_digest(self):
        value = self.packet_inventory({"packet.has_storage": "1", "packet.data_defined": "0",
                                       "packet.functional_bytes": "0"})
        self.assertEqual(inspect_packet_payloads(value), 1)

    def test_pending_read_payload_digest_refused(self):
        value = self.packet_inventory({"packet.has_storage": "1", "packet.data_defined": "0",
                                       "packet.data.sha256": "a" * 64,
                                       "packet.functional_bytes": "0"})
        with self.assertRaises(ValueError):
            inspect_packet_payloads(value)

    def test_defined_write_payload_requires_matching_extent(self):
        value = self.packet_inventory({"packet.has_storage": "1", "packet.data_defined": "1",
                                       "packet.size": "8", "packet.data.bytes": "8",
                                       "packet.data.sha256": "a" * 64,
                                       "packet.functional_bytes": "0"})
        self.assertEqual(inspect_packet_payloads(value), 1)
        value["objects"][0]["modeled_fields"]["packet.data.bytes"] = "7"
        with self.assertRaises(ValueError):
            inspect_packet_payloads(value)

    def test_functional_partial_read_observes_only_valid_bytes(self):
        fields = {"packet.has_storage": "1", "packet.data_defined": "0",
                  "packet.functional_bytes": "2", "packet.functional_byte[0]": "1",
                  "packet.functional_byte[1]": "0", "packet.functional_value[0]": "42"}
        value = self.packet_inventory(fields)
        self.assertEqual(inspect_packet_payloads(value), 1)
        value["objects"][0]["modeled_fields"]["packet.functional_value[1]"] = "99"
        with self.assertRaises(ValueError):
            inspect_packet_payloads(value)

    def test_selected_memory_map_budget_is_still_bounded(self):
        fields = self.inventory["objects"][0]["modeled_fields"]
        fields.update({f"memory.extra[{index}]": "0" for index in range(131073)})
        with self.assertRaises(ValueError):
            inspect_inventory(self.inventory, 1024)


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: memory-state-coverage-check.py --self-test")
    unittest.main(argv=[sys.argv[0]])
