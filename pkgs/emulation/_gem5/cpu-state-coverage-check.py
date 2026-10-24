# SPDX-License-Identifier: MIT
"""Checks partial native CPU diagnostics and refuses complete-state qualification.

This checker validates diagnostic coverage, not process-image provenance. It is
used by the actual x86/Arm O3 continuation witness and can run its adversarial
checks using ``python3 cpu-state-coverage-check.py --self-test``.
"""

import copy
import unittest


MAX_OBJECTS = 65536
MAX_FIELDS_PER_OBJECT = 262144
# The selected Arm O3 profile has 16,384 physical vector elements. Its full
# register, rename, scoreboard, and pipeline map measured 347,648 fields at the
# event-5000 witness cut. Keep its map budget separate from container counts.
MAX_O3_FIELDS = 524288
MAX_REFERENCES = 1048576

REQUIRED_FIELDS = {
    "o3": {
        "cpu.status", "cpu.instruction_sequence", "cpu.fetch_target_sequence",
        "cpu.thread_count", "registers.integer.count", "registers.integer.register_bytes",
        "scoreboard.count", "instruction.count", "remove_list.count",
        "active_threads.count", "waiting_threads.count",
    },
    "predictor": {"threads", "requires_btb_hit", "conditional_predictor", "return_stack"},
    "tournament": {
        "local_counters.count", "local_history.count", "global_counters.count",
        "global_history.count", "choice_counters.count", "history_register_mask",
    },
    "return_stack": {"threads", "entries"},
    "x86_tlb": {"size", "next_lru_sequence", "configuration_address", "free_list.count", "walker"},
    "arm_tlb": {
        "size", "stage_two", "walk_cache", "vmid", "table.entry_count",
        "table.replacement_policy", "table.previous_present", "observed_page_size.count",
    },
}


def _kind(native_type):
    """Recognizes only visitor classes present in the pinned native source."""
    return {
        "N4gem52o33CPUE": "o3",
        "N4gem517branch_prediction9BPredUnitE": "predictor",
        "N4gem517branch_prediction12TournamentBPE": "tournament",
        "N4gem517branch_prediction15ReturnAddrStackE": "return_stack",
        "N4gem56X86ISA3TLBE": "x86_tlb",
        "N4gem56ArmISA3TLBE": "arm_tlb",
        "BPredUnit": "predictor", "TournamentBP": "tournament",
        "ReturnAddrStack": "return_stack",
    }.get(native_type)


def _decimal(fields, key):
    value = fields.get(key)
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise ValueError(f"missing or invalid native decimal: {key}")
    result = int(value)
    if result > MAX_FIELDS_PER_OBJECT:
        raise ValueError(f"diagnostic count exceeds the selected witness ceiling: {key}")
    return result


def inspect_inventory(inventory, guest_isa):
    """Returns precise omission records after checking the selected CPU visitors.

    Raises ``ValueError`` for missing native fields, unbounded inventories, unknown
    guest profiles, fabricated complete flags, or ambiguous object identities.
    """
    if guest_isa not in ("x86_64", "aarch64"):
        raise ValueError("unknown CPU witness profile")
    if inventory.get("schema") != "crucible.gem5.modeled-state.v1":
        raise ValueError("unknown native inventory schema")
    if inventory.get("complete") is not False:
        raise ValueError("partial native visitor cannot assert complete state")
    objects = inventory.get("objects")
    if not isinstance(objects, list) or len(objects) > MAX_OBJECTS:
        raise ValueError("native object roster exceeds its ceiling")

    names, visited, omissions = set(), set(), []
    for item in objects:
        name, native_type = item.get("name"), item.get("native_type")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("native object identity is missing or duplicated")
        names.add(name)
        if not isinstance(native_type, str) or not native_type:
            raise ValueError("native object type is missing")
        if item.get("state_complete") is not False:
            raise ValueError(f"unqualified native object asserts complete state: {name}")
        kind = _kind(native_type)
        field_limit = MAX_O3_FIELDS if kind == "o3" else MAX_FIELDS_PER_OBJECT
        fields = item.get("modeled_fields")
        if not isinstance(fields, dict) or len(fields) > field_limit:
            raise ValueError(f"invalid or unbounded native field map: {name}")
        if any(not isinstance(key, str) or not isinstance(value, str)
               for key, value in fields.items()):
            raise ValueError(f"native field map contains untyped values: {name}")

        if kind is None:
            omissions.append((name, native_type, "native-type-not-qualified-by-cpu-witness"))
            continue
        visited.add(kind)
        missing = REQUIRED_FIELDS[kind] - fields.keys()
        if missing:
            raise ValueError(f"native {kind} visitor omitted required fields: {sorted(missing)}")
        unsupported = fields.get("coverage.unsupported")
        if not unsupported:
            raise ValueError(f"native {kind} visitor omitted its unsupported-state ledger")
        omissions.extend((name, native_type, domain) for domain in unsupported.split(";") if domain)
        omissions.extend((name, native_type, value) for key, value in fields.items()
                         if key.endswith(".coverage.unsupported") and value)

        if kind == "o3":
            count = _decimal(fields, "registers.integer.count")
            register_bytes = _decimal(fields, "registers.integer.register_bytes")
            if not count or not register_bytes:
                raise ValueError("O3 physical integer register bank is empty")
            for index in range(count):
                prefix = f"registers.integer[{index}].value"
                if _decimal(fields, prefix + ".bytes") != register_bytes:
                    raise ValueError("physical register byte count differs from its bank")
                digest = fields.get(prefix + ".sha256", "")
                if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    raise ValueError("physical register content digest is missing or malformed")
            for index in range(_decimal(fields, "cpu.thread_count")):
                for mapping in ("speculative_rename", "committed_rename"):
                    _decimal(fields, f"thread[{index}].{mapping}.class[0].count")

    required = {"o3", "predictor", "tournament", "return_stack",
                "x86_tlb" if guest_isa == "x86_64" else "arm_tlb"}
    if not required <= visited:
        raise ValueError(f"native CPU profile lacks typed visitors: {sorted(required - visited)}")
    if not omissions:
        raise ValueError("partial native profile lacks an omission ledger")
    return omissions


def require_complete_inventory(inventory, guest_isa):
    """Refuses exact qualification while any native domain remains unvisited."""
    omissions = inspect_inventory(inventory, guest_isa)
    raise ValueError(f"complete microstate qualification refused: {len(omissions)} unvisited domains")


def _u64(value, subject):
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise ValueError(f"invalid native identity: {subject}")
    result = int(value)
    if result >= 1 << 64:
        raise ValueError(f"native identity exceeds u64: {subject}")
    return result


def inspect_pipeline_inventory(inventory, guest_isa):
    """Checks selected pipeline storage, age order, and semantic alias collisions.

    This additional diagnostic profile requires the pipeline patch. It refuses
    missing physical slots and contradictory identities even when all retained
    references have syntactically valid ledger IDs. Coverage remains partial.
    """
    omissions = inspect_inventory(inventory, guest_isa)
    ledger = inventory.get("reference_ledger")
    if not isinstance(ledger, list) or len(ledger) > MAX_REFERENCES:
        raise ValueError("missing or unbounded native reference ledger")
    for index, reference in enumerate(ledger):
        if (reference.get("reference_identity") != str(index)
                or not isinstance(reference.get("kind"), str) or not reference["kind"]
                or reference.get("payload_complete") is not False):
            raise ValueError("ambiguous or complete-claiming reference ledger")

    semantic_aliases, identities = {}, {}
    for item in inventory["objects"]:
        fields = item["modeled_fields"]
        for key, alias in fields.items():
            if not key.endswith(".alias"):
                continue
            prefix = key[:-6]
            present = fields.get(prefix + ".present")
            if present is None:
                continue
            if present == "0":
                if alias != "null":
                    raise ValueError("absent instruction has a live alias")
                continue
            if present != "1":
                raise ValueError("invalid native instruction presence flag")
            index = _u64(alias, key)
            if index >= len(ledger) or ledger[index]["kind"] != "instruction":
                raise ValueError("instruction alias is missing or has a conflicting kind")
            cpu = fields.get(prefix + ".cpu")
            if not isinstance(cpu, str) or not cpu:
                raise ValueError("instruction semantic identity lacks its allocating CPU")
            sequence = _u64(fields.get(prefix + ".sequence"), prefix)
            thread = _u64(fields.get(prefix + ".thread"), prefix)
            semantic = cpu, sequence
            if semantic in semantic_aliases and semantic_aliases[semantic] != alias:
                raise ValueError("distinct instruction aliases collide on CPU sequence identity")
            identity = cpu, sequence, thread
            if alias in identities and identities[alias] != identity:
                raise ValueError("one instruction alias has contradictory semantic identities")
            semantic_aliases[semantic], identities[alias] = alias, identity

        if _kind(item["native_type"]) != "o3":
            continue
        threads = _decimal(fields, "cpu.thread_count")
        for ring in ("backward", "fetch", "decode", "rename", "iew"):
            prefix = "handoff." + ring
            past, future = _decimal(fields, prefix + ".past"), _decimal(fields, prefix + ".future")
            size, base = _decimal(fields, prefix + ".size"), _decimal(fields, prefix + ".base")
            if size != past + future + 1 or base >= size:
                raise ValueError("handoff ring geometry or cursor is inconsistent")
            for lane in range(-past, future + 1):
                key = prefix + f".lane[{lane}]"
                if ring == "backward":
                    for thread in range(threads):
                        if key + f".thread[{thread}].decodeBlock" not in fields:
                            raise ValueError("retained backward handoff lane is missing")
                else:
                    _decimal(fields, key + ".size")
        for thread in range(threads):
            prefix = f"stage.iew.load_store_queue.thread[{thread}]"
            for queue in ("load_queue", "store_queue"):
                key = prefix + "." + queue
                capacity = _decimal(fields, key + ".capacity")
                size = _decimal(fields, key + ".size")
                if not capacity or size > capacity:
                    raise ValueError("native load/store queue geometry is inconsistent")
                _u64(fields.get(key + ".head"), key)
                for slot in range(capacity):
                    row = key + f".slot[{slot}]"
                    if fields.get(row + ".valid") not in ("0", "1"):
                        raise ValueError("retained load/store physical slot is missing")
                    if queue == "store_queue":
                        if not _decimal(fields, row + ".store_data.bytes"):
                            raise ValueError("store buffer byte storage is missing")
                        digest = fields.get(row + ".store_data.sha256", "")
                        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                            raise ValueError("store buffer content commitment is missing")
        prefix = "stage.iew.instruction_queue.age_order"
        previous = -1
        for index in range(_decimal(fields, prefix + ".count")):
            oldest = _u64(fields.get(prefix + f"[{index}].oldest_sequence"), prefix)
            if oldest < previous:
                raise ValueError("native ready instruction age order is contradictory")
            previous = oldest
    return omissions


def inspect_instruction_inventory(inventory, guest_isa):
    """Checks ISA-family fields and ordered macroop microop references.

    Requires the additional instruction-family visitor. Generated instruction
    leaf fields remain unsupported; populated base fields do not qualify them.
    """
    omissions = inspect_pipeline_inventory(inventory, guest_isa)
    ledger = inventory["reference_ledger"]
    visited = 0
    for item in inventory["objects"]:
        fields = item["modeled_fields"]
        for key in fields:
            if not key.endswith(".native_type"):
                continue
            prefix = key[:-12]
            if prefix + ".flags" not in fields:
                continue

            # Other native payloads (notably LSQ SenderState requests) also
            # expose a type and flags. The audited alias kind identifies the
            # actual static-instruction body independently of those field names.
            identity_value = fields.get(prefix + ".identity", fields.get(prefix + ".alias"))
            identity = _u64(identity_value, prefix)
            if identity >= len(ledger):
                raise ValueError("native typed body references an absent alias")
            if ledger[identity]["kind"] != "static-instruction":
                continue

            visited += 1
            unsupported = fields.get(prefix + ".coverage.unsupported")
            if not unsupported:
                raise ValueError("static instruction body lost its leaf omission ledger")
            if guest_isa == "x86_64":
                for suffix in ("legacy", "rex", "vex", "opcode_type", "opcode", "mod_rm",
                               "sib", "immediate", "displacement", "operand_size", "address_size",
                               "stack_size", "displacement_size", "mode"):
                    value = fields.get(prefix + ".x86." + suffix)
                    if not isinstance(value, str) or not value.isascii():
                        raise ValueError("x86 static instruction lacks typed machine fields")
                    digits = value[1:] if value.startswith("-") else value
                    if not digits.isdigit() or len(digits) > 20 or not -(1 << 63) <= int(value) < 1 << 64:
                        raise ValueError("x86 static instruction lacks typed machine fields")
            else:
                _u64(fields.get(prefix + ".arm.machine_instruction"), prefix)
                if (fields.get(prefix + ".arm.aarch64") not in ("0", "1")
                        or fields.get(prefix + ".arm.integer_width") not in ("32", "64")):
                    raise ValueError("Arm static instruction lacks typed execution width")

            count_key = prefix + ".macroop.microop_count"
            if count_key not in fields:
                continue
            count = _decimal(fields, count_key)
            if count > 65536:
                raise ValueError("macroop microop count exceeds its native visitor ceiling")
            for index in range(count):
                microop = prefix + f".macroop.microop[{index}]"
                present, alias = fields.get(microop + ".present"), fields.get(microop + ".identity")
                if present == "0" and alias == "null":
                    continue
                if present != "1":
                    raise ValueError("macroop microop slot is missing or inconsistent")
                identity = _u64(alias, microop)
                if identity >= len(ledger) or ledger[identity]["kind"] != "static-instruction":
                    raise ValueError("macroop microop reference has a missing or conflicting kind")

    if not visited:
        raise ValueError("native CPU cut lacks instruction-family payload visitors")
    return omissions


class CoverageTests(unittest.TestCase):
    """Exercises adversarial evidence rather than accepting a populated field map."""

    def fixture(self):
        types = {
            "o3": "N4gem52o33CPUE", "predictor": "BPredUnit",
            "tournament": "TournamentBP", "return_stack": "ReturnAddrStack",
            "x86_tlb": "N4gem56X86ISA3TLBE",
        }
        objects = []
        for kind, native_type in types.items():
            fields = {key: "1" for key in REQUIRED_FIELDS[kind]}
            fields["coverage.unsupported"] = "pending-callback-payloads;unknown-polymorphic-state"
            if kind == "o3":
                fields.update({
                    "registers.integer.register_bytes": "8",
                    "registers.integer[0].value.bytes": "8",
                    "registers.integer[0].value.sha256": "a" * 64,
                    "thread[0].speculative_rename.class[0].count": "1",
                    "thread[0].committed_rename.class[0].count": "1",
                })
            objects.append({"name": kind, "native_type": native_type,
                            "state_complete": False, "modeled_fields": fields})
        return {"schema": "crucible.gem5.modeled-state.v1", "complete": False, "objects": objects}

    def test_populated_diagnostics_never_grant_complete_qualification(self):
        inventory = self.fixture()
        self.assertTrue(inspect_inventory(inventory, "x86_64"))
        with self.assertRaisesRegex(ValueError, "qualification refused"):
            require_complete_inventory(inventory, "x86_64")

    def test_omitted_register_content_is_refused(self):
        inventory = self.fixture()
        del inventory["objects"][0]["modeled_fields"]["registers.integer[0].value.sha256"]
        with self.assertRaisesRegex(ValueError, "digest"):
            inspect_inventory(inventory, "x86_64")

    def test_missing_committed_mapping_is_refused(self):
        inventory = self.fixture()
        del inventory["objects"][0]["modeled_fields"]["thread[0].committed_rename.class[0].count"]
        with self.assertRaisesRegex(ValueError, "native decimal"):
            inspect_inventory(inventory, "x86_64")

    def test_hidden_complete_flag_is_refused(self):
        inventory = self.fixture()
        inventory["objects"][2]["state_complete"] = True
        with self.assertRaisesRegex(ValueError, "asserts complete"):
            inspect_inventory(inventory, "x86_64")

    def test_unknown_predictor_does_not_inherit_tournament_qualification(self):
        inventory = self.fixture()
        inventory["objects"][2]["native_type"] = "UnknownPredictor"
        with self.assertRaisesRegex(ValueError, "lacks typed visitors"):
            inspect_inventory(inventory, "x86_64")

    def test_deleted_omission_ledger_is_refused(self):
        inventory = self.fixture()
        del inventory["objects"][0]["modeled_fields"]["coverage.unsupported"]
        with self.assertRaisesRegex(ValueError, "unsupported-state ledger"):
            inspect_inventory(inventory, "x86_64")

    def test_duplicate_native_identity_is_refused(self):
        inventory = self.fixture()
        inventory["objects"].append(copy.deepcopy(inventory["objects"][0]))
        with self.assertRaisesRegex(ValueError, "duplicated"):
            inspect_inventory(inventory, "x86_64")

    def test_unbounded_register_roster_is_refused_before_iteration(self):
        inventory = self.fixture()
        inventory["objects"][0]["modeled_fields"]["registers.integer.count"] = str(MAX_FIELDS_PER_OBJECT + 1)
        with self.assertRaisesRegex(ValueError, "ceiling"):
            inspect_inventory(inventory, "x86_64")

    def test_measured_arm_sized_o3_map_preserves_partial_qualification(self):
        inventory = self.fixture()
        fields = inventory["objects"][0]["modeled_fields"]
        fields.update((f"diagnostic[{index}]", "0") for index in range(347648 - len(fields)))

        self.assertEqual(len(fields), 347648)
        self.assertTrue(inspect_inventory(inventory, "x86_64"))
        with self.assertRaisesRegex(ValueError, "qualification refused"):
            require_complete_inventory(inventory, "x86_64")

    def test_o3_map_is_still_bounded_before_field_walk(self):
        inventory = self.fixture()
        fields = inventory["objects"][0]["modeled_fields"]
        fields.update((f"diagnostic[{index}]", "0") for index in range(MAX_O3_FIELDS + 1 - len(fields)))

        with self.assertRaisesRegex(ValueError, "unbounded native field map"):
            inspect_inventory(inventory, "x86_64")

    def test_unknown_native_type_cannot_claim_larger_o3_map_budget(self):
        inventory = self.fixture()
        inventory["objects"][0]["native_type"] = "UnknownO3CPU"
        fields = inventory["objects"][0]["modeled_fields"]
        fields.update((f"diagnostic[{index}]", "0")
                      for index in range(MAX_FIELDS_PER_OBJECT + 1 - len(fields)))

        with self.assertRaisesRegex(ValueError, "unbounded native field map"):
            inspect_inventory(inventory, "x86_64")

    def test_similarly_named_unknown_native_subclass_is_not_qualified(self):
        inventory = self.fixture()
        inventory["objects"][2]["native_type"] = "UnknownTournamentBPWrapper"
        with self.assertRaisesRegex(ValueError, "lacks typed visitors"):
            inspect_inventory(inventory, "x86_64")

    def pipeline_fixture(self):
        inventory = self.fixture()
        inventory["reference_ledger"] = [
            {"reference_identity": str(index), "kind": "instruction", "payload_complete": False}
            for index in range(2)
        ]
        fields = inventory["objects"][0]["modeled_fields"]
        for ring in ("backward", "fetch", "decode", "rename", "iew"):
            prefix = "handoff." + ring
            fields.update({prefix + ".past": "0", prefix + ".future": "0",
                           prefix + ".size": "1", prefix + ".base": "0"})
            suffix = ".thread[0].decodeBlock" if ring == "backward" else ".size"
            fields[prefix + ".lane[0]" + suffix] = "0"
        for queue in ("load_queue", "store_queue"):
            prefix = "stage.iew.load_store_queue.thread[0]." + queue
            fields.update({prefix + ".capacity": "1", prefix + ".size": "0",
                           prefix + ".head": "0", prefix + ".slot[0].valid": "0"})
            if queue == "store_queue":
                fields[prefix + ".slot[0].store_data.bytes"] = "16"
                fields[prefix + ".slot[0].store_data.sha256"] = "b" * 64
        fields["stage.iew.instruction_queue.age_order.count"] = "0"
        return inventory

    def instruction_reference(self, fields, prefix, alias, sequence, thread="0"):
        fields.update({prefix + ".alias": alias, prefix + ".present": "1",
                       prefix + ".cpu": "system.cpu", prefix + ".sequence": sequence,
                       prefix + ".thread": thread})

    def test_pipeline_diagnostics_remain_partial(self):
        self.assertTrue(inspect_pipeline_inventory(self.pipeline_fixture(), "x86_64"))

    def test_inactive_handoff_lane_cannot_be_omitted(self):
        inventory = self.pipeline_fixture()
        del inventory["objects"][0]["modeled_fields"]["handoff.rename.lane[0].size"]
        with self.assertRaisesRegex(ValueError, "native decimal"):
            inspect_pipeline_inventory(inventory, "x86_64")

    def test_inactive_store_slot_bytes_are_required(self):
        inventory = self.pipeline_fixture()
        key = "stage.iew.load_store_queue.thread[0].store_queue.slot[0].store_data.sha256"
        del inventory["objects"][0]["modeled_fields"][key]
        with self.assertRaisesRegex(ValueError, "store buffer"):
            inspect_pipeline_inventory(inventory, "x86_64")

    def test_distinct_allocations_cannot_share_semantic_sequence_identity(self):
        inventory = self.pipeline_fixture()
        fields = inventory["objects"][0]["modeled_fields"]
        self.instruction_reference(fields, "rob.first", "0", "12")
        self.instruction_reference(fields, "issue.second", "1", "12")
        with self.assertRaisesRegex(ValueError, "collide"):
            inspect_pipeline_inventory(inventory, "x86_64")

    def test_shared_alias_cannot_change_thread_identity(self):
        inventory = self.pipeline_fixture()
        fields = inventory["objects"][0]["modeled_fields"]
        self.instruction_reference(fields, "rob.first", "0", "12")
        self.instruction_reference(fields, "issue.same", "0", "12", "1")
        with self.assertRaisesRegex(ValueError, "contradictory semantic"):
            inspect_pipeline_inventory(inventory, "x86_64")

    def test_valid_alias_with_wrong_native_kind_is_refused(self):
        inventory = self.pipeline_fixture()
        inventory["reference_ledger"][0]["kind"] = "packet"
        self.instruction_reference(inventory["objects"][0]["modeled_fields"], "issue.first", "0", "12")
        with self.assertRaisesRegex(ValueError, "conflicting kind"):
            inspect_pipeline_inventory(inventory, "x86_64")

    def test_reverse_ready_age_order_is_refused(self):
        inventory = self.pipeline_fixture()
        fields = inventory["objects"][0]["modeled_fields"]
        fields.update({"stage.iew.instruction_queue.age_order.count": "2",
                       "stage.iew.instruction_queue.age_order[0].oldest_sequence": "15",
                       "stage.iew.instruction_queue.age_order[1].oldest_sequence": "10"})
        with self.assertRaisesRegex(ValueError, "age order"):
            inspect_pipeline_inventory(inventory, "x86_64")

    def test_queue_capacity_is_bounded_before_physical_slot_walk(self):
        inventory = self.pipeline_fixture()
        key = "stage.iew.load_store_queue.thread[0].store_queue.capacity"
        inventory["objects"][0]["modeled_fields"][key] = str(MAX_FIELDS_PER_OBJECT + 1)
        with self.assertRaisesRegex(ValueError, "ceiling"):
            inspect_pipeline_inventory(inventory, "x86_64")

    def instruction_fixture(self):
        inventory = self.pipeline_fixture()
        inventory["reference_ledger"].append(
            {"reference_identity": "2", "kind": "static-instruction", "payload_complete": False})
        fields = inventory["objects"][0]["modeled_fields"]
        prefix = "instruction[0].static_instruction"
        fields.update({prefix + ".native_type": "GeneratedMacroop", prefix + ".flags": "001",
                       prefix + ".identity": "2",
                       prefix + ".coverage.unsupported": "generated-leaf-private-fields",
                       prefix + ".macroop.microop_count": "1",
                       prefix + ".macroop.microop[0].present": "1",
                       prefix + ".macroop.microop[0].identity": "2"})
        for suffix in ("legacy", "rex", "vex", "opcode_type", "opcode", "mod_rm", "sib",
                       "immediate", "displacement", "operand_size", "address_size", "stack_size",
                       "displacement_size", "mode"):
            fields[prefix + ".x86." + suffix] = "0"
        return inventory

    def test_instruction_family_visitor_still_reports_generated_leaf_omissions(self):
        self.assertTrue(inspect_instruction_inventory(self.instruction_fixture(), "x86_64"))

    def test_missing_macroop_slot_is_refused(self):
        inventory = self.instruction_fixture()
        del inventory["objects"][0]["modeled_fields"][
            "instruction[0].static_instruction.macroop.microop[0].identity"]
        with self.assertRaisesRegex(ValueError, "native identity"):
            inspect_instruction_inventory(inventory, "x86_64")

    def test_macroop_cannot_reference_dynamic_instruction_as_static_microop(self):
        inventory = self.instruction_fixture()
        inventory["objects"][0]["modeled_fields"][
            "instruction[0].static_instruction.macroop.microop[0].identity"] = "0"
        with self.assertRaisesRegex(ValueError, "conflicting kind"):
            inspect_instruction_inventory(inventory, "x86_64")

    def test_other_typed_payload_flags_do_not_imply_static_instruction_fields(self):
        inventory = self.instruction_fixture()
        inventory["reference_ledger"].append(
            {"reference_identity": "3", "kind": "sender-state", "payload_complete": False})
        inventory["objects"][0]["modeled_fields"].update({
            "queue.request.native_type": "LSQRequest",
            "queue.request.alias": "3", "queue.request.flags": "1"})

        self.assertTrue(inspect_instruction_inventory(inventory, "x86_64"))

    def test_typed_payload_cannot_invent_an_alias_outside_the_native_roster(self):
        inventory = self.instruction_fixture()
        inventory["objects"][0]["modeled_fields"].update({
            "queue.request.native_type": "LSQRequest",
            "queue.request.identity": "65535", "queue.request.flags": "1"})

        with self.assertRaisesRegex(ValueError, "absent alias"):
            inspect_instruction_inventory(inventory, "x86_64")

    def test_missing_instruction_family_fields_are_refused(self):
        inventory = self.instruction_fixture()
        del inventory["objects"][0]["modeled_fields"]["instruction[0].static_instruction.x86.mode"]
        with self.assertRaisesRegex(ValueError, "typed machine"):
            inspect_instruction_inventory(inventory, "x86_64")

    def test_old_pipeline_visitor_cannot_claim_instruction_family_coverage(self):
        with self.assertRaisesRegex(ValueError, "instruction-family"):
            inspect_instruction_inventory(self.pipeline_fixture(), "x86_64")

    def test_machine_field_repeated_sign_is_refused(self):
        inventory = self.instruction_fixture()
        inventory["objects"][0]["modeled_fields"][
            "instruction[0].static_instruction.x86.displacement"] = "--1"
        with self.assertRaisesRegex(ValueError, "typed machine"):
            inspect_instruction_inventory(inventory, "x86_64")

    def arm_instruction_fixture(self):
        inventory = self.instruction_fixture()
        tlb = inventory["objects"][-1]
        tlb["native_type"] = "N4gem56ArmISA3TLBE"
        tlb["modeled_fields"] = {key: "1" for key in REQUIRED_FIELDS["arm_tlb"]}
        tlb["modeled_fields"]["coverage.unsupported"] = "walker-private-fields"
        fields = inventory["objects"][0]["modeled_fields"]
        prefix = "instruction[0].static_instruction"
        fields.update({prefix + ".arm.machine_instruction": "18446744073709551615",
                       prefix + ".arm.aarch64": "1", prefix + ".arm.integer_width": "64"})
        return inventory

    def test_arm_instruction_family_preserves_full_machine_word(self):
        self.assertTrue(inspect_instruction_inventory(self.arm_instruction_fixture(), "aarch64"))

    def test_arm_instruction_execution_width_cannot_be_omitted(self):
        inventory = self.arm_instruction_fixture()
        del inventory["objects"][0]["modeled_fields"][
            "instruction[0].static_instruction.arm.integer_width"]
        with self.assertRaisesRegex(ValueError, "typed execution width"):
            inspect_instruction_inventory(inventory, "aarch64")


if __name__ == "__main__":
    import sys
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: cpu-state-coverage-check.py --self-test")
    unittest.main(argv=[sys.argv[0]])
