# Crucible scenario and world reference

This page lists the top-level tables of the canonical scenario TOML and
every `[scenario]` and `[world]` field. It is part of the
[Crucible reference](reference.md), which also defines the value
notation used in the tables.

## Canonical scenario document

A scenario contains exactly four top-level tables. The `id` on each top-level
table is a validated content address generated from that canonical component;
changing its content requires regenerating that ID. Nested node, device, event,
and assertion IDs are scenario-local names instead.

| Table | Required fields | Contents |
| --- | --- | --- |
| `[scenario]` | `id`, `seed`, `app_random_draw_cap` | Scenario identity, deterministic seed material, and maximum guest application-random draws. |
| `[world]` | `id` | VM nodes, I/O device sub-nodes, and links. `node` and `link` arrays default empty. |
| `[plan]` | `id`, `fault_model`, `fault_signal_semantic_version` | Event graph plus the sole signal/binding fault representation. |
| `[properties]` | `id` | Named assertions. `assertion` defaults empty. |

### `[scenario]` fields

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | content-address string | Hash of the complete scenario definition. Generated and validated. |
| `seed` | canonical seed string | Root deterministic seed, commonly a full `0x` byte string. |
| `app_random_draw_cap` | unsigned integer or decimal string | Maximum white-box application-random draws admitted by the scenario. Zero rejects all such draws. |

### `[[world.node]]` VM fields

VM rows are untagged: they do not carry `kind`.

| Field | Type/default | Meaning |
| --- | --- | --- |
| `id` | Required string | Unique scenario-local node name. |
| `arch` | `x86_64` (default) or `aarch64` | Guest architecture. |
| `memory_mib` | Default `512` | Guest memory in MiB. |
| `cmdline` | Default empty string | Additional kernel command line. |
| `smp_vcpus` | Required unsigned integer | Virtual CPU count. |
| `kernel` | Optional content address | Per-node kernel artifact. The production lifecycle may supply a configured artifact when absent. |
| `root_image` | Optional content address | Per-node root-image artifact. |
| `initrd` | Optional content address | Per-node initrd artifact. |
| `ready_point` | Required nested table | Deterministic snapshot point; see below. |
| `white_box` | Required `enabled` or `disabled` | Permit or prohibit the guest-host white-box channel. |

Crucible fixes QEMU's instruction-count shift at 0. Scenario TOML has no
`icount_shift` field; including one is a schema error.

VM enum values, as defined by the
[TOML schema source](../../../crates/crucible/crucible-engine/src/model/toml.rs):

| Field | Value | Meaning |
| --- | --- | --- |
| `arch` | `x86_64` | Run an x86-64 guest. |
| `arch` | `aarch64` | Run an AArch64 guest. |
| `white_box` | `disabled` | Prohibit the optional guest-host observation/control channel. |
| `white_box` | `enabled` | Allow typed guest markers and application-random requests through the white-box doorbell. |

`[world.node.ready_point]` kinds:

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `fixed_icount` | `retired: u64` | Snapshot after exactly this many retired guest instructions. |
| `network_idle` | `window_nanos: u64` | Snapshot after the first network-idle window of this length. |
| `console_marker` | `marker: string` | Snapshot when the guest console emits the marker. |
| `agent_signal` | None | Snapshot when the optional in-guest agent signals readiness. |

### `[[world.node]]` I/O device fields

I/O rows share the VM node array but carry a `kind`. Every field listed for the
selected kind is required.

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `block` | `id`, `owner`, `shift_bits`, `artifact`, `artifact_length`, `read_base_ns`, `write_base_ns`, `flush_ns`, `get_length_ns`, `per_byte_ns` | Deterministic block sub-node backed by a content-addressed base image. `owner` is a VM ID; latency is the operation base plus the per-byte component. |
| `nine_p` | `id`, `owner`, `shift_bits`, `artifact`, `control_ns`, `data_ns`, `per_byte_ns` | Deterministic read-only 9p filesystem sub-node. `owner` is a VM ID; control/data bases and the per-byte term model completion latency. |

For both kinds, `id` is the unique device name, `shift_bits` maps device work to
virtual time, and `artifact` is a content-addressed blob reference.

### `[[world.link]]` fields

| Field | Type | Meaning |
| --- | --- | --- |
| `endpoint_a`, `endpoint_b` | Required node IDs | The two distinct VM endpoints. Ordering is canonicalized. |
| `latency_nanos` | Required unsigned integer | One-way base latency. |
| `jitter_nanos` | Required unsigned integer | Maximum subtractive jitter. `latency_nanos - jitter_nanos` must remain above Crucible's minimum. |
| `loss_millionths` | Required integer `0..=1000000` | Baseline deterministic link-loss probability. |
| `bandwidth_bps` | Optional positive integer | Baseline bits-per-virtual-second cap. |

Bindings refer to a unique link by its canonical link ID. Generate target IDs
through a Rust scenario builder so they remain bound to the admitted World.

### `[[world.node_fault_capabilities]]` fields

Each VM that accepts node-level faults has one closed capability declaration.
The declaration is an admission contract, not a request for best-effort QEMU
behavior: the run fails before boot if the realized CPU type or canonical
register manifest differs. `register_schema` is the BLAKE3 content hash of the
complete encoded register manifest, represented in TOML as
`{ bytes = [32 decimal byte values] }`.

| Field | Required value | Meaning |
| --- | --- | --- |
| `id` | Unique string | Scenario-local capability declaration ID. |
| `node` | VM node ID | VM governed by this declaration. |
| `architecture` | `x86_64` or `aarch64` | Exact guest architecture ABI. It must agree with the VM's `arch`. |
| `cpu_model` | Printable QOM typename | Exact realized QEMU CPU type, including the architecture suffix reported by QEMU. |
| `register_schema` | Content hash table | BLAKE3 of the canonical public register-manifest bytes. |
| `registers` | Nonempty array | Exhaustive register rows described below, ordered canonically by `numeric_id`. |
| `address_spaces` | Nonempty array | Guest memory ranges which node faults may address. |
| `page_bytes` | Power-of-two integer | Guest page size used by memory-fault contracts. |
| `dram_geometry` | Table | Exact QEMU DRAM coordinate mapping described below. |
| `interrupts` | Array | Fully routed interrupt targets. May be empty. |
| `hardware_errors` | Array | Architecture and platform error rows; see [Hardware-error rows](topology.md#hardware-error-rows). |
| `clock_sources` | Array | Guest-visible clock sources. May be empty. |
| `accelerators` | Array | Declared accelerator devices. May be empty; sensor devices are not accepted. |
| `ready_markers` | Canonically ordered unique string array | Exact guest event-marker names allowed to complete `require_ready`; an undeclared marker rejects the run before boot. May be empty. |
| `semantic_version` | `1` | Capability schema version. |

#### Register rows

Every guest-visible or implementation-private register in the pinned CPU model
appears in `[[world.node_fault_capabilities.registers]]`. A row with an all-zero
`writable_mask_hex` is reference-only: it must advertise neither `impulse` nor
`persistent`, has no model phases or side effects, and cannot be selected for a
mutation. A writable row advertises at least one mutation mode, has VMState
coverage, and lists every safe hook phase. The four masks partition every
in-range bit exactly once; padding bits above `width_bits` are zero. Mask bytes
use lowercase hexadecimal in least-significant-byte-first order.

| Field | Required value | Meaning |
| --- | --- | --- |
| `id` | Unique string | Stable selector ID for this register. |
| `name` | Canonical lowercase identifier | Exact name exported by QEMU. |
| `numeric_id` | Nonzero integer | Stable private-to-public manifest row ID. |
| `group` | Register-group value below | Architecture category used by coverage gates. |
| `width_bits` | `1..=65536` | Architectural value width. |
| `per_vcpu` | `true` | Values are independently selected by vCPU index. |
| `model_phases` | Ordered unique array | Writable rows use `before_instruction`, `after_instruction`, or both; reference-only rows use `[]`. |
| `side_effects` | Ordered unique array | Derived QEMU state recomputed by the architecture setter; reference-only rows use `[]`. |
| `impulse` | Boolean | Supports one exact mutation at a selected occurrence. |
| `persistent` | Boolean | Supports a rule applied at every selected register hook. |
| `vmstate` | Boolean | Register value and any advertised persistent rule survive save/restore. Required for writable rows. |
| `writable_mask_hex` | Exact-width lowercase hex | Bits the fault ABI may change. |
| `reserved_mask_hex` | Exact-width lowercase hex | Architecturally reserved bits, always preserved. |
| `ignored_mask_hex` | Exact-width lowercase hex | Bits whose architectural writes are ignored. |
| `read_only_mask_hex` | Exact-width lowercase hex | Readable or implementation-private bits that cannot be mutated. |

Register-group values are exhaustive:

| Value | Contents |
| --- | --- |
| `general_purpose` | Integer data and address registers. |
| `control_flow` | Program counters and explicit control-flow registers. |
| `flags` | Integer condition and status flags. |
| `segment` | Segment selectors, bases, limits, and attributes. |
| `control` | Translation and execution-control registers. |
| `system` | Other guest-visible architecture system registers. |
| `debug` | Guest-visible debug registers. |
| `floating_point` | Floating-point data, status, and control registers. |
| `vector` | SIMD, vector, and predicate registers. |
| `error` | Architecture-defined error status and syndrome registers. |

Register side-effect values are exhaustive:

| Value | Required architecture action |
| --- | --- |
| `tlb_flush` | Flush affected vCPU translations. |
| `translation_block_flush` | Invalidate affected translated code. |
| `flags_recompute` | Rebuild cached flags or execution state. |
| `interrupt_reevaluate` | Recompute interrupt masking and delivery. |
| `timer_rearm` | Recompute and arm derived timer deadlines. |
| `control_flow_synchronize` | Synchronize the next guest instruction location. |

#### Memory, interrupt, clock, and accelerator rows

| Nested location | Required fields | Meaning |
| --- | --- | --- |
| `[[world.node_fault_capabilities.address_spaces]]` | `id`, `start_address`, positive `length_bytes` | One non-wrapping guest address range. Address and length accept a TOML integer or canonical decimal/hex string. |
| `[world.node_fault_capabilities.dram_geometry]` | `channels=2`, `ranks=2`, `banks=16`, `interleave_bytes=64`, `semantic_version=1` | The only currently implemented GPA-to-DRAM mapping. |
| `[[world.node_fault_capabilities.interrupts]]` | All interrupt-row fields below | One exact source-to-controller route and its mutation contract. |
| `[[world.node_fault_capabilities.clock_sources]]` | `id`, `implementation`, `source_kind`, `base_domain`, `epoch_ns`, `timer_relationship`, `width_bits`, `wraps`, `read_error`, `frequency_numerator`, `frequency_denominator`, `model_phases`, `monotonicity`, `vmstate`, `semantic_version` | One registered guest-visible clock source; see [Clock-source rows](topology.md#clock-source-rows). |
| `[[world.node_fault_capabilities.accelerators]]` | `id`, nonempty sorted `classes`, `semantic_version=1`, `capability_manifest` | One realized fault device and its exact content-addressed manifest; `classes` contains any supported combination of `gpu`, `tpu`, and `fpga`. |

`ready_markers` is part of the content-addressed QEMU launch contract. Each
entry names a decoded guest `event` marker, not an assertion, lifecycle,
coverage, or random-request marker. The host carries the exact set admitted by
the World through setup and node construction, and rejects a lifecycle or
watchdog action whose `ready_marker` is absent from the selected live node.

Interrupt rows are exhaustive realized-machine contracts. Every field is
required; there are no inferred controller defaults. A scenario is rejected
before boot if QEMU reports a different family, controller version, electrical
mode, route, priority, phase set, replacement range, drop transition, or
VMState coverage.

| Interrupt field | Required value | Meaning |
| --- | --- | --- |
| `id` | Unique string | Stable manifest-row identity. |
| `controller` | Controller object ID | Controller selected by a fault target. |
| `source` | Source object ID | Device, timer, or vCPU source selected by a fault target. |
| `controller_version` | Printable non-whitespace string | Exact realized QEMU controller implementation/version identity. |
| `family` | Interrupt-family value below | Architecture path whose hooks and state semantics are implemented. |
| `vector_start` | Family-valid integer | Inclusive first x86 vector or Arm INTID this source may produce after guest programming. |
| `vector_end` | Family-valid integer | Inclusive last runtime vector or INTID; must be at least `vector_start`. Each opportunity records the exact observed value. |
| `replacement_vector_start` | Family-valid integer | Inclusive first replacement accepted for this row. |
| `replacement_vector_end` | Family-valid integer | Inclusive last replacement accepted for this row; must be at least `replacement_vector_start`. |
| `trigger` | `edge` or `level` | Electrical pending-state behavior. Families fixed to edge reject `level`. |
| `polarity` | `active_high` or `active_low` | Active line level or edge direction. |
| `target_vcpus` | Sorted unique nonempty integer array | Complete closed route target set. |
| `model_phases` | Sorted unique nonempty phase array | Any subset of `raise`, `route`, and `interrupt_deliver` actually implemented for this row. |
| `priority` | Integer `0..=255` | Controller priority used by deterministic ordering. |
| `delivery_drop` | Drop-state value below | Exact controller transition when a selected delivery is dropped. |
| `vmstate` | `true` | The controller state and Crucible interrupt overlay survive save/restore. |

Interrupt-family values and valid vector domains are exhaustive:

| Family | Architecture | Valid vector/INTID | Required trigger |
| --- | --- | --- | --- |
| `x86_local_apic_fixed` | x86-64 | `16..=255` | `edge` or `level` |
| `x86_ipi` | x86-64 | `16..=255` | `edge` |
| `x86_io_apic` | x86-64 | `16..=255` | `edge` or `level` |
| `x86_pic` | x86-64 | `0..=255` | `edge` or `level` |
| `x86_msi` | x86-64 | `16..=255` | `edge` |
| `x86_msi_x` | x86-64 | `16..=255` | `edge` |
| `x86_nmi` | x86-64 | exactly `2` | `edge` |
| `x86_timer` | x86-64 | `16..=255` | `edge` or `level`, as realized |
| `arm_gic_sgi` | AArch64 | `0..=15` | `edge` |
| `arm_gic_ppi` | AArch64 | `16..=31` | `edge` or `level` |
| `arm_gic_spi` | AArch64 | `32..=1019` | `edge` or `level` |
| `arm_gic_lpi` | AArch64 | `8192..=16777215` | `edge` |
| `arm_timer` | AArch64 | `16..=31` | `edge` or `level`, as realized |

`delivery_drop` is constrained by `trigger` so that dropping cannot silently
change controller semantics:

| Value | Allowed trigger | Exact transition |
| --- | --- | --- |
| `consume_edge` | `edge` | Consume the selected pending edge without creating active guest exception state. |
| `repend_asserted_level` | `level` | Consume the sampled opportunity and re-pend according to the unchanged physical line assertion. |

SMI is intentionally absent: the current QEMU contract does not implement the
complete SMM state transition. Arm SError is configured as a typed
`cpu_exception`, not as an interrupt-manifest family.
