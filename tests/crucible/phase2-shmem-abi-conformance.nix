{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.shmemAbiConformance",
  taskIds ? ["T-SHM-14" "T-SHM-19"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  # The `#[repr(C)]` structs and their static layout assertions live in the
  # `shmem/` submodules re-exported by lib.rs; concatenate them so the assertion
  # conformance needles resolve against the whole ABI surface.
  shmemLib =
    import ./_crucible-shmem-source.nix {inherit lib;}
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/region.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/frame_entry.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/futex.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/preemption_mailbox.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_coverage.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_guest_introspection.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_whitebox_marker.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/fingerprint_sample.rs;
  shmemGate =
    builtins.readFile ../../crates/crucible-shmem/tests/gate_abi_conformance.rs
    + builtins.readFile ../../crates/crucible-shmem/tests/gate_abi_conformance/gate_cases.rs;
  preemptionMailboxGate =
    builtins.readFile ../../crates/crucible-shmem/tests/preemption_mailbox.rs;
  setupValidation = builtins.readFile ../../crates/crucible-shmem/tests/setup_validation.rs;
  goldenFixture = builtins.readFile ../../crates/crucible-shmem/tests/fixtures/shmem_abi_golden.fixture;
  generatedHeader = builtins.readFile ../../crates/crucible-shmem/include/crucible_shmem_abi.h;
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "region header magic Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_MAGIC_OFFSET == 0);";
      }
      {
        label = "region header ABI version Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_ABI_VERSION_OFFSET == 8);";
      }
      {
        label = "region header node count Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_NODE_COUNT_OFFSET == 12);";
      }
      {
        label = "region header queue capacity Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_QUEUE_CAPACITY_OFFSET == 16);";
      }
      {
        label = "region header ring count Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_RING_COUNT_OFFSET == 20);";
      }
      {
        label = "region header ring header offset Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_RING_HDR_OFF_OFFSET == 24);";
      }
      {
        label = "region header ring data offset Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_RING_DATA_OFF_OFFSET == 32);";
      }
      {
        label = "region header entry stride Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_ENTRY_STRIDE_OFFSET == 40);";
      }
      {
        label = "region header region size Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_REGION_SIZE_OFFSET == 48);";
      }
      {
        label = "region header icount shift Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_ICOUNT_SHIFT_OFFSET == 56);";
      }
      {
        label = "region header pause flag Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_PAUSE_REQUESTED_OFFSET == 60);";
      }
      {
        label = "region header shutdown flag Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET == 61);";
      }
      {
        label = "region header reserved Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_RESERVED_OFFSET == 62);";
      }
      {
        label = "region header size Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_SIZE == 256);";
      }
      {
        label = "region header alignment Rust static assertion";
        needle = "const _: () = assert!(REGION_HEADER_ALIGN == 128);";
      }
      {
        label = "ring header read index Rust static assertion";
        needle = "const _: () = assert!(RING_HEADER_READ_IDX_OFFSET == 0);";
      }
      {
        label = "ring header read padding Rust static assertion";
        needle = "const _: () = assert!(RING_HEADER_PAD_READ_OFFSET == 8);";
      }
      {
        label = "ring header write index Rust static assertion";
        needle = "const _: () = assert!(RING_HEADER_WRITE_IDX_OFFSET == 64);";
      }
      {
        label = "ring header write padding Rust static assertion";
        needle = "const _: () = assert!(RING_HEADER_PAD_WRITE_OFFSET == 72);";
      }
      {
        label = "ring header size Rust static assertion";
        needle = "const _: () = assert!(RING_HEADER_SIZE == 128);";
      }
      {
        label = "ring header alignment Rust static assertion";
        needle = "const _: () = assert!(RING_HEADER_ALIGN == 128);";
      }
      {
        label = "frame entry delivery icount Rust static assertion";
        needle = "const _: () = assert!(FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET == 0);";
      }
      {
        label = "frame entry source node Rust static assertion";
        needle = "const _: () = assert!(FRAME_ENTRY_SRC_NODE_OFFSET == 8);";
      }
      {
        label = "frame entry sequence Rust static assertion";
        needle = "const _: () = assert!(FRAME_ENTRY_SEQ_OFFSET == 12);";
      }
      {
        label = "frame entry length Rust static assertion";
        needle = "const _: () = assert!(FRAME_ENTRY_LEN_OFFSET == 16);";
      }
      {
        label = "frame entry padding Rust static assertion";
        needle = "const _: () = assert!(FRAME_ENTRY_PAD_OFFSET == 18);";
      }
      {
        label = "frame entry data Rust static assertion";
        needle = "const _: () = assert!(FRAME_ENTRY_DATA_OFFSET == 24);";
      }
      {
        label = "frame entry Rust static assertions";
        needle = "const _: () = assert!(FRAME_ENTRY_SIZE == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);";
      }
      {
        label = "frame entry alignment Rust static assertion";
        needle = "const _: () = assert!(FRAME_ENTRY_ALIGN == 8);";
      }
      {
        label = "coverage entry exact-icount Rust static assertion";
        needle = "const _: () = assert!(COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET == 0);";
      }
      {
        label = "coverage entry map-index Rust static assertion";
        needle = "const _: () = assert!(COVERAGE_ENTRY_MAP_INDEX_OFFSET == 16);";
      }
      {
        label = "coverage entry vCPU Rust static assertion";
        needle = "const _: () = assert!(COVERAGE_ENTRY_VCPU_INDEX_OFFSET == 24);";
      }
      {
        label = "coverage entry block-length Rust static assertion";
        needle = "const _: () = assert!(COVERAGE_ENTRY_BLOCK_LEN_OFFSET == 28);";
      }
      {
        label = "coverage entry reserved Rust static assertion";
        needle = "const _: () = assert!(COVERAGE_ENTRY_RESERVED_OFFSET == 32);";
      }
      {
        label = "coverage entry size Rust static assertion";
        needle = "const _: () = assert!(COVERAGE_ENTRY_SIZE == 64);";
      }
      {
        label = "coverage entry alignment Rust static assertion";
        needle = "const _: () = assert!(COVERAGE_ENTRY_ALIGN == 64);";
      }
      {
        label = "white-box marker exact-icount Rust static assertion";
        needle = "assert!(WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET == 0);";
      }
      {
        label = "white-box marker payload Rust static assertion";
        needle = "assert!(WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET == 16);";
      }
      {
        label = "white-box marker reserved Rust static assertion";
        needle = "assert!(WHITEBOX_MARKER_ENTRY_RESERVED_OFFSET == 16 + MAX_FRAME_DATA);";
      }
      {
        label = "white-box marker size Rust static assertion";
        needle = "assert!(WHITEBOX_MARKER_ENTRY_SIZE == 4_672);";
      }
      {
        label = "white-box marker alignment Rust static assertion";
        needle = "assert!(WHITEBOX_MARKER_ENTRY_ALIGN == 64);";
      }
      {
        label = "node slot current icount Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_CURRENT_ICOUNT_OFFSET == 0);";
      }
      {
        label = "node slot current ns Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_CURRENT_NS_OFFSET == 8);";
      }
      {
        label = "node slot max advance Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET == 16);";
      }
      {
        label = "node slot idle wake Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET == 24);";
      }
      {
        label = "node slot wake signal Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_WAKE_SIGNAL_OFFSET == 32);";
      }
      {
        label = "node slot status Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_STATUS_OFFSET == 36);";
      }
      {
        label = "node slot kind Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_KIND_OFFSET == 37);";
      }
      {
        label = "node slot device I/O flag Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET == 38);";
      }
      {
        label = "node slot padding Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PAD0_OFFSET == 39);";
      }
      {
        label = "node slot publish generation Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PUBLISH_GEN_OFFSET == 40);";
      }
      {
        label = "node slot device completion Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_DEVICE_COMPLETION_DEADLINE_ICOUNT_OFFSET == 48);";
      }
      {
        label = "node slot preemption icount Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET == 56);";
      }
      {
        label = "node slot preemption deadline Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET == 64);";
      }
      {
        label = "node slot preemption ceiling Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET == 72);";
      }
      {
        label = "node slot published preemption sequence Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET == 80);";
      }
      {
        label = "node slot consumed preemption sequence Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET == 84);";
      }
      {
        label = "node slot first preemption argument Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PREEMPTION_ARG0_OFFSET == 88);";
      }
      {
        label = "node slot second preemption argument Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PREEMPTION_ARG1_OFFSET == 92);";
      }
      {
        label = "node slot preemption kind Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_PREEMPTION_KIND_OFFSET == 96);";
      }
      {
        label = "node slot reserved Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_RESERVED_OFFSET == 97);";
      }
      {
        label = "node slot size Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_SIZE == 128);";
      }
      {
        label = "node slot alignment Rust static assertion";
        needle = "const _: () = assert!(NODE_SLOT_ALIGN == 128);";
      }
      {
        label = "fingerprint sample slot gen offset Rust static assertion";
        needle = "const _: () = assert!(FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET == 0);";
      }
      {
        label = "fingerprint sample slot words offset Rust static assertion";
        needle = "const _: () = assert!(FINGERPRINT_SAMPLE_SLOT_WORDS_OFFSET == 8);";
      }
      {
        label = "fingerprint sample slot alignment Rust static assertion";
        needle = "const _: () = assert!(FINGERPRINT_SAMPLE_SLOT_ALIGN == 128);";
      }
      {
        label = "generated C header API";
        needle = "pub use abi_header::generated_c_header;";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/gate_abi_conformance.rs" shmemGate [
      {
        label = "gate test aggregator";
        needle = "gate_abi_conformance_checks_generated_header_and_golden_vectors";
      }
      {
        label = "committed header diff test";
        needle = "generated_header_matches_committed_copy";
      }
      {
        label = "static assert coverage test";
        needle = "generated_header_carries_static_asserts_for_every_shared_struct";
      }
      {
        label = "Rust golden-vector round trip";
        needle = "rust_golden_vector_round_trip_matches_fixture";
      }
      {
        label = "layout drift negative control";
        needle = "golden_vector_negative_control_detects_layout_drift";
      }
      {
        label = "frozen golden vector marker";
        needle = "assert_frozen_golden_vectors(";
      }
      {
        label = "decode/encode round-trip marker";
        needle = "assert_decode_encode_roundtrip(";
      }
      {
        label = "ABI version marker";
        needle = "assert_abi_version_field(";
      }
      {
        label = "version bump marker";
        needle = "assert_version_bump_regenerates_vectors(";
      }
      {
        label = "structure-aware corpus marker";
        needle = "assert_structure_aware_fuzz_corpus(";
      }
      {
        label = "regression corpus marker";
        needle = "regression_corpus";
      }
      {
        label = "committed header include";
        needle = "include_str!(\"../include/crucible_shmem_abi.h\")";
      }
      {
        label = "golden fixture include";
        needle = "include_str!(\"fixtures/shmem_abi_golden.fixture\")";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/setup_validation.rs" setupValidation [
      {
        label = "current ABI explicitly rejects an older region header";
        needle = "abi_version: ABI_VERSION - 1";
      }
      {
        label = "current ABI also rejects future region headers";
        needle = "abi_version: ABI_VERSION + 1";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/gate_abi_conformance.rs" shmemGate [
      {
        label = "ignored ABI conformance test";
        needle = "#[ignore";
      }
      {
        label = "placeholder panic";
        needle = "implementation is pending";
      }
      {
        label = "red placeholder";
        needle = "Red placeholder";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/preemption_mailbox.rs" preemptionMailboxGate [
      {
        label = "preemption mailbox round-trip";
        needle = "preemption_mailbox_round_trips_switch_interrupt_and_acknowledgement";
      }
      {
        label = "preemption mailbox negative cases";
        needle = "preemption_mailbox_rejects_overwrite_wrong_ack_and_invalid_window";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/fixtures/shmem_abi_golden.fixture" goldenFixture [
      {
        label = "ABI version";
        needle = "abi_version=6";
      }
      {
        label = "total serialized length";
        needle = "total_len=14552";
      }
      {
        label = "region magic";
        needle = "0=4352554353484d31";
      }
      {
        label = "payload marker";
        needle = "536=50494e47";
      }
      {
        label = "coverage entry exact-icount marker";
        needle = "5144=8503000000000000";
      }
      {
        label = "coverage entry block marker";
        needle = "5172=04000000";
      }
      {
        label = "white-box marker exact-icount marker";
        needle = "5208=9103000000000000";
      }
      {
        label = "white-box marker payload marker";
        needle = "5224=4d41524b";
      }
      {
        label = "guest-introspection sequence marker";
        needle = "9880=1300000000000000";
      }
      {
        label = "guest-introspection complete CRGI record marker";
        needle = "9896=4352474901000700010000000000000000000000";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/include/crucible_shmem_abi.h" generatedHeader [
      {
        label = "region header static assert";
        needle = "sizeof(crucible_shmem_region_header) == CRUCIBLE_SHMEM_REGION_HEADER_SIZE";
      }
      {
        label = "region header alignment static assert";
        needle = "_Alignof(crucible_shmem_region_header) == CRUCIBLE_SHMEM_REGION_HEADER_ALIGN";
      }
      {
        label = "region header magic offset static assert";
        needle = "offsetof(crucible_shmem_region_header, magic) == CRUCIBLE_SHMEM_REGION_HEADER_MAGIC_OFFSET";
      }
      {
        label = "region header ABI version offset static assert";
        needle = "offsetof(crucible_shmem_region_header, abi_version) == CRUCIBLE_SHMEM_REGION_HEADER_ABI_VERSION_OFFSET";
      }
      {
        label = "region header node count offset static assert";
        needle = "offsetof(crucible_shmem_region_header, node_count) == CRUCIBLE_SHMEM_REGION_HEADER_NODE_COUNT_OFFSET";
      }
      {
        label = "region header queue capacity offset static assert";
        needle = "offsetof(crucible_shmem_region_header, queue_capacity) == CRUCIBLE_SHMEM_REGION_HEADER_QUEUE_CAPACITY_OFFSET";
      }
      {
        label = "region header ring count offset static assert";
        needle = "offsetof(crucible_shmem_region_header, ring_count) == CRUCIBLE_SHMEM_REGION_HEADER_RING_COUNT_OFFSET";
      }
      {
        label = "region header ring header offset static assert";
        needle = "offsetof(crucible_shmem_region_header, ring_hdr_off) == CRUCIBLE_SHMEM_REGION_HEADER_RING_HDR_OFF_OFFSET";
      }
      {
        label = "region header ring data offset static assert";
        needle = "offsetof(crucible_shmem_region_header, ring_data_off) == CRUCIBLE_SHMEM_REGION_HEADER_RING_DATA_OFF_OFFSET";
      }
      {
        label = "region header entry stride offset static assert";
        needle = "offsetof(crucible_shmem_region_header, entry_stride) == CRUCIBLE_SHMEM_REGION_HEADER_ENTRY_STRIDE_OFFSET";
      }
      {
        label = "region header region size offset static assert";
        needle = "offsetof(crucible_shmem_region_header, region_size) == CRUCIBLE_SHMEM_REGION_HEADER_REGION_SIZE_OFFSET";
      }
      {
        label = "region header icount shift offset static assert";
        needle = "offsetof(crucible_shmem_region_header, icount_shift) == CRUCIBLE_SHMEM_REGION_HEADER_ICOUNT_SHIFT_OFFSET";
      }
      {
        label = "region header pause flag offset static assert";
        needle = "offsetof(crucible_shmem_region_header, pause_requested) == CRUCIBLE_SHMEM_REGION_HEADER_PAUSE_REQUESTED_OFFSET";
      }
      {
        label = "region header shutdown flag offset static assert";
        needle = "offsetof(crucible_shmem_region_header, shutdown_requested) == CRUCIBLE_SHMEM_REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET";
      }
      {
        label = "region header reserved offset static assert";
        needle = "offsetof(crucible_shmem_region_header, reserved) == CRUCIBLE_SHMEM_REGION_HEADER_RESERVED_OFFSET";
      }
      {
        label = "node slot static assert";
        needle = "sizeof(crucible_shmem_node_slot) == CRUCIBLE_SHMEM_NODE_SLOT_SIZE";
      }
      {
        label = "node slot alignment static assert";
        needle = "_Alignof(crucible_shmem_node_slot) == CRUCIBLE_SHMEM_NODE_SLOT_ALIGN";
      }
      {
        label = "node slot current icount offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, current_icount) == CRUCIBLE_SHMEM_NODE_SLOT_CURRENT_ICOUNT_OFFSET";
      }
      {
        label = "node slot current ns offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, current_ns) == CRUCIBLE_SHMEM_NODE_SLOT_CURRENT_NS_OFFSET";
      }
      {
        label = "node slot max advance offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, max_advance_icount) == CRUCIBLE_SHMEM_NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET";
      }
      {
        label = "node slot idle wake offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, idle_wake_icount) == CRUCIBLE_SHMEM_NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET";
      }
      {
        label = "node slot wake signal offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, wake_signal) == CRUCIBLE_SHMEM_NODE_SLOT_WAKE_SIGNAL_OFFSET";
      }
      {
        label = "node slot status offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, status) == CRUCIBLE_SHMEM_NODE_SLOT_STATUS_OFFSET";
      }
      {
        label = "node slot kind offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, kind) == CRUCIBLE_SHMEM_NODE_SLOT_KIND_OFFSET";
      }
      {
        label = "node slot device I/O flag offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, device_io_active) == CRUCIBLE_SHMEM_NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET";
      }
      {
        label = "node slot padding offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, pad0) == CRUCIBLE_SHMEM_NODE_SLOT_PAD0_OFFSET";
      }
      {
        label = "node slot publish generation offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, publish_gen) == CRUCIBLE_SHMEM_NODE_SLOT_PUBLISH_GEN_OFFSET";
      }
      {
        label = "node slot device completion offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, device_completion_deadline_icount) == CRUCIBLE_SHMEM_NODE_SLOT_DEVICE_COMPLETION_DEADLINE_ICOUNT_OFFSET";
      }
      {
        label = "node slot preemption icount offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, preemption_at_icount) == CRUCIBLE_SHMEM_NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET";
      }
      {
        label = "node slot preemption deadline offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, preemption_deadline_icount) == CRUCIBLE_SHMEM_NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET";
      }
      {
        label = "node slot preemption ceiling offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, preemption_ceiling_icount) == CRUCIBLE_SHMEM_NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET";
      }
      {
        label = "node slot published preemption sequence offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, preemption_published_sequence) == CRUCIBLE_SHMEM_NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET";
      }
      {
        label = "node slot consumed preemption sequence offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, preemption_consumed_sequence) == CRUCIBLE_SHMEM_NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET";
      }
      {
        label = "node slot first preemption argument offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, preemption_arg0) == CRUCIBLE_SHMEM_NODE_SLOT_PREEMPTION_ARG0_OFFSET";
      }
      {
        label = "node slot second preemption argument offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, preemption_arg1) == CRUCIBLE_SHMEM_NODE_SLOT_PREEMPTION_ARG1_OFFSET";
      }
      {
        label = "node slot preemption kind offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, preemption_kind) == CRUCIBLE_SHMEM_NODE_SLOT_PREEMPTION_KIND_OFFSET";
      }
      {
        label = "node slot reserved offset static assert";
        needle = "offsetof(crucible_shmem_node_slot, reserved) == CRUCIBLE_SHMEM_NODE_SLOT_RESERVED_OFFSET";
      }
      {
        label = "ring header static assert";
        needle = "sizeof(crucible_shmem_ring_header) == CRUCIBLE_SHMEM_RING_HEADER_SIZE";
      }
      {
        label = "ring header alignment static assert";
        needle = "_Alignof(crucible_shmem_ring_header) == CRUCIBLE_SHMEM_RING_HEADER_ALIGN";
      }
      {
        label = "ring header read index offset static assert";
        needle = "offsetof(crucible_shmem_ring_header, read_idx) == CRUCIBLE_SHMEM_RING_HEADER_READ_IDX_OFFSET";
      }
      {
        label = "ring header read padding offset static assert";
        needle = "offsetof(crucible_shmem_ring_header, pad_read) == CRUCIBLE_SHMEM_RING_HEADER_PAD_READ_OFFSET";
      }
      {
        label = "ring header write index offset static assert";
        needle = "offsetof(crucible_shmem_ring_header, write_idx) == CRUCIBLE_SHMEM_RING_HEADER_WRITE_IDX_OFFSET";
      }
      {
        label = "ring header write padding offset static assert";
        needle = "offsetof(crucible_shmem_ring_header, pad_write) == CRUCIBLE_SHMEM_RING_HEADER_PAD_WRITE_OFFSET";
      }
      {
        label = "frame entry static assert";
        needle = "sizeof(crucible_shmem_frame_entry) == CRUCIBLE_SHMEM_FRAME_ENTRY_SIZE";
      }
      {
        label = "frame entry alignment static assert";
        needle = "_Alignof(crucible_shmem_frame_entry) == CRUCIBLE_SHMEM_FRAME_ENTRY_ALIGN";
      }
      {
        label = "frame delivery icount offset static assert";
        needle = "offsetof(crucible_shmem_frame_entry, delivery_icount) == CRUCIBLE_SHMEM_FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET";
      }
      {
        label = "frame source node offset static assert";
        needle = "offsetof(crucible_shmem_frame_entry, src_node) == CRUCIBLE_SHMEM_FRAME_ENTRY_SRC_NODE_OFFSET";
      }
      {
        label = "frame sequence offset static assert";
        needle = "offsetof(crucible_shmem_frame_entry, seq) == CRUCIBLE_SHMEM_FRAME_ENTRY_SEQ_OFFSET";
      }
      {
        label = "frame length offset static assert";
        needle = "offsetof(crucible_shmem_frame_entry, len) == CRUCIBLE_SHMEM_FRAME_ENTRY_LEN_OFFSET";
      }
      {
        label = "frame padding offset static assert";
        needle = "offsetof(crucible_shmem_frame_entry, pad) == CRUCIBLE_SHMEM_FRAME_ENTRY_PAD_OFFSET";
      }
      {
        label = "frame payload offset static assert";
        needle = "offsetof(crucible_shmem_frame_entry, data) == CRUCIBLE_SHMEM_FRAME_ENTRY_DATA_OFFSET";
      }
      {
        label = "coverage entry static assert";
        needle = "sizeof(crucible_shmem_coverage_entry) == CRUCIBLE_SHMEM_COVERAGE_ENTRY_SIZE";
      }
      {
        label = "coverage entry alignment static assert";
        needle = "_Alignof(crucible_shmem_coverage_entry) == CRUCIBLE_SHMEM_COVERAGE_ENTRY_ALIGN";
      }
      {
        label = "coverage current icount offset static assert";
        needle = "offsetof(crucible_shmem_coverage_entry, current_icount) == CRUCIBLE_SHMEM_COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET";
      }
      {
        label = "coverage map index offset static assert";
        needle = "offsetof(crucible_shmem_coverage_entry, map_index) == CRUCIBLE_SHMEM_COVERAGE_ENTRY_MAP_INDEX_OFFSET";
      }
      {
        label = "coverage reserved offset static assert";
        needle = "offsetof(crucible_shmem_coverage_entry, reserved) == CRUCIBLE_SHMEM_COVERAGE_ENTRY_RESERVED_OFFSET";
      }
      {
        label = "fingerprint sample slot C struct";
        needle = "crucible_shmem_fingerprint_sample_slot";
      }
      {
        label = "fingerprint sample slot size static assert";
        needle = "sizeof(crucible_shmem_fingerprint_sample_slot) == CRUCIBLE_SHMEM_FINGERPRINT_SAMPLE_SLOT_SIZE";
      }
      {
        label = "fingerprint sample slot words offset static assert";
        needle = "offsetof(crucible_shmem_fingerprint_sample_slot, words) == CRUCIBLE_SHMEM_FINGERPRINT_SAMPLE_SLOT_WORDS_OFFSET";
      }
      {
        label = "white-box marker entry C struct";
        needle = "crucible_shmem_whitebox_marker_entry";
      }
      {
        label = "white-box marker entry size static assert";
        needle = "sizeof(crucible_shmem_whitebox_marker_entry) == CRUCIBLE_SHMEM_WHITEBOX_MARKER_ENTRY_SIZE";
      }
      {
        label = "white-box marker payload offset static assert";
        needle = "offsetof(crucible_shmem_whitebox_marker_entry, payload) == CRUCIBLE_SHMEM_WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET";
      }
      {
        label = "vCPU-switch preemption kind C constant";
        needle = "#define CRUCIBLE_SHMEM_PREEMPTION_KIND_VCPU_SWITCH 1u";
      }
      {
        label = "interrupt preemption kind C constant";
        needle = "#define CRUCIBLE_SHMEM_PREEMPTION_KIND_INTERRUPT_AT 2u";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "shmem ABI gate target implemented";
        needle = ''
          package: "crucible-shmem",
                  test_target: "gate_abi_conformance",
                  required_features: &[],
                  placeholder: false,
        '';
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "shmem ABI mapping implemented";
        needle = ''
          package = "crucible-shmem";
                testTarget = "gate_abi_conformance";
                requiredFeatures = [];
                placeholder = false;
        '';
      }
      {
        label = "placeholder target count";
        needle = "placeholder_targets=0";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes shmem ABI conformance check";
        needle = "shmemAbiConformance = import ./phase2-shmem-abi-conformance.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 shmem ABI conformance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-shmem-abi-conformance";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-shmem-abi-conformance";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-shmem \
              --test gate_abi_conformance \
              -- --test-threads=1

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-shmem \
              --test preemption_mailbox \
              -- --test-threads=1

            cargo run \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-abi-conformance-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-shmem \
              --example crucible-shmem-abi-header \
              --quiet \
              > "$TMPDIR/crucible_shmem_abi.generated.h"
            diff -u \
              crates/crucible-shmem/include/crucible_shmem_abi.h \
              "$TMPDIR/crucible_shmem_abi.generated.h"

            cat > "$TMPDIR/crucible-shmem-golden-expand.rs" <<'RS_EOF'
            use std::env;
            use std::fs;
            use std::path::Path;

            fn main() -> Result<(), Box<dyn std::error::Error>> {
                let args: Vec<String> = env::args().collect();
                if args.len() != 3 {
                    return Err("usage: crucible-shmem-golden-expand FIXTURE OUT".into());
                }
                let fixture = fs::read_to_string(&args[1])?;
                let bytes = parse_fixture(&fixture)?;
                fs::write(Path::new(&args[2]), bytes)?;
                Ok(())
            }

            fn parse_fixture(fixture: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                let mut total_len = None;
                let mut segments: Vec<(usize, Vec<u8>)> = Vec::new();
                for raw_line in fixture.lines() {
                    let line = raw_line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let Some((key, value)) = line.split_once('=') else {
                        return Err(format!("invalid fixture line: {line}").into());
                    };
                    if key == "abi_version" {
                        continue;
                    }
                    if key == "total_len" {
                        total_len = Some(value.parse::<usize>()?);
                        continue;
                    }
                    let offset = key.parse::<usize>()?;
                    segments.push((offset, parse_hex(value)?));
                }

                let Some(total_len) = total_len else {
                    return Err("missing total_len".into());
                };
                let mut bytes = vec![0; total_len];
                for (offset, segment) in segments {
                    let end = offset
                        .checked_add(segment.len())
                        .ok_or("fixture segment overflow")?;
                    if end > bytes.len() {
                        return Err("fixture segment extends past total_len".into());
                    }
                    bytes[offset..end].copy_from_slice(&segment);
                }
                Ok(bytes)
            }

            fn parse_hex(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                if hex.len() % 2 != 0 {
                    return Err("odd-length hex payload".into());
                }
                let mut bytes = Vec::with_capacity(hex.len() / 2);
                for pair_index in 0..hex.len() / 2 {
                    let start = pair_index * 2;
                    let pair = &hex[start..start + 2];
                    bytes.push(u8::from_str_radix(pair, 16)?);
                }
                Ok(bytes)
            }
            RS_EOF
            rustc "$TMPDIR/crucible-shmem-golden-expand.rs" \
              -o "$TMPDIR/crucible-shmem-golden-expand"
            "$TMPDIR/crucible-shmem-golden-expand" \
              crates/crucible-shmem/tests/fixtures/shmem_abi_golden.fixture \
              "$TMPDIR/shmem_abi_golden.bin"

            cat > "$TMPDIR/crucible-shmem-c-encode.c" <<'C_EOF'
            #include "crucible_shmem_abi.h"

            #include <stdatomic.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>

            static int write_exact(FILE *out, const void *ptr, size_t len, const char *label) {
                if (fwrite(ptr, 1, len, out) != len) {
                    fprintf(stderr, "failed to write %s\n", label);
                    return 1;
                }
                return 0;
            }

            int main(int argc, char **argv) {
                if (argc != 2) {
                    fprintf(stderr, "usage: crucible-shmem-c-encode OUT\n");
                    return 2;
                }

                FILE *out = fopen(argv[1], "wb");
                if (out == NULL) {
                    perror("fopen");
                    return 1;
                }

                crucible_shmem_region_header header;
                memset(&header, 0, sizeof(header));
                atomic_init(&header.magic, CRUCIBLE_SHMEM_REGION_MAGIC);
                atomic_init(&header.abi_version, CRUCIBLE_SHMEM_ABI_VERSION);
                atomic_init(&header.node_count, CRUCIBLE_SHMEM_MAX_NODES);
                atomic_init(&header.queue_capacity, 8u);
                atomic_init(&header.ring_count, 12u);
                atomic_init(&header.ring_hdr_off, 4352u);
                atomic_init(&header.ring_data_off, 5888u);
                atomic_init(&header.entry_stride, CRUCIBLE_SHMEM_FRAME_ENTRY_SIZE);
                atomic_init(&header.region_size, 19605760u);
                atomic_init(&header.icount_shift, 4u);
                atomic_init(&header.pause_requested, 1u);
                atomic_init(&header.shutdown_requested, 0u);

                crucible_shmem_node_slot slot;
                memset(&slot, 0, sizeof(slot));
                atomic_init(&slot.current_icount, 128u);
                atomic_init(&slot.current_ns, 2048u);
                atomic_init(&slot.max_advance_icount, 256u);
                atomic_init(&slot.idle_wake_icount, 180u);
                atomic_init(&slot.wake_signal, 7u);
                atomic_init(&slot.status, CRUCIBLE_SHMEM_STATUS_IDLE);
                atomic_init(&slot.kind, CRUCIBLE_SHMEM_KIND_VM);
                atomic_init(&slot.device_io_active, 1u);
                atomic_init(&slot.publish_gen, 4u);
                atomic_init(&slot.preemption_at_icount, 160u);
                atomic_init(&slot.preemption_deadline_icount, 128u);
                atomic_init(&slot.preemption_ceiling_icount, 256u);
                atomic_init(&slot.preemption_published_sequence, 9u);
                atomic_init(&slot.preemption_consumed_sequence, 8u);
                atomic_init(&slot.preemption_arg0, 0u);
                atomic_init(&slot.preemption_arg1, 1u);
                atomic_init(
                    &slot.preemption_kind,
                    CRUCIBLE_SHMEM_PREEMPTION_KIND_VCPU_SWITCH
                );

                crucible_shmem_ring_header ring;
                memset(&ring, 0, sizeof(ring));
                atomic_init(&ring.read_idx, 5u);
                atomic_init(&ring.write_idx, 9u);

                crucible_shmem_frame_entry frame;
                memset(&frame, 0, sizeof(frame));
                frame.delivery_icount = 777u;
                frame.src_node = 2u;
                frame.seq = 42u;
                frame.len = 4u;
                memcpy(frame.data, "PING", 4);

                crucible_shmem_coverage_entry coverage;
                memset(&coverage, 0, sizeof(coverage));
                coverage.current_icount = 901u;
                coverage.guest_pc = 0x4010u;
                coverage.map_index = 17u;
                coverage.vcpu_index = 2u;
                coverage.block_len = 4u;

                crucible_shmem_whitebox_marker_entry marker;
                memset(&marker, 0, sizeof(marker));
                marker.current_icount = 913u;
                marker.vcpu_index = 2u;
                marker.kind = 4u;
                marker.payload_len = 4u;
                memcpy(marker.payload, "MARK", 4);

                static const uint8_t close_record[20] = {
                    'C', 'R', 'G', 'I', 1u, 0u, 7u, 0u,
                    1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
                    0u, 0u, 0u, 0u,
                };
                crucible_shmem_guest_introspection_entry guest_introspection;
                memset(&guest_introspection, 0, sizeof(guest_introspection));
                guest_introspection.sequence = 19u;
                guest_introspection.len = sizeof(close_record);
                memcpy(
                    guest_introspection.data,
                    close_record,
                    sizeof(close_record)
                );

                int failed = 0;
                uint32_t request_ring = UINT32_MAX;
                uint32_t response_ring = UINT32_MAX;
                crucible_shmem_guest_introspection_layout guest_layout;
                if (crucible_shmem_guest_introspection_ring_index(
                        1u,
                        CRUCIBLE_SHMEM_GUEST_INTROSPECTION_REQUEST_RING_OFFSET,
                        &request_ring
                    ) != 0
                    || crucible_shmem_guest_introspection_ring_index(
                        1u,
                        CRUCIBLE_SHMEM_GUEST_INTROSPECTION_RESPONSE_RING_OFFSET,
                        &response_ring
                    ) != 0
                    || request_ring != 2u
                    || response_ring != 3u
                    || crucible_shmem_guest_introspection_layout_compute(
                        5888u,
                        12u,
                        8u,
                        CRUCIBLE_SHMEM_FRAME_ENTRY_SIZE,
                        2u,
                        19605760u,
                        &guest_layout
                    ) != 0
                    || guest_layout.ring_count != 4u
                    || guest_layout.queue_capacity
                        != CRUCIBLE_SHMEM_GUEST_INTROSPECTION_QUEUE_CAPACITY
                    || guest_layout.ring_hdr_off != 18409216u
                    || guest_layout.ring_data_off != 18409728u
                    || guest_layout.entry_stride
                        != CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_SIZE
                    || guest_layout.region_size != 19605760u) {
                    fprintf(stderr, "guest-introspection geometry validation failed\n");
                    failed = 1;
                }
                failed |= write_exact(out, &header, sizeof(header), "region header");
                failed |= write_exact(out, &slot, sizeof(slot), "node slot");
                failed |= write_exact(out, &ring, sizeof(ring), "ring header");
                failed |= write_exact(out, &frame, sizeof(frame), "frame entry");
                failed |= write_exact(out, &coverage, sizeof(coverage), "coverage entry");
                failed |= write_exact(out, &marker, sizeof(marker), "white-box marker entry");
                failed |= write_exact(
                    out,
                    &guest_introspection,
                    sizeof(guest_introspection),
                    "guest-introspection entry"
                );
                if (fclose(out) != 0) {
                    perror("fclose");
                    failed = 1;
                }
                return failed;
            }
            C_EOF
            cc -std=c11 -Wall -Wextra -Werror \
              -I crates/crucible-shmem/include \
              "$TMPDIR/crucible-shmem-c-encode.c" \
              -o "$TMPDIR/crucible-shmem-c-encode"
            "$TMPDIR/crucible-shmem-c-encode" "$TMPDIR/shmem_abi_c_encoded.bin"
            cmp "$TMPDIR/shmem_abi_golden.bin" "$TMPDIR/shmem_abi_c_encoded.bin"

            cat > "$TMPDIR/crucible-shmem-c-roundtrip.c" <<'C_EOF'
            #include "crucible_shmem_abi.h"

            #include <stdatomic.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>

            static int read_exact(FILE *in, void *ptr, size_t len, const char *label) {
                if (fread(ptr, 1, len, in) != len) {
                    fprintf(stderr, "failed to read %s\n", label);
                    return 1;
                }
                return 0;
            }

            static int write_exact(FILE *out, const void *ptr, size_t len, const char *label) {
                if (fwrite(ptr, 1, len, out) != len) {
                    fprintf(stderr, "failed to write %s\n", label);
                    return 1;
                }
                return 0;
            }

            int main(int argc, char **argv) {
                if (argc != 3) {
                    fprintf(stderr, "usage: crucible-shmem-c-roundtrip IN OUT\n");
                    return 2;
                }

                FILE *in = fopen(argv[1], "rb");
                if (in == NULL) {
                    perror("fopen input");
                    return 1;
                }

                crucible_shmem_region_header header;
                crucible_shmem_node_slot slot;
                crucible_shmem_ring_header ring;
                crucible_shmem_frame_entry frame;
                crucible_shmem_coverage_entry coverage;
                crucible_shmem_whitebox_marker_entry marker;
                crucible_shmem_guest_introspection_entry guest_introspection;

                int failed = 0;
                failed |= read_exact(in, &header, sizeof(header), "region header");
                failed |= read_exact(in, &slot, sizeof(slot), "node slot");
                failed |= read_exact(in, &ring, sizeof(ring), "ring header");
                failed |= read_exact(in, &frame, sizeof(frame), "frame entry");
                failed |= read_exact(in, &coverage, sizeof(coverage), "coverage entry");
                failed |= read_exact(in, &marker, sizeof(marker), "white-box marker entry");
                failed |= read_exact(
                    in,
                    &guest_introspection,
                    sizeof(guest_introspection),
                    "guest-introspection entry"
                );
                if (fclose(in) != 0) {
                    perror("fclose input");
                    failed = 1;
                }
                if (failed != 0) {
                    return failed;
                }

                if (atomic_load_explicit(&header.magic, memory_order_acquire) != CRUCIBLE_SHMEM_REGION_MAGIC
                    || atomic_load_explicit(&header.abi_version, memory_order_acquire) != CRUCIBLE_SHMEM_ABI_VERSION
                    || atomic_load_explicit(&header.node_count, memory_order_acquire) != CRUCIBLE_SHMEM_MAX_NODES
                    || atomic_load_explicit(&header.queue_capacity, memory_order_acquire) != 8u
                    || atomic_load_explicit(&header.ring_count, memory_order_acquire) != 12u
                    || atomic_load_explicit(&header.ring_hdr_off, memory_order_acquire) != 4352u
                    || atomic_load_explicit(&header.ring_data_off, memory_order_acquire) != 5888u
                    || atomic_load_explicit(&header.entry_stride, memory_order_acquire) != CRUCIBLE_SHMEM_FRAME_ENTRY_SIZE
                    || atomic_load_explicit(&header.region_size, memory_order_acquire) != 19605760u
                    || atomic_load_explicit(&header.icount_shift, memory_order_acquire) != 4u
                    || atomic_load_explicit(&header.pause_requested, memory_order_acquire) != 1u
                    || atomic_load_explicit(&header.shutdown_requested, memory_order_acquire) != 0u) {
                    fprintf(stderr, "region header validation failed\n");
                    return 1;
                }

                if (atomic_load_explicit(&slot.current_icount, memory_order_acquire) != 128u
                    || atomic_load_explicit(&slot.current_ns, memory_order_acquire) != 2048u
                    || atomic_load_explicit(&slot.max_advance_icount, memory_order_acquire) != 256u
                    || atomic_load_explicit(&slot.idle_wake_icount, memory_order_acquire) != 180u
                    || atomic_load_explicit(&slot.wake_signal, memory_order_acquire) != 7u
                    || atomic_load_explicit(&slot.status, memory_order_acquire) != CRUCIBLE_SHMEM_STATUS_IDLE
                    || atomic_load_explicit(&slot.kind, memory_order_acquire) != CRUCIBLE_SHMEM_KIND_VM
                    || atomic_load_explicit(&slot.device_io_active, memory_order_acquire) != 1u
                    || atomic_load_explicit(&slot.publish_gen, memory_order_acquire) != 4u
                    || atomic_load_explicit(&slot.preemption_at_icount, memory_order_acquire) != 160u
                    || atomic_load_explicit(&slot.preemption_deadline_icount, memory_order_acquire) != 128u
                    || atomic_load_explicit(&slot.preemption_ceiling_icount, memory_order_acquire) != 256u
                    || atomic_load_explicit(&slot.preemption_published_sequence, memory_order_acquire) != 9u
                    || atomic_load_explicit(&slot.preemption_consumed_sequence, memory_order_acquire) != 8u
                    || atomic_load_explicit(&slot.preemption_arg0, memory_order_acquire) != 0u
                    || atomic_load_explicit(&slot.preemption_arg1, memory_order_acquire) != 1u
                    || atomic_load_explicit(&slot.preemption_kind, memory_order_acquire)
                        != CRUCIBLE_SHMEM_PREEMPTION_KIND_VCPU_SWITCH) {
                    fprintf(stderr, "node slot validation failed\n");
                    return 1;
                }

                if (atomic_load_explicit(&ring.read_idx, memory_order_acquire) != 5u
                    || atomic_load_explicit(&ring.write_idx, memory_order_acquire) != 9u) {
                    fprintf(stderr, "ring header validation failed\n");
                    return 1;
                }

                if (frame.delivery_icount != 777u
                    || frame.src_node != 2u
                    || frame.seq != 42u
                    || frame.len != 4u
                    || memcmp(frame.data, "PING", 4) != 0) {
                    fprintf(stderr, "frame entry validation failed\n");
                    return 1;
                }

                if (coverage.current_icount != 901u
                    || coverage.guest_pc != 0x4010u
                    || coverage.map_index != 17u
                    || coverage.vcpu_index != 2u
                    || coverage.block_len != 4u) {
                    fprintf(stderr, "coverage entry validation failed\n");
                    return 1;
                }

                if (marker.current_icount != 913u
                    || marker.vcpu_index != 2u
                    || marker.kind != 4u
                    || marker.payload_len != 4u
                    || memcmp(marker.payload, "MARK", 4) != 0) {
                    fprintf(stderr, "white-box marker entry validation failed\n");
                    return 1;
                }

                static const uint8_t close_record[20] = {
                    'C', 'R', 'G', 'I', 1u, 0u, 7u, 0u,
                    1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
                    0u, 0u, 0u, 0u,
                };
                if (guest_introspection.sequence != 19u
                    || guest_introspection.len != sizeof(close_record)
                    || memcmp(
                        guest_introspection.data,
                        close_record,
                        sizeof(close_record)
                    ) != 0) {
                    fprintf(stderr, "guest-introspection entry validation failed\n");
                    return 1;
                }

                FILE *out = fopen(argv[2], "wb");
                if (out == NULL) {
                    perror("fopen output");
                    return 1;
                }
                failed |= write_exact(out, &header, sizeof(header), "region header");
                failed |= write_exact(out, &slot, sizeof(slot), "node slot");
                failed |= write_exact(out, &ring, sizeof(ring), "ring header");
                failed |= write_exact(out, &frame, sizeof(frame), "frame entry");
                failed |= write_exact(out, &coverage, sizeof(coverage), "coverage entry");
                failed |= write_exact(out, &marker, sizeof(marker), "white-box marker entry");
                failed |= write_exact(
                    out,
                    &guest_introspection,
                    sizeof(guest_introspection),
                    "guest-introspection entry"
                );
                if (fclose(out) != 0) {
                    perror("fclose output");
                    failed = 1;
                }
                return failed;
            }
            C_EOF
            cc -std=c11 -Wall -Wextra -Werror \
              -I crates/crucible-shmem/include \
              "$TMPDIR/crucible-shmem-c-roundtrip.c" \
              -o "$TMPDIR/crucible-shmem-c-roundtrip"
            "$TMPDIR/crucible-shmem-c-roundtrip" \
              "$TMPDIR/shmem_abi_golden.bin" \
              "$TMPDIR/shmem_abi_c_roundtrip.bin"
            cmp "$TMPDIR/shmem_abi_golden.bin" "$TMPDIR/shmem_abi_c_roundtrip.bin"
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cp crates/crucible-shmem/include/crucible_shmem_abi.h "$out/crucible_shmem_abi.h"
            cp crates/crucible-shmem/tests/fixtures/shmem_abi_golden.fixture "$out/shmem_abi_golden.fixture"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:abi-conformance
            rust_tests=crucible-shmem::gate_abi_conformance,crucible-shmem::preemption_mailbox
            generated_header_diff=checked
            bilateral_static_asserts=compiled
            golden_vector_roundtrip=rust,c
            golden_vector_fixture=shmem_abi_golden.fixture
            RESULT
          '';
        }
      ];
    }
