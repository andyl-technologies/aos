{
  pkgs,
  lib,
}: let
  phase0S4 = import ./phase0-s4.nix {inherit pkgs;};

  shmemSource = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-shmem/src/lib.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/frame_entry.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/delivery_errors.rs)
  ];
  shmemTest = builtins.readFile ../../crates/crucible-shmem/tests/icount_stamped_injection.rs;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "crates/crucible-shmem/src/lib.rs + shmem/frame_node.rs + shmem/delivery_errors.rs" shmemSource [
      {
        label = "frame payload capacity";
        needle = "pub const MAX_FRAME_DATA: usize = 4608;";
      }
      {
        label = "capacity fits frame length field";
        needle = "assert!(MAX_FRAME_DATA <= u16::MAX as usize);";
      }
      {
        label = "C ABI representation";
        needle = "#[repr(C)]";
      }
      {
        label = "C ABI frame entry";
        needle = "pub struct FrameEntry";
      }
      {
        label = "in-band delivery icount";
        needle = "pub delivery_icount: u64";
      }
      {
        label = "source node tie-break";
        needle = "pub src_node: u32";
      }
      {
        label = "sequence tie-break";
        needle = "pub seq: u32";
      }
      {
        label = "delivery-icount predicate";
        needle = "pub fn is_deliverable_at";
      }
      {
        label = "deterministic delivery key";
        needle = "pub struct FrameDeliveryKey";
      }
      {
        label = "consumer-side visible frame ordering";
        needle = "pub fn deliverable_frames_at";
      }
      {
        label = "oversized payload rejection";
        needle = "PayloadLengthExceedsCapacity";
      }
      {
        label = "delivery icount offset assertion";
        needle = "assert!(core::mem::offset_of!(FrameEntry, delivery_icount) == 0);";
      }
      {
        label = "source node offset assertion";
        needle = "assert!(core::mem::offset_of!(FrameEntry, src_node) == 8);";
      }
      {
        label = "sequence offset assertion";
        needle = "assert!(core::mem::offset_of!(FrameEntry, seq) == 12);";
      }
      {
        label = "length offset assertion";
        needle = "assert!(core::mem::offset_of!(FrameEntry, len) == 16);";
      }
      {
        label = "payload offset assertion";
        needle = "assert!(core::mem::offset_of!(FrameEntry, data) == FRAME_ENTRY_DATA_OFFSET);";
      }
      {
        label = "frame entry size assertion";
        needle = "assert!(core::mem::size_of::<FrameEntry>() == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);";
      }
      {
        label = "frame entry alignment assertion";
        needle = "assert!(core::mem::align_of::<FrameEntry>() == 8);";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/icount_stamped_injection.rs" shmemTest [
      {
        label = "in-band delivery-icount test";
        needle = "frame_entry_carries_delivery_icount_in_band";
      }
      {
        label = "arrival-order independence test";
        needle = "deliverability_depends_on_consumer_icount_not_arrival_order";
      }
      {
        label = "oversized payload rejection test";
        needle = "frame_entry_rejects_oversized_payload";
      }
      {
        label = "malformed length rejection test";
        needle = "frame_entry_rejects_malformed_payload_length";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/icount_stamped_injection.rs" shmemTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-11 checklist complete";
        needle = "- [x] **T-DET-11**";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes icount-stamped injection check";
        needle = "icountStampedInjection = import ./phase1-icount-stamped-injection.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 icount-stamped injection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-icount-stamped-injection";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ];

      phases = [
        {
          name = "record-icount-stamped-injection";
          script = ''
            set -eu
            s4_result="${phase0S4}/result"

            grep -q '^PASS$' "$s4_result"
            grep -q '^delivery_rule=delivery_icount_lte_current_icount$' "$s4_result"
            grep -q '^tie_break_key=delivery_icount_src_node_seq$' "$s4_result"
            grep -q '^consumer_ceiling=delivery_icount_minus_1_until_group_present$' "$s4_result"
            grep -q '^visibility_icounts_equal_delivery_icount=true$' "$s4_result"
            grep -q '^scope=phase0_shmem_visibility_discipline_not_qemu_device_injection$' "$s4_result"

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.icountStampedInjection
            tasks=T-DET-11
            crate=crucible-shmem
            abi_type=FrameEntry
            in_band_delivery_icount=true
            deliverability_rule=delivery_icount_lte_consumer_current_icount
            arrival_order_visible=false
            deterministic_order=delivery_icount,src_node,seq
            phase0_evidence=checks.crucible.phase0.s4ShmemVisibility
            RESULT
          '';
        }
      ];
    }
