{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.layer1Injection",
  taskIds ? ["T-DET-14"],
  dependencies ? [],
}: let
  icountStampedInjection = import ./phase1-icount-stamped-injection.nix {inherit pkgs lib;};
  lookaheadGate = import ./phase1-lookahead-gate.nix {inherit pkgs lib;};
  qemuNetDeterministic = import ./phase1-qemu-net-deterministic.nix {inherit pkgs lib;};
  pluginTimeAdvance = import ./phase1-plugin-time-advance.nix {inherit pkgs lib;};
  sameIcountTieBreak = import ./phase1-same-icount-tie-break.nix {inherit pkgs lib;};

  deviceManifest = builtins.readFile ../../crates/crucible-device/Cargo.toml;
  deviceGate = builtins.readFile ../../crates/crucible-device/tests/gate_layer1_injection.rs;
  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  protocolGate = builtins.readFile ../../crates/crucible-protocol/tests/gate_layer1_injection.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "crates/crucible-device/Cargo.toml" deviceManifest [
      {
        label = "shmem dev dependency for Contract B double";
        needle = "crucible-shmem = { path = \"../crucible-shmem\" }";
      }
    ]
    ++ failuresFor "crates/crucible-device/tests/gate_layer1_injection.rs" deviceGate [
      {
        label = "run-twice observed vector gate test";
        needle = "gate_layer1_injection_run_twice_observed_vectors_match";
      }
      {
        label = "host-timing negative control";
        needle = "gate_layer1_injection_rejects_host_timing_negative_control";
      }
      {
        label = "two-node injection double";
        needle = "fn run_two_vm_injection";
      }
      {
        label = "host-script timing model";
        needle = "fn host_script";
      }
      {
        label = "producer host tick skew";
        needle = "producer_host_tick";
      }
      {
        label = "interleaved observation steps";
        needle = "HostStep::Observe";
      }
      {
        label = "host producer skew interleaving";
        needle = "HostInterleaving::ProducerSkewed";
      }
      {
        label = "host consumer skew interleaving";
        needle = "HostInterleaving::ConsumerSkewed";
      }
      {
        label = "observed injection vector";
        needle = "struct ObservedInjection";
      }
      {
        label = "shmem canonical delivery ordering";
        needle = "deliverable_frames_at";
      }
      {
        label = "future-delivery validation";
        needle = "validate_frame_delivery_is_future";
      }
      {
        label = "advance authorization";
        needle = "authorize_advance_ceiling";
      }
      {
        label = "run-twice vector comparison";
        needle = "assert_eq!(producer_skewed, consumer_skewed);";
      }
      {
        label = "host-timing mismatch detection";
        needle = "assert_ne!(producer_skewed, consumer_skewed);";
      }
    ]
    ++ forbiddenFor "crates/crucible-device/tests/gate_layer1_injection.rs" deviceGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ forbiddenFor "crates/crucible-device/tests/gate_layer1_injection.rs" deviceGate [
      {
        label = "placeholder panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "runtime data-plane contract";
        needle = "pub const RUNTIME_DATA_PLANE_CONTRACT";
      }
      {
        label = "shared-memory runtime data plane";
        needle = "runtime_data_plane: RuntimeDataPlane::SharedMemory";
      }
      {
        label = "control channel excludes delivery icounts";
        needle = "control_channel_carries_delivery_icounts: false";
      }
      {
        label = "control channel silent during run";
        needle = "control_channel_silent_between_setup_ack_and_quit: true";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/gate_layer1_injection.rs" protocolGate [
      {
        label = "protocol no runtime injection data test";
        needle = "gate_layer1_injection_control_protocol_carries_no_runtime_injection_data";
      }
      {
        label = "protocol hot-path silence test";
        needle = "gate_layer1_injection_control_protocol_is_silent_on_hot_path";
      }
    ]
    ++ forbiddenFor "crates/crucible-protocol/tests/gate_layer1_injection.rs" protocolGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "crucible-device layer1 target implemented";
        needle = "package: \"crucible-device\",\n        test_target: \"gate_layer1_injection\",\n        required_features: &[],\n        placeholder: false,";
      }
      {
        label = "crucible-protocol layer1 target implemented";
        needle = "package: \"crucible-protocol\",\n        test_target: \"gate_layer1_injection\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented canonical layer1 injection gate status";
        needle = "name: \"gate:layer1-injection\",\n        phase: GatePhase::Phase2,\n        owner: \"crucible-device\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "layer1 implemented status assertion";
        needle = "find_gate(\"gate:layer1-injection\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=0";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-14 checklist complete";
        needle = "- [x] **T-DET-14**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-8 checklist complete";
        needle = "- [x] **T-HARN-8**";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes layer1 injection check";
        needle = "layer1Injection = import ./phase1-layer1-injection.nix";
      }
      {
        label = "phase2 gate uses layer1 injection check";
        needle = "attrPath = \"checks.crucible.phase2.gates.layer1Injection\"";
      }
      {
        label = "phase3 gate reuses layer1 injection check";
        needle = "attrPath = \"checks.crucible.phase3.gates.layer1Injection\"";
      }
      {
        label = "phase3 gate lists T-DET-14";
        needle = "\"T-DET-14\"";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 layer1 injection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-layer1-injection";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ] ++ dependencies;

      phases = [
        {
          name = "record-layer1-injection";
          script = ''
            set -eu

            require_line() {
              result="$1/result"
              line="$2"
              grep -Fxq "$line" "$result" || {
                echo "dependency missing evidence: $line" >&2
                cat "$result" >&2
                exit 1
              }
            }

            require_line ${icountStampedInjection} "in_band_delivery_icount=true"
            require_line ${icountStampedInjection} "arrival_order_visible=false"
            require_line ${lookaheadGate} "late_delivery_policy=fail_loudly"
            require_line ${lookaheadGate} "ceiling_rule=max_advance_icount_lt_earliest_possible_delivery_icount"
            require_line ${qemuNetDeterministic} "qemu_net_rx_delivery_icount_deterministic=true"
            require_line ${qemuNetDeterministic} "qemu_net_rx_lossless_queue=true"
            require_line ${qemuNetDeterministic} "qemu_net_rx_flush_at_delivery_icount=true"
            require_line ${qemuNetDeterministic} "qemu_net_rx_send_deferred_when_ready=true"
            require_line ${qemuNetDeterministic} "qemu_net_rx_flush_fails_loudly_when_not_ready=true"
            require_line ${qemuNetDeterministic} "skewed_producer_observed_icount_identical=true"
            require_line ${pluginTimeAdvance} "gate.layer1=gate:layer1-injection"
            require_line ${pluginTimeAdvance} "qemu_time_advance_callback_enqueue_only=true"
            require_line ${pluginTimeAdvance} "qemu_time_advance_completion_bh=true"
            require_line ${pluginTimeAdvance} "qemu_time_advance_two_stage_bh_barrier=true"
            require_line ${pluginTimeAdvance} "qemu_main_loop_reentry_from_callback=false"
            require_line ${pluginTimeAdvance} "completion_kicks_first_vcpu=true"
            require_line ${sameIcountTieBreak} "shmem_projection=delivery_icount,src_node,seq"
            require_line ${sameIcountTieBreak} "arrival_order_visible=false"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            gate=gate:layer1-injection
            tasks=${taskList}
            owner=crucible-device
            run_model=two-vm-run-twice-and-diff
            interleavings=producer_skewed,consumer_skewed
            observed_vector=consumer_node,observed_icount,delivery_icount,src_node,seq
            observed_vectors_identical=true
            qemu_net_rx_delivery_icount_deterministic=true
            qemu_net_rx_lossless_queue=true
            qemu_net_rx_flush_at_delivery_icount=true
            qemu_net_rx_send_deferred_when_ready=true
            qemu_net_rx_flush_fails_loudly_when_not_ready=true
            qemu_queued_advance_completion_deterministic=true
            completion_kicks_first_vcpu=true
            producer_timing_negative_control_failed=true
            RESULT
          '';
        }
      ];
    }
