{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.layer1Injection",
  taskIds ? ["T-DET-14"],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  icountStampedInjection = import ./phase1-icount-stamped-injection.nix {
    inherit pkgs lib campaignComposition testing;
  };
  lookaheadGate = import ./phase1-lookahead-gate.nix {
    inherit pkgs lib campaignComposition testing;
  };
  atomicPatchEvidence = import ./phase2-patch-microtests.nix {
    inherit pkgs lib campaignComposition testing;
  };
  sameIcountTieBreak = import ./phase1-same-icount-tie-break.nix {
    inherit pkgs lib campaignComposition testing;
  };

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
        needle = "package: \"crucible-device\",\n        test_target: \"gate_layer1_injection\",\n        required_features: &[],";
      }
      {
        label = "crucible-protocol layer1 target implemented";
        needle = "package: \"crucible-protocol\",\n        test_target: \"gate_layer1_injection\",\n        required_features: &[],";
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
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
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
  dependencyResultName =
    if campaignComposition == null
    then "result"
    else "raw-result";
  runtimeInputs = [pkgs.coreutils pkgs.grep] ++ dependencies;
  runtimeScript = ''
    set -eu

    require_line() {
      result="$1"
      line="$2"
      grep -Fxq "$line" "$result" || {
        echo "dependency missing evidence: $line" >&2
        cat "$result" >&2
        exit 1
      }
    }

    icount_result="${icountStampedInjection}/${dependencyResultName}"
    lookahead_result="${lookaheadGate}/${dependencyResultName}"
    patch_result="${atomicPatchEvidence}/${dependencyResultName}"
    tie_break_result="${sameIcountTieBreak}/${dependencyResultName}"
    ${lib.optionalString (campaignComposition != null) ''
      for result in \
        "$icount_result" \
        "$lookahead_result" \
        "$patch_result" \
        "$tie_break_result"; do
        require_line "$result" "campaign_mode=${campaignComposition.mode}"
        require_line "$result" \
          "campaign_configuration_identity=${campaignComposition.system.config.aos.services.crucibleCampaign._runtimeIdentity}"
        require_line "$result" \
          "campaign_toplevel=${campaignComposition.system.config.system.build.toplevel}"
      done
    ''}
    require_line "$icount_result" "in_band_delivery_icount=true"
    require_line "$icount_result" "arrival_order_visible=false"
    require_line "$lookahead_result" "late_delivery_policy=fail_loudly"
    require_line "$lookahead_result" "ceiling_rule=max_advance_icount_lt_earliest_possible_delivery_icount"
    require_line "$patch_result" "gate=gate:patch-microtests"
    require_line "$patch_result" "atomic_patch_runtime_is_shipped_qemu=true"
    require_line "$patch_result" "qemu_plugin_net_exports_present=true"
    require_line "$patch_result" "qemu_plugin_time_drain_exports_present=true"
    require_line "$tie_break_result" "shmem_projection=delivery_icount,src_node,seq"
    require_line "$tie_break_result" "arrival_order_visible=false"

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
    qemu_atomic_patch_evidence=phase2PatchMicrotests
    qemu_net_and_time_exports_present=true
    retired_partial_patch_fixtures=0
    producer_timing_negative_control_failed=true
    RESULT
  '';
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-phase1-layer1-injection";
    version = "0";
    src = null;
    buildDeps = runtimeInputs;
    phases = [
      {
        name = "record-layer1-injection";
        script = runtimeScript;
      }
    ];
  };
in
  if failures != []
  then throw "crucible phase1 layer1 injection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing runtimeInputs runtimeScript;
      inherit (campaignComposition) mode system;
      gateName = "gate:layer1-injection";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "layer1-injection";
      runtimeClosures = [
        icountStampedInjection
        lookaheadGate
        atomicPatchEvidence
        sameIcountTieBreak
      ];
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
