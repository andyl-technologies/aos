{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.singleVmFingerprint",
  taskIds ? ["T-ASRT-18" "T-DET-9" "T-EXEC-17" "T-EXEC-18" "T-PAT-9"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };
  s1Fingerprint = import ./phase0-s1.nix {
    inherit pkgs lib;
  };

  phase0S1 = builtins.readFile ./phase0-s1.nix;
  crucibleManifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  crucibleTrigger = import ./_crucible-trigger-source.nix {inherit lib;};
  crucibleModelGate = builtins.readFile ../../crates/crucible/tests/gate_single_vm_fingerprint.rs;
  assertionProximityTest = builtins.readFile ../../crates/crucible/tests/assertion_proximity_gradient.rs;
  harnessAdversarial = builtins.readFile ../../crates/crucible-harness/src/adversarial.rs;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuGateRoot = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint.rs;
  qemuGateCompare = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/compare.rs;
  qemuGateProbe = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/probe.rs;
  qemuGateRun = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/run.rs;
  qemuGateStateDump = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/state_dump.rs;
  qemuGateTypes = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/types.rs;
  qemuGateHook = qemuGateRoot + qemuGateCompare + qemuGateProbe + qemuGateRun + qemuGateStateDump + qemuGateTypes;
  qemuGateTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs;
  qemuTracePlugin = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  assertionProperties = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  executionModel = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/Cargo.toml" crucibleManifest [
      {
        label = "model single-VM fingerprint target";
        needle = ''name = "gate_single_vm_fingerprint"'';
      }
      {
        label = "model single-VM fingerprint target path";
        needle = ''path = "tests/gate_single_vm_fingerprint.rs"'';
      }
      {
        label = "model gate requires test-double feature";
        needle = ''required-features = ["test-double"]'';
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_single_vm_fingerprint.rs" crucibleModelGate [
      {
        label = "adversarial host profile matrix test";
        needle = "gate_single_vm_fingerprint_model_determinism_survives_adversarial_host_profiles";
      }
      {
        label = "shared adversarial host matrix";
        needle = "canonical_host_adversary_matrix()";
      }
      {
        label = "shared profiled runner";
        needle = "run_profiled_tasks(profile, fixtures.len()";
      }
      {
        label = "determinism matrix equality";
        needle = "assert_eq!(candidate, baseline";
      }
      {
        label = "adversarial profiles use same-configuration fixtures";
        needle = "same_configuration_fixtures(&scenario)";
      }
      {
        label = "adversarial matrix validates same-configuration fixture";
        needle = "validate_same_configuration_fixture(scenario, fixture)";
      }
      {
        label = "same-configuration validator test";
        needle = "gate_single_vm_fingerprint_same_configuration_twice_validates_start_resume_fork_and_snapshot_completeness";
      }
      {
        label = "shared validator helper";
        needle = "fn validate_same_configuration_twice";
      }
      {
        label = "start probe";
        needle = "SameConfigurationProbe::Start";
      }
      {
        label = "resume probe";
        needle = "SameConfigurationProbe::Resume";
      }
      {
        label = "fork probe";
        needle = "SameConfigurationProbe::Fork";
      }
      {
        label = "replay-oracle probe";
        needle = "SameConfigurationProbe::SnapshotCompleteness";
      }
      {
        label = "exact snapshot branch";
        needle = "graph_with_exact_snapshot_only";
      }
      {
        label = "ancestor replay branch";
        needle = "graph_with_ancestor_snapshot_only";
      }
      {
        label = "saved checkpoint branch";
        needle = "graph_with_saved_checkpoint_exact_only";
      }
      {
        label = "no genesis fallback for forced branch paths";
        needle = "assert!(graph.genesis_snapshot(scenario).is_none());";
      }
      {
        label = "saved checkpoint replay-oracle evidence";
        needle = "source_graph.replay_checkpoint(configuration, &checkpoint)";
      }
      {
        label = "saved checkpoint fingerprint equality";
        needle = "assert_eq!(replay_check.fat_checkpoint, replay_check.thin_checkpoint);";
      }
      {
        label = "fingerprint equality assertion";
        needle = "assert_eq!(first.fingerprint, second.fingerprint);";
      }
      {
        label = "different-configuration rejection";
        needle = "gate_single_vm_fingerprint_rejects_different_configuration_fingerprints";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/adversarial.rs" harnessAdversarial [
      {
        label = "host adversary profile type";
        needle = "pub struct HostAdversaryProfile";
      }
      {
        label = "canonical host matrix";
        needle = "pub fn canonical_host_adversary_matrix";
      }
      {
        label = "host load profile";
        needle = "loaded-single-core";
      }
      {
        label = "task reordering profile";
        needle = "reordered-two-core";
      }
      {
        label = "varied core count profile";
        needle = "loaded-many-core";
      }
      {
        label = "host task ordering variation";
        needle = "pub enum HostTaskOrder";
      }
      {
        label = "seeded randomized scheduling";
        needle = "SeededPermutation";
      }
      {
        label = "logical affinity variation";
        needle = "pub enum HostAffinity";
      }
      {
        label = "seeded randomized affinity";
        needle = "HostAffinity::Seeded";
      }
      {
        label = "producer consumer skew";
        needle = "pub enum ProducerConsumerSkew";
      }
      {
        label = "affinity drives worker assignment";
        needle = "let worker_index = logical_core % profile.worker_count;";
      }
      {
        label = "worker-count variation";
        needle = "worker_count: 4";
      }
      {
        label = "host load configuration";
        needle = "HostLoad::spinning";
      }
      {
        label = "yield perturbation";
        needle = "std::thread::yield_now();";
      }
      {
        label = "shared profiled task runner";
        needle = "pub fn run_profiled_tasks";
      }
      {
        label = "concurrent host load wrapper";
        needle = "pub fn with_profiled_host_load";
      }
      {
        label = "background load worker";
        needle = "scope.spawn(move || inject_host_load(profile, task))";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_single_vm_fingerprint.rs" crucibleModelGate [
      {
        label = "ignored model gate target";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "single-VM fingerprint module";
        needle = "mod single_vm_fingerprint;";
      }
      {
        label = "single-VM fingerprint gate export";
        needle = "run_single_vm_fingerprint_gate";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/single_vm_fingerprint.rs" qemuGateHook [
      {
        label = "QEMU runner hook";
        needle = "pub trait SingleVmFingerprintRunner";
      }
      {
        label = "fixed scenario type";
        needle = "pub struct SingleVmFingerprintScenario";
      }
      {
        label = "host-condition profile";
        needle = "pub struct SingleVmHostProfile";
      }
      {
        label = "first run ordinal";
        needle = "SingleVmFingerprintRunOrdinal::First";
      }
      {
        label = "second run ordinal";
        needle = "SingleVmFingerprintRunOrdinal::Second";
      }
      {
        label = "run-twice gate driver";
        needle = "pub fn run_single_vm_fingerprint_gate";
      }
      {
        label = "stream comparator";
        needle = "pub fn compare_single_vm_fingerprint_streams";
      }
      {
        label = "definition digest validation";
        needle = "fingerprint_definition_digest";
      }
      {
        label = "run horizon";
        needle = "run_horizon_icount";
      }
      {
        label = "required horizon sample";
        needle = "fingerprint stream must include a sample at the scenario horizon";
      }
      {
        label = "final fingerprint icount";
        needle = "final_icount";
      }
      {
        label = "mismatch diagnostics";
        needle = "pub struct SingleVmFingerprintMismatch";
      }
      {
        label = "bisection request";
        needle = "pub struct SingleVmFingerprintBisectionRequest";
      }
      {
        label = "bisection report";
        needle = "pub struct SingleVmFingerprintBisectionReport";
      }
      {
        label = "content-addressed state dump report";
        needle = "pub fn state_dump_content_address(&self) -> &str";
      }
      {
        label = "backend bisection hook";
        needle = "fn bisect_single_vm_fingerprint_mismatch";
      }
      {
        label = "fallible exact-icount probe backend";
        needle = "pub trait SingleVmFingerprintProbeRunner";
      }
      {
        label = "instruction-exact probe bisection";
        needle = "pub fn bisect_single_vm_fingerprint_with_probes";
      }
      {
        label = "one-instruction refinement invariant";
        needle = "while high - low > 1";
      }
      {
        label = "cumulative prefix probe witness";
        needle = "prefix_fingerprint";
      }
      {
        label = "pre-execution genesis equality probe";
        needle = "let mut low_pair = probe_pair(runner, request.scenario(), low";
      }
      {
        label = "provenance-bound state dump probe";
        needle = "pub struct SingleVmFingerprintStateDumpProbe";
      }
      {
        label = "scheduler-causal retained events";
        needle = "from_causal_projection_entry";
      }
      {
        label = "complete retained scheduler entries";
        needle = "scheduler_entry: SchedulerEventLogEntry";
      }
      {
        label = "fixed last-N event retention";
        needle = "SINGLE_VM_FINGERPRINT_STATE_DUMP_EVENT_LIMIT: u64 = 64";
      }
      {
        label = "custom runner report scenario revalidation";
        needle = "bisection state dump must match the scenario definition, inputs, and vCPU topology";
      }
      {
        label = "report constructor topology validation";
        needle = "state dump vCPU topology must match the report scenario";
      }
      {
        label = "strictly lower coarse boundary";
        needle = "find(|sample| sample.icount < first_different_icount)";
      }
      {
        label = "content-addressed both-side state dump";
        needle = "state_dump.content_digest()";
      }
      {
        label = "bisection failure error";
        needle = "BisectionFailed";
      }
      {
        label = "previous matching icount";
        needle = "previous_matching_icount";
      }
      {
        label = "first differing icount";
        needle = "first_different_icount";
      }
      {
        label = "diagnostic streams on mismatch";
        needle = "first_stream: Box<SingleVmFingerprintStream>";
      }
      {
        label = "diagnostic bisection on mismatch";
        needle = "bisection: Box<SingleVmFingerprintBisectionReport>";
      }
      {
        label = "mismatch path invokes bisection";
        needle = ".bisect_single_vm_fingerprint_mismatch(&request)";
      }
      {
        label = "bisection alignment validation";
        needle = "validate_bisection_report_for_mismatch";
      }
      {
        label = "no tolerance on mismatches";
        needle = "SingleVmFingerprintGateError::Mismatch";
      }
      {
        label = "backend stream validation";
        needle = "InvalidStreamForRun";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs" qemuGateTest [
      {
        label = "implemented gate target marker";
        needle = "gate_single_vm_fingerprint_runs_fixed_scenario_twice";
      }
      {
        label = "sample window localization";
        needle = "gate_single_vm_fingerprint_reports_first_sample_window";
      }
      {
        label = "bisection required on mismatch";
        needle = "gate_single_vm_fingerprint_requires_bisection_on_mismatch";
      }
      {
        label = "misaligned bisection rejection";
        needle = "gate_single_vm_fingerprint_rejects_misaligned_bisection_report";
      }
      {
        label = "final mismatch horizon localization";
        needle = "gate_single_vm_fingerprint_reports_final_mismatch_at_horizon";
      }
      {
        label = "definition drift rejection";
        needle = "gate_single_vm_fingerprint_rejects_definition_drift";
      }
      {
        label = "backend failure handling";
        needle = "gate_single_vm_fingerprint_surfaces_backend_failure_without_extra_runs";
      }
      {
        label = "truncated stream rejection";
        needle = "gate_single_vm_fingerprint_rejects_truncated_backend_streams";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs" qemuGateTest [
      {
        label = "ignored placeholder target";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-s1.nix" phase0S1 [
      {
        label = "real-QEMU coarse mismatch localization";
        needle = "localization_result=coarse-trace-sample-window";
      }
      {
        label = "real-QEMU first differing sample icount";
        needle = "coarse_first_different_sample_icount=";
      }
      {
        label = "real-QEMU left stream emitted on mismatch";
        needle = "cat \"$TMPDIR/trace-a-cadence.jsonl\" >&2";
      }
      {
        label = "real-QEMU right stream emitted on mismatch";
        needle = "cat \"$TMPDIR/trace-b-cadence.jsonl\" >&2";
      }
      {
        label = "real-QEMU coarse trace evidence";
        needle = "coarse_trace_evidence=trace-a-cadence.jsonl,trace-b-cadence.jsonl";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" qemuTracePlugin [
      {
        label = "icount retired counter";
        needle = "static uint64_t retired;";
      }
      {
        label = "icount cadence observer trigger";
        needle = "const bool periodic_due = current_icount >= next_sample;";
      }
      {
        label = "cadence advances by instruction period";
        needle = "next_sample += cadence;";
      }
      {
        label = "stop-at horizon icount trigger";
        needle = "reached_stop = stop_at != 0 && retired >= stop_at && !stop_requested;";
      }
      {
        label = "stop-at horizon event sample";
        needle = "if (reached_stop)";
      }
      {
        label = "architectural register digest summary";
        needle = "struct register_digest_summary";
      }
      {
        label = "canonical batched vCPU register reader";
        needle = "qemu_plugin_read_vcpu_regs(";
      }
      {
        label = "writable guest RAM cryptographic digest";
        needle = "qemu_plugin_crucible_guest_ram_sha256(ram_digest, &ram_bytes)";
      }
      {
        label = "register digests folded into diagnostic fingerprint";
        needle = "diagnostic_register_fnv(&register_digests)";
      }
      {
        label = "RAM digest folded into diagnostic fingerprint";
        needle = "fnv1a_bytes(diagnostic_extended_fnv, ram_digest, 32)";
      }
      {
        label = "current device-state digest folded into diagnostic fingerprint";
        needle = "fnv1a_bytes(diagnostic_extended_fnv, device_state.digest, 32)";
      }
      {
        label = "current device-state byte count folded into diagnostic fingerprint";
        needle = "fnv1a_u64(diagnostic_extended_fnv, device_state.bytes)";
      }
      {
        label = "per-vCPU register digests in samples";
        needle = "register_digests";
      }
      {
        label = "RAM digest in samples";
        needle = "ram_digest";
      }
      {
        label = "memory event callback";
        needle = "qemu_plugin_register_vcpu_mem_cb";
      }
      {
        label = "register-readable instruction callback";
        needle = "qemu_plugin_register_vcpu_insn_exec_cb(\n        qinsn, on_insn, QEMU_PLUGIN_CB_R_REGS, insn);";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/crucible-qemu-trace-plugin.c" qemuTracePlugin [
      {
        label = "instruction callback that hides architectural register reads";
        needle = "qemu_plugin_register_vcpu_insn_exec_cb(\n        qinsn, on_insn, QEMU_PLUGIN_CB_NO_REGS, insn);";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "Crucible model gate target";
        needle = "gate: \"gate:single-vm-fingerprint\",\n        package: \"crucible\",\n        test_target: \"gate_single_vm_fingerprint\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
      {
        label = "Crucible model target feature";
        needle = "required_features: &[\"test-double\"]";
      }
      {
        label = "QEMU gate target";
        needle = "package: \"crucible-qemu\"";
      }
      {
        label = "implemented QEMU gate target";
        needle = "placeholder: false";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented canonical gate status";
        needle = "name: \"gate:single-vm-fingerprint\",\n        phase: GatePhase::Phase1,\n        owner: \"crucible-qemu\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented model gate target in Nix lint";
        needle = "gate = \"gate:single-vm-fingerprint\";\n      package = \"crucible\";\n      testTarget = \"gate_single_vm_fingerprint\";\n      requiredFeatures = [\"test-double\"];\n      placeholder = false;";
      }
      {
        label = "implemented QEMU gate target in Nix lint";
        needle = "placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=0";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes single VM fingerprint check";
        needle = "singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix";
      }
      {
        label = "phase1 gate no longer uses red placeholder";
        needle = "attrPath = \"checks.crucible.phase1.gates.singleVmFingerprint\"";
      }
      {
        label = "phase2 real-QEMU gate no longer uses red placeholder";
        needle = "attrPath = \"checks.crucible.phase2.gates.singleVmFingerprint\"";
      }
      {
        label = "phase1 gate lists T-ASRT-18";
        needle = "\"T-ASRT-18\"";
      }
      {
        label = "phase1 gate lists T-DET-9";
        needle = "\"T-DET-9\"";
      }
      {
        label = "phase1 gate lists T-EXEC-17";
        needle = "\"T-EXEC-17\"";
      }
      {
        label = "phase1 gate lists T-EXEC-18";
        needle = "\"T-EXEC-18\"";
      }
      {
        label = "phase1 gate lists T-PAT-9";
        needle = "\"T-PAT-9\"";
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 single-VM fingerprint red placeholder";
        needle = "single-VM fingerprint gate is intentionally pending";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionProperties [
      {
        label = "T-ASRT-18 names single-VM fingerprint gate";
        needle = "`checks.crucible.phase1.gates.singleVmFingerprint`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" crucibleTrigger [
      {
        label = "proximity report type";
        needle = "pub struct HostAssertionProximity";
      }
      {
        label = "proximity is report projection";
        needle = "proximities: Vec<HostAssertionProximity>";
      }
      {
        label = "verdict construction ignores proximity";
        needle = "verdict: AssertionRunVerdict::failed(failures)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_proximity_gradient.rs" assertionProximityTest [
      {
        label = "proximity verdict non-effect";
        needle = "proximity_gradient_tracks_armed_eventually_without_changing_verdict";
      }
      {
        label = "proximity omitted after satisfaction";
        needle = "proximity_gradient_omits_satisfied_and_never_triggered_obligations";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-6 checklist entry";
        needle = "**T-HARN-6**";
      }
      {
        label = "T-HARN-7 checklist entry";
        needle = "**T-HARN-7**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" executionModel [
      {
        label = "T-EXEC-17 completion note";
        needle = "Completed by `crates/crucible/tests/gate_single_vm_fingerprint.rs`";
      }
      {
        label = "T-EXEC-18 completion note";
        needle = "gate_single_vm_fingerprint_model_determinism_survives_adversarial_host_profiles";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-9 completion names same-configuration fingerprint gate";
        needle = "same-configuration-twice";
      }
      {
        label = "T-PAT-9 completion names replay-oracle probe";
        needle = "snapshot-completeness";
      }
      {
        label = "T-PAT-9 completion names single VM fingerprint gate";
        needle = "`checks.crucible.phase1.gates.singleVmFingerprint`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 single-VM fingerprint gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-single-vm-fingerprint-gate";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.grep
          pkgs.rust
          pkgs.sed
          s1Fingerprint
        ]
        ++ dependencies;

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
          name = "run-model-single-vm-fingerprint";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-model-single-vm-fingerprint-target" \
              -p crucible \
              --features test-double \
              --test assertion_proximity_gradient \
              --test gate_single_vm_fingerprint \
              -- --test-threads=1
          '';
        }
        {
          name = "record-single-vm-fingerprint-gate";
          script = ''
            set -eu
            mkdir -p "$out"

            s1_result="${s1Fingerprint}/result"
            require_fixed() {
              needle="$1"
              grep -F "$needle" "$s1_result" >/dev/null || {
                echo "missing S1 evidence: $needle" >&2
                cat "$s1_result" >&2
                exit 1
              }
            }
            require_regex() {
              regex="$1"
              grep -E "$regex" "$s1_result" >/dev/null || {
                echo "missing S1 evidence matching regex: $regex" >&2
                cat "$s1_result" >&2
                exit 1
              }
            }

            require_fixed "PASS"
            require_fixed "spike=single-vm-fingerprint"
            require_fixed "scenario=stock-linux-diskless-initramfs-workload"
            require_fixed "host_adversary=jitter-load"
            require_fixed "samples=36"
            require_fixed "horizon_icount=3600000000"
            require_fixed "extended_fingerprint_match=true"
            require_fixed "aggregate_icount_stream_match=true"
            require_fixed "cadence_fingerprint_match=true"
            require_fixed "horizon_fingerprint_match=true"
            require_fixed "plugin_exit_fingerprint_compared=true"
            require_fixed "plugin_exit_device_state_comparison=diagnostic_not_gated"
            require_fixed "mismatch_localization=component"
            require_fixed "first_differing_line=none"
            require_fixed "first_differing_component=none"
            require_fixed "register_read_failures=0"
            require_fixed "register_count_assertion=nonempty_single_vcpu"
            require_fixed "device_event_capture=true"
            require_regex "^horizon_register_hash=[0-9a-f]{64}$"
            require_regex "^horizon_ram_hash=[0-9a-f]{64}$"
            require_regex "^horizon_ram_bytes=[1-9][0-9]*$"
            require_regex "^horizon_memory_events=[1-9][0-9]*$"
            require_regex "^horizon_io_events=[1-9][0-9]*$"

            cp "$s1_result" "$out/s1-result"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:single-vm-fingerprint
            tasks=${builtins.concatStringsSep "," taskIds}
            gate_target=crucible-qemu::gate_single_vm_fingerprint
            model_gate_target=crucible::gate_single_vm_fingerprint
            model_validator=same-configuration-twice
            model_probes=start,resume,fork,snapshot-completeness
            pattern_PAT_11=start-resume-fork-equality
            model_adversarial_profiles=quiet-single-core,loaded-single-core,reordered-two-core,loaded-many-core
            model_adversarial_dimensions=host-load,task-reordering,varied-core-counts
            real_qemu_source=checks.crucible.phase0.s1Fingerprint
            run_model=run-twice-and-diff
            scenario=stock-linux-diskless-initramfs-workload
            host_adversary=jitter-load
            samples=36
            horizon_icount=3600000000
            execution_fingerprint=icount-registers-ram
            sampling_axis=icount
            sampling_period_instructions=100000000
            observation_mode=plugin-read-only
            plugin_exit_device_state_comparison=diagnostic_not_gated
            register_fingerprint=architectural-register-file
            memory_fingerprint=guest-ram-hash
            assertion_proximity_fingerprint=report-only-no-verdict-effect
            rolling_fingerprint=extended-hash-over-samples
            register_read_failures=0
            ram_bytes=nonzero
            mismatch_policy=first-mismatch-is-failure
            bisection_result=required-on-mismatch
            mismatch_output=streams-and-bisection-result
            RESULT
          '';
        }
      ];
    }
