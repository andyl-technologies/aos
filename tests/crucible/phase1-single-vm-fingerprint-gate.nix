{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.singleVmFingerprint",
  taskIds ? ["T-HARN-6" "T-HARN-7" "T-DET-9"],
}: let
  s1Fingerprint = import ./phase0-s1.nix {
    inherit pkgs lib;
  };

  phase0S1 = builtins.readFile ./phase0-s1.nix;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuGateRoot = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint.rs;
  qemuGateCompare = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/compare.rs;
  qemuGateRun = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/run.rs;
  qemuGateTypes = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/types.rs;
  qemuGateHook = qemuGateRoot + qemuGateCompare + qemuGateRun + qemuGateTypes;
  qemuGateTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs;
  qemuTracePlugin = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
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
        label = "private bisection report constructor";
        needle = "pub fn state_dump_artifact(&self) -> &str";
      }
      {
        label = "backend bisection hook";
        needle = "fn bisect_single_vm_fingerprint_mismatch";
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
        label = "real-QEMU mismatch bisection result";
        needle = "bisection_result=trace-sample-bisection";
      }
      {
        label = "real-QEMU first differing sample icount";
        needle = "first_different_sample_icount=";
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
        label = "real-QEMU state dump artifact";
        needle = "state_dump_artifact=trace-a-cadence.jsonl,trace-b-cadence.jsonl";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" qemuTracePlugin [
      {
        label = "icount retired counter";
        needle = "static uint64_t retired;";
      }
      {
        label = "icount cadence sample trigger";
        needle = "if (retired >= next_sample)";
      }
      {
        label = "cadence advances by instruction period";
        needle = "next_sample += cadence;";
      }
      {
        label = "stop-at horizon icount trigger";
        needle = "if (stop_at != 0 && retired >= stop_at";
      }
      {
        label = "architectural register hash summary";
        needle = "struct register_hash_summary";
      }
      {
        label = "vCPU register reader";
        needle = "qemu_plugin_crucible_read_vcpu_register";
      }
      {
        label = "guest RAM hash";
        needle = "qemu_plugin_crucible_ram_hash(&ram_bytes)";
      }
      {
        label = "register hash folded into rolling fingerprint";
        needle = "extended_hash = fnv1a_u64(extended_hash, register_hashes.aggregate);";
      }
      {
        label = "RAM hash folded into rolling fingerprint";
        needle = "extended_hash = fnv1a_u64(extended_hash, ram_hash);";
      }
      {
        label = "per-vCPU register hashes in samples";
        needle = "register_hashes";
      }
      {
        label = "RAM hash in samples";
        needle = "ram_hash";
      }
      {
        label = "memory event callback";
        needle = "qemu_plugin_register_vcpu_mem_cb";
      }
      {
        label = "read-only instruction callback";
        needle = "QEMU_PLUGIN_CB_NO_REGS";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
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
        label = "implemented QEMU gate target in Nix lint";
        needle = "placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=15";
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
        label = "phase1 gate lists T-HARN-6";
        needle = "\"T-HARN-6\"";
      }
      {
        label = "phase1 gate lists T-DET-9";
        needle = "\"T-DET-9\"";
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 single-VM fingerprint red placeholder";
        needle = "single-VM fingerprint gate is intentionally pending";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-9 checklist complete";
        needle = "- [x] **T-DET-9**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-6 checklist complete";
        needle = "- [x] **T-HARN-6**";
      }
      {
        label = "T-HARN-7 checklist complete";
        needle = "- [x] **T-HARN-7**";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 single-VM fingerprint gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-single-vm-fingerprint-gate";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        s1Fingerprint
      ];

      phases = [
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
            require_fixed "samples=32"
            require_fixed "horizon_icount=3200000000"
            require_fixed "extended_fingerprint_match=true"
            require_fixed "aggregate_icount_stream_match=true"
            require_fixed "cadence_fingerprint_match=true"
            require_fixed "horizon_fingerprint_match=true"
            require_fixed "plugin_exit_fingerprint_compared=true"
            require_fixed "mismatch_localization=component"
            require_fixed "first_differing_line=none"
            require_fixed "first_differing_component=none"
            require_fixed "register_read_failures=0"
            require_fixed "register_count_assertion=nonempty_single_vcpu"
            require_fixed "device_event_capture=true"
            require_regex "^horizon_register_hash=[0-9a-f]{16}$"
            require_regex "^horizon_ram_hash=[0-9a-f]{16}$"
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
            real_qemu_source=checks.crucible.phase0.s1Fingerprint
            run_model=run-twice-and-diff
            scenario=stock-linux-diskless-initramfs-workload
            host_adversary=jitter-load
            samples=32
            horizon_icount=3200000000
            execution_fingerprint=icount-registers-ram
            sampling_axis=icount
            sampling_period_instructions=100000000
            observation_mode=plugin-read-only
            register_fingerprint=architectural-register-file
            memory_fingerprint=guest-ram-hash
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
