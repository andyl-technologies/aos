{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.singleVmFingerprint",
  taskIds ? ["T-DET-9"],
}: let
  s1Fingerprint = import ./phase0-s1.nix {
    inherit pkgs lib;
  };

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuGateRoot = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint.rs;
  qemuGateCompare = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/compare.rs;
  qemuGateRun = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/run.rs;
  qemuGateTypes = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/types.rs;
  qemuGateHook = qemuGateRoot + qemuGateCompare + qemuGateRun + qemuGateTypes;
  qemuGateTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;

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
        needle = "placeholder_targets=24";
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
        label = "phase1 gate lists T-DET-9";
        needle = "\"T-DET-9\"";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-9 checklist complete";
        needle = "- [x] **T-DET-9**";
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
            mismatch_policy=first-mismatch-is-failure
            mismatch_output=streams-and-icount-window
            RESULT
          '';
        }
      ];
    }
