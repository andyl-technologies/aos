{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuSingleVmFingerprint",
  taskIds ? ["T-QEMU-11"],
}: let
  singleVmFingerprint = import ./phase1-single-vm-fingerprint-gate.nix {
    inherit pkgs lib;
    attrPath = "${attrPath}.gate";
    taskIds = ["T-QEMU-11" "T-HARN-6" "T-HARN-7" "T-DET-9"];
  };

  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuGateRoot = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint.rs;
  qemuGateCompare = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/compare.rs;
  qemuGateRun = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/run.rs;
  qemuGateTypes = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/types.rs;
  qemuGateHook = qemuGateRoot + qemuGateCompare + qemuGateRun + qemuGateTypes;
  qemuGateTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs;

  taskList = builtins.concatStringsSep "," taskIds;

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

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "T-QEMU-11 checklist complete";
        needle = "- [x] **T-QEMU-11**";
      }
      {
        label = "QEMU-34 single-VM fingerprint requirement";
        needle = "**[QEMU-34]** The host MUST expose the single-VM fingerprint hook";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "single-VM fingerprint exports";
        needle = "run_single_vm_fingerprint_gate";
      }
      {
        label = "single-VM fingerprint runner export";
        needle = "SingleVmFingerprintRunner";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/single_vm_fingerprint*.rs" qemuGateHook [
      {
        label = "single-VM fingerprint runner trait";
        needle = "pub trait SingleVmFingerprintRunner";
      }
      {
        label = "run-twice gate driver";
        needle = "pub fn run_single_vm_fingerprint_gate";
      }
      {
        label = "fixed scenario digest";
        needle = "fingerprint_definition_digest";
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
        label = "canonical stream comparator";
        needle = "pub fn compare_single_vm_fingerprint_streams";
      }
      {
        label = "first mismatch localization";
        needle = "first_different_icount";
      }
      {
        label = "bisection hook";
        needle = "fn bisect_single_vm_fingerprint_mismatch";
      }
      {
        label = "diagnostic streams on mismatch";
        needle = "first_stream: Box<SingleVmFingerprintStream>";
      }
      {
        label = "bisection validation";
        needle = "validate_bisection_report_for_mismatch";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs" qemuGateTest [
      {
        label = "run twice test";
        needle = "gate_single_vm_fingerprint_runs_fixed_scenario_twice";
      }
      {
        label = "first sample localization test";
        needle = "gate_single_vm_fingerprint_reports_first_sample_window";
      }
      {
        label = "final horizon localization test";
        needle = "gate_single_vm_fingerprint_reports_final_mismatch_at_horizon";
      }
      {
        label = "definition drift test";
        needle = "gate_single_vm_fingerprint_rejects_definition_drift";
      }
      {
        label = "required bisection test";
        needle = "gate_single_vm_fingerprint_requires_bisection_on_mismatch";
      }
      {
        label = "misaligned bisection test";
        needle = "gate_single_vm_fingerprint_rejects_misaligned_bisection_report";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu single-VM fingerprint task check";
        needle = "qemuSingleVmFingerprint = import ./phase2-qemu-single-vm-fingerprint.nix";
      }
      {
        label = "phase2 gate remains wired to canonical single-VM fingerprint gate";
        needle = "attrPath = \"checks.crucible.phase2.gates.singleVmFingerprint\"";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu single-VM fingerprint check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-single-vm-fingerprint";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ];

      phases = [
        {
          name = "aggregate-qemu-single-vm-fingerprint";
          script = ''
            set -eu

            mkdir -p "$out"
            gate_result="${singleVmFingerprint}/result"

            grep -q '^PASS$' "$gate_result"
            grep -q '^gate=gate:single-vm-fingerprint$' "$gate_result"
            grep -q '^gate_target=crucible-qemu::gate_single_vm_fingerprint$' "$gate_result"
            grep -q '^real_qemu_source=checks.crucible.phase0.s1Fingerprint$' "$gate_result"
            grep -q '^run_model=run-twice-and-diff$' "$gate_result"
            grep -q '^host_adversary=jitter-load$' "$gate_result"
            grep -q '^execution_fingerprint=icount-registers-ram$' "$gate_result"
            grep -q '^mismatch_policy=first-mismatch-is-failure$' "$gate_result"
            grep -q '^bisection_result=required-on-mismatch$' "$gate_result"

            cp "$gate_result" "$out/single-vm-fingerprint.result"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:single-vm-fingerprint
            hook=crucible-qemu::run_single_vm_fingerprint_gate
            run_model=run-twice-and-diff
            host_adversary=jitter-load
            fingerprint_definition=content-addressed
            mismatch_policy=first-mismatch-is-failure
            bisection=required-on-mismatch
            real_qemu_source=checks.crucible.phase0.s1Fingerprint
            RESULT
          '';
        }
      ];
    }
