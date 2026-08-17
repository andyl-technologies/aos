{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0081-crucible-deferred-result-evidence-test.patch",
}: let
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  instructionFaults = import ./phase2-qemu-instruction-faults.nix {
    inherit pkgs lib qemuPackage;
  };
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  failures = failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "typed deferred-result evidence validation";
        needle = "test_validate_rule_evidence(";
      }
      {
        label = "apply-operation evidence binding";
        needle = "CRUCIBLE_NODE_FAULT_OPERATION_APPLY";
      }
      {
        label = "composed second-command payload selection";
        needle = "test_compose_mode() && result.command_sequence == 4";
      }
      {
        label = "obsolete empty deferred-evidence assertion removal";
        needle = ''-                test_fail("deferred fault completion carried premature "'';
      }
    ];
in
  if failures != []
  then throw "Crucible deferred-result evidence microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-deferred-result-evidence";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        instructionFaults
      ];

      phases = [
        {
          name = "verify-deferred-result-evidence";
          script = ''
            set -eu

            mkdir -p "$out"
            cp "${instructionFaults}/result" "$out/live-instruction-faults.result"
            grep -Fxq PASS "$out/live-instruction-faults.result"
            grep -Fxq 'backend=actual-patched-and-stock-qemu' \
              "$out/live-instruction-faults.result"

            cat > "$out/result" <<RESULT
            PASS
            gate=gate:patch-microtests
            patch=${patchName}
            task_ids=T-QEMU-0081
            typed_deferred_result_evidence=true
            composed_payload_binding=true
            live_instruction_matrix=true
            qemu_package=${qemuPackage}
            RESULT
          '';
        }
      ];
    }
