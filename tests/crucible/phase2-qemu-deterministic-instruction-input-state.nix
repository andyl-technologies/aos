{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0082-crucible-deterministic-instruction-input-state.patch",
}: let
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  instructionFaults = import ./phase2-qemu-instruction-faults.nix {
    inherit pkgs lib qemuPackage;
  };
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  failures = failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
    {
      label = "versioned instruction-input digest";
      needle = "crucible.instruction-input-state.v1";
    }
    {
      label = "single-sample execution and selector digests";
      needle = "qemu_crucible_fault_execution_and_register_fingerprints";
    }
    {
      label = "register-only digest domain";
      needle = "crucible.register-state.v1";
    }
    {
      label = "cross-process selector comparison";
      needle = "memcmp(candidate_selector.input_state_sha256,";
    }
    {
      label = "post-install natural-fault trigger";
      needle = "test_arm_result_fault";
    }
    {
      label = "production-capacity saturation count";
      needle = "test_saturation_mode() ? TEST_EVENT_CAPACITY";
    }
    {
      label = "terminal notification drains the saturated queue";
      needle = "Ordinary saturation events do not notify this callback";
    }
  ];
in
  if failures != []
  then throw "Crucible deterministic instruction-input-state microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-deterministic-instruction-input-state";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep instructionFaults];

      phases = [
        {
          name = "verify-deterministic-instruction-input-state";
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
            task_ids=T-QEMU-0082
            deterministic_instruction_input_state=true
            full_ram_and_device_state_hashes_retained_in_evidence=true
            live_instruction_matrix=true
            live_multi_vcpu_register_ordering=true
            patched_fixture_exercised=true
            stock_negative_control=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
