# Real runtime evidence for the QEMU 11 semantic compatibility patch.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  runtimePkgs = pkgs // {qemu-crucible = qemuPackage;};
  aarch64 = import ./phase0-aarch64-s1-s6.nix {
    pkgs = runtimePkgs;
    inherit lib;
  };
  hardwareErrors = import ./phase2-qemu-hardware-error-faults.nix {
    inherit pkgs lib qemuPackage;
  };
  rawState = import ./phase2-qemu-raw-state-export.nix {
    inherit pkgs lib qemuPackage;
  };
  vcpuService = import ./phase2-qemu-vcpu-service.nix {
    inherit pkgs lib qemuPackage;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-runtime-semantics";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep];
    phases = [
      {
        name = "verify-runtime-semantics";
        script = ''
          set -eu
          mkdir -p "$out"
          for evidence in ${aarch64} ${hardwareErrors} ${rawState} ${vcpuService}; do
            grep -Fxq PASS "$evidence/result"
          done

          grep -Fxq 'ordinary_tcg_aarch64_boot=true' ${aarch64}/result
          grep -Fxq 'extended_fingerprint_match=true' ${aarch64}/result
          grep -Fxq 'live_mutations=corrected-ecc,x86-mca,aarch64-ras' ${hardwareErrors}/result
          grep -Fxq 'vmstate_terminal_one_shot=true' ${rawState}/result
          grep -Fxq 'raw_state_export_passed=true' ${rawState}/result
          grep -Fxq 'architectures=x86_64,aarch64' ${vcpuService}/result

          cat > "$out/result" <<'RESULT'
          PASS
          ordinary_tcg_aarch64_boot=true
          seeded_aarch64_fingerprint=true
          aarch64_hardware_error_dispatch=true
          terminal_vmstate_stream_header=true
          vcpu_service_trajectories=true
          RESULT
        '';
      }
    ];
  }
