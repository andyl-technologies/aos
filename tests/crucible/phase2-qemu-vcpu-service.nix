{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0055-crucible-vcpu-service-control.patch",
  attrPath ? "checks.crucible.phase2.qemuVcpuService",
  taskIds ? ["T-QEMU-0055"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "live RR service-budget clamp";
        needle = "qemu_crucible_fault_vcpu_service_clamp_budget";
      }
      {
        label = "checked instruction-to-virtual-time conversion";
        needle = "icount_crucible_instructions_to_ns";
      }
      {
        label = "bounded work-conserving donation ledger";
        needle = "donated_credit";
      }
      {
        label = "fixed-topology scheduler eligibility";
        needle = "qemu_crucible_fault_vcpu_service_eligible";
      }
      {
        label = "reserved state-transition evidence";
        needle = "CRUCVST1";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "host sleep throttle";
        needle = "g_usleep";
      }
      {
        label = "host scheduler throttle";
        needle = "setpriority";
      }
      {
        label = "host control-group throttle";
        needle = "cgroup";
      }
    ];
in
  if failures != []
  then throw "Crucible QEMU vCPU-service microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-vcpu-service";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils qemuPackage];
      phases = [
        {
          name = "verify-built-backend";
          script = ''
            set -eu
            test -x ${qemuPackage}/bin/qemu-system-x86_64
            test -x ${qemuPackage}/bin/qemu-system-aarch64
            mkdir -p "$out"
            {
              printf 'PASS\n'
              printf 'check=%s\n' '${attrPath}'
              printf 'tasks=%s\n' '${taskList}'
              printf 'architectures=x86_64,aarch64\n'
              printf 'test_double=false\n'
            } > "$out/result"
          '';
        }
      ];
    }
