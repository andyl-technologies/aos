{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginQuantumSmp",
  taskIds ? ["T-PLUG-24"],
}: let
  smpGuest = import ./phase2-qemu-live-plugin-quantum-smp-guest.nix {inherit pkgs;};
  liveQuantumSmp = import ./phase2-qemu-live-plugin-quantum.nix {
    inherit pkgs lib;
    attrPath = "${attrPath}.live";
    taskIds = [];
    openTaskIds = [];
    smpVcpus = "4";
    memoryMib = "64";
    maxSearch = "80000000";
    idleHorizonMargin = "80000000";
    customGuestKernel = "${smpGuest}/smp-idle-guest.elf";
  };

  pluginDoc = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  idlePatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0025-crucible-sim-idle-callbacks.patch;
  smpGuestSource = builtins.readFile ./phase2-qemu-live-plugin-quantum-smp-guest.nix;
  quantumGate = builtins.readFile ./phase2-qemu-live-plugin-quantum.nix;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginDoc [
      {
        label = "live SMP idle completion gate";
        needle = "checks.crucible.phase2.qemuLivePluginQuantumSmp";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0025-crucible-sim-idle-callbacks.patch" idlePatch [
      {
        label = "all-vCPU idle predicate";
        needle = "rr_crucible_sim_all_vcpus_halted";
      }
      {
        label = "all-idle callback dispatch";
        needle = "qemu_plugin_maybe_fire_vcpu_idle_cb(cpu);";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-live-plugin-quantum-smp-guest.nix" smpGuestSource [
      {
        label = "directed AP startup";
        needle = "directed-init-sipi-sipi";
      }
      {
        label = "all-vCPU HLT workload";
        needle = "guest_idle=all-vcpus-hlt";
      }
      {
        label = "live PIT deadline";
        needle = "guest_deadline=periodic-pit-channel-0";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-live-plugin-quantum.nix" quantumGate [
      {
        label = "SMP vCPU launch control";
        needle = "CRUCIBLE_QUANTUM_SMP_VCPUS = smpVcpus;";
      }
      {
        label = "all-vCPUs-halted live result assertion";
        needle = "all_vcpus_halted_idle_observed=true";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "live SMP quantum gate import";
        needle = "qemuLivePluginQuantumSmp = import ./phase2-qemu-live-plugin-quantum-smp.nix";
      }
    ];
in
  if failures != []
  then throw "crucible live SMP plugin quantum check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-live-plugin-quantum-smp";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        liveQuantumSmp
      ];

      phases = [
        {
          name = "run-live-smp-plugin-quantum";
          script = ''
            set -eu
            grep -Fxq PASS ${liveQuantumSmp}/result
            grep -Fxq 'smp_vcpus=4' ${liveQuantumSmp}/result
            grep -Fxq 'memory_mib=64' ${liveQuantumSmp}/result
            grep -Fxq 'all_vcpus_halted_idle_observed=true' ${liveQuantumSmp}/result
            grep -Fxq 'idle_kind=timer-deadline' ${liveQuantumSmp}/result
            grep -Fxq 'idle_jump_proven=true' ${liveQuantumSmp}/result
            grep -Fxq 'deterministic_under_host_load=true' ${liveQuantumSmp}/result
            grep -Fxq 'sim_double_schedule_matches=true' ${liveQuantumSmp}/result

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            live_backend=qemu-system-x86_64
            smp_vcpus=4
            memory_mib=64
            rr_subdivision=fixed-quantum-ascending
            all_vcpus_halted_idle_observed=true
            idle_wake=minimum-live-timer-deadline
            deterministic_under_host_load=true
            RESULT
          '';
        }
      ];
    }
