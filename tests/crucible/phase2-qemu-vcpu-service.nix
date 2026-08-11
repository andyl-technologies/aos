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
      {
        label = "partial-window configuration-change evidence";
        needle = "configuration_interrupted";
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
      buildDeps = [
        pkgs.binutils
        pkgs.coreutils
        pkgs.glib
        pkgs.llvm
        pkgs.pkg-config
        qemuPackage
      ];
      phases = [
        {
          name = "build-live-fixtures";
          script = ''
            set -eu
            test -x ${qemuPackage}/bin/qemu-system-x86_64
            test -x ${qemuPackage}/bin/qemu-system-aarch64
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-vcpu-service.c} \
              -o crucible-vcpu-service.so \
              $(pkg-config --libs glib-2.0)
            as --32 ${./phase2-qemu-fault-guest.S} -o fault-guest-x86.o
            ld -m elf_i386 -T ${./phase2-qemu-fault-guest.ld} \
              fault-guest-x86.o -o fault-guest-x86.elf
            ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
              -c ${./phase2-qemu-fault-guest-aarch64.S} \
              -o fault-guest-aarch64.o
            ${pkgs.llvm}/bin/ld.lld \
              -T ${./phase2-qemu-fault-guest-aarch64.ld} \
              fault-guest-aarch64.o -o fault-guest-aarch64.elf
          '';
        }
        {
          name = "run-live-service-trajectories";
          script = ''
            set -eu
            mkdir -p logs
            run_service() {
              architecture="$1"
              architecture_id="$2"
              numerator="$3"
              denominator="$4"
              case "$architecture" in
                x86_64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine_args='-machine pc -m 64M'
                  guest=fault-guest-x86.elf
                  ;;
                aarch64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine_args='-machine virt -cpu max -m 64M'
                  guest=fault-guest-aarch64.elf
                  ;;
                *)
                  echo "unknown architecture: $architecture" >&2
                  exit 1
                  ;;
              esac
              log="logs/$architecture-$numerator-$denominator.log"
              timeout 120 "$qemu_binary" \
                $machine_args \
                -accel sim \
                -icount shift=0,rr_switch_quantum=256 \
                -smp 1 \
                -nographic \
                -no-reboot \
                -serial none \
                -monitor none \
                -kernel "$guest" \
                -plugin "$PWD/crucible-vcpu-service.so,architecture=$architecture_id,numerator=$numerator,denominator=$denominator,quantum=96,windows=6" \
                > "$log" 2>&1
              cat "$log"
              grep -Fq \
                "CRUCIBLE_VCPU_SERVICE_LIVE_PASS architecture=$architecture_id ratio=$numerator/$denominator quantum=96 windows=6" \
                "$log"
              test "$(grep -Fc CRUCIBLE_VCPU_SERVICE_LIVE_PASS "$log")" -eq 1
              ! grep -Fq 'Crucible vCPU service live test failed' "$log"
            }

            for ratio in 1/1 1/2 1/3; do
              numerator="''${ratio%/*}"
              denominator="''${ratio#*/}"
              run_service x86_64 2 "$numerator" "$denominator"
              run_service aarch64 3 "$numerator" "$denominator"
            done
          '';
        }
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out"
            cp -R logs "$out/"
            {
              printf 'PASS\n'
              printf 'check=%s\n' '${attrPath}'
              printf 'tasks=%s\n' '${taskList}'
              printf 'architectures=x86_64,aarch64\n'
              printf 'test_double=false\n'
              printf 'backend=actual-patched-qemu\n'
              printf 'live_ratios=1/1,1/2,1/3\n'
              printf 'live_windows_per_case=6\n'
            } > "$out/result"
          '';
        }
      ];
    }
