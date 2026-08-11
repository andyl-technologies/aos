{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0056-crucible-node-lifecycle-faults.patch",
  attrPath ? "checks.crucible.phase2.qemuNodeLifecycle",
  taskIds ? ["T-QEMU-0056"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "deferred native reset completion";
        needle = "qemu_crucible_fault_lifecycle_reset_complete";
      }
      {
        label = "writable volatile RAM treatment";
        needle = "crucible_lifecycle_clear_ram";
      }
      {
        label = "fixed-topology hang eligibility";
        needle = "qemu_crucible_fault_vcpu_hung";
      }
      {
        label = "lifecycle evidence format";
        needle = "CRUCLIF1";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "host sleep hang";
        needle = "g_usleep";
      }
      {
        label = "host signal-stop hang";
        needle = "SIGSTOP";
      }
    ];
in
  if failures != []
  then throw "Crucible QEMU node-lifecycle microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-node-lifecycle";
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
            "$CC" -shared -fPIC -Wall -Wextra -Werror \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-node-lifecycle.c} \
              -o crucible-node-lifecycle.so \
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
          name = "run-live-lifecycle-matrix";
          script = ''
            set -eu
            mkdir -p logs
            run_reset() {
              architecture="$1"
              architecture_id="$2"
              volatile_policy="$3"
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
              log="logs/$architecture-$volatile_policy.log"
              if ! timeout 120 "$qemu_binary" \
                  $machine_args \
                  -accel sim \
                  -icount shift=0,rr_switch_quantum=256 \
                  -smp 1 \
                  -nographic \
                  -serial none \
                  -monitor none \
                  -kernel "$guest" \
                  -plugin "$PWD/crucible-node-lifecycle.so,architecture=$architecture_id,volatile_policy=$volatile_policy" \
                  > "$log" 2>&1; then
                cat "$log" >&2
                return 1
              fi
              cat "$log"
              grep -Fq \
                "CRUCIBLE_NODE_LIFECYCLE_LIVE_PASS architecture=$architecture_id volatile_policy=$volatile_policy" \
                "$log"
              test "$(grep -Fc CRUCIBLE_NODE_LIFECYCLE_LIVE_PASS "$log")" -eq 1
            }

            for volatile_policy in 1 2; do
              run_reset x86_64 2 "$volatile_policy"
              run_reset aarch64 3 "$volatile_policy"
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
              printf 'volatile_policies=preserve,clear\n'
              printf 'device_policy=device_reset\n'
            } > "$out/result"
          '';
        }
      ];
    }
