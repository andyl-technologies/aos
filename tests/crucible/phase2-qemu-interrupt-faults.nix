{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0053-crucible-interrupt-faults.patch",
  attrPath ? "checks.crucible.phase2.qemuInterruptFaults",
  taskIds ? ["T-QEMU-0053"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "realized interrupt manifest";
        needle = "qemu_plugin_crucible_fault_interrupt_manifest";
      }
      {
        label = "transactional interrupt interceptor";
        needle = "qemu_crucible_fault_interrupt_intercept";
      }
      {
        label = "controller route validation";
        needle = "qemu_crucible_fault_interrupt_register_route_validator";
      }
      {
        label = "bounded deferred interrupt queue";
        needle = "CRUCIBLE_INTERRUPT_DEFERRED_CAPACITY";
      }
      {
        label = "bounded provenance state";
        needle = "CRUCIBLE_INTERRUPT_PROVENANCE_CAPACITY";
      }
      {
        label = "finite storm execution";
        needle = "crucible_interrupt_storm_cb";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "test-double interrupt backend";
        needle = "CRUCIBLE_TEST_DOUBLE";
      }
    ];
in
  if failures != []
  then throw "Crucible QEMU interrupt-fault microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-interrupt-faults";
      version = "0";
      src = null;
      buildDeps = [
        pkgs.binutils
        pkgs.coreutils
        pkgs.glib
        pkgs.grep
        pkgs.llvm
        pkgs.pkg-config
        qemuPackage
      ];
      phases = [
        {
          name = "build-live-probe";
          script = ''
            set -eu
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-interrupt-manifest.c} \
              -o crucible-interrupt-manifest.so \
              $(pkg-config --libs glib-2.0)
            as --32 ${./phase2-qemu-fault-guest.S} \
              -o interrupt-guest-x86.o
            ld -m elf_i386 -T ${./phase2-qemu-fault-guest.ld} \
              interrupt-guest-x86.o -o interrupt-guest-x86.elf
            ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
              -c ${./phase2-qemu-fault-guest-aarch64.S} \
              -o interrupt-guest-aarch64.o
            ${pkgs.llvm}/bin/ld.lld \
              -T ${./phase2-qemu-fault-guest-aarch64.ld} \
              interrupt-guest-aarch64.o \
              -o interrupt-guest-aarch64.elf
          '';
        }
        {
          name = "run-realized-controller-manifests";
          script = ''
            set -eu
            mkdir -p logs
            run_manifest() {
              architecture="$1"
              architecture_id="$2"
              qemu_binary="$3"
              machine_args="$4"
              guest="$5"
              set +e
              timeout 30 "$qemu_binary" \
                $machine_args \
                -accel sim \
                -icount shift=0,rr_switch_quantum=256 \
                -smp 1 \
                -nographic \
                -no-reboot \
                -serial none \
                -monitor none \
                -kernel "$guest" \
                -plugin "$PWD/crucible-interrupt-manifest.so,architecture=$architecture_id" \
                > "logs/$architecture.log" 2>&1
              status=$?
              set -e
              cat "logs/$architecture.log"
              test "$status" -eq 0
              grep -Fq \
                "CRUCIBLE_INTERRUPT_MANIFEST_LIVE_PASS architecture=$architecture_id" \
                "logs/$architecture.log"
              ! grep -Fq CRUCIBLE_INTERRUPT_MANIFEST_LIVE_FAIL \
                "logs/$architecture.log"
            }
            run_manifest x86_64 2 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              '-machine pc -m 64M' \
              interrupt-guest-x86.elf
            run_manifest aarch64 3 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              '-machine virt,gic-version=3 -cpu max -m 64M' \
              interrupt-guest-aarch64.elf
            mkdir -p "$out"
            {
              printf 'PASS\n'
              printf 'check=%s\n' '${attrPath}'
              printf 'tasks=%s\n' '${taskList}'
              printf 'live_architectures=x86_64,aarch64\n'
              printf 'backend=patched-qemu-realized-controllers\n'
              printf 'test_double=false\n'
            } > "$out/result"
          '';
        }
      ];
    }
