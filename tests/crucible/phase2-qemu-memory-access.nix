{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0050-crucible-memory-access-faults.patch",
  attrPath ? "checks.crucible.phase2.qemuMemoryAccess",
  taskIds ? ["T-QEMU-0050"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "live memory-access rule engine";
        needle = "qemu_crucible_fault_memory_access";
      }
      {
        label = "identified virtio DMA";
        needle = "crucible_dma_identity";
      }
      {
        label = "live test plugin";
        needle = "CRUCIBLE_MEMORY_ACCESS_LIVE_PASS";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "host sleeps as modeled latency";
        needle = "g_usleep";
      }
      {
        label = "debug memory shortcut";
        needle = "cpu_memory_rw_debug";
      }
    ];
  pluginSource = pkgs.mkDerivation {
    pname = "crucible-qemu-memory-access-plugin-source";
    version = "0";
    src = qemuPackage.src;
    buildDeps = [pkgs.coreutils pkgs.patch pkgs.tar pkgs.xz];
    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          tar -xf "$src"
          cd qemu-${series.qemuVersion}
        '';
      }
      {
        name = "apply-series";
        script = ''
          set -eu
          for patch_file in ${builtins.concatStringsSep " " series.patchFiles}; do
            patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/$patch_file"
          done
        '';
      }
      {
        name = "install";
        script = ''
          set -eu
          mkdir -p "$out"
          install -m 644 tests/tcg/plugins/crucible-memory-access.c "$out/"
        '';
      }
    ];
  };
in
  if failures != []
  then throw "Crucible live QEMU memory-access microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-memory-access";
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
        referenceQemu
      ];
      phases = [
        {
          name = "build-live-fixtures";
          script = ''
            set -eu
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${pluginSource}/crucible-memory-access.c \
              -o crucible-memory-access.so \
              $(pkg-config --libs glib-2.0)
            as --32 ${./phase2-qemu-memory-access-guest.S} -o guest-x86.o
            ld -m elf_i386 -T ${./phase2-qemu-memory-access-guest.ld} \
              guest-x86.o -o guest-x86.elf
            ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
              -c ${./phase2-qemu-memory-access-guest-aarch64.S} \
              -o guest-aarch64.o
            ${pkgs.llvm}/bin/ld.lld \
              -T ${./phase2-qemu-memory-access-guest-aarch64.ld} \
              guest-aarch64.o -o guest-aarch64.elf
          '';
        }
        {
          name = "run-live-matrix";
          script = ''
            set -eu
            mkdir -p logs
            run_case() {
              architecture="$1"
              case "$architecture" in
                x86_64)
                  binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine='-machine pc -m 64M'
                  guest=guest-x86.elf
                  address=0x102000
                  result=0x102001
                  ;;
                aarch64)
                  binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine='-machine virt -cpu max -m 64M'
                  guest=guest-aarch64.elf
                  address=0x40300000
                  result=0x40300001
                  ;;
                *) exit 1 ;;
              esac
              timeout 120 $binary $machine -accel sim -icount shift=0 \
                -smp 1 -nographic -no-reboot -serial none -monitor none \
                -kernel "$guest" \
                -plugin "$PWD/crucible-memory-access.so,address=$address,result=$result,expected=0xa5,kind=1,classes=2,length=1" \
                >"logs/$architecture.log" 2>&1
              cat "logs/$architecture.log"
              grep -Fxq CRUCIBLE_MEMORY_ACCESS_LIVE_PASS \
                "logs/$architecture.log"
              test "$(grep -Fc CRUCIBLE_MEMORY_ACCESS_LIVE_PASS \
                "logs/$architecture.log")" -eq 1
            }
            run_case x86_64
            run_case aarch64

            set +e
            timeout 5 ${referenceQemu}/bin/qemu-system-x86_64 \
              -machine pc -m 64M -accel tcg -icount shift=0 -smp 1 \
              -nographic -no-reboot -serial none -monitor none \
              -kernel guest-x86.elf \
              -plugin "$PWD/crucible-memory-access.so,address=0x102000,result=0x102001,expected=0xa5,kind=1,classes=2,length=1" \
              >logs/stock.log 2>&1
            stock_status=$?
            set -e
            test "$stock_status" -ne 0
            test "$stock_status" -ne 124
            ! grep -q CRUCIBLE_MEMORY_ACCESS_LIVE_PASS logs/stock.log

            mkdir -p "$out"
            cp -R logs "$out/"
            {
              printf 'PASS\n'
              printf 'gate=gate:patch-microtests\n'
              printf 'patch=%s\n' '${patchName}'
              printf 'attr_path=%s\n' '${attrPath}'
              printf 'task_ids=%s\n' '${taskList}'
              printf 'backend=actual-patched-and-stock-qemu\n'
              printf 'architectures=x86_64,aarch64\n'
            } >"$out/result"
          '';
        }
      ];
    }
