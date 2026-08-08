{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0050-crucible-memory-access-faults.patch",
  attrPath ? "checks.crucible.phase2.qemuMemoryAccess",
  taskIds ? ["T-QEMU-0050"],
  focus ? "",
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  dmaGuest = import ./phase2-qemu-live-block-io-guest.nix {inherit pkgs;};
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
          install -m 644 tests/tcg/plugins/crucible-memory-dma.c "$out/"
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
        pkgs.linux
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
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${pluginSource}/crucible-memory-dma.c \
              -o crucible-memory-dma.so \
              $(pkg-config --libs glib-2.0)
            for mode in $(seq 1 18); do
              ${pkgs.llvm}/bin/clang --target=i386-none-elf \
                -c -Wa,-defsym,TEST_MODE=$mode \
                ${./phase2-qemu-memory-access-guest.S} \
                -o "guest-x86-$mode.o"
              ${pkgs.llvm}/bin/ld.lld -m elf_i386 \
                -T ${./phase2-qemu-memory-access-guest.ld} \
                "guest-x86-$mode.o" -o "guest-x86-$mode.elf"
              ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
                -c -Wa,-defsym,TEST_MODE=$mode \
                ${./phase2-qemu-memory-access-guest-aarch64.S} \
                -o "guest-aarch64-$mode.o"
              ${pkgs.llvm}/bin/ld.lld \
                -T ${./phase2-qemu-memory-access-guest-aarch64.ld} \
                "guest-aarch64-$mode.o" -o "guest-aarch64-$mode.elf"
            done
          '';
        }
        {
          name = "run-live-matrix";
          script = ''
            set -eu
            mkdir -p logs
            focus='${focus}'
            should_run() {
              test -z "$focus" || test "$focus" = "$1"
            }
            run_case() {
              architecture="$1"
              mode="$2"
              kind="$3"
              classes="$4"
              length="$5"
              expected="$6"
              mask="$7"
              replacement="$8"
              atomic="$9"
              should_run "$architecture-base-$mode" || return 0
              case "$architecture" in
                x86_64)
                  binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine='-machine pc -cpu max -m 64M'
                  guest="guest-x86-$mode.elf"
                  case "$mode" in
                    1|4) address=0x102000; result=0x102100 ;;
                    2|5) address=0x102201; result=0x102300 ;;
                    3|6) address=0x102ffc; result=0x103100 ;;
                    7) address=0x109001; result=0x103400 ;;
                    *) address=0x103200; result=0x103300 ;;
                  esac
                  ;;
                aarch64)
                  binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine='-machine virt -cpu max -m 64M'
                  guest="guest-aarch64-$mode.elf"
                  case "$mode" in
                    1|4) address=0x40300000; result=0x40300100 ;;
                    2|5) address=0x40300201; result=0x40300300 ;;
                    3|6) address=0x40300ffc; result=0x40301100 ;;
                    7) address=0x40210000; result=0x40301400 ;;
                    *) address=0x40301200; result=0x40301300 ;;
                  esac
                  ;;
                *) exit 1 ;;
              esac
              set +e
              timeout 120 $binary $machine -accel sim -icount shift=0 \
                -smp 1 -nographic -no-reboot -serial none -monitor none \
                -kernel "$guest" \
                -plugin "$PWD/crucible-memory-access.so,address=$address,result=$result,expected=$expected,kind=$kind,classes=$classes,length=$length,mask=$mask,replacement=$replacement,atomic=$atomic" \
                >"logs/$architecture-$mode.log" 2>&1
              case_status=$?
              set -e
              cat "logs/$architecture-$mode.log"
              test "$case_status" -eq 0
              grep -Fxq CRUCIBLE_MEMORY_ACCESS_LIVE_PASS \
                "logs/$architecture-$mode.log"
              test "$(grep -Fc CRUCIBLE_MEMORY_ACCESS_LIVE_PASS \
                "logs/$architecture-$mode.log")" -eq 1
            }
            run_architecture_matrix() {
              architecture="$1"
              run_case "$architecture" 1 1 2 1 a5 ff a5 0
              run_case "$architecture" 2 2 2 4 a5a5a5a5 ffffffff none 0
              run_case "$architecture" 3 1 2 8 a5a5a5a5a5a5a5a5 \
                ffffffffffffffff a5a5a5a5a5a5a5a5 0
              run_case "$architecture" 4 1 4 4 3c3c3c3c ffffffff 3c3c3c3c 0
              run_case "$architecture" 5 3 4 4 5a5a5a5a none none 0
              run_case "$architecture" 6 4 4 8 a55aa55aa55aa55a none \
                ff00ff00ff00ff00 0
              if test "$architecture" = x86_64; then
                run_case "$architecture" 7 1 1 1 a5 ff a5 0
              else
                run_case "$architecture" 7 1 1 2 a5 ffff a014 0
              fi
              run_case "$architecture" 8 4 4 1 55 none 0f 1
              run_case "$architecture" 9 4 4 2 a55a none ff00 1
              run_case "$architecture" 10 4 4 4 a55aa55a none ff00ff00 1
              run_case "$architecture" 11 4 4 8 a55aa55aa55aa55a none \
                ff00ff00ff00ff00 1
              run_case "$architecture" 12 4 4 16 \
                a55aa55aa55aa55aa55aa55aa55aa55a none \
                ff00ff00ff00ff00ff00ff00ff00ff00 1
              run_case "$architecture" 13 2 2 16 \
                a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5 \
                ffffffffffffffffffffffffffffffff none 0
            }
            run_architecture_matrix x86_64
            run_architecture_matrix aarch64

            run_advanced_case() {
              architecture="$1"
              mode="$2"
              scenario="$3"
              expected="$4"
              should_run "$architecture-advanced-$scenario" || return 0
              case "$architecture" in
                x86_64)
                  binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine='-machine pc -cpu max -m 64M'
                  guest="guest-x86-$mode.elf"
                  address=0x102000
                  if test "$mode" -eq 1; then
                    result=0x102100
                  else
                    result=0x108000
                  fi
                  ;;
                aarch64)
                  binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine='-machine virt -cpu max -m 64M'
                  guest="guest-aarch64-$mode.elf"
                  address=0x40300000
                  if test "$mode" -eq 1; then
                    result=0x40300100
                  else
                    result=0x40310000
                  fi
                  ;;
                *) exit 1 ;;
              esac
              set +e
              timeout 120 $binary $machine -accel sim -icount shift=0 \
                -smp 1 -nographic -no-reboot -serial none -monitor none \
                -kernel "$guest" \
                -plugin "$PWD/crucible-memory-access.so,address=$address,result=$result,expected=$expected,kind=1,classes=2,length=1,mask=ff,replacement=a5,atomic=0,scenario=$scenario" \
                >"logs/$architecture-advanced-$scenario.log" 2>&1
              case_status=$?
              set -e
              cat "logs/$architecture-advanced-$scenario.log"
              test "$case_status" -eq 0
              case "$scenario" in
                invalid-*) pass_marker=CRUCIBLE_MEMORY_REJECTION_LIVE_PASS ;;
                *) pass_marker=CRUCIBLE_MEMORY_ACCESS_LIVE_PASS ;;
              esac
              grep -Fxq "$pass_marker" \
                "logs/$architecture-advanced-$scenario.log"
              test "$(grep -Fc "$pass_marker" \
                "logs/$architecture-advanced-$scenario.log")" -eq 1
            }
            run_advanced_architecture_matrix() {
              architecture="$1"
              case "$architecture" in
                x86_64) exception_scenario=poison-exception-x86 ;;
                aarch64) exception_scenario=poison-exception-aarch64 ;;
                *) exit 1 ;;
              esac
              run_advanced_case "$architecture" 17 poison-corrected a5
              run_advanced_case "$architecture" 14 poison-access-error e1
              run_advanced_case "$architecture" 14 \
                "$exception_scenario" e1
              run_advanced_case "$architecture" 14 failed-region e1
              run_advanced_case "$architecture" 15 retention 00
              run_advanced_case "$architecture" 16 rowhammer a5
              run_advanced_case "$architecture" 17 service 5a
              if test "$architecture" = x86_64; then
                run_advanced_case "$architecture" 18 retry-x86 a5
              else
                run_advanced_case "$architecture" 18 retry-aarch64 a5
              fi
              run_advanced_case "$architecture" 17 invalid-mmio 5a
              run_advanced_case "$architecture" 17 invalid-atomic 5a
              run_advanced_case "$architecture" 17 invalid-geometry 5a
            }
            run_advanced_architecture_matrix x86_64
            run_advanced_architecture_matrix aarch64

            vmlinuz=$(ls ${pkgs.linux}/boot/vmlinuz-* | head -1)
            test -n "$vmlinuz"
            dd if=/dev/zero of=dma-disk.raw bs=1M count=8 status=none
            run_dma_case() {
              class="$1"
              label="$2"
              should_run "dma-$label" || return 0
              timeout 180 ${qemuPackage}/bin/qemu-system-x86_64 \
                -nodefaults -no-user-config -display none -monitor none \
                -machine q35 -accel sim,thread=single \
                -icount shift=0,sleep=off,align=off -m 256 -smp 1 \
                -cpu qemu64,-rdrand,-rdseed \
                -kernel "$vmlinuz" -initrd ${dmaGuest}/initrd.img \
                -append 'console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off' \
                -drive id=dma,file=dma-disk.raw,format=raw,if=none,cache=unsafe \
                -device virtio-blk-pci,drive=dma,id=dma-probe \
                -plugin "$PWD/crucible-memory-dma.so,start=0x100000,length=0xff00000,class=$class,device=dma-probe" \
                >"logs/dma-$label.log" 2>&1
              cat "logs/dma-$label.log"
              grep -Fxq CRUCIBLE_MEMORY_DMA_LIVE_PASS \
                "logs/dma-$label.log"
              test "$(grep -Fc CRUCIBLE_MEMORY_DMA_LIVE_PASS \
                "logs/dma-$label.log")" -eq 1
            }
            run_dma_case 8 read
            run_dma_case 16 write

            if should_run stock; then
              set +e
              timeout 5 ${referenceQemu}/bin/qemu-system-x86_64 \
              -machine pc -m 64M -accel tcg -icount shift=0 -smp 1 \
              -nographic -no-reboot -serial none -monitor none \
              -kernel guest-x86-1.elf \
              -plugin "$PWD/crucible-memory-access.so,address=0x102000,result=0x102100,expected=a5,kind=1,classes=2,length=1,mask=ff,replacement=a5,atomic=0" \
              >logs/stock.log 2>&1
              stock_status=$?
              set -e
              test "$stock_status" -ne 0
              test "$stock_status" -ne 124
              ! grep -q CRUCIBLE_MEMORY_ACCESS_LIVE_PASS logs/stock.log
            fi

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
              printf 'cpu_access_matrix=fetch,aligned,unaligned,cross-page,load,store,atomic-1-2-4-8-16,cmpxchg-success-failure\n'
              printf 'transform_matrix=stuck,read-corrupt,lost-write,torn-write\n'
              printf 'advanced_matrix=corrected-poison,access-error,architectural-exception,failed-region,retention,rowhammer,service\n'
              printf 'dma_backend=actual-device-scoped-virtio-blk-read-write\n'
            } >"$out/result"
          '';
        }
      ];
    }
