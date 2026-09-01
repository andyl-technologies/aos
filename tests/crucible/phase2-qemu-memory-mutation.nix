{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0049-crucible-memory-boundary-mutate.patch",
  attrPath ? "checks.crucible.phase2.qemuMemoryMutation",
  taskIds ? ["T-QEMU-0049"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  liveCaseCount = 40;

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "real RAM mutation commit";
        needle = "memory_region_fault_commit_ram";
      }
      {
        label = "x86 exact virtual translation";
        needle = "x86_cpu_get_fault_translation";
      }
      {
        label = "AArch64 exact virtual translation";
        needle = "arm_cpu_get_fault_translation";
      }
      {
        label = "all-or-nothing prepare phase";
        needle = "crucible_memory_prepare";
      }
      {
        label = "infallible commit phase";
        needle = "crucible_memory_commit";
      }
      {
        label = "live QEMU test plugin";
        needle = "CRUCIBLE_MEMORY_MUTATION_LIVE_PASS";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "host pointer in public mutation evidence";
        needle = "host_pointer";
      }
      {
        label = "debugger memory write shortcut";
        needle = "cpu_memory_rw_debug";
      }
    ];

  patchedPluginSource = pkgs.mkDerivation {
    pname = "crucible-qemu-memory-live-plugin-source";
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
        name = "apply-authoritative-series";
        script = ''
          set -eu
          for patch_file in ${builtins.concatStringsSep " " series.patchFiles}; do
            patch --batch --forward --fuzz=0 -p1 \
              -i "${patchDir}/$patch_file"
          done
        '';
      }
      {
        name = "install-test-plugin-source";
        script = ''
          set -eu
          mkdir -p "$out"
          install -m 644 tests/tcg/plugins/crucible-memory.c \
            "$out/crucible-memory.c"
        '';
      }
    ];
  };
in
  if failures != []
  then throw "Crucible live QEMU memory-mutation microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-memory-mutation";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.binutils
        pkgs.coreutils
        pkgs.glib
        pkgs.glib.dev
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
              ${patchedPluginSource}/crucible-memory.c \
              -o crucible-memory.so \
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
          name = "run-live-memory-matrix";
          script = ''
            set -eu
            mkdir -p logs

            run_case() {
              architecture="$1"
              case_name="$2"
              plugin_args="$3"
              case "$architecture" in
                x86_64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine_args='-machine pc -m 64M'
                  guest=fault-guest-x86.elf
                  loader_args='-device loader,addr=0x9ffff,data=0x5a,data-len=1'
                  ;;
                aarch64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine_args='-machine virt -cpu max -m 64M'
                  guest=fault-guest-aarch64.elf
                  loader_args='-device loader,addr=0x43ffffff,data=0x5a,data-len=1'
                  ;;
                *)
                  echo "unknown live-test architecture: $architecture" >&2
                  exit 1
                  ;;
              esac
              set +e
              timeout 120 $qemu_binary \
                $machine_args \
                -accel sim \
                -icount shift=0 \
                -smp 1 \
                -nographic \
                -no-reboot \
                -serial none \
                -monitor none \
                -kernel "$guest" \
                $loader_args \
                -plugin "$PWD/crucible-memory.so,$plugin_args" \
                > "logs/$architecture-$case_name.log" 2>&1
              case_status=$?
              set -e
              cat "logs/$architecture-$case_name.log"
              test "$case_status" -eq 0
              grep -Fxq CRUCIBLE_MEMORY_MUTATION_LIVE_PASS \
                "logs/$architecture-$case_name.log"
              test "$(grep -Fc CRUCIBLE_MEMORY_MUTATION_LIVE_PASS \
                "logs/$architecture-$case_name.log")" -eq 1
              ! grep -q 'Crucible memory mutation live test failed' \
                "logs/$architecture-$case_name.log"
            }

            run_architecture_matrix() {
              architecture="$1"
              case "$architecture" in
                x86_64)
                  mutation=0x102000
                  cross=0x102fff
                  unmapped=0x70000000
                  rollback=0x9ffff
                  large=0x1000000
                  paging=0x102001
                  execution_result=0x102002
                  readonly=0x105000
                  rom=0xffff0000
                  mmio=0xfee00000
                  translation=1db71a69a29f61f2cc29c125602043f908c0e936270f3f3a5b4ec046ae9ee7f3
                  cross_translation=2836d92be4f95a57a3dd43ae3f03d9858c527cd4bb90147272c2f84fcc308cc0
                  deferred_target='target-mode=current-tb'
                  executable_args='address=0x104001,length=1,before=0x5a,after=0xa5,target-mode=current-tb,tb-invalidated=required,execution-result=0x102002,submit=paging-ready,paging-ready=0x102001'
                  ;;
                aarch64)
                  mutation=0x40300000
                  cross=0x40300fff
                  unmapped=0x50000000
                  rollback=0x43ffffff
                  large=0x41000000
                  paging=0x40300001
                  execution_result=0x40300002
                  readonly=0x40302000
                  rom=0x0
                  mmio=0x08000000
                  translation=391323646bed3dcedb4031ddfd8376c760eebd15f167ef85ecbf0929bfa15d24
                  cross_translation=c9dad7f6c3814d6caa2f222dd46c4608df79904e5b57815c6ef778425441f5b4
                  deferred_target='target-mode=current-tb'
                  executable_args='address=0x40201000,length=4,before-bytes=400b8052,after-bytes=a0148052,before=0x5a,after=0xa5,target-mode=current-tb,tb-invalidated=required,execution-result=0x40300002,submit=paging-ready,paging-ready=0x40300001'
                  ;;
              esac

              run_case "$architecture" gpa-replace \
                "address=$mutation,before=0x5a,after=0xa5,icount=100"
              run_case "$architecture" gpa-bit-flip \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,transform=bit-flip"
              run_case "$architecture" gpa-cross-page \
                "address=$cross,length=2,before=0x5a,after=0xa5,icount=100"
              run_case "$architecture" precondition-mismatch \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,status=precondition-mismatch"
              run_case "$architecture" unmapped-target \
                "address=$unmapped,before=0x5a,after=0xa5,icount=100,status=invalid-target"
              run_case "$architecture" malformed-zero-length \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,malformed=zero-length"
              run_case "$architecture" malformed-overflow \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,malformed=overflow"
              run_case "$architecture" malformed-over-limit \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,malformed=over-limit"
              run_case "$architecture" canonical-overlap-order \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,mode=overlap-order"
              run_case "$architecture" same-boundary-prepare-commit \
                "address=$mutation,before=0x5a,after=0xa5,icount=100"
              run_case "$architecture" gva-replace \
                "address=$mutation,address-space=gva,vcpu=0,translations=1,translation=$translation,before=0x5a,after=0xa5,$deferred_target,tb-invalidated=required,submit=paging-ready,paging-ready=$paging"
              run_case "$architecture" gva-cross-page \
                "address=$cross,address-space=gva,vcpu=0,translations=2,fragments=2,translation=$cross_translation,length=2,before=0x5a,after=0xa5,$deferred_target,tb-invalidated=required,submit=paging-ready,paging-ready=$paging"
              run_case "$architecture" changed-proposal-after-prepare \
                "address=$mutation,address-space=gva,vcpu=0,translations=1,translation=$translation,before=0x5a,after=0xa5,$deferred_target,status=prepared-state-mismatch,submit=paging-ready,paging-ready=$paging"
              run_case "$architecture" executable-page "$executable_args"
              run_case "$architecture" gva-write-protected \
                "address=$readonly,address-space=gva,vcpu=0,translations=1,translation=1111111111111111111111111111111111111111111111111111111111111111,before=0x5a,after=0xa5,$deferred_target,status=invalid-target,submit=paging-ready,paging-ready=$paging"
              run_case "$architecture" rom-target \
                "address=$rom,before=0x5a,after=0xa5,icount=100,status=invalid-target"
              run_case "$architecture" mmio-target \
                "address=$mmio,before=0x5a,after=0xa5,icount=100,status=invalid-target"
              run_case "$architecture" valid-prefix-invalid-suffix \
                "address=$rollback,length=2,before=0x5a,after=0xa5,icount=100,status=invalid-target,unchanged-vaddr=$rollback"
              run_case "$architecture" hash-only-evidence \
                "address=$large,length=65537,before=0x00,after=0xa5,icount=100"
              run_case "$architecture" hard-bound-success \
                "address=$large,length=16777216,before=0x00,after=0xa5,icount=100"
            }

            printf 'info mtree -f\nquit\n' | \
              ${qemuPackage}/bin/qemu-system-x86_64 \
                -machine pc -m 64M -accel tcg -S -nographic \
                -serial none -monitor stdio > logs/x86_64-memory-map.log 2>&1
            grep -Fq '00000000fffc0000-00000000ffffffff (prio 0, rom): pc.bios' \
              logs/x86_64-memory-map.log
            grep -Fq '00000000fee00000-00000000feefffff (prio 4096, i/o): apic-msi' \
              logs/x86_64-memory-map.log
            printf 'info mtree -f\nquit\n' | \
              ${qemuPackage}/bin/qemu-system-aarch64 \
                -machine virt -cpu max -m 64M -accel tcg -S -nographic \
                -serial none -monitor stdio > logs/aarch64-memory-map.log 2>&1
            grep -Fq '0000000000000000-0000000003ffffff (prio 0, romd): virt.flash0' \
              logs/aarch64-memory-map.log
            grep -Fq '0000000008000000-0000000008000fff (prio 0, i/o): gic_dist' \
              logs/aarch64-memory-map.log

            run_architecture_matrix x86_64
            run_architecture_matrix aarch64

            set +e
            timeout 5 ${referenceQemu}/bin/qemu-system-x86_64 \
              -machine pc -m 64M \
              -accel tcg \
              -icount shift=0 \
              -smp 1 \
              -nographic \
              -no-reboot \
              -serial none \
              -monitor none \
              -kernel fault-guest-x86.elf \
              -plugin "$PWD/crucible-memory.so,address=0x102000,before=0x5a,after=0xa5,icount=100" \
              > logs/stock.log 2>&1
            stock_status=$?
            set -e
            cat logs/stock.log
            test "$stock_status" -ne 0
            test "$stock_status" -ne 124
            ! grep -q CRUCIBLE_MEMORY_MUTATION_LIVE_PASS logs/stock.log
            ! nm -D --defined-only \
              ${referenceQemu}/bin/qemu-system-x86_64 \
              | grep -q qemu_plugin_crucible_fault_submit

            mkdir -p "$out"
            cp -R logs "$out/"
            {
              printf 'PASS\n'
              printf 'gate=gate:patch-microtests\n'
              printf 'patch=%s\n' '${patchName}'
              printf 'patched_fixture_exercised=true\n'
              printf 'stock_negative_control=true\n'
              printf 'qemu_package=%s\n' '${qemuPackage}'
              printf 'qemu_package_version=%s\n' '${qemuPackage.version}'
              printf 'attr_path=%s\n' '${attrPath}'
              printf 'task_ids=%s\n' '${taskList}'
              printf 'backend=actual-patched-and-stock-qemu\n'
              printf 'live_cases=%s\n' '${toString liveCaseCount}'
              printf 'architectures=%s\n' 'x86_64,aarch64'
              printf 'gva_translation_matrix=%s\n' 'x86_64+aarch64:single-page,cross-page,stale-digest,write-protected'
              printf 'executable_tb_invalidation=%s\n' 'x86_64+aarch64:behavior-observed'
              printf 'all_or_nothing=%s\n' 'valid-prefix-invalid-suffix-unchanged'
              printf 'evidence_bounds=%s\n' 'inline,hash-only,16MiB-hard-bound'
              printf 'disallowed_target_matrix=%s\n' 'x86_64+aarch64:unmapped,rom,mmio,write-protected'
              printf 'target_types_introspected=%s\n' 'rom,romd,mmio'
              printf 'production_effect_row=memory.mutation|physical-virtual-atomic-matrix|gate:patch-microtests|actual-patched-qemu|translation+before-after+dirty-tracking\n'
            } > "$out/result"
          '';
        }
      ];
    }
