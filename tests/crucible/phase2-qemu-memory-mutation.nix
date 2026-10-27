{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  attrPath ? "checks.crucible.phase2.qemuMemoryMutation",
  taskIds ? ["T-QEMU-0049"],
}: let
  ramObserver = pkgs.callPackage ../../pkgs/emulation/crucible-qemu-plugin.nix {
    nativeConformance = true;
    qemu-crucible = qemuPackage;
  };
  correspondingSource = pkgs.callPackage ../../pkgs/emulation/qemu-crucible-source.nix {
    qemu-crucible = qemuPackage;
  };
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  patchSource = builtins.readFile (patchDir + "/${atomicPatch.file}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  rejectionCaseCount = 18;

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${atomicPatch.file}" patchSource [
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
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${atomicPatch.file}" patchSource [
      {
        label = "host pointer in public mutation evidence";
        needle = "host_pointer";
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
          cd qemu-${atomicPatch.qemuVersion}
        '';
      }
      {
        name = "apply-atomic-patch";
        script = ''
          set -eu
          patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/${atomicPatch.file}"
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
        ramObserver
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
            cat > memory-refusal-status.c <<'EOF'
            #include <stdio.h>
            #include <qemu-plugin.h>
            #include "aos/crucible/crucible_shmem_abi.h"
            int main(void)
            {
                printf("prepare status=%u expected=%u\n",
                       CRUCIBLE_FAULT_STATUS_INTERNAL_ERROR,
                       CRUCIBLE_FAULT_STATUS_PREPARED);
                return 0;
            }
            EOF
            "$CC" -I${qemuPackage}/include/qemu -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              memory-refusal-status.c -o memory-refusal-status
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
                -icount shift=0,align=off,sleep=off \
                -smp 1 \
                -nographic \
                -no-reboot \
                -serial none \
                -monitor none \
                -kernel "$guest" \
                $loader_args \
                -plugin "${ramObserver}/lib/libcrucible_qemu_plugin.so,ram_metadata_budget=268435456" \
                -plugin "$PWD/crucible-memory.so,$plugin_args" \
                > "logs/$architecture-$case_name.log" 2>&1
              case_status=$?
              set -e
              cat "logs/$architecture-$case_name.log"
              if test "$case_name" = unmanaged-positive-refused; then
                test "$case_status" -ne 0
                test "$case_status" -ne 124
                test "$case_status" -ne 137
                grep -Fxq "$(./memory-refusal-status)" \
                  "logs/$architecture-$case_name.log"
                grep -Fq 'preparation returned the wrong status' \
                  "logs/$architecture-$case_name.log"
                ! grep -q CRUCIBLE_MEMORY_MUTATION_LIVE_PASS \
                  "logs/$architecture-$case_name.log"
                return
              fi
              test "$case_status" -eq 0
              grep -Fxq CRUCIBLE_MEMORY_MUTATION_LIVE_PASS \
                "logs/$architecture-$case_name.log"
              test "$(grep -Fc CRUCIBLE_MEMORY_MUTATION_LIVE_PASS \
                "logs/$architecture-$case_name.log")" -eq 1
              ! grep -q 'Crucible memory mutation live test failed' \
                "logs/$architecture-$case_name.log"
              ! grep -q CRUCIBLE-RAM-ORACLE-FAIL \
                "logs/$architecture-$case_name.log"
              case "$plugin_args" in
                *status=*|*malformed=*) ;;
                *)
                  grep -Fq CRUCIBLE-RAM-ORACLE-PASS \
                    "logs/$architecture-$case_name.log"
                  ;;
              esac
            }

            run_architecture_matrix() {
              architecture="$1"
              case "$architecture" in
                x86_64)
                  mutation=0x102000
                  unmapped=0x70000000
                  rollback=0x9ffff
                  paging=0x102001
                  readonly=0x105000
                  rom=0xffff0000
                  mmio=0xfee00000
                  deferred_target='target-mode=current-tb'
                  ;;
                aarch64)
                  mutation=0x40300000
                  unmapped=0x50000000
                  rollback=0x43ffffff
                  paging=0x40300001
                  readonly=0x40302000
                  rom=0x0
                  mmio=0x08000000
                  deferred_target='target-mode=current-tb'
                  ;;
              esac

              # A logical observer cannot issue physical mutation grants.
              # This refusal does not qualify any managed mutation semantics.
              run_case "$architecture" unmanaged-positive-refused \
                "address=$mutation,before=0x5a,after=0xa5,icount=100"
              run_case "$architecture" unmapped-target \
                "address=$unmapped,before=0x5a,after=0xa5,icount=100,status=invalid-target"
              run_case "$architecture" malformed-zero-length \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,malformed=zero-length"
              run_case "$architecture" malformed-overflow \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,malformed=overflow"
              run_case "$architecture" malformed-over-limit \
                "address=$mutation,before=0x5a,after=0xa5,icount=100,malformed=over-limit"
              run_case "$architecture" gva-write-protected \
                "address=$readonly,address-space=gva,vcpu=0,translations=1,translation=1111111111111111111111111111111111111111111111111111111111111111,before=0x5a,after=0xa5,$deferred_target,status=invalid-target,submit=paging-ready,paging-ready=$paging"
              run_case "$architecture" rom-target \
                "address=$rom,before=0x5a,after=0xa5,icount=100,status=invalid-target"
              run_case "$architecture" mmio-target \
                "address=$mmio,before=0x5a,after=0xa5,icount=100,status=invalid-target"
              run_case "$architecture" valid-prefix-invalid-suffix \
                "address=$rollback,length=2,before=0x5a,after=0xa5,icount=100,status=invalid-target,unchanged-vaddr=$rollback"
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
            mkdir -p "$out/share/aos"
            ln -s ${correspondingSource} "$out/share/aos/qemu-crucible-source"
            {
              printf 'PASS\n'
              printf 'gate=gate:patch-microtests\n'
              printf 'atomic_patch=%s\n' '${atomicPatch.file}'
              printf 'patched_fixture_exercised=true\n'
              printf 'stock_negative_control=true\n'
              printf 'qemu_package=%s\n' '${qemuPackage}'
              printf 'qemu_package_version=%s\n' '${qemuPackage.version}'
              printf 'attr_path=%s\n' '${attrPath}'
              printf 'task_ids=%s\n' '${taskList}'
              printf 'backend=actual-patched-and-stock-qemu\n'
              printf 'rejection_cases=%s\n' '${toString rejectionCaseCount}'
              printf 'architectures=%s\n' 'x86_64,aarch64'
              printf 'unmanaged_positive_requests_refused=true\n'
              printf 'managed_mutation_qualified=false\n'
              printf 'gva_write_protected_rejected=true\n'
              printf 'invalid_suffix_preserves_valid_prefix=true\n'
              printf 'malformed_payload_matrix=%s\n' 'zero-length,overflow,over-limit'
              printf 'remaining_managed_coverage=%s\n' 'gva-resolution,executable-tb,precondition,changed-proposal,overlap-order,hash-only,hard-bound'
              printf 'disallowed_target_matrix=%s\n' 'x86_64+aarch64:unmapped,rom,mmio,write-protected'
              printf 'target_types_introspected=%s\n' 'rom,romd,mmio'
              printf 'component_effect_row=memory.rejection|malformed-and-nonram-matrix|gate:patch-microtests|actual-patched-qemu|unchanged-valid-prefix+typed-refusal\n'
            } > "$out/result"
          '';
        }
      ];
    }
