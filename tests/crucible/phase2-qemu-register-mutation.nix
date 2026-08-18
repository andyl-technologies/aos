{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0051-crucible-add-architecture-register-fault-mutations.patch",
  attrPath ? "checks.crucible.phase2.qemuRegisterMutation",
  taskIds ? ["T-QEMU-0051"],
  rejectionAtomicity ? false,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  liveCaseCount = 67;

  patchRequirements =
    if rejectionAtomicity
    then [
      {
        label = "exact serialized RR ownership admission";
        needle = "qemu_plugin_crucible_exact_boundary_active";
      }
      {
        label = "whole-machine canonical rejection observation";
        needle = "qemu_plugin_crucible_register_rejection_observe";
      }
      {
        label = "all-vCPU manifest validation";
        needle = "crucible_register_all_cpus_match_manifest";
      }
      {
        label = "production side-effect observation";
        needle = "qemu_crucible_fault_register_side_effect_observed";
      }
      {
        label = "mutation-only side-effect audit scope";
        needle = "qemu_crucible_fault_register_side_effect_scope_enter";
      }
      {
        label = "live rejection side-effect assertion";
        needle = "test_rejection_side_effects_unchanged";
      }
    ]
    else [
      {
        label = "architecture-owned register descriptors";
        needle = "crucible_register_describe";
      }
      {
        label = "exact instruction boundary handling";
        needle = "qemu_crucible_fault_register_instruction_boundary";
      }
      {
        label = "post-write architectural readback";
        needle = "memcmp(after->data, desired, bytes)";
      }
      {
        label = "live impulse and persistent mutation plugin";
        needle = "CRUCIBLE_REGISTER_MUTATION_LIVE_PASS";
      }
      {
        label = "live canonical register evidence validation";
        needle = "test_validate_register_evidence";
      }
    ];

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "GDB mutation shortcut";
        needle = "qemu_plugin_write_vcpu_regs";
      }
      {
        label = "native CPU-state offset in public manifest";
        needle = "fieldoffset";
      }
    ];

  patchedPluginSource = pkgs.mkDerivation {
    pname = "crucible-qemu-register-live-plugin-source";
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
          install -m 644 tests/tcg/plugins/crucible-register.c \
            "$out/crucible-register.c"
        '';
      }
    ];
  };
in
  if failures != []
  then throw "Crucible QEMU register-mutation microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-register-mutation";
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
              ${./phase2-qemu-register-manifest.c} \
              -o crucible-register-manifest.so \
              $(pkg-config --libs glib-2.0)
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${patchedPluginSource}/crucible-register.c \
              -o crucible-register.so \
              $(pkg-config --libs glib-2.0)
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-register-stock-negative.c} \
              -o crucible-register-stock-negative.so \
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
            x86_result_address="$(${pkgs.binutils}/bin/nm -n \
              fault-guest-x86.elf | \
              awk '$3 == "persistent_register_result" { print $1; exit }')"
            aarch64_result_address="$(${pkgs.binutils}/bin/nm -n \
              fault-guest-aarch64.elf | \
              awk '$3 == "persistent_register_result" { print $1; exit }')"
            test -n "$x86_result_address"
            test -n "$aarch64_result_address"
            {
              echo "x86_result_address=0x$x86_result_address"
              echo "aarch64_result_address=0x$aarch64_result_address"
            } > register-result-addresses
          '';
        }
        {
          name = "run-live-register-matrix";
          script = ''
            set -eu
            ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc -cpu max -accel tcg,thread=single -S \
              -display none -nodefaults \
              -plugin ./crucible-register-manifest.so,architecture=2 \
              2> x86.log
            grep -q 'CRUCIBLE_REGISTER_MANIFEST_LIVE_PASS architecture=2' x86.log

            ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt -cpu max -accel tcg,thread=single -S \
              -display none -nodefaults \
              -plugin ./crucible-register-manifest.so,architecture=3 \
              2> aarch64.log
            grep -q 'CRUCIBLE_REGISTER_MANIFEST_LIVE_PASS architecture=3' aarch64.log

            mkdir -p logs
            . ./register-result-addresses
            run_mutation() {
              architecture="$1"
              mode="$2"
              register="$3"
              expected_group="$4"
              phase="$5"
              terminal_cursor="''${6:-false}"
              smp="''${7:-1}"
              case "$architecture" in
                x86_64)
                  architecture_id=2
                  qemu_binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine_args='-machine pc -m 64M'
                  guest=fault-guest-x86.elf
                  result_address="$x86_result_address"
                  ;;
                aarch64)
                  architecture_id=3
                  qemu_binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine_args='-machine virt -cpu max -m 64M'
                  guest=fault-guest-aarch64.elf
                  result_address="$aarch64_result_address"
                  ;;
                *)
                  echo "unknown register gate architecture: $architecture" >&2
                  exit 1
                  ;;
              esac
              plugin_args="$PWD/crucible-register.so,architecture=$architecture_id,mode=$mode,register=$register,phase=$phase"
              case_suffix=""
              if test "$mode" = persistent && test "$expected_group" = 1; then
                plugin_args="$plugin_args,result-address=$result_address"
              fi
              if test "$terminal_cursor" = true; then
                plugin_args="$plugin_args,terminal-cursor=true"
                case_suffix="-terminal-cursor"
              fi
              if test "$smp" != 1; then
                case_suffix="$case_suffix-smp$smp"
              fi
              set +e
              timeout 120 $qemu_binary \
                $machine_args \
                -accel sim \
                -icount shift=0,rr_switch_quantum=256 \
                -smp "$smp" \
                -nographic \
                -no-reboot \
                -serial none \
                -monitor none \
                -kernel "$guest" \
                -plugin "$plugin_args" \
                > "logs/$architecture-$mode-$register-$phase$case_suffix.log" 2>&1
              mutation_status=$?
              set -e
              cat "logs/$architecture-$mode-$register-$phase$case_suffix.log"
              test "$mutation_status" -eq 0
              grep -Fq \
                "CRUCIBLE_REGISTER_MUTATION_LIVE_PASS architecture=$architecture_id mode=$mode register=$register" \
                "logs/$architecture-$mode-$register-$phase$case_suffix.log"
              grep -Fq \
                "group=$expected_group phase=$phase" \
                "logs/$architecture-$mode-$register-$phase$case_suffix.log"
              if test "$mode" = persistent && test "$expected_group" = 1; then
                grep -Fq 'guest_observed=true' \
                  "logs/$architecture-$mode-$register-$phase$case_suffix.log"
              fi
              if test "$terminal_cursor" = true; then
                grep -Fq 'terminal_cursor=true' \
                  "logs/$architecture-$mode-$register-$phase$case_suffix.log"
              fi
              test "$(grep -Fc CRUCIBLE_REGISTER_MUTATION_LIVE_PASS \
                "logs/$architecture-$mode-$register-$phase$case_suffix.log")" -eq 1
              ! grep -q 'Crucible register mutation live test failed' \
                "logs/$architecture-$mode-$register-$phase$case_suffix.log"
            }

            for phase in before after; do
              run_mutation x86_64 impulse rdi 1 "$phase"
              run_mutation x86_64 impulse rip 2 "$phase"
              run_mutation x86_64 impulse rflags 3 "$phase"
              run_mutation x86_64 impulse ds-base 4 "$phase"
              run_mutation x86_64 impulse cr2 5 "$phase"
              run_mutation x86_64 impulse kernel-gs-base 6 "$phase"
              run_mutation x86_64 impulse dr0 7 "$phase"
              run_mutation x86_64 impulse mm0 8 "$phase"
              run_mutation x86_64 impulse xmm15 9 "$phase"

              run_mutation aarch64 impulse x28 1 "$phase"
              run_mutation aarch64 impulse pc 2 "$phase"
              run_mutation aarch64 impulse pstate 3 "$phase"
              run_mutation aarch64 impulse fpsr 8 "$phase"
              run_mutation aarch64 impulse v28 9 "$phase"

              run_mutation x86_64 persistent rdi 1 "$phase"
              run_mutation x86_64 persistent rip 2 "$phase"
              run_mutation x86_64 persistent rflags 3 "$phase"
              run_mutation x86_64 persistent ds-base 4 "$phase"
              run_mutation x86_64 persistent cr2 5 "$phase"
              run_mutation x86_64 persistent kernel-gs-base 6 "$phase"
              run_mutation x86_64 persistent dr0 7 "$phase"
              run_mutation x86_64 persistent mm0 8 "$phase"
              run_mutation x86_64 persistent xmm15 9 "$phase"
              run_mutation aarch64 persistent x28 1 "$phase"
              run_mutation aarch64 persistent elr-el1 2 "$phase"
              run_mutation aarch64 persistent pstate 3 "$phase"
              run_mutation aarch64 persistent fpsr 8 "$phase"
              run_mutation aarch64 persistent v28 9 "$phase"
            done
            run_mutation x86_64 impulse rdi 1 after true
            run_mutation x86_64 impulse rdi 1 before false 2
            single_vcpu_fingerprint="$(sed -n \
              's/.* fingerprint=\([0-9a-f]*\) .*/\1/p' \
              logs/x86_64-impulse-rdi-before.log)"
            two_vcpu_fingerprint="$(sed -n \
              's/.* fingerprint=\([0-9a-f]*\) .*/\1/p' \
              logs/x86_64-impulse-rdi-before-smp2.log)"
            test "''${#single_vcpu_fingerprint}" -eq 64
            test "''${#two_vcpu_fingerprint}" -eq 64
            test "$single_vcpu_fingerprint" != "$two_vcpu_fingerprint"
            run_mutation x86_64 reject-invalid efer 6 before
            run_mutation x86_64 reject-reserved cr0 5 before
            run_mutation x86_64 reject-read-only cr0 5 before
            run_mutation x86_64 reject-out-of-range cr2 5 before
            run_mutation x86_64 reject-mismatched-register-identity rdi 1 before
            run_mutation x86_64 reject-unknown-register-identity cr2 5 before
            run_mutation x86_64 reject-architecture-identity cr2 5 before
            run_mutation x86_64 reject-vcpu cr2 5 before
            run_mutation x86_64 reject-precondition cr2 5 before

            set +e
            timeout 5 ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc -m 64M \
              -accel tcg \
              -icount shift=0 \
              -smp 1 \
              -nographic \
              -no-reboot \
              -serial none \
              -monitor none \
              -kernel fault-guest-x86.elf \
              -plugin "$PWD/crucible-register.so,architecture=2,mode=impulse,register=rdi,phase=before" \
              > logs/patched-tcg-unavailable.log 2>&1
            patched_tcg_status=$?
            set -e
            cat logs/patched-tcg-unavailable.log
            test "$patched_tcg_status" -ne 0
            test "$patched_tcg_status" -ne 124
            grep -Fq \
              'the complete fault registry is unavailable' \
              logs/patched-tcg-unavailable.log
            ! grep -q CRUCIBLE_REGISTER_MUTATION_LIVE_PASS \
              logs/patched-tcg-unavailable.log

            if ${referenceQemu}/bin/qemu-system-x86_64 \
              -machine pc -cpu max -accel tcg,thread=single -S \
              -display none -nodefaults \
              -plugin ./crucible-register-manifest.so,architecture=2 \
              > reference.log 2>&1; then
              echo "unpatched QEMU unexpectedly loaded the register manifest plugin" >&2
              exit 1
            fi

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
              -plugin "$PWD/crucible-register-stock-negative.so" \
              > logs/stock-mutation.log 2>&1
            stock_status=$?
            set -e
            cat logs/stock-mutation.log
            test "$stock_status" -ne 0
            test "$stock_status" -ne 124
            grep -Fq \
              'undefined symbol: qemu_plugin_crucible_fault_submit' \
              logs/stock-mutation.log
            ! grep -q CRUCIBLE_REGISTER_MUTATION_LIVE_PASS \
              logs/stock-mutation.log
          '';
        }
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out"
            cp -R logs "$out/"
            {
              echo PASS
              echo gate=gate:patch-microtests
              echo patch=${patchName}
              echo attr_path=${attrPath}
              echo task_ids=${taskList}
              echo patched_fixture_exercised=true
              echo stock_negative_control=true
              echo patched_non_sim_inert=true
              echo qemu_package=${qemuPackage}
              echo qemu_package_version=${qemuPackage.version}
              echo backend=actual-patched-and-stock-qemu
              echo live_mutation_cases=${toString liveCaseCount}
              echo live_x86_64_manifest=true
              echo live_aarch64_manifest=true
              echo live_x86_64_impulse_groups=1,2,3,4,5,6,7,8,9
              echo live_x86_64_persistent_groups=1,2,3,4,5,6,7,8,9
              echo live_x86_64_persistent_gpr_guest_read_write=true
              echo live_x86_64_multivcpu_fingerprint_indices=0,1
              echo live_x86_64_invalid_transition_rejected=true
              echo live_x86_64_rejection_matrix=reserved,read-only,out-of-range,mismatched-register-identity,unknown-register-identity,architecture-identity,vcpu,precondition
              echo live_aarch64_impulse_groups=1,2,3,8,9
              echo live_aarch64_persistent_groups=1,2,3,8,9
              echo live_aarch64_persistent_gpr_guest_read_write=true
              echo live_before_instruction=true
              echo live_after_instruction=true
              echo mutation_evidence=architecture,row,phase,range,before,after,mask,value,rr,baseline_and_post_execution_fingerprints
            } > "$out/result"
          '';
        }
      ];
    }
