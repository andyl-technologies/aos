{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0052-crucible-instruction-and-exception-faults.patch",
  attrPath ? "checks.crucible.phase2.qemuInstructionFaults",
  taskIds ? ["T-QEMU-0052"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  liveCaseCount = 73;

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "instruction transform implementation";
        needle = "qemu_crucible_fault_instruction_prepare";
      }
      {
        label = "exact sparse instruction boundary index";
        needle = "interval_tree_iter_first";
      }
      {
        label = "canonical instruction evidence";
        needle = "CRUCINS1";
      }
      {
        label = "canonical exception evidence";
        needle = "CRUCEXC1";
      }
      {
        label = "live instruction and exception plugin";
        needle = "CRUCIBLE_INSTRUCTION_LIVE_PASS";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "debugger mutation shortcut";
        needle = "gdb_set_reg";
      }
      {
        label = "test-only instruction emulation";
        needle = "CRUCIBLE_TEST_DOUBLE";
      }
    ];

  patchedPluginSource = pkgs.mkDerivation {
    pname = "crucible-qemu-instruction-live-plugin-source";
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
          install -m 644 tests/tcg/plugins/crucible-instruction.c \
            "$out/crucible-instruction.c"
        '';
      }
    ];
  };
in
  if failures != []
  then throw "Crucible QEMU instruction-fault microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-instruction-faults";
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
              ${patchedPluginSource}/crucible-instruction.c \
              -o crucible-instruction.so \
              $(pkg-config --libs glib-2.0)
            "$CC" -shared -fPIC \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-register-stock-negative.c} \
              -o crucible-instruction-stock-negative.so \
              $(pkg-config --libs glib-2.0)

            as --32 ${./phase2-qemu-instruction-guest.S} \
              -o instruction-guest-x86.o
            ld -m elf_i386 -T ${./phase2-qemu-fault-guest.ld} \
              instruction-guest-x86.o -o instruction-guest-x86.elf
            ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
              -march=armv8.1-a+lse \
              -c ${./phase2-qemu-instruction-guest-aarch64.S} \
              -o instruction-guest-aarch64.o
            ${pkgs.llvm}/bin/ld.lld \
              -T ${./phase2-qemu-fault-guest-aarch64.ld} \
              instruction-guest-aarch64.o \
              -o instruction-guest-aarch64.elf

            instruction_address() {
              nm_binary="$1"
              guest="$2"
              symbol="$3"
              address="$($nm_binary -n "$guest" | \
                awk -v symbol="$symbol" '$3 == symbol { print $1; exit }')"
              if test -z "$address"; then
                return 1
              fi
              echo "0x$address"
            }
            instruction_bytes() {
              objdump_binary="$1"
              nm_binary="$2"
              guest="$3"
              symbol="$4"
              objdump_args="$5"
              address="$(instruction_address \
                "$nm_binary" "$guest" "$symbol")"
              start="$((address))"
              stop="$((start + 32))"
              bytes="$($objdump_binary $objdump_args -d --wide \
                --start-address="$start" --stop-address="$stop" \
                "$guest" | awk '
                  {
                    if ($1 ~ /:$/) {
                      output = ""
                      if (length($2) == 8 && $2 ~ /^[[:xdigit:]]+$/) {
                        output = substr($2, 7, 2) substr($2, 5, 2) \
                                 substr($2, 3, 2) substr($2, 1, 2)
                      } else {
                        for (field = 2; field <= NF; field++) {
                          if ($field !~ /^[[:xdigit:]][[:xdigit:]]$/) break
                          output = output $field
                        }
                      }
                      if (output != "" && first == "") first = output
                    }
                  }
                  END { print first }
                ')"
              if test -z "$bytes"; then
                echo "could not extract bytes for $symbol at $address in $guest" >&2
                return 1
              fi
              echo "$bytes"
            }
            write_fixture() {
              architecture="$1"
              guest="$2"
              nm_binary="$3"
              objdump_binary="$4"
              objdump_args="$5"
              {
                for symbol in \
                  instruction_result instruction_skip instruction_replay \
                  instruction_exception_probe instruction_control \
                  instruction_atomic instruction_load_instruction \
                  instruction_store_instruction instruction_atomic_instruction \
                  instruction_fp_simd instruction_exception_instruction \
                  instruction_device_instruction \
                  instruction_self_modify_instruction \
                  instruction_result_fault_instruction \
                  instruction_replay_exception_instruction; do
                  if ! pc="$(instruction_address \
                    "$nm_binary" "$guest" "$symbol")"; then
                    continue
                  fi
                  echo "$architecture''${symbol#instruction_}_pc=$pc"
                  echo "$architecture''${symbol#instruction_}_bytes=$(instruction_bytes \
                    "$objdump_binary" "$nm_binary" "$guest" "$symbol" \
                    "$objdump_args")"
                done
                for symbol in instruction_iterations instruction_result_value \
                  instruction_skip_count instruction_replay_count \
                  instruction_exception_count instruction_natural_exception_count \
                  instruction_control_count instruction_store_count \
                  instruction_atomic_count instruction_load_result \
                  instruction_fp_result instruction_result_fault_value; do
                  echo "$architecture''${symbol#instruction_}_address=$(instruction_address \
                    "$nm_binary" "$guest" "$symbol")"
                done
              } >> instruction-fixtures
            }
            write_fixture x86_ instruction-guest-x86.elf \
              ${pkgs.binutils}/bin/nm ${pkgs.binutils}/bin/objdump \
              '-m i386:x86-64'
            write_fixture aarch64_ instruction-guest-aarch64.elf \
              ${pkgs.llvm}/bin/llvm-nm ${pkgs.llvm}/bin/llvm-objdump ""
          '';
        }
        {
          name = "run-live-instruction-matrix";
          script = ''
            set -eu
            mkdir -p logs
            . ./instruction-fixtures
            run_instruction() {
              architecture="$1"
              mode="$2"
              target="$3"
              register="$4"
              input_state="''${5-}"
              case "$architecture" in
                x86_64)
                  architecture_id=2
                  qemu_binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine_args='-machine pc -m 64M'
                  guest=instruction-guest-x86.elf
                  eval "pc=\$x86_''${target}_pc"
                  eval "bytes=\$x86_''${target}_bytes"
                  case "$mode" in
                    skip) selected_address="$x86_skip_count_address" ;;
                    replay) selected_address="$x86_replay_count_address" ;;
                    result-load) selected_address="$x86_load_result_address" ;;
                    result-fp-simd) selected_address="$x86_fp_result_address" ;;
                    skip-load|replay-load) selected_address="$x86_load_result_address" ;;
                    skip-fp-simd|replay-fp-simd) selected_address="$x86_fp_result_address" ;;
                    skip-store) selected_address="$x86_store_count_address" ;;
                    skip-control) selected_address="$x86_control_count_address" ;;
                    skip-exception) selected_address="$x86_natural_exception_count_address" ;;
                    input-mismatch) selected_address="$x86_skip_count_address" ;;
                    replay-store) selected_address="$x86_store_count_address" ;;
                    replay-atomic) selected_address="$x86_atomic_count_address" ;;
                    result-fault-retry) selected_address="$x86_result_fault_value_address" ;;
                    *) selected_address="$x86_result_value_address" ;;
                  esac
                  iterations_address="$x86_iterations_address"
                  exception_address="$x86_exception_count_address"
                  ;;
                aarch64)
                  architecture_id=3
                  qemu_binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine_args='-machine virt -cpu max -m 64M'
                  guest=instruction-guest-aarch64.elf
                  eval "pc=\$aarch64_''${target}_pc"
                  eval "bytes=\$aarch64_''${target}_bytes"
                  case "$mode" in
                    skip) selected_address="$aarch64_skip_count_address" ;;
                    replay) selected_address="$aarch64_replay_count_address" ;;
                    result-load) selected_address="$aarch64_load_result_address" ;;
                    result-fp-simd) selected_address="$aarch64_fp_result_address" ;;
                    skip-load|replay-load) selected_address="$aarch64_load_result_address" ;;
                    skip-fp-simd|replay-fp-simd) selected_address="$aarch64_fp_result_address" ;;
                    skip-store) selected_address="$aarch64_store_count_address" ;;
                    skip-control) selected_address="$aarch64_control_count_address" ;;
                    skip-exception) selected_address="$aarch64_natural_exception_count_address" ;;
                    input-mismatch) selected_address="$aarch64_skip_count_address" ;;
                    replay-store) selected_address="$aarch64_store_count_address" ;;
                    replay-atomic) selected_address="$aarch64_atomic_count_address" ;;
                    result-fault-retry) selected_address="$aarch64_result_fault_value_address" ;;
                    *) selected_address="$aarch64_result_value_address" ;;
                  esac
                  iterations_address="$aarch64_iterations_address"
                  exception_address="$aarch64_exception_count_address"
                  ;;
                *)
                  echo "unknown instruction architecture: $architecture" >&2
                  exit 1
                  ;;
              esac
              plugin_args="$PWD/crucible-instruction.so,architecture=$architecture_id,mode=$mode,pc=$pc,bytes=$bytes,register=$register,selected-address=$selected_address,iterations-address=$iterations_address,exception-address=$exception_address"
              if test -n "$input_state"; then
                plugin_args="$plugin_args,input-state=$input_state"
              fi
              case "$bytes" in
                ""|*[!0123456789abcdefABCDEF]*)
                  echo "invalid instruction bytes for $architecture/$mode/$target: '$bytes'" >&2
                  exit 1
                  ;;
              esac
              test "$(( ''${#bytes} % 2 ))" -eq 0
              test "''${#bytes}" -le 64
              echo "running instruction case architecture=$architecture mode=$mode target=$target pc=$pc bytes=$bytes"
              set +e
              timeout 120 $qemu_binary \
                $machine_args \
                -accel sim \
                -icount shift=0,rr_switch_quantum=256 \
                -smp 1 \
                -nographic \
                -no-reboot \
                -serial none \
                -monitor none \
                -kernel "$guest" \
                -plugin "$plugin_args" \
                > "logs/$architecture-$mode-$target.log" 2>&1
              status=$?
              set -e
              cat "logs/$architecture-$mode-$target.log"
              test "$status" -eq 0
              grep -Fq \
                "CRUCIBLE_INSTRUCTION_LIVE_PASS architecture=$architecture_id" \
                "logs/$architecture-$mode-$target.log"
              test "$(grep -Fc CRUCIBLE_INSTRUCTION_LIVE_PASS \
                "logs/$architecture-$mode-$target.log")" -eq 1
              ! grep -q 'Crucible instruction live test failed' \
                "logs/$architecture-$mode-$target.log"
            }

            run_instruction x86_64 result result rax
            run_instruction x86_64 result-compose result rax
            x86_result_input="$(sed -n 's/^CRUCIBLE_MATCHED_INPUT_STATE=//p' \
              logs/x86_64-result-result.log | head -n 1)"
            x86_compose_input="$(sed -n 's/^CRUCIBLE_MATCHED_INPUT_STATE=//p' \
              logs/x86_64-result-compose-result.log | head -n 1)"
            test "''${#x86_result_input}" -eq 64
            test "''${#x86_compose_input}" -eq 64
            run_instruction x86_64 result-input result rax "$x86_result_input"
            run_instruction x86_64 result-input-compose result rax "$x86_compose_input"
            run_instruction x86_64 result-fault-retry result_fault_instruction rax
            run_instruction x86_64 event-saturation result rax
            run_instruction x86_64 reject-overlap result rax
            run_instruction x86_64 exclusive-selectors result rax
            run_instruction x86_64 skip skip rax
            run_instruction x86_64 replay replay rax
            run_instruction x86_64 exception-before exception_probe rax
            run_instruction x86_64 exception-after exception_probe rax
            run_instruction x86_64 result-load load_instruction rdx
            run_instruction x86_64 result-fp-simd fp_simd xmm0
            run_instruction x86_64 skip-load load_instruction rdx
            run_instruction x86_64 replay-load load_instruction rdx
            run_instruction x86_64 skip-store store_instruction rax
            run_instruction x86_64 skip-fp-simd fp_simd xmm0
            run_instruction x86_64 replay-fp-simd fp_simd xmm0
            run_instruction x86_64 skip-control control rax
            run_instruction x86_64 skip-exception exception_instruction rax
            run_instruction x86_64 replay-store store_instruction rax
            run_instruction x86_64 replay-atomic atomic_instruction rax
            run_instruction x86_64 replay-device device_instruction rax
            run_instruction x86_64 input-mismatch skip rax
            run_instruction x86_64 replay-self-modify self_modify_instruction rax
            run_instruction x86_64 reject-atomic-skip atomic_instruction rax
            run_instruction x86_64 reject-control-replay control rax
            run_instruction x86_64 reject-destination result rax
            run_instruction x86_64 reject-bytes result rax
            run_instruction x86_64 reject-opcode-class result rax
            run_instruction x86_64 reject-prefix fp_simd xmm0
            run_instruction x86_64 reject-lock result rax
            run_instruction x86_64 reject-x86-sse-prefix fp_simd xmm0
            run_instruction x86_64 reject-x86-far-register control rax

            run_instruction aarch64 result result x0
            run_instruction aarch64 result-compose result x0
            aarch64_result_input="$(sed -n 's/^CRUCIBLE_MATCHED_INPUT_STATE=//p' \
              logs/aarch64-result-result.log | head -n 1)"
            aarch64_compose_input="$(sed -n 's/^CRUCIBLE_MATCHED_INPUT_STATE=//p' \
              logs/aarch64-result-compose-result.log | head -n 1)"
            test "''${#aarch64_result_input}" -eq 64
            test "''${#aarch64_compose_input}" -eq 64
            run_instruction aarch64 result-input result x0 "$aarch64_result_input"
            run_instruction aarch64 result-input-compose result x0 "$aarch64_compose_input"
            run_instruction aarch64 result-fault-retry result_fault_instruction x9
            run_instruction aarch64 event-saturation result x0
            run_instruction aarch64 reject-overlap result x0
            run_instruction aarch64 exclusive-selectors result x0
            run_instruction aarch64 skip skip x0
            run_instruction aarch64 replay replay x0
            run_instruction aarch64 exception-before exception_probe x0
            run_instruction aarch64 exception-after exception_probe x0
            run_instruction aarch64 result-load load_instruction x9
            run_instruction aarch64 result-fp-simd fp_simd v0
            run_instruction aarch64 skip-load load_instruction x9
            run_instruction aarch64 replay-load load_instruction x9
            run_instruction aarch64 skip-store store_instruction x0
            run_instruction aarch64 skip-fp-simd fp_simd v0
            run_instruction aarch64 replay-fp-simd fp_simd v0
            run_instruction aarch64 skip-control control x0
            run_instruction aarch64 skip-exception exception_instruction x0
            run_instruction aarch64 replay-store store_instruction x0
            run_instruction aarch64 replay-atomic atomic_instruction x0
            run_instruction aarch64 input-mismatch skip x0
            run_instruction aarch64 replay-self-modify self_modify_instruction x0
            run_instruction aarch64 replay-exception replay_exception_instruction x0
            run_instruction aarch64 reject-atomic-skip atomic_instruction x0
            run_instruction aarch64 reject-control-replay control x0
            run_instruction aarch64 reject-destination result x0
            run_instruction aarch64 reject-bytes result x0
            run_instruction aarch64 reject-opcode-class result x0
            run_instruction aarch64 reject-a64-cmp-sp result sp
            run_instruction aarch64 reject-a64-fp-compare-destination result v0
            run_instruction aarch64 reject-a64-shift-imm6 result x0
            run_instruction aarch64 reject-a64-vector-mode result v0
            run_instruction aarch64 reject-a64-exception-encoding result x0
            run_instruction aarch64 reject-a64-fp-type result v0
            run_instruction aarch64 reject-a64-vector-size result v0

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
              -kernel instruction-guest-x86.elf \
              -plugin "$PWD/crucible-instruction.so,architecture=2,mode=result,pc=$x86_result_pc,bytes=$x86_result_bytes,register=rax,selected-address=$x86_result_value_address,iterations-address=$x86_iterations_address,exception-address=$x86_exception_count_address" \
              > logs/patched-tcg-inert.log 2>&1
            patched_tcg_status=$?
            set -e
            cat logs/patched-tcg-inert.log
            test "$patched_tcg_status" -ne 0
            test "$patched_tcg_status" -ne 124
            ! grep -q CRUCIBLE_INSTRUCTION_LIVE_PASS \
              logs/patched-tcg-inert.log

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
              -kernel instruction-guest-x86.elf \
              -plugin "$PWD/crucible-instruction-stock-negative.so" \
              > logs/stock-instruction.log 2>&1
            stock_status=$?
            set -e
            cat logs/stock-instruction.log
            test "$stock_status" -ne 0
            test "$stock_status" -ne 124
            grep -Fq \
              'undefined symbol: qemu_plugin_crucible_fault_submit' \
              logs/stock-instruction.log
            ! grep -q CRUCIBLE_INSTRUCTION_LIVE_PASS \
              logs/stock-instruction.log
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
              echo live_x86_64_result_corruption=true
              echo live_x86_64_skip=true
              echo live_x86_64_replay=true
              echo live_x86_64_exception_before_after=true
              echo live_aarch64_result_corruption=true
              echo live_aarch64_skip=true
              echo live_aarch64_replay=true
              echo live_aarch64_exception_before_after=true
              echo atomic_skip_rejected=true
              echo control_flow_replay_rejected=true
              echo invalid_destination_rejected=true
              echo evidence=instruction_bytes,opcode_class,pc,gpa,vcpu,rr_fingerprints,replay_ordinals,register_delta,exception_record
            } > "$out/result"
          '';
        }
      ];
    }
