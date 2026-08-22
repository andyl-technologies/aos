{
  pkgs,
  lib,
}: let
  fcLib = import ../../lib/testing/firecracker.nix {inherit pkgs lib;};
  workloadSource = builtins.readFile ./phase0-coverage-workload.c;
  pluginSource = builtins.readFile ./phase0-coverage-plugin.c;
  iterations = "20000000";

  workload = pkgs.mkDerivation {
    pname = "crucible-phase0-coverage-workload";
    version = "0";
    src = null;

    source = workloadSource;
    passAsFile = ["source"];

    phases = [
      {
        name = "build";
        script = ''
          cp "$sourcePath" phase0-coverage-workload.c
          cc -std=c11 -O2 -Wall -Wextra phase0-coverage-workload.c -o crucible-coverage-workload
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp crucible-coverage-workload "$out/bin/"
        '';
      }
    ];
  };

  rootfs = fcLib.mkFirecrackerRootfs {
    pname = "crucible-phase0-coverage";
    rootfsDeps = [workload];
    testScript = ''
      crucible-coverage-workload ${iterations}
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-coverage-overhead";
    version = "0";
    src = null;

    plugin = pluginSource;
    passAsFile = ["plugin"];

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.glib
      pkgs.glib.dev
      pkgs.grep
      pkgs.pkg-config
      pkgs.qemu-crucible
    ];

    QEMU = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
    KERNEL = builtins.toString pkgs.linux;
    ROOTFS = builtins.toString rootfs;
    ITERATIONS = iterations;

    phases = [
      {
        name = "build-plugin";
        script = ''
          cp "$pluginPath" phase0-coverage-plugin.c
          cc -fPIC -shared -O2 -Wall -Wextra \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            phase0-coverage-plugin.c \
            -o phase0-coverage-plugin.so
        '';
      }
      {
        name = "run-s8";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          plugin="$PWD/phase0-coverage-plugin.so"
          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-coverage-seed-v1\n' > "$seed"
          : > "$TMPDIR/wall.txt"
          : > "$TMPDIR/samples.tsv"

          run_qemu() {
            label="$1"
            mode="$2"
            cp "$ROOTFS" "$TMPDIR/rootfs-$label.img"
            chmod u+w "$TMPDIR/rootfs-$label.img"

            start_ns=$(date +%s%N)
            if [ "$mode" = none ]; then
              timeout 300 "$QEMU" \
                -nodefaults \
                -no-user-config \
                -display none \
                -monitor none \
                -machine q35 \
                -accel sim,thread=single \
                -icount shift=0,sleep=off,align=off \
                -cpu qemu64 \
                -m 512 \
                -smp 1 \
                -rtc base=2026-01-01T00:00:00,clock=vm \
                -seed 0x0010c001 \
                -fw_cfg name=opt/crucible/seed,file="$seed" \
                -kernel "$vmlinuz" \
                -append "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
                -drive id=rootfs,file="$TMPDIR/rootfs-$label.img",format=raw,if=none,cache=unsafe \
                -device virtio-blk-pci,drive=rootfs \
                -chardev file,id=serial0,path="$TMPDIR/serial-$label.log" \
                -serial chardev:serial0 \
                -no-reboot
            else
              timeout 300 "$QEMU" \
                -nodefaults \
                -no-user-config \
                -display none \
                -monitor none \
                -machine q35 \
                -accel sim,thread=single \
                -icount shift=0,sleep=off,align=off \
                -cpu qemu64 \
                -m 512 \
                -smp 1 \
                -rtc base=2026-01-01T00:00:00,clock=vm \
                -seed 0x0010c001 \
                -fw_cfg name=opt/crucible/seed,file="$seed" \
                -kernel "$vmlinuz" \
                -append "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
                -drive id=rootfs,file="$TMPDIR/rootfs-$label.img",format=raw,if=none,cache=unsafe \
                -device virtio-blk-pci,drive=rootfs \
                -chardev file,id=serial0,path="$TMPDIR/serial-$label.log" \
                -serial chardev:serial0 \
                -plugin "$plugin",mode="$mode",out="$TMPDIR/plugin-$label.txt" \
                -no-reboot
            fi
            end_ns=$(date +%s%N)
            printf '%s_wall_ns=%s\n' "$label" "$((end_ns - start_ns))" >> "$TMPDIR/wall.txt"

            grep -q "TEST_RESULT:PASS" "$TMPDIR/serial-$label.log"
            grep -q "CRUCIBLE_COVERAGE_WORKLOAD" "$TMPDIR/serial-$label.log"
          }

          get_value() {
            file="$1"
            key="$2"
            awk -F= -v key="$key" '$1 == key {print $2}' "$file"
          }

          get_wall() {
            label="$1"
            awk -F= -v key="$label"_wall_ns '$1 == key {print $2}' "$TMPDIR/wall.txt"
          }

          run_rep() {
            rep="$1"
            case "$rep" in
              1)
                run_qemu baseline_1 none
                run_qemu disabled_1 disabled
                run_qemu hook_1 count
                run_qemu coverage_1 coverage
                ;;
              2)
                run_qemu coverage_2 coverage
                run_qemu hook_2 count
                run_qemu baseline_2 none
                run_qemu disabled_2 disabled
                ;;
              3)
                run_qemu disabled_3 disabled
                run_qemu baseline_3 none
                run_qemu coverage_3 coverage
                run_qemu hook_3 count
                ;;
              *)
                echo "unknown repetition: $rep" >&2
                exit 1
                ;;
            esac

            baseline_workload=$(grep "CRUCIBLE_COVERAGE_WORKLOAD" "$TMPDIR/serial-baseline_$rep.log")
            disabled_workload=$(grep "CRUCIBLE_COVERAGE_WORKLOAD" "$TMPDIR/serial-disabled_$rep.log")
            hook_workload=$(grep "CRUCIBLE_COVERAGE_WORKLOAD" "$TMPDIR/serial-hook_$rep.log")
            coverage_workload=$(grep "CRUCIBLE_COVERAGE_WORKLOAD" "$TMPDIR/serial-coverage_$rep.log")
            [ "$baseline_workload" = "$disabled_workload" ]
            [ "$baseline_workload" = "$hook_workload" ]
            [ "$baseline_workload" = "$coverage_workload" ]

            disabled_file="$TMPDIR/plugin-disabled_$rep.txt"
            hook_file="$TMPDIR/plugin-hook_$rep.txt"
            coverage_file="$TMPDIR/plugin-coverage_$rep.txt"

            disabled_mode=$(get_value "$disabled_file" mode)
            hook_mode=$(get_value "$hook_file" mode)
            coverage_mode=$(get_value "$coverage_file" mode)
            hook_retired=$(get_value "$hook_file" retired_instructions)
            coverage_retired=$(get_value "$coverage_file" retired_instructions)
            hook_tb_execs=$(get_value "$hook_file" tb_execs)
            coverage_tb_execs=$(get_value "$coverage_file" tb_execs)
            coverage_entries=$(get_value "$coverage_file" unique_coverage_entries)
            coverage_overflow=$(get_value "$coverage_file" coverage_overflow)
            disabled_icount_failures=$(get_value "$disabled_file" exact_icount_failures)
            hook_icount_failures=$(get_value "$hook_file" exact_icount_failures)
            coverage_icount_failures=$(get_value "$coverage_file" exact_icount_failures)
            hook_icount_regressions=$(get_value "$hook_file" icount_regressions)
            coverage_icount_regressions=$(get_value "$coverage_file" icount_regressions)
            hook_first_entry=$(get_value "$hook_file" first_entry_icount)
            coverage_first_entry=$(get_value "$coverage_file" first_entry_icount)
            hook_last_entry=$(get_value "$hook_file" last_entry_icount)
            coverage_last_entry=$(get_value "$coverage_file" last_entry_icount)
            baseline_wall=$(get_wall baseline_"$rep")
            disabled_wall=$(get_wall disabled_"$rep")
            hook_wall=$(get_wall hook_"$rep")
            coverage_wall=$(get_wall coverage_"$rep")

            [ "$disabled_mode" = disabled ]
            [ "$hook_mode" = count ]
            [ "$coverage_mode" = coverage ]
            [ "$hook_retired" -gt 0 ]
            [ "$coverage_retired" -gt 0 ]
            [ "$hook_tb_execs" -gt 0 ]
            [ "$coverage_tb_execs" -gt 0 ]
            [ "$coverage_entries" -gt 0 ]
            [ "$coverage_overflow" = 0 ]
            [ "$disabled_icount_failures" = 0 ]
            [ "$hook_icount_failures" = 0 ]
            [ "$coverage_icount_failures" = 0 ]
            [ "$hook_icount_regressions" = 0 ]
            [ "$coverage_icount_regressions" = 0 ]
            [ "$hook_first_entry" = 0 ]
            [ "$hook_last_entry" = 0 ]
            [ "$coverage_last_entry" -gt "$coverage_first_entry" ]

            awk \
              -v rep="$rep" \
              -v hook_retired="$hook_retired" \
              -v coverage_retired="$coverage_retired" \
              -v hook_tb_execs="$hook_tb_execs" \
              -v coverage_tb_execs="$coverage_tb_execs" \
              -v coverage_entries="$coverage_entries" \
              -v baseline_wall="$baseline_wall" \
              -v disabled_wall="$disabled_wall" \
              -v hook_wall="$hook_wall" \
              -v coverage_wall="$coverage_wall" \
              'function abs(value) {
                 return value < 0 ? -value : value;
               }
               BEGIN {
                 baseline_ips = hook_retired * 1000000000.0 / baseline_wall;
                 disabled_ips = hook_retired * 1000000000.0 / disabled_wall;
                 hook_ips = hook_retired * 1000000000.0 / hook_wall;
                 coverage_ips = coverage_retired * 1000000000.0 / coverage_wall;
                 disabled_vs_baseline = disabled_ips / baseline_ips;
                 coverage_vs_baseline = coverage_ips / baseline_ips;
                 coverage_vs_hook = coverage_ips / hook_ips;
                 retired_delta = abs(hook_retired - coverage_retired) / hook_retired;
                 tb_exec_delta = abs(hook_tb_execs - coverage_tb_execs) / hook_tb_execs;
                 pass = coverage_vs_baseline >= 0.70 &&
                   coverage_vs_hook >= 0.70 &&
                   retired_delta <= 0.001 &&
                   tb_exec_delta <= 0.001;
                 printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f\t%.2f\t%.2f\t%.2f\t%.4f\t%.4f\t%.4f\t%.6f\t%.6f\n",
                   rep, baseline_wall, disabled_wall, hook_wall, coverage_wall,
                   hook_retired, coverage_retired, hook_tb_execs, coverage_tb_execs,
                   coverage_entries, baseline_ips, disabled_ips, hook_ips, coverage_ips,
                   disabled_vs_baseline, coverage_vs_baseline, coverage_vs_hook,
                   retired_delta, tb_exec_delta;
                 exit(pass ? 0 : 1);
               }' >> "$TMPDIR/samples.tsv"
          }

          run_rep 1
          run_rep 2
          run_rep 3

          mkdir -p "$out"

          awk \
            -v iterations="$ITERATIONS" \
            'BEGIN {
               min_coverage_vs_baseline = 0;
               min_coverage_vs_hook = 0;
               min_disabled_vs_baseline = 0;
               min_coverage_entries = 0;
               max_retired_delta = 0;
               max_tb_exec_delta = 0;
             }
             {
               reps++;
               baseline_wall_sum += $2;
               disabled_wall_sum += $3;
               hook_wall_sum += $4;
               coverage_wall_sum += $5;
               hook_retired_sum += $6;
               coverage_retired_sum += $7;
               hook_tb_execs_sum += $8;
               coverage_tb_execs_sum += $9;
               baseline_ips_sum += $11;
               disabled_ips_sum += $12;
               hook_ips_sum += $13;
               coverage_ips_sum += $14;
               if (reps == 1 || $15 < min_disabled_vs_baseline) {
                 min_disabled_vs_baseline = $15;
               }
               if (reps == 1 || $16 < min_coverage_vs_baseline) {
                 min_coverage_vs_baseline = $16;
               }
               if (reps == 1 || $17 < min_coverage_vs_hook) {
                 min_coverage_vs_hook = $17;
               }
               if (reps == 1 || $10 < min_coverage_entries) {
                 min_coverage_entries = $10;
               }
               if ($18 > max_retired_delta) {
                 max_retired_delta = $18;
               }
               if ($19 > max_tb_exec_delta) {
                 max_tb_exec_delta = $19;
               }
             }
             END {
               pass = reps == 3 &&
                 min_coverage_vs_baseline >= 0.70 &&
                 min_coverage_vs_hook >= 0.70 &&
                 max_retired_delta <= 0.001 &&
                 max_tb_exec_delta <= 0.001;
               print pass ? "PASS" : "FAIL";
               print "spike=tcg-exec-coverage-overhead";
               print "workload_iterations=" iterations;
               print "repetitions=" reps;
               print "baseline_retired_reference=hook_off_retired_instructions";
               print "coverage_representation=translated_tb_id_set_first_execution";
               print "guest_output_across_coverage_modes=identical";
               print "exact_tb_entry_icount=nonmutating-helper-no-failures-or-regressions";
               print "coverage_plugin_scope=c-abi-probe-not-production-rust-plugin";
               print "canonical_st_fingerprint_compared=false";
               printf "baseline_wall_ns_avg=%.0f\n", baseline_wall_sum / reps;
               printf "disabled_wall_ns_avg=%.0f\n", disabled_wall_sum / reps;
               printf "hook_off_wall_ns_avg=%.0f\n", hook_wall_sum / reps;
               printf "coverage_on_wall_ns_avg=%.0f\n", coverage_wall_sum / reps;
               printf "hook_off_retired_instructions_avg=%.0f\n", hook_retired_sum / reps;
               printf "coverage_on_retired_instructions_avg=%.0f\n", coverage_retired_sum / reps;
               printf "hook_off_tb_execs_avg=%.0f\n", hook_tb_execs_sum / reps;
               printf "coverage_on_tb_execs_avg=%.0f\n", coverage_tb_execs_sum / reps;
               printf "coverage_unique_entries_min=%.0f\n", min_coverage_entries;
               printf "baseline_ips_avg=%.2f\n", baseline_ips_sum / reps;
               printf "disabled_ips_avg=%.2f\n", disabled_ips_sum / reps;
               printf "hook_off_ips_avg=%.2f\n", hook_ips_sum / reps;
               printf "coverage_on_ips_avg=%.2f\n", coverage_ips_sum / reps;
               printf "disabled_on_vs_baseline_min=%.4f\n", min_disabled_vs_baseline;
               printf "coverage_on_vs_baseline_min=%.4f\n", min_coverage_vs_baseline;
               printf "coverage_on_vs_hook_off_min=%.4f\n", min_coverage_vs_hook;
               printf "max_retired_instruction_delta=%.6f\n", max_retired_delta;
               printf "max_tb_exec_delta=%.6f\n", max_tb_exec_delta;
               print "coverage_budget_min=0.7000";
               exit(pass ? 0 : 1);
             }' "$TMPDIR/samples.tsv" > "$out/result"

          cp "$TMPDIR/samples.tsv" "$out/samples.tsv"
          cp "$TMPDIR"/plugin-*.txt "$out/"
          cp "$TMPDIR"/serial-*.log "$out/"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 TCG-exec coverage overhead spike";
    };
  }
