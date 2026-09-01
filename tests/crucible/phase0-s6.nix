{
  pkgs,
  lib,
}: let
  boundedSchedulerPreemptionCheck = import ./phase0-bounded-scheduler-preemption.nix {inherit pkgs lib;};
  cadence = 200000000;
  horizon = 3600000000;
  rrSwitchQuantum = 4096;
  probeSource = builtins.readFile ./phase0-s6-probe.c;

  probe = pkgs.mkDerivation {
    pname = "crucible-phase0-s6-probe";
    version = "0";
    src = null;

    probe = probeSource;
    passAsFile = ["probe"];

    phases = [
      {
        name = "build-probe";
        script = ''
          mkdir -p "$out/bin"
          cp "$probePath" phase0-s6-probe.c
          cc -std=c11 -O2 -Wall -Wextra -Werror \
            phase0-s6-probe.c \
            -o "$out/bin/s6-probe"

          cat > s6-spin.c <<'SPIN_C'
          #include <stdint.h>

          enum {
            ITERS = 600000000
          };

          static volatile uint64_t sink;

          int main(void) {
            uint64_t state = 0x0010c0065eedULL;

            for (uint64_t i = 0; i < ITERS; i++) {
              state ^= i + 0x9e3779b97f4a7c15ULL;
              state = (state << 11) | (state >> 53);
              state *= 0xbf58476d1ce4e5b9ULL;
            }

            sink = state;
            return sink == 0 ? 1 : 0;
          }
          SPIN_C

          cc -std=c11 -O2 -Wall -Wextra -Werror \
            s6-spin.c \
            -o "$out/bin/s6-spin"
        '';
      }
    ];
  };

  rebootHelper = pkgs.mkDerivation {
    pname = "crucible-phase0-s6-reboot";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-reboot-helper";
        script = ''
          mkdir -p "$out/bin"

          cat > reboot.c <<'REBOOT_C'
          #include <stdio.h>
          #include <sys/reboot.h>
          #include <unistd.h>

          int main(void) {
            sync();
            if (reboot(RB_AUTOBOOT) != 0) {
              perror("reboot");
              return 1;
            }
            return 0;
          }
          REBOOT_C

          cc reboot.c -o "$out/bin/s6-reboot"
        '';
      }
    ];
  };

  initramfs = let
    initramfsDeps = [
      pkgs.bash
      pkgs.coreutils
      probe
      rebootHelper
    ];
    depPaths = builtins.concatStringsSep ":" (
      builtins.concatMap (
        dep: let
          base = builtins.toString dep;
        in [
          "${base}/bin"
          "${base}/sbin"
        ]
      )
      initramfsDeps
    );
    graphPairs =
      lib.concatLists
      (lib.imap (i: dep: [
          "closure-${builtins.toString i}"
          dep
        ])
        initramfsDeps);
  in
    pkgs.mkDerivation {
      pname = "crucible-phase0-s6-initramfs";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.cpio
        pkgs.findutils
        pkgs.grep
        pkgs.pigz
      ];

      exportReferencesGraph = graphPairs;

      phases = [
        {
          name = "build-initramfs";
          script = ''
            set -eu

            grep -h '^/nix/store/' closure-* | sort -u > closure-paths

            mkdir -p root/bin root/sbin root/nix/store root/tmp root/proc root/sys root/dev root/run
            while IFS= read -r p; do
              cp -a "$p" root"$p"
            done < closure-paths

            ln -sfn ${pkgs.bash}/bin/bash root/bin/sh
            ln -sfn ${pkgs.bash}/bin/bash root/bin/bash
            ln -sfn ${rebootHelper}/bin/s6-reboot root/sbin/reboot

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            echo "CRUCIBLE_S6_READY"
            test_result=0
            s6-probe || test_result=1

            if [ "$test_result" -eq 0 ]; then
              echo 'TEST_RESULT:PASS'
            else
              echo 'TEST_RESULT:FAIL'
            fi

            sync
            s6-spin
            reboot
            INIT
            chmod +x root/init

            mkdir -p "$out"
            (
              cd root
              find . -print0 \
                | LC_ALL=C sort -z \
                | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
                | pigz -9 -n -p "''${NIX_BUILD_CORES:-1}" > "$out/initrd.img"
            )
          '';
        }
      ];

      meta = {
        description = "Crucible Phase 0 S6 diskless initramfs";
      };
    };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s6-kaslr-aslr";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.grep
      pkgs.jq
      pkgs.qemu-crucible
      pkgs.socat
      pkgs.crucible-qemu-trace-plugin
    ];

    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL = builtins.toString pkgs.linux;
    PLUGIN = "${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so";
    CADENCE = builtins.toString cadence;
    HORIZON = builtins.toString horizon;
    RR_SWITCH_QUANTUM = builtins.toString rrSwitchQuantum;
    BOUNDED_PREEMPTION_HARNESS = ./_bounded-scheduler-preemption.sh;
    BOUNDED_PREEMPTION_TARGET_WRAPPER = ./_bounded-scheduler-preemption-target.sh;
    BOUNDED_PREEMPTION_CHECK = boundedSchedulerPreemptionCheck;

    phases = [
      {
        name = "run-s6-kaslr-aslr-fingerprint";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true
          grep -Fxq PASS "$BOUNDED_PREEMPTION_CHECK/result"

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          bool_eq() {
            if [ "$1" = "$2" ]; then
              printf true
            else
              printf false
            fi
          }

          bool_ne() {
            if [ "$1" != "$2" ]; then
              printf true
            else
              printf false
            fi
          }

          bool_nonzero_hex() {
            case "$1" in
              0 | 0000000000000000)
                printf false
                ;;
              *)
                printf true
                ;;
            esac
          }

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          if [ -z "$vmlinuz" ]; then
            fail "no vmlinuz under $KERNEL/boot"
          fi

          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-s6-seed-v1\n' > "$seed"

          . "$BOUNDED_PREEMPTION_HARNESS"
          trap 'bounded_preemption_cleanup' EXIT
          trap 'bounded_preemption_cleanup; exit 143' TERM
          trap 'bounded_preemption_cleanup; exit 130' INT

          qmp_cmd() {
            socket="$1"
            request="$2"
            response="$3"
            response_err="$response.err"

            {
              printf '{"execute":"qmp_capabilities"}\r\n'
              printf '%s\r\n' "$request"
            } | socat -T 1 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

            if [ ! -s "$response" ]; then
              cat "$response_err" >&2
              return 1
            fi

            if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
              cat "$response" >&2
              return 1
            fi
            jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null
          }

          wait_for_socket() {
            socket="$1"
            waited=0
            while [ "$waited" -lt 600 ]; do
              if [ -S "$socket" ]; then
                return 0
              fi
              sleep 0.1
              waited=$((waited + 1))
            done
            return 1
          }

          wait_for_horizon_pause() {
            label="$1"
            socket="$2"
            waited=0
            qmp_failures=0
            while [ "$waited" -lt 1200 ]; do
              if qmp_cmd "$socket" '{"execute":"query-status"}' "$TMPDIR/qmp-status-$label.json"; then
                qmp_failures=0
                status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$TMPDIR/qmp-status-$label.json")
                case "$status" in
                  paused)
                    return 0
                    ;;
                  shutdown | internal-error | guest-panicked)
                    cat "$TMPDIR/qmp-status-$label.json" >&2
                    return 1
                    ;;
                esac
              else
                qmp_failures=$((qmp_failures + 1))
                if [ "$qmp_failures" -ge 10 ]; then
                  echo "QMP did not return query-status for guest $label" >&2
                  if [ -f "$TMPDIR/qmp-status-$label.json" ]; then
                    cat "$TMPDIR/qmp-status-$label.json" >&2
                  fi
                  return 1
                fi
              fi
              sleep 0.5
              waited=$((waited + 1))
            done
            if [ -f "$TMPDIR/qmp-status-$label.json" ]; then
              cat "$TMPDIR/qmp-status-$label.json" >&2
            fi
            return 1
          }

          wait_for_guest_pass() {
            label="$1"
            serial="$TMPDIR/serial-$label.log"
            waited=0
            while [ "$waited" -lt 1200 ]; do
              if [ -f "$serial" ] \
                && grep -q "TEST_RESULT:PASS" "$serial" \
                && grep -q "CRUCIBLE_S6_DONE" "$serial"; then
                return 0
              fi
              sleep 0.5
              waited=$((waited + 1))
            done
            return 1
          }

          run_one() {
            mode="$1"
            suffix="$2"
            label="$mode-$suffix"
            qmp_socket="$TMPDIR/qmp-$label.sock"
            rm -f "$qmp_socket"

            append="console=ttyS0 reboot=k panic=1 rdinit=/init quiet random.trust_cpu=off net.ifnames=0 crucible_s6_mode=$mode"
            case "$mode" in
              control)
                append="$append nokaslr norandmaps"
                ;;
              kaslr)
                ;;
              *)
                fail "unknown S6 mode $mode"
                ;;
            esac

            set -- qemu-system-x86_64 \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel sim,thread=single \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum="$RR_SWITCH_QUANTUM" \
              -cpu qemu64 \
              -m 256 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c006 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -object rng-builtin,id=rng0 \
              -device virtio-rng-pci,rng=rng0 \
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "$append" \
              -chardev file,id=serial0,path="$TMPDIR/serial-$label.log" \
              -serial chardev:serial0 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -plugin "$PLUGIN",out="$TMPDIR/trace-$label.jsonl",cadence="$CADENCE",stop_at="$HORIZON",extended=on,mem_events=off,vcpus=1 \
              -no-shutdown \
              -no-reboot

            printf '%s\n' "$@" > "$TMPDIR/qemu-args-$label.txt"
            if grep -E -q '^-drive$|^-blockdev$|^-cdrom$|^-hda$|^-hdb$|^-hdc$|^-hdd$|virtio-blk|scsi|nvme|ahci|ide-' "$TMPDIR/qemu-args-$label.txt"; then
              fail "guest $label launch is not diskless"
            fi

            case "$mode" in
              control)
                grep -F -q nokaslr "$TMPDIR/qemu-args-$label.txt" \
                  || fail "control launch omitted nokaslr"
                grep -F -q norandmaps "$TMPDIR/qemu-args-$label.txt" \
                  || fail "control launch omitted norandmaps"
                ;;
              kaslr)
                if grep -E -q 'nokaslr|norandmaps' "$TMPDIR/qemu-args-$label.txt"; then
                  fail "randomization-enabled launch still contains conservative flags"
                fi
                ;;
            esac

            qemu_binary=$(command -v "$1")
            bounded_preemption_launch_qemu \
              1200 "$TMPDIR/qemu-target-$label.pid" - "$qemu_binary" "$@" \
              || fail "guest $label QEMU launch failed"

            wait_for_socket "$qmp_socket" || fail "guest $label QMP socket did not appear"
            if [ "''${label##*-}" = b ]; then
              # ASLR/KASLR fingerprints must depend on scenario inputs, never
              # on host scheduling. The first trace coordinate proves guest
              # execution is active before finite preemption begins; no
              # synthetic busy CPU time is consumed.
              progress_needle="\"observed_icount\":$CADENCE"
              bounded_preemption_wait_for_guest_progress \
                "$TMPDIR/trace-$label.jsonl" "$progress_needle" 12000 0.1 \
                || fail "guest $label made no pre-adversary trace progress"
              bounded_preemption_start \
                "$TMPDIR/preemption-$label.log" \
                "$TMPDIR/trace-$label.jsonl" "$progress_needle" \
                || fail "guest $label scheduler adversary did not start"
            fi

            wait_for_horizon_pause "$label" "$qmp_socket" \
              || fail "guest $label did not pause at horizon"
            if ! wait_for_guest_pass "$label"; then
              if [ -f "$TMPDIR/serial-$label.log" ]; then
                cat "$TMPDIR/serial-$label.log" >&2
              fi
              fail "guest $label did not report TEST_RESULT:PASS before horizon"
            fi
            if [ "''${label##*-}" = b ]; then
              bounded_preemption_finish "$TMPDIR/preemption-$label.log" \
                || fail "guest $label scheduler adversary was incomplete"
            fi
            qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" || true
            bounded_preemption_wait_qemu \
              || fail "guest $label QEMU exited unsuccessfully"
          }

          run_pair() {
            mode="$1"
            run_one "$mode" a
            run_one "$mode" b
          }

          extract_bases() {
            label="$1"
            mode="$2"
            serial="$TMPDIR/serial-$label.log"
            line=$(grep -F "CRUCIBLE_S6_BASES mode=$mode " "$serial" | tail -1 || true)
            if [ -z "$line" ]; then
              cat "$serial" >&2
              fail "missing S6 base line for $label"
            fi

            printf '%s\n' "$line" > "$TMPDIR/bases-$label.line"
            printf '%s\n' "$line" \
              | tr ' ' '\n' \
              | gawk -F= 'NF == 2 { print $1 "=" $2 }' \
              | sort > "$TMPDIR/bases-$label.kv"
          }

          get_kv() {
            label="$1"
            key="$2"
            gawk -F= -v key="$key" '
              $1 == key { print $2; found = 1 }
              END { if (!found) exit 1 }
            ' "$TMPDIR/bases-$label.kv"
          }

          compare_trace() {
            mode="$1"
            left="$TMPDIR/trace-$mode-a.jsonl"
            right="$TMPDIR/trace-$mode-b.jsonl"
            comparable_left="$TMPDIR/trace-$mode-a-comparable.jsonl"
            comparable_right="$TMPDIR/trace-$mode-b-comparable.jsonl"

            sed "s/$mode-a/$mode-run/g" "$TMPDIR/qemu-args-$mode-a.txt" \
              > "$TMPDIR/qemu-args-$mode-a-canonical.txt"
            sed "s/$mode-b/$mode-run/g" "$TMPDIR/qemu-args-$mode-b.txt" \
              > "$TMPDIR/qemu-args-$mode-b-canonical.txt"
            if ! diff -u \
              "$TMPDIR/qemu-args-$mode-a-canonical.txt" \
              "$TMPDIR/qemu-args-$mode-b-canonical.txt" \
              > "$out/qemu-args-$mode.diff"; then
              fail "$mode S6 launches differ beyond run-local output paths"
            fi

            # QEMU attests the exact process argv, including the serial, QMP,
            # and trace output paths. Those paths contain the run label and
            # therefore differ by construction. The canonical argv comparison
            # above proves that this is the only launch difference before the
            # path-sensitive digest is removed from the execution comparison.
            jq -c 'del(.process_argv_digest)' "$left" > "$comparable_left"
            jq -c 'del(.process_argv_digest)' "$right" > "$comparable_right"

            samples_a=$(wc -l < "$left")
            samples_b=$(wc -l < "$right")
            echo "$samples_a" > "$TMPDIR/samples-$mode-a"
            echo "$samples_b" > "$TMPDIR/samples-$mode-b"

            if diff -u "$comparable_left" "$comparable_right" > "$out/trace-$mode.diff"; then
              echo true > "$TMPDIR/trace-$mode-match"
              echo none > "$TMPDIR/first-differing-line-$mode"
              echo none > "$TMPDIR/first-differing-component-$mode"
              return 0
            fi

            echo false > "$TMPDIR/trace-$mode-match"
            gawk '
              NR == FNR { left[FNR] = $0; next }
              left[FNR] != $0 {
                print FNR "\t" left[FNR] "\t" $0
                exit 0
              }
            ' "$comparable_left" "$comparable_right" > "$TMPDIR/first-difference-$mode.tsv"
            first_differing_line=$(cut -f1 "$TMPDIR/first-difference-$mode.tsv")
            left_json=$(cut -f2 "$TMPDIR/first-difference-$mode.tsv")
            right_json=$(cut -f3 "$TMPDIR/first-difference-$mode.tsv")
            printf '%s\n' "$left_json" > "$TMPDIR/first-left-$mode.json"
            printf '%s\n' "$right_json" > "$TMPDIR/first-right-$mode.json"
            first_differing_component=$(
              jq -n -r \
                --slurpfile left "$TMPDIR/first-left-$mode.json" \
                --slurpfile right "$TMPDIR/first-right-$mode.json" \
                '
                  def component:
                    if $left[0].retired != $right[0].retired then "retired"
                    elif $left[0].vcpu != $right[0].vcpu then "vcpu"
                    elif $left[0].process_argv_attestation_version != $right[0].process_argv_attestation_version then "process_argv_attestation_version"
                    elif $left[0].process_argv_encoding != $right[0].process_argv_encoding then "process_argv_encoding"
                    elif $left[0].process_argv_argc != $right[0].process_argv_argc then "process_argv_argc"
                    elif $left[0].process_argv_raw_bytes != $right[0].process_argv_raw_bytes then "process_argv_raw_bytes"
                    elif $left[0].process_argv_status != $right[0].process_argv_status then "process_argv_status"
                    elif $left[0].stream_hash != $right[0].stream_hash then "stream_hash"
                    elif $left[0].register_counts != $right[0].register_counts then "register_counts[0]"
                    elif $left[0].register_digests != $right[0].register_digests then "register_digests[0]"
                    elif $left[0].ram_digest != $right[0].ram_digest then "ram_digest"
                    elif $left[0].device_event_hash != $right[0].device_event_hash then "device_event_hash"
                    elif $left[0].diagnostic_extended_fnv != $right[0].diagnostic_extended_fnv then "diagnostic_extended_fnv"
                    else "unknown"
                    end;
                  component
                '
            )
            echo "$first_differing_line" > "$TMPDIR/first-differing-line-$mode"
            echo "$first_differing_component" > "$TMPDIR/first-differing-component-$mode"
            return 1
          }

          diagnose_trace_structure() {
            label="$1"
            jq -c -s '
              map({
                schema,
                final,
                tracked_vcpus,
                stop_at,
                sample_register_failures,
                register_read_failures,
                process_argv_attestation_version,
                process_argv_encoding,
                process_argv_argc,
                process_argv_raw_bytes,
                process_argv_digest,
                process_argv_status,
                ram_bytes,
                ram_digest,
                memory_events_enabled,
                device_event_capture,
                device_event_hash,
                register_digests,
                register_counts,
                register_file_bytes,
                register_schema_digests
              })
            ' "$TMPDIR/trace-$label.jsonl" >&2 || true
          }

          run_pair control
          run_pair kaslr

          mkdir -p "$out"
          cp "$TMPDIR/preemption-control-b.log" "$out/preemption-control-b.log"
          cp "$TMPDIR/preemption-kaslr-b.log" "$out/preemption-kaslr-b.log"

          for label in control-a control-b kaslr-a kaslr-b; do
            if ! jq -e -s --argjson horizon "$HORIZON" \
              --argjson rr_switch_quantum "$RR_SWITCH_QUANTUM" '
              length >= 2
              and all(.[]; (
                .schema == "crucible.qemu.trace-fingerprint.v6"
                and .tracked_vcpus == 1
                and .stop_at == $horizon
                and .sample_register_failures == 0
                and .register_read_failures == 0
                and .rr_current_vcpu == 0
                and .rr_switch_quantum == $rr_switch_quantum
                and .rr_cursor_valid == true
                and .rr_cursor_position < .rr_switch_quantum
                and .process_argv_attestation_version == 2
                and .process_argv_encoding == "raw-unix-argv-v2"
                and .process_argv_argc > 0
                and .process_argv_raw_bytes > 0
                and (.process_argv_digest | test("^[0-9a-f]{64}$"))
                and .process_argv_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                and .process_argv_status == 0
                and .ram_bytes > 0
                and (.ram_digest | test("^[0-9a-f]{64}$"))
                and .ram_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                and .memory_events_enabled == false
                and .device_event_capture == false
                and .device_event_hash == null
                and (.register_digests | type == "array")
                and (.register_digests | length) == 1
                and (.register_digests[0] | test("^[0-9a-f]{64}$"))
                and .register_digests[0] != "0000000000000000000000000000000000000000000000000000000000000000"
                and (.register_counts | type == "array")
                and (.register_counts | length) == 1
                and .register_counts[0] > 0
                and (.register_file_bytes | type == "array")
                and (.register_file_bytes | length) == 1
                and .register_file_bytes[0] > 0
                and (.register_schema_digests | type == "array")
                and (.register_schema_digests | length) == 1
                and (.register_schema_digests[0] | test("^[0-9a-f]{64}$"))
                and .register_schema_digests[0] != "0000000000000000000000000000000000000000000000000000000000000000"
              ))
              and ([.[].process_argv_digest] | unique | length) == 1
              and any(.[]; .final == true)
            ' "$TMPDIR/trace-$label.jsonl" >/dev/null; then
              diagnose_trace_structure "$label"
              fail "trace $label failed structural S6 assertions"
            fi
          done

          for label in control-a control-b; do
            extract_bases "$label" control
          done
          for label in kaslr-a kaslr-b; do
            extract_bases "$label" kaslr
          done

          compare_trace control || fail "control S6 fingerprint mismatch"
          control_trace_match=$(cat "$TMPDIR/trace-control-match")
          control_samples_a=$(cat "$TMPDIR/samples-control-a")
          control_samples_b=$(cat "$TMPDIR/samples-control-b")
          [ "$control_samples_a" = "$control_samples_b" ] \
            || fail "control sample count mismatch: $control_samples_a/$control_samples_b"

          if cmp -s "$TMPDIR/bases-control-a.kv" "$TMPDIR/bases-control-b.kv"; then
            control_bases_match=true
          else
            control_bases_match=false
          fi
          [ "$control_bases_match" = true ] || fail "control base report mismatch"

          compare_trace kaslr || true
          kaslr_trace_match=$(cat "$TMPDIR/trace-kaslr-match")
          kaslr_samples_a=$(cat "$TMPDIR/samples-kaslr-a")
          kaslr_samples_b=$(cat "$TMPDIR/samples-kaslr-b")
          kaslr_sample_count_match=$(bool_eq "$kaslr_samples_a" "$kaslr_samples_b")

          if cmp -s "$TMPDIR/bases-kaslr-a.kv" "$TMPDIR/bases-kaslr-b.kv"; then
            kaslr_bases_match=true
          else
            kaslr_bases_match=false
          fi

          control_randomize_va_space=$(get_kv control-a randomize_va_space)
          kaslr_randomize_va_space=$(get_kv kaslr-a randomize_va_space)
          control_kernel_text=$(get_kv control-a kernel_text)
          kaslr_kernel_text_a=$(get_kv kaslr-a kernel_text)
          kaslr_kernel_text_b=$(get_kv kaslr-b kernel_text)
          control_stack=$(get_kv control-a stack)
          kaslr_stack_a=$(get_kv kaslr-a stack)
          kaslr_stack_b=$(get_kv kaslr-b stack)
          control_heap=$(get_kv control-a heap)
          kaslr_heap_a=$(get_kv kaslr-a heap)
          kaslr_heap_b=$(get_kv kaslr-b heap)
          control_brk=$(get_kv control-a brk)
          kaslr_brk_a=$(get_kv kaslr-a brk)
          kaslr_brk_b=$(get_kv kaslr-b brk)
          control_mmap=$(get_kv control-a mmap)
          kaslr_mmap_a=$(get_kv kaslr-a mmap)
          kaslr_mmap_b=$(get_kv kaslr-b mmap)
          control_vdso=$(get_kv control-a vdso)
          kaslr_vdso_a=$(get_kv kaslr-a vdso)
          kaslr_vdso_b=$(get_kv kaslr-b vdso)

          kernel_text_nonzero=$(bool_nonzero_hex "$kaslr_kernel_text_a")
          kernel_base_identical=$(bool_eq "$kaslr_kernel_text_a" "$kaslr_kernel_text_b")
          stack_base_identical=$(bool_eq "$kaslr_stack_a" "$kaslr_stack_b")
          heap_base_identical=$(bool_eq "$kaslr_heap_a" "$kaslr_heap_b")
          brk_base_identical=$(bool_eq "$kaslr_brk_a" "$kaslr_brk_b")
          mmap_base_identical=$(bool_eq "$kaslr_mmap_a" "$kaslr_mmap_b")
          vdso_base_identical=$(bool_eq "$kaslr_vdso_a" "$kaslr_vdso_b")
          kernel_base_differs_from_control=$(bool_ne "$kaslr_kernel_text_a" "$control_kernel_text")
          stack_base_differs_from_control=$(bool_ne "$kaslr_stack_a" "$control_stack")
          heap_base_differs_from_control=$(bool_ne "$kaslr_heap_a" "$control_heap")
          brk_base_differs_from_control=$(bool_ne "$kaslr_brk_a" "$control_brk")
          mmap_base_differs_from_control=$(bool_ne "$kaslr_mmap_a" "$control_mmap")
          vdso_base_differs_from_control=$(bool_ne "$kaslr_vdso_a" "$control_vdso")

          if [ "$control_randomize_va_space" = 0 ] \
            && [ "$kaslr_randomize_va_space" = 2 ] \
            && [ "$kaslr_trace_match" = true ] \
            && [ "$kaslr_sample_count_match" = true ] \
            && [ "$kaslr_bases_match" = true ] \
            && [ "$kernel_text_nonzero" = true ] \
            && [ "$kernel_base_identical" = true ] \
            && [ "$stack_base_identical" = true ] \
            && [ "$heap_base_identical" = true ] \
            && [ "$brk_base_identical" = true ] \
            && [ "$mmap_base_identical" = true ] \
            && [ "$vdso_base_identical" = true ] \
            && [ "$kernel_base_differs_from_control" = true ] \
            && [ "$stack_base_differs_from_control" = true ] \
            && [ "$heap_base_differs_from_control" = true ] \
            && [ "$brk_base_differs_from_control" = true ] \
            && [ "$mmap_base_differs_from_control" = true ] \
            && [ "$vdso_base_differs_from_control" = true ]; then
            randomization_reenabled_capability=true
            fallback_adopted=none
            default_decision=randomization_may_be_enabled_per_image
            result_status=PASS
          else
            randomization_reenabled_capability=false
            fallback_adopted=keep_nokaslr_norandmaps
            default_decision=keep_conservative_randomization_flags
            result_status=PASS_WITH_FALLBACK
          fi

          final_line=$(grep '"final":true' "$TMPDIR/trace-kaslr-a.jsonl" | tail -1)
          final_extended_hash=$(printf '%s\n' "$final_line" | jq -r '.diagnostic_extended_fnv')
          final_register_hash=$(printf '%s\n' "$final_line" | jq -r '.register_digests[0]')
          final_ram_hash=$(printf '%s\n' "$final_line" | jq -r '.ram_digest')
          final_ram_bytes=$(printf '%s\n' "$final_line" | jq -r '.ram_bytes')
          final_device_event_hash=$(printf '%s\n' "$final_line" | jq -r '.device_event_hash')
          final_memory_events=$(printf '%s\n' "$final_line" | jq -r '.memory_events')
          final_io_events=$(printf '%s\n' "$final_line" | jq -r '.io_events')
          final_register_read_failures=$(printf '%s\n' "$final_line" | jq -r '.register_read_failures')
          control_process_argv_digest_a=$(jq -r -s '.[0].process_argv_digest' "$TMPDIR/trace-control-a.jsonl")
          control_process_argv_digest_b=$(jq -r -s '.[0].process_argv_digest' "$TMPDIR/trace-control-b.jsonl")
          kaslr_process_argv_digest_a=$(jq -r -s '.[0].process_argv_digest' "$TMPDIR/trace-kaslr-a.jsonl")
          kaslr_process_argv_digest_b=$(jq -r -s '.[0].process_argv_digest' "$TMPDIR/trace-kaslr-b.jsonl")

          cp "$TMPDIR"/trace-control-a.jsonl "$out/trace-control-a.jsonl"
          cp "$TMPDIR"/trace-control-b.jsonl "$out/trace-control-b.jsonl"
          cp "$TMPDIR"/trace-kaslr-a.jsonl "$out/trace-kaslr-a.jsonl"
          cp "$TMPDIR"/trace-kaslr-b.jsonl "$out/trace-kaslr-b.jsonl"
          cp "$TMPDIR"/serial-control-a.log "$out/serial-control-a.log"
          cp "$TMPDIR"/serial-control-b.log "$out/serial-control-b.log"
          cp "$TMPDIR"/serial-kaslr-a.log "$out/serial-kaslr-a.log"
          cp "$TMPDIR"/serial-kaslr-b.log "$out/serial-kaslr-b.log"
          cp "$TMPDIR"/qemu-args-control-a.txt "$out/qemu-args-control-a.txt"
          cp "$TMPDIR"/qemu-args-control-b.txt "$out/qemu-args-control-b.txt"
          cp "$TMPDIR"/qemu-args-kaslr-a.txt "$out/qemu-args-kaslr-a.txt"
          cp "$TMPDIR"/qemu-args-kaslr-b.txt "$out/qemu-args-kaslr-b.txt"
          cp "$TMPDIR"/qemu-args-control-a-canonical.txt "$out/qemu-args-control-a-canonical.txt"
          cp "$TMPDIR"/qemu-args-control-b-canonical.txt "$out/qemu-args-control-b-canonical.txt"
          cp "$TMPDIR"/qemu-args-kaslr-a-canonical.txt "$out/qemu-args-kaslr-a-canonical.txt"
          cp "$TMPDIR"/qemu-args-kaslr-b-canonical.txt "$out/qemu-args-kaslr-b-canonical.txt"
          cp "$TMPDIR"/bases-control-a.kv "$out/bases-control-a.kv"
          cp "$TMPDIR"/bases-control-b.kv "$out/bases-control-b.kv"
          cp "$TMPDIR"/bases-kaslr-a.kv "$out/bases-kaslr-a.kv"
          cp "$TMPDIR"/bases-kaslr-b.kv "$out/bases-kaslr-b.kv"

          {
            echo "$result_status"
            echo spike=kaslr-aslr-determinism
            echo check=checks.crucible.phase0.s6KaslrAslr
            echo scenario=stock-linux-diskless-initramfs-kaslr-aslr
            echo boot_medium=initramfs
            echo block_devices=0
            echo vcpus=1
            echo cadence="$CADENCE"
            echo horizon_icount="$HORIZON"
            echo host_adversary=bounded-scheduler-preemption
            echo host_adversary_perturbations_per_run=6
            echo host_adversary_runs=2
            echo host_adversary_configured_pause_milliseconds=15
            echo host_adversary_configured_total_stopped_milliseconds_per_run=90
            echo host_adversary_nominal_worker_wall_milliseconds_per_run=95
            echo host_adversary_worker_wall_timeout_seconds=2
            echo host_adversary_busy_workers=0
            echo qemu_internal_seed=0x0010c006
            echo guest_entropy_seed=fw_cfg_and_deterministic_virtio_rng
            echo process_argv_comparison=canonical_launch_with_run_local_output_paths_normalized
            echo trace_comparison=process_argv_digest_excluded_after_canonical_argv_match
            echo control_process_argv_digest_a="$control_process_argv_digest_a"
            echo control_process_argv_digest_b="$control_process_argv_digest_b"
            echo randomized_process_argv_digest_a="$kaslr_process_argv_digest_a"
            echo randomized_process_argv_digest_b="$kaslr_process_argv_digest_b"
            echo control_cmdline_has_nokaslr_norandmaps=true
            echo randomized_cmdline_has_nokaslr_norandmaps=false
            echo control_fingerprint_match="$control_trace_match"
            echo control_bases_identical="$control_bases_match"
            echo control_samples="$control_samples_a"
            echo randomized_fingerprint_match="$kaslr_trace_match"
            echo randomized_sample_count_match="$kaslr_sample_count_match"
            echo randomized_bases_identical="$kaslr_bases_match"
            echo randomized_samples_a="$kaslr_samples_a"
            echo randomized_samples_b="$kaslr_samples_b"
            echo control_randomize_va_space="$control_randomize_va_space"
            echo randomized_randomize_va_space="$kaslr_randomize_va_space"
            echo kernel_text_nonzero="$kernel_text_nonzero"
            echo kernel_base_identical="$kernel_base_identical"
            echo stack_base_identical="$stack_base_identical"
            echo heap_base_identical="$heap_base_identical"
            echo brk_base_identical="$brk_base_identical"
            echo mmap_base_identical="$mmap_base_identical"
            echo vdso_base_identical="$vdso_base_identical"
            echo kernel_base_differs_from_control="$kernel_base_differs_from_control"
            echo stack_base_differs_from_control="$stack_base_differs_from_control"
            echo heap_base_differs_from_control="$heap_base_differs_from_control"
            echo brk_base_differs_from_control="$brk_base_differs_from_control"
            echo mmap_base_differs_from_control="$mmap_base_differs_from_control"
            echo vdso_base_differs_from_control="$vdso_base_differs_from_control"
            echo control_kernel_text="$control_kernel_text"
            echo randomized_kernel_text="$kaslr_kernel_text_a"
            echo control_stack="$control_stack"
            echo randomized_stack="$kaslr_stack_a"
            echo control_heap="$control_heap"
            echo randomized_heap="$kaslr_heap_a"
            echo control_brk="$control_brk"
            echo randomized_brk="$kaslr_brk_a"
            echo control_mmap="$control_mmap"
            echo randomized_mmap="$kaslr_mmap_a"
            echo control_vdso="$control_vdso"
            echo randomized_vdso="$kaslr_vdso_a"
            echo final_extended_hash="$final_extended_hash"
            echo final_register_hash="$final_register_hash"
            echo final_ram_hash="$final_ram_hash"
            echo final_ram_bytes="$final_ram_bytes"
            echo final_device_event_hash="$final_device_event_hash"
            echo final_memory_events="$final_memory_events"
            echo final_io_events="$final_io_events"
            echo register_read_failures="$final_register_read_failures"
            echo rr_switch_quantum="$RR_SWITCH_QUANTUM"
            echo device_event_capture=false
            echo block_device_assertion=launch_argv_scan
            echo first_differing_line=$(cat "$TMPDIR/first-differing-line-kaslr")
            echo first_differing_component=$(cat "$TMPDIR/first-differing-component-kaslr")
            echo randomization_reenabled_capability="$randomization_reenabled_capability"
            echo default_decision="$default_decision"
            echo fallback_adopted="$fallback_adopted"
            echo s6_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S6 KASLR/ASLR determinism spike";
    };
  }
