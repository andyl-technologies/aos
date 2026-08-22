{
  pkgs,
  lib,
  enableSchedulerPreemption ? true,
  hostAdversary ? (
    if enableSchedulerPreemption
    then "bounded-scheduler-preemption"
    else "none"
  ),
  sampleCount ? 36,
}: let
  boundedSchedulerPreemptionCheck = import ./phase0-bounded-scheduler-preemption.nix {inherit pkgs lib;};
  cadence = 100000000;
  horizon = cadence * sampleCount;
  rrSwitchQuantum = 4096;

  workload = pkgs.mkDerivation {
    pname = "crucible-phase0-s1-workload";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-workload";
        script = ''
          mkdir -p "$out/bin"

          cat > s1-workload.c <<'S1_C'
          #include <stdint.h>
          #include <stdio.h>

          enum {
            WORDS = 8192,
            ITERS = 24000,
            SPIN_ITERS = 400000000
          };

          static uint64_t words[WORDS];
          static volatile uint64_t sink;

          int main(void) {
            uint64_t state = 0x0010c0015eedf00dULL;

            for (uint64_t i = 0; i < WORDS; i++) {
              state ^= i + 0x9e3779b97f4a7c15ULL;
              state *= 0xbf58476d1ce4e5b9ULL;
              words[i] = state ^ (i << 17);
            }

            for (uint64_t i = 0; i < ITERS; i++) {
              const uint64_t idx = (state ^ (state >> 29)) & (WORDS - 1);
              state ^= words[idx] + i + (state << 11);
              state = (state << 7) | (state >> 57);
              words[idx] ^= state + (i << 32);
              words[(idx + 97) & (WORDS - 1)] += state ^ words[idx];
            }

            uint64_t checksum = 0;
            for (uint64_t i = 0; i < WORDS; i++) {
              checksum ^= words[i] + (checksum << 5) + (checksum >> 2);
            }

            printf(
                "CRUCIBLE_S1_DONE state=%016llx checksum=%016llx\n",
                (unsigned long long)state,
                (unsigned long long)checksum);
            if (checksum == 0) {
              printf("TEST_RESULT:FAIL\n");
              return 1;
            }

            printf("TEST_RESULT:PASS\n");
            fflush(stdout);

            for (uint64_t i = 0; i < SPIN_ITERS; i++) {
              state ^= i + 0x9e3779b97f4a7c15ULL;
              state = (state << 13) | (state >> 51);
              state *= 0xd6e8feb86659fd93ULL;
            }

            sink = state;
            return sink == 0 ? 1 : 0;
          }
          S1_C

          cc -std=c11 -O2 s1-workload.c -o "$out/bin/s1-workload"

          cat > s1-spin.c <<'SPIN_C'
          #include <stdint.h>

          enum {
            ITERS = 400000000
          };

          static volatile uint64_t sink;

          int main(void) {
            uint64_t state = 0x0010c0015eed51f1ULL;

            for (uint64_t i = 0; i < ITERS; i++) {
              state ^= i + 0x9e3779b97f4a7c15ULL;
              state = (state << 13) | (state >> 51);
              state *= 0xd6e8feb86659fd93ULL;
            }

            sink = state;
            return sink == 0 ? 1 : 0;
          }
          SPIN_C

          cc -std=c11 -O2 s1-spin.c -o "$out/bin/s1-spin"
        '';
      }
    ];
  };

  poweroffHelper = pkgs.mkDerivation {
    pname = "crucible-phase0-s1-poweroff";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-poweroff-helper";
        script = ''
          mkdir -p "$out/bin"

          cat > poweroff.c <<'POWEROFF_C'
          #include <stdio.h>
          #include <sys/reboot.h>
          #include <unistd.h>

          #ifndef RB_POWER_OFF
          #define RB_POWER_OFF 0x4321fedc
          #endif

          int main(void) {
            sync();
            if (reboot(RB_POWER_OFF) != 0) {
              perror("poweroff");
              return 1;
            }
            return 0;
          }
          POWEROFF_C

          cc poweroff.c -o "$out/bin/s1-poweroff"
        '';
      }
    ];
  };

  initramfs = let
    initramfsDeps = [
      pkgs.bash
      pkgs.coreutils
      workload
      poweroffHelper
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
      pname = "crucible-phase0-s1-initramfs";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.findutils
        pkgs.cpio
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
            ln -sfn ${poweroffHelper}/bin/s1-poweroff root/sbin/poweroff

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            echo "CRUCIBLE_S1_READY"
            test_result=0
            s1-workload || test_result=1

            if [ "$test_result" -eq 0 ]; then
              echo 'TEST_RESULT:PASS'
            else
              echo 'TEST_RESULT:FAIL'
            fi

            s1-spin
            poweroff
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
        description = "Crucible Phase 0 S1 diskless initramfs";
      };
    };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s1-fingerprint";
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
    ENABLE_SCHEDULER_PREEMPTION =
      if enableSchedulerPreemption
      then "1"
      else "0";
    HOST_ADVERSARY = hostAdversary;
    BOUNDED_PREEMPTION_HARNESS = ./_bounded-scheduler-preemption.sh;
    BOUNDED_PREEMPTION_TARGET_WRAPPER = ./_bounded-scheduler-preemption-target.sh;
    BOUNDED_PREEMPTION_CHECK = boundedSchedulerPreemptionCheck;

    phases = [
      {
        name = "run-s1-single-vm-fingerprint";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true
          grep -Fxq PASS "$BOUNDED_PREEMPTION_CHECK/result"

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          if [ -z "$vmlinuz" ]; then
            fail "no vmlinuz under $KERNEL/boot"
          fi

          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-s1-seed-v2\n' > "$seed"

          . "$BOUNDED_PREEMPTION_HARNESS"
          trap 'bounded_preemption_cleanup' EXIT
          trap 'bounded_preemption_cleanup; exit 143' TERM
          trap 'bounded_preemption_cleanup; exit 130' INT

          json_string() {
            printf '%s\n' "$1" | jq -R .
          }

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
            if [ -f "$serial" ] \
              && grep -q "TEST_RESULT:PASS" "$serial" \
              && grep -q "CRUCIBLE_S1_DONE" "$serial"; then
              return 0
            fi
            if [ -f "$serial" ]; then
              cat "$serial" >&2
            fi
            return 1
          }

          wait_for_migration() {
            label="$1"
            socket="$2"
            waited=0
            while [ "$waited" -lt 1200 ]; do
              if qmp_cmd "$socket" '{"execute":"query-migrate"}' "$TMPDIR/qmp-query-migrate-$label.json"; then
                status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$TMPDIR/qmp-query-migrate-$label.json")
                case "$status" in
                  completed)
                    return 0
                    ;;
                  failed | cancelled)
                    cat "$TMPDIR/qmp-query-migrate-$label.json" >&2
                    return 1
                    ;;
                esac
              fi
              sleep 0.5
              waited=$((waited + 1))
            done
            return 1
          }

          migrate_state() {
            label="$1"
            socket="$2"
            state="$TMPDIR/migration-$label.bin"
            uri=$(json_string "file:$state")
            request=$(printf '{"execute":"migrate","arguments":{"uri":%s}}' "$uri")

            qmp_cmd "$socket" "$request" "$TMPDIR/qmp-migrate-$label.json" \
              || fail "guest $label migration command failed"
            wait_for_migration "$label" "$socket" \
              || fail "guest $label migration did not complete"
            [ -s "$state" ] || fail "guest $label migration state is empty"
            sha256sum "$state" | gawk '{print $1}' > "$TMPDIR/migration-$label.sha256"
          }

          run_one() {
            label="$1"
            qmp_socket="$TMPDIR/qmp-current.sock"
            serial_path="$TMPDIR/serial-current.log"
            trace_path="$TMPDIR/trace-current.jsonl"
            rm -f "$qmp_socket" "$serial_path" "$trace_path"

            set -- qemu-system-x86_64 \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel sim,thread=single \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum="$RR_SWITCH_QUANTUM" \
              -cpu qemu64,-rdrand,-rdseed \
              -m 256 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c001 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off net.ifnames=0" \
              -chardev file,id=serial0,path="$serial_path" \
              -serial chardev:serial0 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -plugin "$PLUGIN",out="$trace_path",cadence="$CADENCE",stop_at="$HORIZON",extended=on,mem_events=on,vcpus=1 \
              -no-shutdown \
              -no-reboot

            printf '%s\n' "$@" > "$TMPDIR/qemu-args-$label.txt"
            if grep -E -q '^-drive$|^-blockdev$|^-cdrom$|^-hda$|^-hdb$|^-hdc$|^-hdd$|virtio-blk|scsi|nvme|ahci|ide-' "$TMPDIR/qemu-args-$label.txt"; then
              fail "guest $label launch is not diskless"
            fi

            qemu_binary=$(command -v "$1")
            bounded_preemption_launch_qemu \
              1200 "$TMPDIR/qemu-target-$label.pid" - "$qemu_binary" "$@" \
              || fail "guest $label QEMU launch failed"

            wait_for_socket "$qmp_socket" || fail "guest $label QMP socket did not appear"
            if [ "$label" = b ] && [ "$ENABLE_SCHEDULER_PREEMPTION" = 1 ]; then
              # The invariant is trace independence from host scheduling. Six
              # short QEMU preemptions begin only after the first guest trace
              # coordinate, perturb scheduling directly with no synthetic CPU
              # load, and retain a two-second independent resume watchdog.
              progress_needle="\"observed_icount\":$CADENCE"
              bounded_preemption_wait_for_guest_progress \
                "$trace_path" "$progress_needle" 12000 0.1 \
                || fail "guest $label made no pre-adversary trace progress"
              bounded_preemption_start \
                "$TMPDIR/preemption-$label.log" "$trace_path" "$progress_needle" \
                || fail "guest $label scheduler adversary did not start"
            fi

            wait_for_horizon_pause "$label" "$qmp_socket" || fail "guest $label did not pause at horizon"

            migrate_state "$label" "$qmp_socket"
            if [ "$label" = b ] && [ "$ENABLE_SCHEDULER_PREEMPTION" = 1 ]; then
              bounded_preemption_finish "$TMPDIR/preemption-$label.log" \
                || fail "guest $label scheduler adversary was incomplete"
            fi
            qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" || true
            bounded_preemption_wait_qemu \
              || fail "guest $label QEMU exited unsuccessfully"
            cp "$serial_path" "$TMPDIR/serial-$label.log"
            cp "$trace_path" "$TMPDIR/trace-$label.jsonl"
            if ! wait_for_guest_pass "$label"; then
              if [ -f "$TMPDIR/trace-$label.jsonl" ]; then
                tail -n 4 "$TMPDIR/trace-$label.jsonl" >&2
              fi
              fail "guest $label did not report TEST_RESULT:PASS before horizon"
            fi
          }

          run_one a
          run_one b

          for label in a b; do
            jq --argjson horizon "$HORIZON" \
              --argjson rr_switch_quantum "$RR_SWITCH_QUANTUM" -e -s '
              length >= 2
              and all(.[]; (
                .tracked_vcpus == 1
                and .stop_at == $horizon
                and .sample_register_failures == 0
                and .register_read_failures == 0
                and .rr_current_vcpu == 0
                and .rr_switch_quantum == $rr_switch_quantum
                and .rr_cursor_valid == true
                and .rr_cursor_position < .rr_switch_quantum
                and .ram_bytes > 0
                and .memory_events_enabled == true
                and .device_event_capture == true
                and .device_event_hash != null
                and .memory_events > 0
                and .io_events > 0
                and (.register_digests | type == "array")
                and (.register_digests | length) == 1
                and (.register_counts | type == "array")
                and (.register_counts | length) == 1
                and .register_counts[0] > 0
              ))
              and any(.[]; (
                .final != true
                and .observed_icount == $horizon
                and .stop_requested == true
              ))
              and any(.[]; .final == true)
            ' "$TMPDIR/trace-$label.jsonl" >/dev/null \
              || fail "trace $label failed structural S1 assertions"
            jq -c 'select(.final != true)' "$TMPDIR/trace-$label.jsonl" \
              > "$TMPDIR/trace-$label-cadence.jsonl"
          done

          samples_a=$(wc -l < "$TMPDIR/trace-a-cadence.jsonl")
          samples_b=$(wc -l < "$TMPDIR/trace-b-cadence.jsonl")
          [ "$samples_a" -ge 2 ] || fail "expected at least 2 samples in run a"
          [ "$samples_a" -eq "$samples_b" ] || fail "sample count mismatch: $samples_a/$samples_b"

          mkdir -p "$out"
          if [ "$ENABLE_SCHEDULER_PREEMPTION" = 1 ]; then
            cp "$TMPDIR/preemption-b.log" "$out/preemption-b.log"
          fi
          if ! diff -u "$TMPDIR/trace-a-cadence.jsonl" "$TMPDIR/trace-b-cadence.jsonl" > "$out/trace.diff"; then
            gawk '
              NR == FNR { left[FNR] = $0; next }
              left[FNR] != $0 {
                print FNR "\t" left[FNR] "\t" $0
                exit 0
              }
            ' "$TMPDIR/trace-a-cadence.jsonl" "$TMPDIR/trace-b-cadence.jsonl" > "$TMPDIR/first-difference.tsv"
            first_differing_line=$(cut -f1 "$TMPDIR/first-difference.tsv")
            left_json=$(cut -f2 "$TMPDIR/first-difference.tsv")
            right_json=$(cut -f3 "$TMPDIR/first-difference.tsv")
            printf '%s\n' "$left_json" > "$TMPDIR/first-left.json"
            printf '%s\n' "$right_json" > "$TMPDIR/first-right.json"
            first_differing_component=$(
              jq -n -r \
                --slurpfile left "$TMPDIR/first-left.json" \
                --slurpfile right "$TMPDIR/first-right.json" \
                '
                  def component:
                    if $left[0].retired != $right[0].retired then "retired"
                    elif $left[0].vcpu != $right[0].vcpu then "vcpu"
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
            first_different_sample_icount=$(
              jq -n -r \
                --slurpfile left "$TMPDIR/first-left.json" \
                --slurpfile right "$TMPDIR/first-right.json" \
                '[$left[0].retired, $right[0].retired] | min'
            )
            previous_matching_icount=none
            if [ "$first_differing_line" -gt 1 ]; then
              previous_line_number=$((first_differing_line - 1))
              previous_matching_icount=$(
                sed -n "''${previous_line_number}p" "$TMPDIR/trace-a-cadence.jsonl" \
                  | jq -r '.retired'
              )
            fi
            cp "$TMPDIR/trace-a-cadence.jsonl" "$out/trace-a-cadence.jsonl"
            cp "$TMPDIR/trace-b-cadence.jsonl" "$out/trace-b-cadence.jsonl"
            {
              echo "first_differing_line=$first_differing_line"
              echo "first_differing_component=$first_differing_component"
              echo "localization_result=coarse-trace-sample-window"
              echo "previous_matching_icount=$previous_matching_icount"
              echo "coarse_first_different_sample_icount=$first_different_sample_icount"
              echo "localization_precision=sample-not-instruction-exact"
              echo "coarse_trace_evidence=trace-a-cadence.jsonl,trace-b-cadence.jsonl"
              echo "left=$left_json"
              echo "right=$right_json"
            } > "$out/first-difference.txt"
            cat "$out/first-difference.txt" >&2
            echo "trace_stream=left" >&2
            cat "$TMPDIR/trace-a-cadence.jsonl" >&2
            echo "trace_stream=right" >&2
            cat "$TMPDIR/trace-b-cadence.jsonl" >&2
            fail "S1 extended fingerprint mismatch"
          fi
          for label in a b; do
            # The exact horizon sample is authoritative. The post-quit record
            # can reflect host-timed VMState cleanup and is used only as stop
            # evidence, so exclude its serialized value size and digest.
            jq -c '
              if .final == true
              then del(.device_state_digest, .device_state_bytes, .diagnostic_extended_fnv)
              else .
              end
            ' "$TMPDIR/trace-$label.jsonl" > "$TMPDIR/trace-$label-exit-comparable.jsonl"
          done
          if ! diff -u \
            "$TMPDIR/trace-a-exit-comparable.jsonl" \
            "$TMPDIR/trace-b-exit-comparable.jsonl" \
            > "$out/trace-full.diff"; then
            cat "$out/trace-full.diff" >&2
            fail "S1 plugin-exit fingerprint mismatch"
          fi

          migration_a_hash=$(cat "$TMPDIR/migration-a.sha256")
          migration_b_hash=$(cat "$TMPDIR/migration-b.sha256")
          if [ "$migration_a_hash" != "$migration_b_hash" ]; then
            chmod a+r "$TMPDIR/migration-a.bin" "$TMPDIR/migration-b.bin" || true
            set +e
            cmp -l "$TMPDIR/migration-a.bin" "$TMPDIR/migration-b.bin" > "$TMPDIR/migration-cmp.raw"
            cmp_status=$?
            set -e
            if [ "$cmp_status" -ne 1 ]; then
              echo "unexpected cmp status: $cmp_status" >&2
            fi
            gawk '
                NR <= 128 { print }
                NR == 1 { first = $1 }
                { count = NR; last = $0 }
                END {
                  print "count=" count
                  print "first_offset=" first
                  print "last=" last
                }
              ' "$TMPDIR/migration-cmp.raw" > "$TMPDIR/migration-byte-differences.txt"
            migration_state_first_offset=$(gawk -F= '/^first_offset=/ { print $2 }' "$TMPDIR/migration-byte-differences.txt")
            if [ -n "$migration_state_first_offset" ]; then
              dump_start=$((migration_state_first_offset > 256 ? migration_state_first_offset - 256 : 0))
              {
                echo "start=$dump_start"
                dd if="$TMPDIR/migration-a.bin" bs=1 skip="$dump_start" count=512 2>/dev/null \
                  | od -An -tx1 -v
              } > "$TMPDIR/migration-a-first-difference.hex" || true
              {
                echo "start=$dump_start"
                dd if="$TMPDIR/migration-b.bin" bs=1 skip="$dump_start" count=512 2>/dev/null \
                  | od -An -tx1 -v
              } > "$TMPDIR/migration-b-first-difference.hex" || true
            fi
            {
              echo "migration_a_hash=$migration_a_hash"
              echo "migration_b_hash=$migration_b_hash"
              sed -n '1,132p' "$TMPDIR/migration-byte-differences.txt"
            } > "$TMPDIR/paused-migration-state.diff"
            cat "$TMPDIR/paused-migration-state.diff" >&2
            echo "warning: S1 paused migration state differs; retaining as diagnostic" >&2
          fi

          horizon_line=$(tail -1 "$TMPDIR/trace-a-cadence.jsonl")
          horizon_retired=$(printf '%s\n' "$horizon_line" | jq -r '.retired')
          horizon_observed_icount=$(printf '%s\n' "$horizon_line" | jq -r '.observed_icount')
          [ "$horizon_observed_icount" = "$HORIZON" ] \
            || fail "final cadence sample did not observe exact horizon: $horizon_observed_icount"
          [ "$horizon_retired" -ge "$HORIZON" ] \
            || fail "final cadence sample retired before horizon: $horizon_retired"
          horizon_extended_hash=$(printf '%s\n' "$horizon_line" | jq -r '.diagnostic_extended_fnv')
          horizon_register_hash=$(printf '%s\n' "$horizon_line" | jq -r '.register_digests[0]')
          horizon_ram_hash=$(printf '%s\n' "$horizon_line" | jq -r '.ram_digest')
          horizon_ram_bytes=$(printf '%s\n' "$horizon_line" | jq -r '.ram_bytes')
          horizon_device_event_hash=$(printf '%s\n' "$horizon_line" | jq -r '.device_event_hash')
          horizon_memory_events=$(printf '%s\n' "$horizon_line" | jq -r '.memory_events')
          horizon_io_events=$(printf '%s\n' "$horizon_line" | jq -r '.io_events')
          horizon_register_read_failures=$(printf '%s\n' "$horizon_line" | jq -r '.register_read_failures')

          pause_line=$(tail -1 "$TMPDIR/trace-a.jsonl")
          pause_retired=$(printf '%s\n' "$pause_line" | jq -r '.retired')
          jq -e '.final == true and .stop_requested == true and .retired >= .stop_at' \
            "$TMPDIR/trace-a.jsonl" >/dev/null \
            || fail "run a did not record a final plugin pause sample"
          jq -e '.final == true and .stop_requested == true and .retired >= .stop_at' \
            "$TMPDIR/trace-b.jsonl" >/dev/null \
            || fail "run b did not record a final plugin pause sample"
          pause_overshoot=$((pause_retired - HORIZON))
          [ "$pause_overshoot" -ge 0 ] || fail "pause retired before requested horizon: $pause_retired"
          pause_extended_hash=$(printf '%s\n' "$pause_line" | jq -r '.diagnostic_extended_fnv')
          pause_register_hash=$(printf '%s\n' "$pause_line" | jq -r '.register_digests[0]')
          pause_ram_hash=$(printf '%s\n' "$pause_line" | jq -r '.ram_digest')
          pause_device_event_hash=$(printf '%s\n' "$pause_line" | jq -r '.device_event_hash')
          pause_memory_events=$(printf '%s\n' "$pause_line" | jq -r '.memory_events')
          pause_io_events=$(printf '%s\n' "$pause_line" | jq -r '.io_events')

          cp "$TMPDIR/trace-a.jsonl" "$out/trace-a.jsonl"
          cp "$TMPDIR/trace-b.jsonl" "$out/trace-b.jsonl"
          cp "$TMPDIR/trace-a-cadence.jsonl" "$out/trace-a-cadence.jsonl"
          cp "$TMPDIR/trace-b-cadence.jsonl" "$out/trace-b-cadence.jsonl"
          cp "$TMPDIR/serial-a.log" "$out/serial-a.log"
          cp "$TMPDIR/serial-b.log" "$out/serial-b.log"
          cp "$TMPDIR/qemu-args-a.txt" "$out/qemu-args-a.txt"
          cp "$TMPDIR/qemu-args-b.txt" "$out/qemu-args-b.txt"
          {
            echo PASS
            echo spike=single-vm-fingerprint
            echo scenario=stock-linux-diskless-initramfs-workload
            echo boot_medium=initramfs
            echo block_devices=0
            echo vcpus=1
            echo cadence="$CADENCE"
            echo horizon_icount="$HORIZON"
            echo host_adversary="$HOST_ADVERSARY"
            if [ "$ENABLE_SCHEDULER_PREEMPTION" = 1 ]; then
              echo host_adversary_perturbations=6
              echo host_adversary_configured_pause_milliseconds=15
              echo host_adversary_configured_total_stopped_milliseconds=90
              echo host_adversary_nominal_worker_wall_milliseconds=240
              echo host_adversary_worker_wall_timeout_seconds=2
              echo host_adversary_busy_workers=0
            else
              echo host_adversary_perturbations=0
            fi
            echo stop_request=plugin-requested-icount-pause
            echo extended_fingerprint_match=true
            echo aggregate_icount_stream_match=true
            echo cadence_fingerprint_match=true
            echo horizon_fingerprint_match=true
            echo plugin_exit_fingerprint_compared=true
            echo plugin_exit_device_state_comparison=diagnostic_not_gated
            echo paused_migration_state_match=not_asserted
            echo samples="$samples_a"
            echo horizon_retired="$horizon_retired"
            echo horizon_observed_icount="$horizon_observed_icount"
            echo horizon_extended_hash="$horizon_extended_hash"
            echo horizon_register_hash="$horizon_register_hash"
            echo horizon_ram_hash="$horizon_ram_hash"
            echo horizon_ram_bytes="$horizon_ram_bytes"
            echo pause_retired="$pause_retired"
            echo pause_overshoot="$pause_overshoot"
            echo pause_extended_hash="$pause_extended_hash"
            echo pause_register_hash="$pause_register_hash"
            echo pause_ram_hash="$pause_ram_hash"
            echo device_event_capture=true
            echo device_event_scope=io_event_multiset
            echo device_event_device_name_scope=excluded
            echo device_event_value_scope=stores_only
            echo device_state_scope=io_event_multiset
            echo horizon_device_event_hash="$horizon_device_event_hash"
            echo horizon_memory_events="$horizon_memory_events"
            echo horizon_io_events="$horizon_io_events"
            echo pause_device_event_hash="$pause_device_event_hash"
            echo pause_memory_events="$pause_memory_events"
            echo pause_io_events="$pause_io_events"
            echo migration_state_hash_a=not_recorded
            echo migration_state_hash_b=not_recorded
            echo migration_state_comparison=diagnostic_not_gated
            echo migration_state_scope=diagnostic_qemu_migration_stream_at_plugin_pause
            echo migration_state_difference_count=not_recorded
            echo migration_state_first_offset=not_recorded
            echo migration_state_last_difference=not_recorded
            echo migration_state_retired="$pause_retired"
            echo migration_normalization=icount_host_timer_offsets_zeroed_by_qemu_patch
            echo register_read_failures="$horizon_register_read_failures"
            echo register_count_assertion=nonempty_single_vcpu
            echo block_device_assertion=launch_argv_scan
            echo mismatch_localization=component
            echo first_differing_line=none
            echo first_differing_component=none
            echo rr_as_diagnostic=not_used
            echo det29_phase0_device_state_scope=io_event_multiset
            echo det29_full_device_cadence_complete=false
            echo s1_complete=true
            echo open_gap=paused_qemu_migration_state_timer_icount_hpet
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S1 single-VM fingerprint spike";
    };
  }
