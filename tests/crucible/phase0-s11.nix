{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  qemuRuntimeDeps ? [],
  tracePluginPackage ? pkgs.crucible-qemu-trace-plugin,
  accelerator ? "sim,thread=single",
  cadence ? 100000000,
  requireGuestPass ? true,
  # The finite four-vCPU workload completed at retired icount 3,215,171,189
  # during calibration. The fixed default leaves 84,828,811 instructions of
  # sustained contention before the predeclared fingerprint horizon.
  stopAt ? 3300000000,
  memoryMib ? 256,
  vcpuCount ? 4,
  detIpiProbe ? false,
  # This bounds host wall time only. The deterministic proof horizon remains
  # the content-addressed stopAt node-icount under all host load conditions.
  runTimeoutSeconds ? 2400,
}: let
  rrSwitchQuantum = 4096;

  workload = pkgs.mkDerivation {
    pname = "crucible-phase0-s11-workload";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-workload";
        script = ''
          mkdir -p "$out/bin"

          cat > smp-contended.c <<'SMP_C'
          #define _GNU_SOURCE

          #include <pthread.h>
          #include <sched.h>
          #include <stdint.h>
          #include <stdio.h>
          #include <string.h>

          enum {
            THREADS = 4,
            ITERS = 8000
          };

          static volatile int spinlock;
          static volatile uint64_t shared_state = 0x0010c001ULL;
          static uint64_t counters[THREADS];
          static volatile unsigned int finite_ready;
          static volatile unsigned int sustain_ready;
          static volatile unsigned int sustain_release;
          static volatile unsigned int affinity_failures;
          static int sustain_mode;

          static int pin_to_vcpu(uintptr_t id) {
            cpu_set_t set;

            CPU_ZERO(&set);
            CPU_SET(id, &set);
            return sched_setaffinity(0, sizeof(set), &set);
          }

          static void lock_spin(void) {
            while (__sync_lock_test_and_set(&spinlock, 1) != 0) {
              sched_yield();
            }
          }

          static void unlock_spin(void) {
            __sync_lock_release(&spinlock);
          }

          static void contention_step(
              uintptr_t id, uint64_t iteration, uint64_t *local) {
            *local ^= iteration + (id << 32);
            *local *= 0xbf58476d1ce4e5b9ULL;

            lock_spin();
            shared_state ^= *local + counters[id] + (shared_state << 7);
            shared_state = (shared_state << 13) | (shared_state >> 51);
            counters[id] += shared_state ^ *local;
            unlock_spin();

            if ((iteration & 127) == 0) {
              sched_yield();
            }
          }

          static void *worker(void *arg) {
            const uintptr_t id = (uintptr_t)arg;
            uint64_t local = 0x9e3779b97f4a7c15ULL ^ id;

            if (pin_to_vcpu(id) != 0) {
              __sync_fetch_and_add(&affinity_failures, 1);
            }

            for (uint64_t i = 0; i < ITERS; i++) {
              contention_step(id, i, &local);
            }

            if (!sustain_mode) {
              return 0;
            }

            __sync_fetch_and_add(&finite_ready, 1);
            while (__atomic_load_n(&sustain_release, __ATOMIC_ACQUIRE) == 0) {
              sched_yield();
            }

            if (__atomic_load_n(&sustain_release, __ATOMIC_ACQUIRE) != 1) {
              return 0;
            }

            for (uint64_t i = ITERS;; i++) {
              contention_step(id, i, &local);
              if (i == ITERS) {
                __sync_fetch_and_add(&sustain_ready, 1);
              }
            }
          }

          static void print_finite_result(void) {
            printf(
              "CRUCIBLE_S11_DONE shared=%016llx c0=%016llx c1=%016llx c2=%016llx c3=%016llx\n",
              (unsigned long long)shared_state,
              (unsigned long long)counters[0],
              (unsigned long long)counters[1],
              (unsigned long long)counters[2],
              (unsigned long long)counters[3]);
          }

          int main(int argc, char **argv) {
            pthread_t threads[THREADS];

            if (argc == 2 && strcmp(argv[1], "--sustain") == 0) {
              sustain_mode = 1;
            } else if (argc != 1) {
              fputs("usage: smp-contended [--sustain]\n", stderr);
              return 2;
            }

            for (uintptr_t i = 0; i < THREADS; i++) {
              if (pthread_create(&threads[i], 0, worker, (void *)i) != 0) {
                puts("CRUCIBLE_S11_PTHREAD_CREATE_FAIL");
                return 1;
              }
            }

            if (sustain_mode) {
              while (__atomic_load_n(&finite_ready, __ATOMIC_ACQUIRE) != THREADS) {
                sched_yield();
              }
              if (__atomic_load_n(&affinity_failures, __ATOMIC_ACQUIRE) != 0) {
                puts("CRUCIBLE_S11_AFFINITY_FAIL");
                __atomic_store_n(&sustain_release, 2, __ATOMIC_RELEASE);
                for (int i = 0; i < THREADS; i++) {
                  (void)pthread_join(threads[i], 0);
                }
                return 1;
              }
              print_finite_result();
              puts("TEST_RESULT:PASS");
              fflush(stdout);
              __atomic_store_n(&sustain_release, 1, __ATOMIC_RELEASE);
              while (__atomic_load_n(&sustain_ready, __ATOMIC_ACQUIRE) != THREADS) {
                sched_yield();
              }
              puts("CRUCIBLE_S11_AFFINITY_ACTIVE vcpus=0,1,2,3");
              puts("CRUCIBLE_S11_SUSTAIN_ACTIVE threads=4 mode=spinlock");
              fflush(stdout);
            }

            for (int i = 0; i < THREADS; i++) {
              if (pthread_join(threads[i], 0) != 0) {
                puts("CRUCIBLE_S11_PTHREAD_JOIN_FAIL");
                return 1;
              }
            }

            if (__atomic_load_n(&affinity_failures, __ATOMIC_ACQUIRE) != 0) {
              puts("CRUCIBLE_S11_AFFINITY_FAIL");
              return 1;
            }

            print_finite_result();
            return 0;
          }
          SMP_C

          cc -std=c11 -O2 -pthread smp-contended.c -o "$out/bin/smp-contended"
        '';
      }
    ];
  };

  rebootHelper = pkgs.mkDerivation {
    pname = "crucible-phase0-s11-reboot";
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

          cc reboot.c -o "$out/bin/s11-reboot"
        '';
      }
    ];
  };

  initramfs = let
    initramfsDeps = [
      pkgs.bash
      pkgs.coreutils
      workload
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
      pname = "crucible-phase0-s11-initramfs";
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
            ln -sfn ${rebootHelper}/bin/s11-reboot root/sbin/reboot

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            echo "CRUCIBLE_S11_READY"
            test_result=0
            if [ "${
              if stopAt == null
              then "0"
              else "1"
            }" -eq 1 ]; then
              smp-contended --sustain || test_result=1
            else
              smp-contended || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              echo 'TEST_RESULT:PASS'
            else
              echo 'TEST_RESULT:FAIL'
            fi

            sync
            sleep 0.5
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
        description = "Crucible Phase 0 S11 diskless initramfs";
      };
    };
in
  assert runTimeoutSeconds > 60;
  pkgs.mkDerivation {
    pname = "crucible-phase0-s11-multi-vcpu-fingerprint";
    version = "0";
    src = null;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.gawk
        pkgs.grep
        pkgs.jq
        qemuPackage
        tracePluginPackage
        pkgs.socat
      ]
      ++ qemuRuntimeDeps;

    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL = builtins.toString pkgs.linux;
    QEMU = "${qemuPackage}/bin/qemu-system-x86_64";
    PLUGIN = "${tracePluginPackage}/lib/qemu/plugins/crucible-qemu-trace-plugin.so";
    CADENCE = builtins.toString cadence;
    RR_SWITCH_QUANTUM = builtins.toString rrSwitchQuantum;
    VCPU_COUNT = builtins.toString vcpuCount;
    MEMORY_MIB = builtins.toString memoryMib;
    ACCELERATOR = accelerator;
    RUN_TIMEOUT_SECONDS = builtins.toString runTimeoutSeconds;
    PAUSE_WAIT_SECONDS = builtins.toString (runTimeoutSeconds - 60);
    REQUIRE_GUEST_PASS =
      if requireGuestPass
      then "1"
      else "0";
    STOP_AT =
      if stopAt == null
      then ""
      else builtins.toString stopAt;
    STOP_AT_VALUE =
      if stopAt == null
      then "0"
      else builtins.toString stopAt;
    SUSTAIN_WORKLOAD =
      if stopAt == null
      then "0"
      else "1";
    DET_IPI_PROBE =
      if detIpiProbe
      then "1"
      else "0";
    # RR cursor / RR switch-quantum export is gated to `-accel sim` in the
    # patch stack; under plain TCG the plugin reports inert cursor fields and
    # emits no rr_switch rows.
    EXPECT_RR_CURSOR =
      if lib.hasPrefix "sim," accelerator || accelerator == "sim"
      then "1"
      else "0";

    phases = [
      {
        name = "run-s11-multi-vcpu-fingerprint";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          active_qemu_pid=""
          cleanup_active_qemu() {
            if [ -n "$active_qemu_pid" ]; then
              kill "$active_qemu_pid" 2>/dev/null || true
              wait "$active_qemu_pid" 2>/dev/null || true
              active_qemu_pid=""
            fi
          }

          fail() {
            cleanup_active_qemu
            echo "FAIL: $*" >&2
            exit 1
          }

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          if [ -z "$vmlinuz" ]; then
            fail "no vmlinuz under $KERNEL/boot"
          fi

          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-s11-seed-v1\n' > "$seed"

          qemu_build_digest=$(sha256sum "$QEMU" | gawk '{ print $1 }')
          trace_plugin_build_digest=$(sha256sum "$PLUGIN" | gawk '{ print $1 }')
          kernel_digest=$(sha256sum "$vmlinuz" | gawk '{ print $1 }')
          initramfs_digest=$(sha256sum "$INITRAMFS" | gawk '{ print $1 }')
          seed_digest=$(sha256sum "$seed" | gawk '{ print $1 }')
          printf '%s\n' \
            "qemu_build_digest=$qemu_build_digest" \
            "trace_plugin_build_digest=$trace_plugin_build_digest" \
            "kernel_digest=$kernel_digest" \
            "initramfs_digest=$initramfs_digest" \
            "seed_digest=$seed_digest" \
            'machine=q35' \
            "accelerator=$ACCELERATOR" \
            "icount=shift=0,sleep=off,align=off,rr_switch_quantum=$RR_SWITCH_QUANTUM" \
            'cpu=qemu64' \
            "memory_mib=$MEMORY_MIB" \
            "vcpus=$VCPU_COUNT" \
            'rtc=base=2026-01-01T00:00:00,clock=vm' \
            'seed=0x0010c011' \
            'kernel_append=console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0' \
            "plugin_cadence=$CADENCE" \
            "plugin_stop_at=$STOP_AT" \
            'plugin_extended=on' \
            'plugin_mem_events=off' \
            "plugin_vcpus=$VCPU_COUNT" \
            "det_ipi_probe=$DET_IPI_PROBE" \
            "sustain_workload=$SUSTAIN_WORKLOAD" \
            > "$TMPDIR/launch-definition.txt"
          launch_definition_digest=$(sha256sum "$TMPDIR/launch-definition.txt" | gawk '{ print $1 }')

          zero_sha256=0000000000000000000000000000000000000000000000000000000000000000
          for digest in \
            "$qemu_build_digest" \
            "$trace_plugin_build_digest" \
            "$kernel_digest" \
            "$initramfs_digest" \
            "$seed_digest" \
            "$launch_definition_digest"; do
            printf '%s\n' "$digest" | grep -E -q '^[0-9a-f]{64}$' \
              || fail "invalid S11 provenance digest: $digest"
            [ "$digest" != "$zero_sha256" ] \
              || fail "zero S11 provenance digest is not accepted"
          done

          jitter_pids=""
          start_jitter() {
            i=0
            while [ "$i" -lt 3 ]; do
              yes > /dev/null &
              jitter_pids="$jitter_pids $!"
              i=$((i + 1))
            done
          }

          stop_jitter() {
            for pid in $jitter_pids; do
              kill "$pid" 2>/dev/null || true
            done
            for pid in $jitter_pids; do
              wait "$pid" 2>/dev/null || true
            done
            jitter_pids=""
          }

          qmp_exchange() {
            socket="$1"
            request="$2"
            response="$3"
            response_err="$response.err"

            {
              sleep 0.1
              printf '{"execute":"qmp_capabilities"}\r\n'
              sleep 0.1
              printf '%s\r\n' "$request"
              sleep 0.5
            } | socat -T 3 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true
          }

          qmp_cmd() {
            socket="$1"
            request="$2"
            response="$3"
            response_err="$response.err"
            attempts=0

            while [ "$attempts" -lt 5 ]; do
              qmp_exchange "$socket" "$request" "$response"

              if [ ! -s "$response" ]; then
                attempts=$((attempts + 1))
                sleep 0.1
                continue
              fi

              if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
                cat "$response" >&2
                return 1
              fi
              if jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null; then
                return 0
              fi

              attempts=$((attempts + 1))
              sleep 0.1
            done

            if [ -s "$response" ]; then
              cat "$response" >&2
            else
              cat "$response_err" >&2
            fi
            return 1
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

          trace_reached_stop_at() {
            label="$1"
            trace="$TMPDIR/trace-$label.jsonl"
            [ -s "$trace" ] || return 1
            tail -200 "$trace" | gawk -v stop_at="$STOP_AT" '
              /"kind":"rr_switch"/ { next }
              /"final":true/ { next }
              match($0, /"retired":([0-9]+)/, retired) && retired[1] + 0 >= stop_at {
                found = 1
              }
              END { exit found ? 0 : 1 }
            '
          }

          wait_for_stop_at_pause() {
            socket="$1"
            label="$2"
            waited=0
            qmp_failures=0
            while [ "$waited" -lt "$PAUSE_WAIT_SECONDS" ]; do
              if trace_reached_stop_at "$label"; then
                if qmp_cmd "$socket" '{"execute":"query-status"}' "$TMPDIR/qmp-status-$label.json"; then
                  qmp_failures=0
                  status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$TMPDIR/qmp-status-$label.json")
                  case "$status" in
                    paused)
                      return 0
                      ;;
                    running | prelaunch)
                      ;;
                    *)
                      cat "$TMPDIR/qmp-status-$label.json" >&2
                      return 1
                      ;;
                  esac
                else
                  qmp_failures=$((qmp_failures + 1))
                  if [ "$qmp_failures" -ge 20 ]; then
                    if [ -f "$TMPDIR/qmp-status-$label.json" ]; then
                      cat "$TMPDIR/qmp-status-$label.json" >&2
                    fi
                    return 1
                  fi
                fi
              fi
              sleep 1
              waited=$((waited + 1))
            done
            if [ -f "$TMPDIR/qmp-status-$label.json" ]; then
              cat "$TMPDIR/qmp-status-$label.json" >&2
            fi
            if [ -f "$TMPDIR/trace-$label.jsonl" ]; then
              tail -20 "$TMPDIR/trace-$label.jsonl" >&2
            fi
            if [ -f "$TMPDIR/serial-$label.log" ]; then
              tail -20 "$TMPDIR/serial-$label.log" >&2
            fi
            return 1
          }

          run_one() {
            label="$1"
            plugin_arg="$PLUGIN,out=$TMPDIR/trace-$label.jsonl,cadence=$CADENCE,extended=on,mem_events=off,vcpus=$VCPU_COUNT,launch_digest=$launch_definition_digest,qemu_build_digest=$qemu_build_digest,plugin_build_digest=$trace_plugin_build_digest"
            qmp_socket="$TMPDIR/qmp-$label.sock"

            if [ "$DET_IPI_PROBE" -eq 1 ]; then
              plugin_arg="$plugin_arg,det_ipi_probe=on"
            fi

            if [ -n "$STOP_AT" ]; then
              plugin_arg="$plugin_arg,stop_at=$STOP_AT"
              rm -f "$qmp_socket"
            fi

            set -- "$QEMU" \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel "$ACCELERATOR" \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum="$RR_SWITCH_QUANTUM" \
              -cpu qemu64 \
              -m "$MEMORY_MIB" \
              -smp "$VCPU_COUNT" \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c011 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
              -chardev file,id=serial0,path="$TMPDIR/serial-$label.log" \
              -serial chardev:serial0 \
              -plugin "$plugin_arg"

            if [ -n "$STOP_AT" ]; then
              set -- "$@" \
                -qmp "unix:$qmp_socket,server=on,wait=off" \
                -no-shutdown
            else
              set -- "$@" \
                -no-reboot
            fi

            printf '%s\n' "$@" > "$TMPDIR/qemu-args-$label.txt"
            if grep -E -q '^-drive$|^-blockdev$|^-cdrom$|^-hda$|^-hdb$|^-hdc$|^-hdd$|virtio-blk|scsi|nvme|ahci|ide-' "$TMPDIR/qemu-args-$label.txt"; then
              fail "guest $label launch is not diskless"
            fi

            if [ -n "$STOP_AT" ]; then
              timeout "$RUN_TIMEOUT_SECONDS" "$@" &
              active_qemu_pid="$!"
              wait_for_socket "$qmp_socket" || fail "QMP socket did not appear for guest $label"
              wait_for_stop_at_pause "$qmp_socket" "$label" || fail "QEMU did not pause at stop_at for guest $label"
              qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" || true
              wait "$active_qemu_pid" || fail "QEMU guest $label exited unsuccessfully"
              active_qemu_pid=""
            else
              timeout 600 "$@"
            fi
          }

          run_one a
          start_jitter
          run_one b
          stop_jitter

          diagnose_trace_structure() {
            label="$1"
            trace="$TMPDIR/trace-$label.jsonl"
            echo "S11 structural diagnostic for trace $label" >&2
            jq -s -c \
              --argjson stop_at "$STOP_AT_VALUE" \
              --argjson cadence "$CADENCE" \
              --argjson quantum "$RR_SWITCH_QUANTUM" \
              '
                [ .[] | select((.kind // "sample") == "sample") ] as $samples
                | [ .[] | select(.kind == "rr_switch") ] as $switches
                | {
                    sample_count: ($samples | length),
                    non_final_sample_count: ([ $samples[]
                      | select(.final != true)
                    ] | length),
                    expected_non_final_sample_count: (($stop_at / $cadence) | ceil),
                    rr_switch_count: ($switches | length),
                    final_sample_count: ([ $samples[] | select(.final == true) ] | length),
                    last_record_kind: (.[-1].kind // "sample"),
                    last_record_final: (.[-1].final // false),
                    horizon_pre_stop_count: ([ $samples[]
                      | select(.final != true and .retired == $stop_at)
                    ] | length),
                    bounded_post_stop_final_count: ([ $samples[]
                      | select(
                          .final == true
                          and .retired >= $stop_at
                          and (.retired - $stop_at) <= $quantum
                          and .stop_requested == true
                        )
                    ] | length)
                  }
              ' "$trace" >&2 || true
            jq -n -c \
              --arg launch_definition_digest "$launch_definition_digest" \
              --arg qemu_build_digest "$qemu_build_digest" \
              --arg trace_plugin_build_digest "$trace_plugin_build_digest" \
              '
                limit(10;
                  inputs
                  | select((.kind // "sample") == "sample")
                  | {
                      retired,
                      final,
                      stop_at,
                      stop_requested,
                      schema,
                      tracked_vcpus,
                      launch_digest_match: (.launch_definition_digest == $launch_definition_digest),
                      qemu_digest_match: (.qemu_build_digest == $qemu_build_digest),
                      plugin_digest_match: (.trace_plugin_build_digest == $trace_plugin_build_digest),
                      rr_current_vcpu,
                      rr_cursor_position,
                      rr_switch_quantum,
                      rr_cursor_valid,
                      rr_cursor_source,
                      sample_register_failures,
                      register_read_failures,
                      ram_bytes,
                      ram_hash,
                      memory_events_enabled,
                      device_event_capture,
                      device_event_hash,
                      register_hash,
                      register_hashes,
                      register_counts,
                      register_file_bytes,
                      register_schema_hashes
                    }
                )
              ' "$trace" >&2 || true
            jq -n -c \
              --argjson vcpus "$VCPU_COUNT" \
              --argjson quantum "$RR_SWITCH_QUANTUM" \
              '
                limit(10;
                  inputs
                  | select(.kind == "rr_switch")
                  | select((
                      .rr_switch_event > 0
                      and .previous_rr_switch_quantum == $quantum
                      and .rr_switch_quantum == $quantum
                      and .from_vcpu >= 0
                      and .from_vcpu < $vcpus
                      and .to_vcpu >= 0
                      and .to_vcpu < $vcpus
                      and .rr_cursor_position <= $quantum
                      and (.per_vcpu_retired | type == "array")
                      and (.per_vcpu_retired | length) == $vcpus
                      and (.per_vcpu_delta | type == "array")
                      and (.per_vcpu_delta | length) == $vcpus
                      and all(.per_vcpu_retired[]; . >= 0)
                      and all(.per_vcpu_delta[]; . >= 0)
                      and any(.per_vcpu_delta[]; . > 0)
                    ) | not)
                )
              ' "$trace" >&2 || true
          }

          for label in a b; do
            if [ "$REQUIRE_GUEST_PASS" -eq 1 ]; then
              grep -q "TEST_RESULT:PASS" "$TMPDIR/serial-$label.log" \
                || fail "guest $label did not report TEST_RESULT:PASS"
              grep -q "CRUCIBLE_S11_DONE" "$TMPDIR/serial-$label.log" \
                || fail "guest $label did not run the SMP workload"
              if [ "$SUSTAIN_WORKLOAD" -eq 1 ]; then
                grep -q "CRUCIBLE_S11_AFFINITY_ACTIVE vcpus=0,1,2,3" \
                  "$TMPDIR/serial-$label.log" \
                  || fail "guest $label did not bind contention workers to vCPUs 0-3"
                grep -q "CRUCIBLE_S11_SUSTAIN_ACTIVE threads=4 mode=spinlock" \
                  "$TMPDIR/serial-$label.log" \
                  || fail "guest $label did not sustain four-thread contention"
              fi
              if grep -q "CRUCIBLE_S11_AFFINITY_FAIL" "$TMPDIR/serial-$label.log"; then
                fail "guest $label failed to bind a contention worker to its vCPU"
              fi
            fi
            if ! jq -e -s \
              --argjson vcpus "$VCPU_COUNT" \
              --argjson quantum "$RR_SWITCH_QUANTUM" \
              --argjson stop_at "$STOP_AT_VALUE" \
              --argjson cadence "$CADENCE" \
              --arg expect_rr_cursor "$EXPECT_RR_CURSOR" \
              --arg sustain_workload "$SUSTAIN_WORKLOAD" \
              --arg launch_definition_digest "$launch_definition_digest" \
              --arg qemu_build_digest "$qemu_build_digest" \
              --arg trace_plugin_build_digest "$trace_plugin_build_digest" \
              '
                def final_sample:
                  .final == true;
                def rr_cursor_expectation:
                  if $expect_rr_cursor != "1" then
                    .rr_switch_quantum == 0
                    and .rr_cursor_valid == false
                  else
                    .rr_switch_quantum == $quantum
                    and .rr_cursor_valid == true
                    and .rr_current_vcpu >= 0
                    and .rr_current_vcpu < $vcpus
                    and .rr_cursor_position >= 0
                    and .rr_cursor_position < .rr_switch_quantum
                    and (
                      if final_sample then
                        .rr_cursor_source == "last_executed_instruction"
                      else
                        .rr_cursor_source == "live_instruction"
                      end
                    )
                  end;
                [ .[] | select((.kind // "sample") == "sample") ] as $samples
                | [ .[] | select(.kind == "rr_switch") ] as $switches
                | ($samples | length) >= 4
                and all($samples[]; (
                  .schema == "crucible.qemu.trace-fingerprint.v6"
                  and .tracked_vcpus == $vcpus
                  and .launch_definition_digest == $launch_definition_digest
                  and .qemu_build_digest == $qemu_build_digest
                  and .trace_plugin_build_digest == $trace_plugin_build_digest
                  and rr_cursor_expectation
                  and .sample_register_failures == 0
                  and .register_read_failures == 0
                  and .ram_bytes > 0
                  and .ram_hash != "0000000000000000"
                  and .memory_events_enabled == false
                  and .device_event_capture == false
                  and .device_event_hash == null
                  and .register_hash != "0000000000000000"
                  and (.register_hashes | type == "array")
                  and (.register_hashes | length) == $vcpus
                  and all(.register_hashes[]; . != "0000000000000000")
                  and (.register_counts | type == "array")
                  and (.register_counts | length) == $vcpus
                  and all(.register_counts[]; . > 0)
                  and (.register_file_bytes | type == "array")
                  and (.register_file_bytes | length) == $vcpus
                  and all(.register_file_bytes[]; . > 0)
                  and (.register_schema_hashes | type == "array")
                  and (.register_schema_hashes | length) == $vcpus
                  and all(.register_schema_hashes[]; . != "0000000000000000")
                ))
                and ([ $samples[] | select(.final == true) ] | length) == 1
                and (.[-1] | ((.kind // "sample") == "sample" and .final == true))
                and (
                  if $sustain_workload == "1" then
                    ([ $samples[] | select(.final != true) ] | length)
                      == (($stop_at / $cadence) | ceil)
                    and ([ $samples[]
                      | select(.final != true and .retired == $stop_at)
                    ] | length) == 1
                    and ([ $samples[]
                      | select(
                          .final != true
                          and .retired == $stop_at
                          and .stop_at == $stop_at
                          and .stop_requested == false
                        )
                    ] | length) == 1
                    and ([ $samples[]
                      | select(
                          .final == true
                          and .retired >= $stop_at
                          and (.retired - $stop_at) <= $quantum
                          and .stop_at == $stop_at
                          and .stop_requested == true
                        )
                    ] | length) == 1
                  else
                    any($samples[]; .final == true)
                  end
                )
                and (
                  if $expect_rr_cursor == "1" then
                    ($switches | length) > 0
                    and all($switches[]; (
                      .rr_switch_event > 0
                      and .previous_rr_switch_quantum == $quantum
                      and .rr_switch_quantum == $quantum
                      and .from_vcpu >= 0
                      and .from_vcpu < $vcpus
                      and .to_vcpu >= 0
                      and .to_vcpu < $vcpus
                      and .rr_cursor_position <= $quantum
                      and (.per_vcpu_retired | type == "array")
                      and (.per_vcpu_retired | length) == $vcpus
                      and (.per_vcpu_delta | type == "array")
                      and (.per_vcpu_delta | length) == $vcpus
                      and all(.per_vcpu_retired[]; . >= 0)
                      and all(.per_vcpu_delta[]; . >= 0)
                      and any(.per_vcpu_delta[]; . > 0)
                    ))
                  else
                    ($switches | length) == 0
                  end
                )
              ' "$TMPDIR/trace-$label.jsonl" >/dev/null; then
              diagnose_trace_structure "$label"
              fail "trace $label failed structural S11 assertions"
            fi
          done

          samples_a=$(jq -s '[.[] | select((.kind // "sample") == "sample")] | length' "$TMPDIR/trace-a.jsonl")
          samples_b=$(jq -s '[.[] | select((.kind // "sample") == "sample")] | length' "$TMPDIR/trace-b.jsonl")
          rr_switch_events_a=$(jq -s '[.[] | select(.kind == "rr_switch")] | length' "$TMPDIR/trace-a.jsonl")
          rr_switch_events_b=$(jq -s '[.[] | select(.kind == "rr_switch")] | length' "$TMPDIR/trace-b.jsonl")
          [ "$samples_a" -ge 4 ] || fail "expected at least 4 samples in run a"
          if [ "$EXPECT_RR_CURSOR" -eq 1 ]; then
            [ "$rr_switch_events_a" -gt 0 ] || fail "expected RR switch events in run a"
          else
            [ "$rr_switch_events_a" -eq 0 ] \
              || fail "unexpected RR switch events under non-sim accelerator in run a"
          fi

          mkdir -p "$out"
          for label in a b; do
            jq -r '
              select(.kind == "rr_switch")
              | [
                  .rr_switch_event,
                  .retired,
                  .from_vcpu,
                  .to_vcpu,
                  .rr_cursor_position,
                  .rr_switch_quantum
                ]
              | @tsv
            ' "$TMPDIR/trace-$label.jsonl" > "$TMPDIR/rr-switch-trace-$label.tsv"
            jq -r '
              select(.kind == "rr_switch")
              | [
                  .rr_switch_event,
                  (.per_vcpu_delta | join(",")),
                  (.per_vcpu_retired | join(","))
                ]
              | @tsv
            ' "$TMPDIR/trace-$label.jsonl" > "$TMPDIR/per-vcpu-delta-trace-$label.tsv"
          done
          localize_first_difference() {
            left_trace="$1"
            right_trace="$2"
            localization_output="$3"
            gawk '
              NR == FNR {
                left[FNR] = $0
                left_count = FNR
                next
              }
              {
                right_count = FNR
              }
              !(FNR in left) || left[FNR] != $0 {
                print FNR "\t" ((FNR in left) ? left[FNR] : "null") "\t" $0
                found = 1
                exit 0
              }
              END {
                if (!found && left_count > right_count) {
                  line = right_count + 1
                  print line "\t" left[line] "\tnull"
                }
              }
            ' "$left_trace" "$right_trace" > "$TMPDIR/first-difference.tsv"
            [ -s "$TMPDIR/first-difference.tsv" ] \
              || fail "mismatched traces did not yield a localizable JSON record"
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
                    if $left[0] == null then "missing_left_trace_record"
                    elif $right[0] == null then "missing_right_trace_record"
                    elif ($left[0].kind // "sample") != ($right[0].kind // "sample") then "kind"
                    elif ($left[0].kind // "sample") == "rr_switch" then
                      if $left[0].rr_switch_event != $right[0].rr_switch_event then "rr_switch_event"
                      elif $left[0].retired != $right[0].retired then "node_icount"
                      elif $left[0].from_vcpu != $right[0].from_vcpu then "from_vcpu"
                      elif $left[0].to_vcpu != $right[0].to_vcpu then "to_vcpu"
                      elif $left[0].rr_cursor_position != $right[0].rr_cursor_position then "rr_cursor_position"
                      elif $left[0].rr_switch_quantum != $right[0].rr_switch_quantum then "rr_switch_quantum"
                      elif $left[0].per_vcpu_delta != $right[0].per_vcpu_delta then
                        ([range(0; ($left[0].per_vcpu_delta | length)) | select($left[0].per_vcpu_delta[.] != $right[0].per_vcpu_delta[.])]) as $diffs
                        | ($diffs[0] // null) as $idx
                        | if $idx == null then "per_vcpu_delta" else "per_vcpu_delta[" + ($idx | tostring) + "]" end
                      elif $left[0].per_vcpu_retired != $right[0].per_vcpu_retired then
                        ([range(0; ($left[0].per_vcpu_retired | length)) | select($left[0].per_vcpu_retired[.] != $right[0].per_vcpu_retired[.])]) as $diffs
                        | ($diffs[0] // null) as $idx
                        | if $idx == null then "per_vcpu_retired" else "per_vcpu_retired[" + ($idx | tostring) + "]" end
                      else "unknown"
                      end
                    elif $left[0].retired != $right[0].retired then "node_icount"
                    elif $left[0].vcpu != $right[0].vcpu then "vcpu"
                    elif $left[0].rr_current_vcpu != $right[0].rr_current_vcpu then "rr_current_vcpu"
                    elif $left[0].rr_cursor_position != $right[0].rr_cursor_position then "rr_cursor_position"
                    elif $left[0].launch_definition_digest != $right[0].launch_definition_digest then "launch_definition_digest"
                    elif $left[0].qemu_build_digest != $right[0].qemu_build_digest then "qemu_build_digest"
                    elif $left[0].trace_plugin_build_digest != $right[0].trace_plugin_build_digest then "trace_plugin_build_digest"
                    elif $left[0].register_hashes != $right[0].register_hashes then
                      ([range(0; ($left[0].register_hashes | length)) | select($left[0].register_hashes[.] != $right[0].register_hashes[.])]) as $diffs
                      | ($diffs[0] // null) as $idx
                      | if $idx == null then "register_hashes" else "register_hashes[" + ($idx | tostring) + "]" end
                    elif $left[0].register_counts != $right[0].register_counts then
                      ([range(0; ($left[0].register_counts | length)) | select($left[0].register_counts[.] != $right[0].register_counts[.])]) as $diffs
                      | ($diffs[0] // null) as $idx
                      | if $idx == null then "register_counts" else "register_counts[" + ($idx | tostring) + "]" end
                    elif $left[0].register_file_bytes != $right[0].register_file_bytes then
                      ([range(0; ($left[0].register_file_bytes | length)) | select($left[0].register_file_bytes[.] != $right[0].register_file_bytes[.])]) as $diffs
                      | ($diffs[0] // null) as $idx
                      | if $idx == null then "register_file_bytes" else "register_file_bytes[" + ($idx | tostring) + "]" end
                    elif $left[0].register_schema_hashes != $right[0].register_schema_hashes then
                      ([range(0; ($left[0].register_schema_hashes | length)) | select($left[0].register_schema_hashes[.] != $right[0].register_schema_hashes[.])]) as $diffs
                      | ($diffs[0] // null) as $idx
                      | if $idx == null then "register_schema_hashes" else "register_schema_hashes[" + ($idx | tostring) + "]" end
                    elif $left[0].register_hash != $right[0].register_hash then "register_hash"
                    elif $left[0].ram_hash != $right[0].ram_hash then "ram_hash"
                    elif $left[0].device_event_hash != $right[0].device_event_hash then "device_event_hash"
                    elif $left[0].stream_hash != $right[0].stream_hash then "stream_hash"
                    elif $left[0].extended_hash != $right[0].extended_hash then "extended_hash"
                    else "unknown"
                    end;
                  component
                '
            )
            first_differing_node_icount=$(
              jq -n -r \
                --slurpfile left "$TMPDIR/first-left.json" \
                --slurpfile right "$TMPDIR/first-right.json" \
                '[ $left[0].retired, $right[0].retired ]
                 | map(select(type == "number"))
                 | min // "unknown"'
            )
            {
              echo "first_differing_line=$first_differing_line"
              echo "first_differing_node_icount=$first_differing_node_icount"
              echo "first_differing_component=$first_differing_component"
              echo "left=$left_json"
              echo "right=$right_json"
            } > "$localization_output"
          }

          rr_switch_trace_match=true
          if ! diff -u "$TMPDIR/rr-switch-trace-a.tsv" "$TMPDIR/rr-switch-trace-b.tsv" > "$out/rr-switch-trace.diff"; then
            rr_switch_trace_match=false
          fi
          per_vcpu_delta_trace_match=true
          if ! diff -u "$TMPDIR/per-vcpu-delta-trace-a.tsv" "$TMPDIR/per-vcpu-delta-trace-b.tsv" > "$out/per-vcpu-delta-trace.diff"; then
            per_vcpu_delta_trace_match=false
          fi
          if ! diff -u "$TMPDIR/trace-a.jsonl" "$TMPDIR/trace-b.jsonl" > "$out/trace.diff"; then
            localize_first_difference \
              "$TMPDIR/trace-a.jsonl" \
              "$TMPDIR/trace-b.jsonl" \
              "$out/first-difference.txt"
            cat "$out/first-difference.txt" >&2
            fail "extended fingerprint mismatch"
          fi
          [ "$rr_switch_trace_match" = true ] \
            || fail "RR switch projection differs despite equal raw traces"
          [ "$per_vcpu_delta_trace_match" = true ] \
            || fail "per-vCPU icount projection differs despite equal raw traces"
          [ "$samples_a" -eq "$samples_b" ] \
            || fail "sample count differs despite equal raw traces: $samples_a/$samples_b"
          [ "$rr_switch_events_a" -eq "$rr_switch_events_b" ] \
            || fail "RR switch event count differs despite equal raw traces: $rr_switch_events_a/$rr_switch_events_b"

          jq -s -c \
            '[.[] | select((.kind // "sample") == "sample" and .final != true)][0]' \
            "$TMPDIR/trace-a.jsonl" > "$TMPDIR/localization-base.jsonl"
          [ -s "$TMPDIR/localization-base.jsonl" ] \
            || fail "trace omitted a sample for mismatch-localization testing"
          localization_expected_icount=$(jq -r '.retired' "$TMPDIR/localization-base.jsonl")
          localization_vcpu_index=$((VCPU_COUNT - 1))
          jq -c --argjson index "$localization_vcpu_index" \
            '.register_hashes[$index] = (if .register_hashes[$index] == "ffffffffffffffff" then "0000000000000000" else "ffffffffffffffff" end)' \
            "$TMPDIR/localization-base.jsonl" > "$TMPDIR/localization-vcpu.jsonl"
          localize_first_difference \
            "$TMPDIR/localization-base.jsonl" \
            "$TMPDIR/localization-vcpu.jsonl" \
            "$out/localization-vcpu.txt"
          grep -q "^first_differing_node_icount=$localization_expected_icount$" \
            "$out/localization-vcpu.txt" \
            || fail "vCPU mismatch localizer reported the wrong node-icount"
          grep -F -q "first_differing_component=register_hashes[$localization_vcpu_index]" \
            "$out/localization-vcpu.txt" \
            || fail "vCPU mismatch localizer did not identify vCPU $localization_vcpu_index"

          jq -c '.rr_cursor_position += 1' \
            "$TMPDIR/localization-base.jsonl" > "$TMPDIR/localization-rr-cursor.jsonl"
          localize_first_difference \
            "$TMPDIR/localization-base.jsonl" \
            "$TMPDIR/localization-rr-cursor.jsonl" \
            "$out/localization-rr-cursor.txt"
          grep -q "^first_differing_node_icount=$localization_expected_icount$" \
            "$out/localization-rr-cursor.txt" \
            || fail "RR cursor mismatch localizer reported the wrong node-icount"
          grep -q '^first_differing_component=rr_cursor_position$' \
            "$out/localization-rr-cursor.txt" \
            || fail "RR cursor mismatch localizer did not identify the cursor"

          final_line=$(grep '"final":true' "$TMPDIR/trace-a.jsonl" | tail -1)
          [ -n "$final_line" ] || fail "trace a omitted the plugin-exit sample"
          final_line_b=$(grep '"final":true' "$TMPDIR/trace-b.jsonl" | tail -1)
          [ -n "$final_line_b" ] || fail "trace b omitted the plugin-exit sample"
          plugin_exit_retired=$(printf '%s\n' "$final_line" | jq -r '.retired')
          plugin_exit_retired_b=$(printf '%s\n' "$final_line_b" | jq -r '.retired')
          plugin_exit_stop_requested=$(printf '%s\n' "$final_line" | jq -r '.stop_requested')
          plugin_exit_stop_requested_b=$(printf '%s\n' "$final_line_b" | jq -r '.stop_requested')
          final_extended_hash=$(printf '%s\n' "$final_line" | jq -r '.extended_hash')
          final_register_hash=$(printf '%s\n' "$final_line" | jq -r '.register_hash')
          final_register_hashes=$(printf '%s\n' "$final_line" | jq -c '.register_hashes')
          final_register_counts=$(printf '%s\n' "$final_line" | jq -c '.register_counts')
          final_register_file_bytes=$(printf '%s\n' "$final_line" | jq -c '.register_file_bytes')
          final_ram_hash=$(printf '%s\n' "$final_line" | jq -r '.ram_hash')
          final_ram_bytes=$(printf '%s\n' "$final_line" | jq -r '.ram_bytes')
          final_rr_cursor=$(printf '%s\n' "$final_line" \
            | jq -c '[.rr_current_vcpu,.rr_cursor_position,.rr_switch_quantum]')
          final_memory_events=$(printf '%s\n' "$final_line" | jq -r '.memory_events')
          final_io_events=$(printf '%s\n' "$final_line" | jq -r '.io_events')
          final_register_read_failures=$(printf '%s\n' "$final_line" | jq -r '.register_read_failures')

          horizon_sample_retired=not-applicable
          horizon_sample_stop_requested=not-applicable
          horizon_sample_plugin_exit_retired_match=not-applicable
          horizon_sample_plugin_exit_stream_match=not-applicable
          horizon_sample_plugin_exit_register_match=not-applicable
          horizon_sample_plugin_exit_ram_match=not-applicable
          horizon_sample_plugin_exit_rr_match=not-applicable
          horizon_sample_cross_run_match=not-applicable
          horizon_sample_plugin_exit_state_comparison=not-applicable
          exact_horizon_authoritative=not-applicable
          plugin_exit_semantics=guest-complete
          plugin_exit_pause_overshoot=not-applicable
          plugin_exit_pause_overshoot_bound=not-applicable
          plugin_exit_pause_overshoot_bounded=not-applicable
          plugin_exit_pause_overshoot_cross_run_match=not-applicable
          periodic_samples_expected=not-applicable
          periodic_samples_observed=not-applicable
          plugin_exit_fingerprint_compared=true
          if [ "$SUSTAIN_WORKLOAD" -eq 1 ]; then
            horizon_line=$(jq -c --argjson stop_at "$STOP_AT_VALUE" \
              'select((.kind // "sample") == "sample" and .final != true and .retired == $stop_at)' \
              "$TMPDIR/trace-a.jsonl" | tail -1)
            [ -n "$horizon_line" ] || fail "trace a omitted the exact stop_at horizon sample"

            horizon_sample_retired=$(printf '%s\n' "$horizon_line" | jq -r '.retired')
            horizon_sample_stop_requested=$(printf '%s\n' "$horizon_line" | jq -r '.stop_requested')
            horizon_stream_hash=$(printf '%s\n' "$horizon_line" | jq -r '.stream_hash')
            horizon_register_hash=$(printf '%s\n' "$horizon_line" | jq -r '.register_hash')
            horizon_register_hashes=$(printf '%s\n' "$horizon_line" | jq -c '.register_hashes')
            horizon_ram_hash=$(printf '%s\n' "$horizon_line" | jq -r '.ram_hash')
            horizon_ram_bytes=$(printf '%s\n' "$horizon_line" | jq -r '.ram_bytes')
            horizon_rr_cursor=$(printf '%s\n' "$horizon_line" \
              | jq -c '[.rr_current_vcpu,.rr_cursor_position,.rr_switch_quantum]')
            plugin_exit_stream_hash=$(printf '%s\n' "$final_line" | jq -r '.stream_hash')

            [ "$horizon_sample_retired" = "$STOP_AT" ] \
              || fail "horizon sample retired mismatch: $horizon_sample_retired/$STOP_AT"
            [ "$horizon_sample_stop_requested" = false ] \
              || fail "horizon sample unexpectedly postdates the plugin stop request"
            [ "$plugin_exit_stop_requested" = true ] \
              || fail "plugin-exit sample omitted the stop request"
            [ "$plugin_exit_stop_requested_b" = true ] \
              || fail "run b plugin-exit sample omitted the stop request"

            [ "$plugin_exit_retired" -ge "$STOP_AT" ] \
              || fail "plugin exit retired before the exact horizon: $plugin_exit_retired/$STOP_AT"
            [ "$plugin_exit_retired_b" -ge "$STOP_AT" ] \
              || fail "run b plugin exit retired before the exact horizon: $plugin_exit_retired_b/$STOP_AT"
            plugin_exit_pause_overshoot=$((plugin_exit_retired - STOP_AT))
            plugin_exit_pause_overshoot_b=$((plugin_exit_retired_b - STOP_AT))
            periodic_samples_expected=$(((STOP_AT + CADENCE - 1) / CADENCE))
            periodic_samples_observed=$((samples_a - 1))
            [ "$periodic_samples_observed" -eq "$periodic_samples_expected" ] \
              || fail "non-final periodic sample count mismatch: $periodic_samples_observed/$periodic_samples_expected"
            [ "$plugin_exit_pause_overshoot" -le "$RR_SWITCH_QUANTUM" ] \
              || fail "plugin-exit pause overshoot exceeds one RR quantum: $plugin_exit_pause_overshoot/$RR_SWITCH_QUANTUM"
            [ "$plugin_exit_pause_overshoot_b" -le "$RR_SWITCH_QUANTUM" ] \
              || fail "run b plugin-exit pause overshoot exceeds one RR quantum: $plugin_exit_pause_overshoot_b/$RR_SWITCH_QUANTUM"
            [ "$plugin_exit_pause_overshoot" -eq "$plugin_exit_pause_overshoot_b" ] \
              || fail "plugin-exit pause overshoot differs across runs: $plugin_exit_pause_overshoot/$plugin_exit_pause_overshoot_b"

            if [ "$horizon_sample_retired" = "$plugin_exit_retired" ]; then
              horizon_sample_plugin_exit_retired_match=true
            else
              horizon_sample_plugin_exit_retired_match=false
            fi
            if [ "$horizon_stream_hash" = "$plugin_exit_stream_hash" ]; then
              horizon_sample_plugin_exit_stream_match=true
            else
              horizon_sample_plugin_exit_stream_match=false
            fi
            if [ "$horizon_register_hash" = "$final_register_hash" ] \
              && [ "$horizon_register_hashes" = "$final_register_hashes" ]; then
              horizon_sample_plugin_exit_register_match=true
            else
              horizon_sample_plugin_exit_register_match=false
            fi
            if [ "$horizon_ram_hash" = "$final_ram_hash" ] \
              && [ "$horizon_ram_bytes" = "$final_ram_bytes" ]; then
              horizon_sample_plugin_exit_ram_match=true
            else
              horizon_sample_plugin_exit_ram_match=false
            fi
            if [ "$horizon_rr_cursor" = "$final_rr_cursor" ]; then
              horizon_sample_plugin_exit_rr_match=true
            else
              horizon_sample_plugin_exit_rr_match=false
            fi
            horizon_sample_cross_run_match=true
            horizon_sample_plugin_exit_state_comparison=recorded-non-authoritative-teardown
            exact_horizon_authoritative=true
            plugin_exit_semantics=post-stop-request-teardown-observation
            plugin_exit_pause_overshoot_bound="$RR_SWITCH_QUANTUM"
            plugin_exit_pause_overshoot_bounded=true
            plugin_exit_pause_overshoot_cross_run_match=true
          fi

          workload_affinity_active=false
          if grep -q "CRUCIBLE_S11_AFFINITY_ACTIVE vcpus=0,1,2,3" "$TMPDIR/serial-a.log" \
            && grep -q "CRUCIBLE_S11_AFFINITY_ACTIVE vcpus=0,1,2,3" "$TMPDIR/serial-b.log"; then
            workload_affinity_active=true
          fi
          sustained_workload_active=false
          if [ "$SUSTAIN_WORKLOAD" -eq 1 ] \
            && [ "$workload_affinity_active" = true ] \
            && grep -q "CRUCIBLE_S11_SUSTAIN_ACTIVE threads=4 mode=spinlock" "$TMPDIR/serial-a.log" \
            && grep -q "CRUCIBLE_S11_SUSTAIN_ACTIVE threads=4 mode=spinlock" "$TMPDIR/serial-b.log"; then
            sustained_workload_active=true
          fi
          if [ -n "$STOP_AT" ]; then
            run_horizon="plugin-stop_at-$STOP_AT"
            result_horizon_icount="$STOP_AT"
            stop_request=plugin-requested-icount-pause
          else
            run_horizon="guest-complete"
            result_horizon_icount=not-applicable
            stop_request=not-requested-guest-reboot
          fi

          cp "$TMPDIR/trace-a.jsonl" "$out/trace-a.jsonl"
          cp "$TMPDIR/trace-b.jsonl" "$out/trace-b.jsonl"
          cp "$TMPDIR/rr-switch-trace-a.tsv" "$out/rr-switch-trace-a.tsv"
          cp "$TMPDIR/rr-switch-trace-b.tsv" "$out/rr-switch-trace-b.tsv"
          cp "$TMPDIR/per-vcpu-delta-trace-a.tsv" "$out/per-vcpu-delta-trace-a.tsv"
          cp "$TMPDIR/per-vcpu-delta-trace-b.tsv" "$out/per-vcpu-delta-trace-b.tsv"
          cp "$TMPDIR/serial-a.log" "$out/serial-a.log"
          cp "$TMPDIR/serial-b.log" "$out/serial-b.log"
          cp "$TMPDIR/qemu-args-a.txt" "$out/qemu-args-a.txt"
          cp "$TMPDIR/qemu-args-b.txt" "$out/qemu-args-b.txt"
          cp "$TMPDIR/launch-definition.txt" "$out/launch-definition.txt"
          {
            echo PASS
            echo spike=multi-vcpu-rr-sim-tcg-fingerprint
            echo scenario=smp-contended-pthread-spinlock
            echo boot_medium=initramfs
            echo block_devices=0
            echo accelerator="$ACCELERATOR"
            echo vcpus="$VCPU_COUNT"
            echo memory_mib="$MEMORY_MIB"
            echo rr_switch_quantum="$RR_SWITCH_QUANTUM"
            echo cadence="$CADENCE"
            echo run_horizon="$run_horizon"
            echo horizon_icount="$result_horizon_icount"
            echo wall_timeout_seconds="$RUN_TIMEOUT_SECONDS"
            echo require_guest_pass="$REQUIRE_GUEST_PASS"
            echo sustain_workload="$SUSTAIN_WORKLOAD"
            echo sustained_workload_active="$sustained_workload_active"
            echo sustained_workload_marker=CRUCIBLE_S11_SUSTAIN_ACTIVE
            echo workload_affinity_active="$workload_affinity_active"
            if [ "$workload_affinity_active" = true ]; then
              echo workload_affinity_vcpus=0,1,2,3
            else
              echo workload_affinity_vcpus=not-observed
            fi
            if [ "$DET_IPI_PROBE" -eq 1 ]; then
              echo det_ipi_probe=enabled
            else
              echo det_ipi_probe=disabled
            fi
            echo host_adversary=jitter-load
            if [ "$EXPECT_RR_CURSOR" -eq 1 ]; then
              echo rr_cursor_export=sim
              echo rr_cursor_assertion=nonempty_valid_snapshot
            else
              echo rr_cursor_export=inert-non-sim
              echo rr_cursor_assertion=inert_non_sim
            fi
            echo extended_fingerprint_match=true
            echo aggregate_icount_stream_match=true
            echo rr_switch_trace_match=true
            echo per_vcpu_delta_trace_match=true
            echo rr_switch_events="$rr_switch_events_a"
            echo horizon_fingerprint_match=true
            echo horizon_sample_retired="$horizon_sample_retired"
            echo horizon_sample_stop_requested="$horizon_sample_stop_requested"
            echo plugin_exit_retired="$plugin_exit_retired"
            echo plugin_exit_stop_requested="$plugin_exit_stop_requested"
            echo exact_horizon_authoritative="$exact_horizon_authoritative"
            echo plugin_exit_semantics="$plugin_exit_semantics"
            echo plugin_exit_pause_overshoot="$plugin_exit_pause_overshoot"
            echo plugin_exit_pause_overshoot_bound="$plugin_exit_pause_overshoot_bound"
            echo plugin_exit_pause_overshoot_bounded="$plugin_exit_pause_overshoot_bounded"
            echo plugin_exit_pause_overshoot_cross_run_match="$plugin_exit_pause_overshoot_cross_run_match"
            echo periodic_samples_expected="$periodic_samples_expected"
            echo periodic_samples_observed="$periodic_samples_observed"
            echo stop_request="$stop_request"
            echo stop_requested="$plugin_exit_stop_requested"
            echo plugin_exit_fingerprint_compared="$plugin_exit_fingerprint_compared"
            echo horizon_sample_cross_run_match="$horizon_sample_cross_run_match"
            echo plugin_exit_cross_run_match=true
            echo horizon_sample_plugin_exit_state_comparison="$horizon_sample_plugin_exit_state_comparison"
            echo horizon_sample_plugin_exit_retired_match="$horizon_sample_plugin_exit_retired_match"
            echo horizon_sample_plugin_exit_stream_match="$horizon_sample_plugin_exit_stream_match"
            echo horizon_sample_plugin_exit_register_match="$horizon_sample_plugin_exit_register_match"
            echo horizon_sample_plugin_exit_ram_match="$horizon_sample_plugin_exit_ram_match"
            echo horizon_sample_plugin_exit_rr_match="$horizon_sample_plugin_exit_rr_match"
            if [ "$SUSTAIN_WORKLOAD" -eq 1 ]; then
              echo horizon_stream_hash="$horizon_stream_hash"
              echo horizon_register_hash="$horizon_register_hash"
              echo horizon_ram_hash="$horizon_ram_hash"
              echo horizon_ram_bytes="$horizon_ram_bytes"
              echo horizon_rr_cursor="$horizon_rr_cursor"
              echo plugin_exit_stream_hash="$plugin_exit_stream_hash"
              echo plugin_exit_rr_cursor="$final_rr_cursor"
            fi
            echo samples="$samples_a"
            echo final_extended_hash="$final_extended_hash"
            echo final_register_hash="$final_register_hash"
            echo final_register_hashes="$final_register_hashes"
            echo final_register_counts="$final_register_counts"
            echo final_register_file_bytes="$final_register_file_bytes"
            echo final_ram_hash="$final_ram_hash"
            echo final_ram_bytes="$final_ram_bytes"
            echo device_event_capture=false
            echo memory_event_capture=false
            echo final_memory_events="$final_memory_events"
            echo final_io_events="$final_io_events"
            echo register_read_failures="$final_register_read_failures"
            echo register_count_assertion=nonempty_per_vcpu
            echo register_hash_assertion=nonzero_per_vcpu
            echo register_file_bytes_assertion=nonempty_per_vcpu
            echo ram_snapshot_assertion=nonempty_nonzero_hash
            echo qemu_build_digest="$qemu_build_digest"
            echo trace_plugin_build_digest="$trace_plugin_build_digest"
            echo launch_definition_digest="$launch_definition_digest"
            echo kernel_digest="$kernel_digest"
            echo initramfs_digest="$initramfs_digest"
            echo seed_digest="$seed_digest"
            echo provenance_digest_source=external-artifacts-and-canonical-launch-material
            echo embedded_zero_digests_sufficient=false
            echo block_device_assertion=launch_argv_scan
            echo mismatch_localization=component
            echo first_differing_line=none
            echo first_differing_node_icount=none
            echo first_differing_component=none
            echo mismatch_localization_vcpu_negative_test=true
            echo mismatch_localization_rr_cursor_negative_test=true
            echo fallback=smp1_not_needed
          } > "$out/result"
        '';
      }
    ];

    passthru = {
      crucibleSmpGuest = {
        inherit initramfs;
        kernel = pkgs.linux;
        kernelAppend = "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0";
        stockEntropyKernelAppend = "console=ttyS0 reboot=k panic=1 rdinit=/init quiet net.ifnames=0";
      };
    };

    meta = {
      description = "Crucible Phase 0 S11 multi-vCPU RR-TCG fingerprint spike";
    };
  }
