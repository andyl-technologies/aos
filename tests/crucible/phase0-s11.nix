{
  pkgs,
  lib,
}: let
  cadence = 100000000;
  rrSwitchQuantum = 4096;
  vcpuCount = 4;

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
          #include <pthread.h>
          #include <sched.h>
          #include <stdint.h>
          #include <stdio.h>

          enum {
            THREADS = 4,
            ITERS = 8000
          };

          static volatile int spinlock;
          static volatile uint64_t shared_state = 0x0010c001ULL;
          static uint64_t counters[THREADS];

          static void lock_spin(void) {
            while (__sync_lock_test_and_set(&spinlock, 1) != 0) {
              sched_yield();
            }
          }

          static void unlock_spin(void) {
            __sync_lock_release(&spinlock);
          }

          static void *worker(void *arg) {
            const uintptr_t id = (uintptr_t)arg;
            uint64_t local = 0x9e3779b97f4a7c15ULL ^ id;

            for (int i = 0; i < ITERS; i++) {
              local ^= (uint64_t)i + (id << 32);
              local *= 0xbf58476d1ce4e5b9ULL;

              lock_spin();
              shared_state ^= local + counters[id] + (shared_state << 7);
              shared_state = (shared_state << 13) | (shared_state >> 51);
              counters[id] += shared_state ^ local;
              unlock_spin();

              if ((i & 127) == 0) {
                sched_yield();
              }
            }

            return 0;
          }

          int main(void) {
            pthread_t threads[THREADS];

            for (uintptr_t i = 0; i < THREADS; i++) {
              if (pthread_create(&threads[i], 0, worker, (void *)i) != 0) {
                puts("CRUCIBLE_S11_PTHREAD_CREATE_FAIL");
                return 1;
              }
            }

            for (int i = 0; i < THREADS; i++) {
              if (pthread_join(threads[i], 0) != 0) {
                puts("CRUCIBLE_S11_PTHREAD_JOIN_FAIL");
                return 1;
              }
            }

            printf(
              "CRUCIBLE_S11_DONE shared=%016llx c0=%016llx c1=%016llx c2=%016llx c3=%016llx\n",
              (unsigned long long)shared_state,
              (unsigned long long)counters[0],
              (unsigned long long)counters[1],
              (unsigned long long)counters[2],
              (unsigned long long)counters[3]);
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
            smp-contended || test_result=1

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
  pkgs.mkDerivation {
    pname = "crucible-phase0-s11-multi-vcpu-fingerprint";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.grep
      pkgs.jq
      pkgs.qemu-crucible
      pkgs.crucible-qemu-trace-plugin
    ];

    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL = builtins.toString pkgs.linux;
    PLUGIN = "${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so";
    CADENCE = builtins.toString cadence;
    RR_SWITCH_QUANTUM = builtins.toString rrSwitchQuantum;
    VCPU_COUNT = builtins.toString vcpuCount;

    phases = [
      {
        name = "run-s11-multi-vcpu-fingerprint";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          if [ -z "$vmlinuz" ]; then
            fail "no vmlinuz under $KERNEL/boot"
          fi

          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-s11-seed-v1\n' > "$seed"

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

          run_one() {
            label="$1"

            set -- qemu-system-x86_64 \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel tcg,thread=single \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum="$RR_SWITCH_QUANTUM" \
              -cpu qemu64 \
              -m 256 \
              -smp "$VCPU_COUNT" \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c011 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
              -chardev file,id=serial0,path="$TMPDIR/serial-$label.log" \
              -serial chardev:serial0 \
              -plugin "$PLUGIN",out="$TMPDIR/trace-$label.jsonl",cadence="$CADENCE",extended=on,mem_events=off,vcpus="$VCPU_COUNT" \
              -no-reboot

            printf '%s\n' "$@" > "$TMPDIR/qemu-args-$label.txt"
            if grep -E -q '^-drive$|^-blockdev$|^-cdrom$|^-hda$|^-hdb$|^-hdc$|^-hdd$|virtio-blk|scsi|nvme|ahci|ide-' "$TMPDIR/qemu-args-$label.txt"; then
              fail "guest $label launch is not diskless"
            fi

            timeout 600 "$@"
          }

          run_one a
          start_jitter
          run_one b
          stop_jitter

          for label in a b; do
            grep -q "TEST_RESULT:PASS" "$TMPDIR/serial-$label.log" \
              || fail "guest $label did not report TEST_RESULT:PASS"
            grep -q "CRUCIBLE_S11_DONE" "$TMPDIR/serial-$label.log" \
              || fail "guest $label did not run the SMP workload"
            jq -e -s \
              --argjson vcpus "$VCPU_COUNT" \
              --argjson quantum "$RR_SWITCH_QUANTUM" \
              '
                length >= 4
                and all(.[]; (
                  .tracked_vcpus == $vcpus
                  and .rr_switch_quantum == $quantum
                  and .sample_register_failures == 0
                  and .register_read_failures == 0
                  and .ram_bytes > 0
                  and .memory_events_enabled == false
                  and .device_event_capture == false
                  and .device_event_hash == null
                  and (.register_hashes | type == "array")
                  and (.register_hashes | length) == $vcpus
                  and (.register_counts | type == "array")
                  and (.register_counts | length) == $vcpus
                  and all(.register_counts[]; . > 0)
                ))
                and any(.[]; .final == true)
              ' "$TMPDIR/trace-$label.jsonl" >/dev/null \
              || fail "trace $label failed structural S11 assertions"
          done

          samples_a=$(wc -l < "$TMPDIR/trace-a.jsonl")
          samples_b=$(wc -l < "$TMPDIR/trace-b.jsonl")
          [ "$samples_a" -ge 4 ] || fail "expected at least 4 samples in run a"
          [ "$samples_a" -eq "$samples_b" ] || fail "sample count mismatch: $samples_a/$samples_b"

          mkdir -p "$out"
          if ! diff -u "$TMPDIR/trace-a.jsonl" "$TMPDIR/trace-b.jsonl" > "$out/trace.diff"; then
            gawk '
              NR == FNR { left[FNR] = $0; next }
              left[FNR] != $0 {
                print FNR "\t" left[FNR] "\t" $0
                exit 0
              }
            ' "$TMPDIR/trace-a.jsonl" "$TMPDIR/trace-b.jsonl" > "$TMPDIR/first-difference.tsv"
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
                    elif $left[0].rr_current_vcpu != $right[0].rr_current_vcpu then "rr_current_vcpu"
                    elif $left[0].rr_cursor_position != $right[0].rr_cursor_position then "rr_cursor_position"
                    elif $left[0].stream_hash != $right[0].stream_hash then "stream_hash"
                    elif $left[0].register_counts != $right[0].register_counts then
                      ([range(0; ($left[0].register_counts | length)) | select($left[0].register_counts[.] != $right[0].register_counts[.])]) as $diffs
                      | ($diffs[0] // null) as $idx
                      | if $idx == null then "register_counts" else "register_counts[" + ($idx | tostring) + "]" end
                    elif $left[0].register_hash != $right[0].register_hash then
                      ([range(0; ($left[0].register_hashes | length)) | select($left[0].register_hashes[.] != $right[0].register_hashes[.])]) as $diffs
                      | ($diffs[0] // null) as $idx
                      | if $idx == null then "register_hash" else "register_hashes[" + ($idx | tostring) + "]" end
                    elif $left[0].ram_hash != $right[0].ram_hash then "ram_hash"
                    elif $left[0].device_event_hash != $right[0].device_event_hash then "device_event_hash"
                    elif $left[0].extended_hash != $right[0].extended_hash then "extended_hash"
                    else "unknown"
                    end;
                  component
                '
            )
            {
              echo "first_differing_line=$first_differing_line"
              echo "first_differing_component=$first_differing_component"
              echo "left=$left_json"
              echo "right=$right_json"
            } > "$out/first-difference.txt"
            cat "$out/first-difference.txt" >&2
            fail "extended fingerprint mismatch"
          fi

          final_line=$(grep '"final":true' "$TMPDIR/trace-a.jsonl" | tail -1)
          final_extended_hash=$(printf '%s\n' "$final_line" | jq -r '.extended_hash')
          final_register_hash=$(printf '%s\n' "$final_line" | jq -r '.register_hash')
          final_ram_hash=$(printf '%s\n' "$final_line" | jq -r '.ram_hash')
          final_ram_bytes=$(printf '%s\n' "$final_line" | jq -r '.ram_bytes')
          final_memory_events=$(printf '%s\n' "$final_line" | jq -r '.memory_events')
          final_io_events=$(printf '%s\n' "$final_line" | jq -r '.io_events')
          final_register_read_failures=$(printf '%s\n' "$final_line" | jq -r '.register_read_failures')

          cp "$TMPDIR/trace-a.jsonl" "$out/trace-a.jsonl"
          cp "$TMPDIR/trace-b.jsonl" "$out/trace-b.jsonl"
          cp "$TMPDIR/serial-a.log" "$out/serial-a.log"
          cp "$TMPDIR/serial-b.log" "$out/serial-b.log"
          cp "$TMPDIR/qemu-args-a.txt" "$out/qemu-args-a.txt"
          cp "$TMPDIR/qemu-args-b.txt" "$out/qemu-args-b.txt"
          {
            echo PASS
            echo spike=multi-vcpu-rr-tcg-fingerprint
            echo scenario=smp-contended-pthread-spinlock
            echo boot_medium=initramfs
            echo block_devices=0
            echo vcpus="$VCPU_COUNT"
            echo rr_switch_quantum="$RR_SWITCH_QUANTUM"
            echo cadence="$CADENCE"
            echo host_adversary=jitter-load
            echo extended_fingerprint_match=true
            echo aggregate_icount_stream_match=true
            echo horizon_fingerprint_match=true
            echo samples="$samples_a"
            echo final_extended_hash="$final_extended_hash"
            echo final_register_hash="$final_register_hash"
            echo final_ram_hash="$final_ram_hash"
            echo final_ram_bytes="$final_ram_bytes"
            echo device_event_capture=false
            echo memory_event_capture=false
            echo final_memory_events="$final_memory_events"
            echo final_io_events="$final_io_events"
            echo register_read_failures="$final_register_read_failures"
            echo register_count_assertion=nonempty_per_vcpu
            echo block_device_assertion=launch_argv_scan
            echo mismatch_localization=component
            echo first_differing_line=none
            echo first_differing_component=none
            echo fallback=smp1_not_needed
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S11 multi-vCPU RR-TCG fingerprint spike";
    };
  }
