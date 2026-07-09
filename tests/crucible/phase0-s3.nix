{
  pkgs,
  lib,
}: let
  snapshotIcount = 100000000;
  segmentIcount = 50000000;
  pluginSource = builtins.readFile ./phase0-s3-segment-plugin.c;
  ownedStateSource = builtins.readFile ./phase0-s3-owned-state.c;
  s2WorkloadSource = builtins.readFile ./phase0-s2-workload.c;

  workload = pkgs.mkDerivation {
    pname = "crucible-phase0-s3-workload";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-workload";
        script = ''
          mkdir -p "$out/bin"

          cat > s3-workload.c <<'S3_WORKLOAD_C'
          #include <stdint.h>
          #include <stdio.h>

          enum {
            WORDS = 4096,
            ITERS = 12000
          };

          static uint64_t words[WORDS];

          static inline void
          marker_post_boot(void)
          {
            __asm__ __volatile__(
                "movl $0xc0100301, %%eax\n\t"
                :
                :
                : "rax", "memory");
          }

          int main(void) {
            uint64_t state = 0x0010c00150300001ULL;

            for (uint64_t i = 0; i < WORDS; i++) {
              state ^= i + 0x9e3779b97f4a7c15ULL;
              state *= 0xbf58476d1ce4e5b9ULL;
              words[i] = state ^ (i << 9);
            }

            for (uint64_t i = 0; i < ITERS; i++) {
              const uint64_t idx = (state ^ (state >> 31)) & (WORDS - 1);
              state ^= words[idx] + i + (state << 5);
              state = (state << 11) | (state >> 53);
              words[idx] ^= state + (i << 24);
            }

            printf("CRUCIBLE_S3_WORKLOAD state=%016llx\n", (unsigned long long)state);
            marker_post_boot();
            return state == 0 ? 1 : 0;
          }
          S3_WORKLOAD_C
          cc -std=c11 -O2 s3-workload.c -o "$out/bin/s3-workload"

          cat > s3-spin.c <<'S3_SPIN_C'
          #include <stdint.h>

          enum {
            ITERS = 500000000
          };

          static volatile uint64_t sink;

          int main(void) {
            uint64_t state = 0x0010c0015030feedULL;

            for (uint64_t i = 0; i < ITERS; i++) {
              state ^= i + 0xd6e8feb86659fd93ULL;
              state = (state << 13) | (state >> 51);
              state *= 0x9e3779b97f4a7c15ULL;
            }

            sink = state;
            return sink == 0 ? 1 : 0;
          }
          S3_SPIN_C
          cc -std=c11 -O2 s3-spin.c -o "$out/bin/s3-spin"

          cp "$s2WorkloadPath" phase0-s2-workload.c
          cc -std=c11 -O2 -Wall -Wextra phase0-s2-workload.c \
            -o "$out/bin/s2-io-workload"
        '';
      }
    ];

    s2Workload = s2WorkloadSource;
    passAsFile = ["s2Workload"];
  };

  blockImage = pkgs.mkDerivation {
    pname = "crucible-phase0-s3-block-image";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
    ];

    phases = [
      {
        name = "build-block-image";
        script = ''
          mkdir -p "$out"
          dd if=/dev/zero of="$out/block.img" bs=1M count=8 status=none
        '';
      }
    ];
  };

  poweroffHelper = pkgs.mkDerivation {
    pname = "crucible-phase0-s3-poweroff";
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

          cc poweroff.c -o "$out/bin/s3-poweroff"
        '';
      }
    ];
  };

  initramfs = let
    initramfsDeps = [
      pkgs.bash
      pkgs.coreutils
      pkgs.kmod
      pkgs.linux
      pkgs.util-linux
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
      pname = "crucible-phase0-s3-initramfs";
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

            mkdir -p root/bin root/sbin root/lib root/nix/store root/tmp root/proc root/sys root/dev root/run root/mnt/virtfs
            while IFS= read -r p; do
              cp -a "$p" root"$p"
            done < closure-paths

            ln -sfn ${pkgs.bash}/bin/bash root/bin/sh
            ln -sfn ${pkgs.bash}/bin/bash root/bin/bash
            ln -sfn ${pkgs.linux}/lib/modules root/lib/modules
            ln -sfn ${poweroffHelper}/bin/s3-poweroff root/sbin/poweroff

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            mount -t proc proc /proc
            mount -t sysfs sysfs /sys
            mount -t devtmpfs devtmpfs /dev
            mount -t tmpfs tmpfs /tmp
            mount -t tmpfs tmpfs /run

            echo "CRUCIBLE_S3_READY"
            test_result=0
            s3-workload || test_result=1

            for module in virtio_pci virtio_blk; do
              modprobe "$module" || true
            done

            i=0
            while [ "$i" -lt 100 ] && [ ! -b /dev/vda ]; do
              sleep 0.05
              i=$((i + 1))
            done
            [ -b /dev/vda ] || test_result=1

            if [ "$test_result" -eq 0 ]; then
              s2-io-workload /dev/vda || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              for module in 9pnet 9pnet_virtio 9p; do
                modprobe "$module" || true
              done
              mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 crucible_s3 /mnt/virtfs || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              s2-io-workload /dev/vda /mnt/virtfs || test_result=1
            fi

            if [ "$test_result" -eq 0 ]; then
              echo 'TEST_RESULT:PASS'
            else
              echo 'TEST_RESULT:FAIL'
              sync
              poweroff
            fi

            sync
            s3-spin
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
        description = "Crucible Phase 0 S3 diskless initramfs";
      };
    };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s3-savevm-loadvm";
    version = "0";
    src = null;

    plugin = pluginSource;
    ownedState = ownedStateSource;
    passAsFile = [
      "plugin"
      "ownedState"
    ];

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.glib
      pkgs.grep
      pkgs.jq
      pkgs.pkg-config
      pkgs.qemu-crucible
      pkgs.socat
    ];

    BLOCK_IMAGE = "${blockImage}/block.img";
    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL = builtins.toString pkgs.linux;
    QEMU = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
    QEMU_IMG = "${pkgs.qemu-crucible}/bin/qemu-img";
    SNAPSHOT_ICOUNT = builtins.toString snapshotIcount;
    SEGMENT_ICOUNT = builtins.toString segmentIcount;

    phases = [
      {
        name = "build-s3-tools";
        script = ''
          cp "$pluginPath" phase0-s3-segment-plugin.c
          cc -fPIC -shared -O2 -Wall -Wextra \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            phase0-s3-segment-plugin.c \
            -o phase0-s3-segment-plugin.so

          cp "$ownedStatePath" phase0-s3-owned-state.c
          cc -std=c11 -O2 -Wall -Wextra -Werror \
            phase0-s3-owned-state.c \
            -o phase0-s3-owned-state
        '';
      }
      {
        name = "run-s3-savevm-loadvm";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          json_string() {
            printf '%s\n' "$1" | jq -R .
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
              sleep 0.25
            } | socat -T 10 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true
          }

          qmp_cmd() {
            socket="$1"
            request="$2"
            response="$3"
            response_err="$response.err"
            attempts=0

            while [ "$attempts" -lt 20 ]; do
              qmp_exchange "$socket" "$request" "$response"

              if [ ! -s "$response" ]; then
                attempts=$((attempts + 1))
                sleep 0.25
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
              sleep 0.25
            done

            if [ -s "$response" ]; then
              cat "$response" >&2
            else
              cat "$response_err" >&2
            fi
            return 1
          }

          qmp_job_started() {
            socket="$1"
            job="$2"
            response="$3.probe"

            if ! qmp_cmd "$socket" '{"execute":"query-jobs"}' "$response"; then
              return 1
            fi
            if jq -e -s --arg job "$job" '
              ([.[] | select(has("return"))][-1].return // [])[]
              | select(.id == $job)
              | has("error")
            ' "$response" >/dev/null; then
              cat "$response" >&2
              return 1
            fi
            jq -e -s --arg job "$job" '
              any((([.[] | select(has("return"))][-1].return // [])[]); .id == $job)
            ' "$response" >/dev/null
          }

          qmp_job_cmd() {
            socket="$1"
            request="$2"
            response="$3"
            job="$4"
            response_err="$response.err"
            attempts=0

            while [ "$attempts" -lt 20 ]; do
              qmp_exchange "$socket" "$request" "$response"

              if [ -s "$response" ]; then
                if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
                  cat "$response" >&2
                  return 1
                fi
                if jq -e -s --arg job "$job" '
                  ([.[] | select(has("return"))] | length >= 2)
                  or any(.[]; .event == "JOB_STATUS_CHANGE" and .data.id == $job)
                ' "$response" >/dev/null; then
                  return 0
                fi
              fi

              if qmp_job_started "$socket" "$job" "$response"; then
                return 0
              fi

              attempts=$((attempts + 1))
              sleep 0.25
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

          wait_for_pause() {
            label="$1"
            socket="$2"
            waited=0
            while [ "$waited" -lt 1200 ]; do
              if qmp_cmd "$socket" '{"execute":"query-status"}' "$TMPDIR/qmp-status-$label.json"; then
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
              fi
              sleep 0.25
              waited=$((waited + 1))
            done
            return 1
          }

          wait_for_job() {
            label="$1"
            socket="$2"
            job="$3"
            waited=0
            while [ "$waited" -lt 1200 ]; do
              if qmp_cmd "$socket" '{"execute":"query-jobs"}' "$TMPDIR/qmp-jobs-$label-$job.json"; then
                if jq -e -s --arg job "$job" '
                  [.[] | select(has("return"))][-1].return[]
                  | select(.id == $job)
                  | has("error")
                ' "$TMPDIR/qmp-jobs-$label-$job.json" >/dev/null; then
                  cat "$TMPDIR/qmp-jobs-$label-$job.json" >&2
                  return 1
                fi
                if jq -e -s --arg job "$job" '
                  [.[] | select(has("return"))][-1].return[]
                  | select(.id == $job)
                  | .status == "concluded"
                ' "$TMPDIR/qmp-jobs-$label-$job.json" >/dev/null; then
                  return 0
                fi
              fi
              sleep 0.25
              waited=$((waited + 1))
            done
            return 1
          }

          cleanup_qemu() {
            if [ -n "''${qemu_pid:-}" ]; then
              kill "$qemu_pid" 2>/dev/null || true
              wait "$qemu_pid" 2>/dev/null || true
              qemu_pid=""
            fi
          }

          trap cleanup_qemu EXIT

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          if [ -z "$vmlinuz" ]; then
            fail "no vmlinuz under $KERNEL/boot"
          fi

          plugin="$PWD/phase0-s3-segment-plugin.so"
          seed="$TMPDIR/seed.bin"
          vmstate="$TMPDIR/vmstate.qcow2"
          ninep_root="$TMPDIR/9p-root"
          printf 'crucible-phase0-s3-seed-v1\n' > "$seed"
          "$QEMU_IMG" create -f qcow2 "$vmstate" 512M >/dev/null
          mkdir -p "$ninep_root"
          i=0
          while [ "$i" -lt 32 ]; do
            dd if=/dev/zero of="$ninep_root/$(printf 'file-%02d.bin' "$i")" bs=4096 count=1 status=none
            i=$((i + 1))
          done
          i=0
          while [ "$i" -lt 8 ]; do
            dd if=/dev/zero of="$ninep_root/$(printf 'warmup-%02d.bin' "$i")" bs=4096 count=1 status=none
            i=$((i + 1))
          done

          ./phase0-s3-owned-state > "$TMPDIR/owned-state.txt"
          grep -q '^owned_state_roundtrip=pass$' "$TMPDIR/owned-state.txt"
          grep -q '^ring_snapshot_restore=pass$' "$TMPDIR/owned-state.txt"
          grep -q '^overlay_delta_roundtrip=pass$' "$TMPDIR/owned-state.txt"
          grep -q '^rng_position_roundtrip=pass$' "$TMPDIR/owned-state.txt"

          run_qemu() {
            label="$1"
            start_paused="$2"
            plugin_args="$3"
            shift
            shift
            shift
            qmp_socket="$TMPDIR/qmp-$label.sock"
            serial="$TMPDIR/serial-$label.log"
            trace="$TMPDIR/trace-$label.jsonl"
            rm -f "$qmp_socket"

            case "$start_paused" in
              yes)
                qemu_start_arg=-S
                ;;
              no)
                qemu_start_arg=
                ;;
              *)
                fail "invalid start_paused value for $label"
                ;;
            esac
            [ "$#" -eq 0 ] || fail "unexpected QEMU arguments for $label"

            timeout 900 "$QEMU" \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel tcg,thread=single \
              -icount shift=0,sleep=off,align=off \
              -cpu qemu64 \
              -m 1024 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c001 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
              -drive id=s3block,file="$BLOCK_IMAGE",format=raw,if=none,readonly=on,cache=unsafe,throttling.iops-read=20 \
              -device virtio-blk-pci,drive=s3block \
              -fsdev local,id=fs0,path="$ninep_root",security_model=none,throttling.iops-read=20 \
              -device virtio-9p-pci,fsdev=fs0,mount_tag=crucible_s3 \
              -blockdev driver=file,filename="$vmstate",node-name=vmfile \
              -blockdev driver=qcow2,file=vmfile,node-name=vmstate \
              -chardev file,id=serial0,path="$serial" \
              -serial chardev:serial0 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              $qemu_start_arg \
              -plugin "$plugin",out="$trace","$plugin_args" \
              -no-shutdown \
              -no-reboot &
            qemu_pid="$!"
          }

          probe_commands() {
            socket="$1"
            waited=0
            while [ "$waited" -lt 40 ]; do
              if qmp_cmd "$socket" '{"execute":"query-commands"}' "$TMPDIR/qmp-commands.json"; then
                break
              fi
              sleep 0.25
              waited=$((waited + 1))
            done
            [ "$waited" -lt 40 ] || fail "query-commands failed"
            jq -r -s '[.[] | select(has("return"))][-1].return[].name' \
              "$TMPDIR/qmp-commands.json" | sort > "$TMPDIR/qmp-command-names.txt"
            grep -F -x -q snapshot-save "$TMPDIR/qmp-command-names.txt"
            grep -F -x -q snapshot-load "$TMPDIR/qmp-command-names.txt"
            grep -F -x -q migrate "$TMPDIR/qmp-command-names.txt"
            grep -F -x -q migrate-incoming "$TMPDIR/qmp-command-names.txt"
            grep -F -x -q human-monitor-command "$TMPDIR/qmp-command-names.txt"
            if grep -F -x -q savevm "$TMPDIR/qmp-command-names.txt"; then
              fail "unexpected typed savevm command present"
            fi
            if grep -F -x -q loadvm "$TMPDIR/qmp-command-names.txt"; then
              fail "unexpected typed loadvm command present"
            fi
          }

          snapshot_save() {
            socket="$1"
            tag="$2"
            job="$3"
            tag_json=$(json_string "$tag")
            job_json=$(json_string "$job")
            request=$(printf '{"execute":"snapshot-save","arguments":{"job-id":%s,"tag":%s,"vmstate":"vmstate","devices":["vmstate"]}}' "$job_json" "$tag_json")
            qmp_job_cmd "$socket" "$request" "$TMPDIR/qmp-snapshot-save.json" "$job" \
              || fail "snapshot-save command failed"
            wait_for_job save "$socket" "$job" || fail "snapshot-save job did not conclude successfully"
          }

          snapshot_load() {
            socket="$1"
            tag="$2"
            job="$3"
            tag_json=$(json_string "$tag")
            job_json=$(json_string "$job")
            request=$(printf '{"execute":"snapshot-load","arguments":{"job-id":%s,"tag":%s,"vmstate":"vmstate","devices":["vmstate"]}}' "$job_json" "$tag_json")
            qmp_job_cmd "$socket" "$request" "$TMPDIR/qmp-snapshot-load.json" "$job" \
              || fail "snapshot-load command failed"
            wait_for_job load "$socket" "$job" || fail "snapshot-load job did not conclude successfully"
          }

          extract_pause_sample() {
            label="$1"
            jq -c 'select(.pause_sample == true)' "$TMPDIR/trace-$label.jsonl" \
              | tail -1 > "$TMPDIR/pause-$label.json"
            [ -s "$TMPDIR/pause-$label.json" ] || fail "missing pause sample for $label"
          }

          normalize_sample() {
            label="$1"
            jq -S '
              {
                segment_retired,
                logical_retired,
                stream_hash,
                register_hash,
                ram_hash,
                ram_bytes,
                rr_current_vcpu,
                rr_cursor_position,
                rr_switch_quantum,
                has_time_control,
                io_events,
                operation_active,
                active_medium,
                pause_medium,
                operation_io_events,
                operation_hlt_events,
                pause_io_events,
                pause_hlt_events,
                post_boot_markers,
                state_hash,
                register_counts
              }
            ' "$TMPDIR/pause-$label.json" > "$TMPDIR/normalized-$label.json"
          }

          assert_segment_sample() {
            label="$1"
            logical_base="$2"
            jq --argjson segment "$SEGMENT_ICOUNT" --argjson logical "$((logical_base + SEGMENT_ICOUNT))" -e '
              .pause_sample == true
              and .segment_started == true
              and .stop_requested == true
              and .segment_retired == $segment
              and .logical_retired == $logical
              and .has_time_control == true
              and .sample_register_failures == 0
              and .register_read_failures == 0
              and .marker_errors == 0
              and .ram_bytes > 0
              and (.register_counts | type == "array")
              and (.register_counts | length) == 1
              and .register_counts[0] > 0
            ' "$TMPDIR/pause-$label.json" >/dev/null \
              || fail "invalid segment sample for $label"
          }

          run_case() {
            case_name="$1"
            point_name="$2"
            save_args="$3"
            expected_medium="$4"
            expected_suffix="$5"

            tag="s3-$case_name"
            case "$expected_suffix" in
              match | diverge)
                ;;
              *)
                fail "invalid expected suffix result for $case_name"
                ;;
            esac
            run_qemu "save-$case_name" no "$save_args,extended=on,vcpus=1,time_control=on"
            wait_for_socket "$TMPDIR/qmp-save-$case_name.sock" \
              || fail "$case_name save QMP socket did not appear"
            probe_commands "$TMPDIR/qmp-save-$case_name.sock"
            wait_for_pause "save-$case_name" "$TMPDIR/qmp-save-$case_name.sock" \
              || fail "$case_name save run did not pause"
            extract_pause_sample "save-$case_name"
            pause_request_icount=$(jq -r '.retired_total' "$TMPDIR/pause-save-$case_name.json")
            [ "$pause_request_icount" -gt 0 ] || fail "$case_name pause request icount missing"
            jq -e '.has_time_control == true and .time_control_requested == true and .marker_errors == 0' \
              "$TMPDIR/pause-save-$case_name.json" >/dev/null \
              || fail "$case_name save sample missing time-control/marker evidence"
            if [ "$expected_medium" != none ]; then
              jq --arg medium "$expected_medium" -e '
                .operation_active == true
                and .active_medium == $medium
                and .pause_io_events >= 1
                and .pause_hlt_events >= 1
                and .io_events >= 1
              ' "$TMPDIR/pause-save-$case_name.json" >/dev/null \
                || fail "$case_name did not pause inside expected I/O operation"
              case "$expected_medium" in
                block)
                  grep -q "CRUCIBLE_S2_BLOCK_DIRECT=1" "$TMPDIR/serial-save-$case_name.log" \
                    || fail "$case_name paused before guest entered direct block workload"
                  ;;
                ninep)
                  grep -q "CRUCIBLE_S2_9P_DONE" "$TMPDIR/serial-save-$case_name.log" \
                    || fail "$case_name paused before guest entered 9p workload"
                  ;;
              esac
            fi
            cp "$TMPDIR/pause-save-$case_name.json" "$out/pause-save-$case_name.json"
            cp "$TMPDIR/serial-save-$case_name.log" "$out/serial-save-$case_name.log"
            snapshot_save "$TMPDIR/qmp-save-$case_name.sock" "$tag" "save-$tag"
            qmp_cmd "$TMPDIR/qmp-save-$case_name.sock" '{"execute":"quit"}' "$TMPDIR/qmp-quit-save-$case_name.json" || true
            wait "$qemu_pid" || fail "$case_name save QEMU exited unsuccessfully"
            qemu_pid=""
            tail -1 "$TMPDIR/trace-save-$case_name.jsonl" > "$TMPDIR/final-save-$case_name.json"
            snapshot_icount=$(jq -r '.retired_total' "$TMPDIR/final-save-$case_name.json")
            [ "$snapshot_icount" -ge "$pause_request_icount" ] \
              || fail "$case_name actual snapshot icount preceded pause request"
            cp "$TMPDIR/final-save-$case_name.json" "$out/final-save-$case_name.json"

            run_qemu "reference-$case_name" no start_at="$snapshot_icount",stop_after="$SEGMENT_ICOUNT",logical_base="$snapshot_icount",extended=on,vcpus=1,time_control=on
            wait_for_socket "$TMPDIR/qmp-reference-$case_name.sock" \
              || fail "$case_name reference QMP socket did not appear"
            wait_for_pause "reference-$case_name" "$TMPDIR/qmp-reference-$case_name.sock" \
              || fail "$case_name reference run did not pause"
            qmp_cmd "$TMPDIR/qmp-reference-$case_name.sock" '{"execute":"quit"}' "$TMPDIR/qmp-quit-reference-$case_name.json" || true
            wait "$qemu_pid" || fail "$case_name reference QEMU exited unsuccessfully"
            qemu_pid=""
            extract_pause_sample "reference-$case_name"
            assert_segment_sample "reference-$case_name" "$snapshot_icount"
            normalize_sample "reference-$case_name"
            cp "$TMPDIR/serial-reference-$case_name.log" "$out/serial-reference-$case_name.log"

            run_qemu "load-$case_name" yes start_at=0,stop_after="$SEGMENT_ICOUNT",logical_base="$snapshot_icount",extended=on,vcpus=1,time_control=on
            wait_for_socket "$TMPDIR/qmp-load-$case_name.sock" \
              || fail "$case_name load QMP socket did not appear"
            snapshot_load "$TMPDIR/qmp-load-$case_name.sock" "$tag" "load-$tag"
            qmp_cmd "$TMPDIR/qmp-load-$case_name.sock" '{"execute":"cont"}' "$TMPDIR/qmp-cont-load-$case_name.json" \
              || fail "$case_name load cont failed"
            wait_for_pause "load-$case_name" "$TMPDIR/qmp-load-$case_name.sock" \
              || fail "$case_name load run did not pause"
            qmp_cmd "$TMPDIR/qmp-load-$case_name.sock" '{"execute":"quit"}' "$TMPDIR/qmp-quit-load-$case_name.json" || true
            wait "$qemu_pid" || fail "$case_name load QEMU exited unsuccessfully"
            qemu_pid=""
            extract_pause_sample "load-$case_name"
            assert_segment_sample "load-$case_name" "$snapshot_icount"
            normalize_sample "load-$case_name"
            cp "$TMPDIR/serial-load-$case_name.log" "$out/serial-load-$case_name.log"

            suffix_match=false
            if diff -u "$TMPDIR/normalized-reference-$case_name.json" "$TMPDIR/normalized-load-$case_name.json" > "$TMPDIR/suffix-$case_name.diff"; then
              suffix_match=true
            elif [ "$expected_suffix" = match ]; then
              cat "$TMPDIR/suffix-$case_name.diff" >&2
              fail "$case_name snapshot-load suffix fingerprint diverged from replayed reference"
            fi
            if [ "$expected_suffix" = diverge ] && [ "$suffix_match" = true ]; then
              fail "$case_name unexpectedly matched despite pending I/O negative-control expectation"
            fi

            cp "$TMPDIR/normalized-reference-$case_name.json" "$out/normalized-reference-$case_name.json"
            cp "$TMPDIR/normalized-load-$case_name.json" "$out/normalized-load-$case_name.json"
            cp "$TMPDIR/suffix-$case_name.diff" "$out/suffix-$case_name.diff"
            reference_line=$(cat "$TMPDIR/pause-reference-$case_name.json")
            printf '%s\n' "$case_name $point_name $snapshot_icount $(printf '%s\n' "$reference_line" | jq -r '.state_hash') $(printf '%s\n' "$reference_line" | jq -r '.stream_hash') $(printf '%s\n' "$reference_line" | jq -r '.register_hash') $(printf '%s\n' "$reference_line" | jq -r '.ram_hash') $(printf '%s\n' "$reference_line" | jq -r '.ram_bytes') $suffix_match" >> "$TMPDIR/case-results.txt"
          }

          ring_live_hash=$(gawk -F= '/^ring_live_hash=/ { print $2 }' "$TMPDIR/owned-state.txt")
          overlay_hash=$(gawk -F= '/^overlay_hash=/ { print $2 }' "$TMPDIR/owned-state.txt")
          rng_next=$(gawk -F= '/^rng_next=/ { print $2 }' "$TMPDIR/owned-state.txt")

          mkdir -p "$out"
          cp "$TMPDIR/owned-state.txt" "$out/owned-state.txt"
          cp phase0-s3-segment-plugin.c "$out/segment-plugin.c"
          cp phase0-s3-owned-state.c "$out/owned-state.c"

          : > "$TMPDIR/case-results.txt"
          run_case boot_window diskless_boot_window "pause_at=$SNAPSHOT_ICOUNT" none match
          run_case cpu_timer_window cpu_timer_window "pause_at=$((SNAPSHOT_ICOUNT + SEGMENT_ICOUNT))" none match
          run_case mid_io_burst block_pending_io "pause_on_io_idle=on,pause_medium=block" block diverge

          suffix_state_hash=$(awk '$1 == "boot_window" { print $4 }' "$TMPDIR/case-results.txt")
          suffix_stream_hash=$(awk '$1 == "boot_window" { print $5 }' "$TMPDIR/case-results.txt")
          suffix_register_hash=$(awk '$1 == "boot_window" { print $6 }' "$TMPDIR/case-results.txt")
          suffix_ram_hash=$(awk '$1 == "boot_window" { print $7 }' "$TMPDIR/case-results.txt")
          suffix_ram_bytes=$(awk '$1 == "boot_window" { print $8 }' "$TMPDIR/case-results.txt")
          boot_window_icount=$(awk '$1 == "boot_window" { print $3 }' "$TMPDIR/case-results.txt")
          cpu_timer_icount=$(awk '$1 == "cpu_timer_window" { print $3 }' "$TMPDIR/case-results.txt")
          mid_io_icount=$(awk '$1 == "mid_io_burst" { print $3 }' "$TMPDIR/case-results.txt")
          boot_window_suffix_match=$(awk '$1 == "boot_window" { print $9 }' "$TMPDIR/case-results.txt")
          cpu_timer_suffix_match=$(awk '$1 == "cpu_timer_window" { print $9 }' "$TMPDIR/case-results.txt")
          mid_io_suffix_match=$(awk '$1 == "mid_io_burst" { print $9 }' "$TMPDIR/case-results.txt")
          mid_io_active_medium=$(jq -r '.active_medium' "$TMPDIR/pause-save-mid_io_burst.json")
          mid_io_pause_medium=$(jq -r '.pause_medium' "$TMPDIR/pause-save-mid_io_burst.json")
          mid_io_pause_io_events=$(jq -r '.pause_io_events' "$TMPDIR/pause-save-mid_io_burst.json")
          mid_io_operation_io_events=$(jq -r '.operation_io_events' "$TMPDIR/pause-save-mid_io_burst.json")
          mid_io_pause_hlt_events=$(jq -r '.pause_hlt_events' "$TMPDIR/pause-save-mid_io_burst.json")
          mid_io_operation_hlt_events=$(jq -r '.operation_hlt_events' "$TMPDIR/pause-save-mid_io_burst.json")
          if grep -q "CRUCIBLE_S2_BLOCK_DIRECT=1" "$TMPDIR/serial-save-mid_io_burst.log"; then
            mid_io_guest_block_direct=true
          else
            mid_io_guest_block_direct=false
          fi
          {
            echo PASS
            echo spike=savevm-loadvm-completeness
            echo check=checks.crucible.phase0.s3SavevmLoadvm
            echo qmp_snapshot_save_available=true
            echo qmp_snapshot_load_available=true
            echo qmp_migrate_available=true
            echo qmp_migrate_incoming_available=true
            echo qmp_human_monitor_command_available=true
            echo qmp_legacy_savevm_loadvm_available=false
            echo hmp_savevm_used=false
            echo restore_transport=snapshot_save_load
            echo vmstate_node=qcow2_internal_snapshot
            echo snapshot_points=3
            echo snapshot_point_0=diskless_boot_window
            echo snapshot_point_1=cpu_timer_window
            echo snapshot_point_2=block_pending_io
            echo snapshot_icount="$boot_window_icount"
            echo cpu_timer_snapshot_icount="$cpu_timer_icount"
            echo mid_io_snapshot_icount="$mid_io_icount"
            echo mid_io_active_medium="$mid_io_active_medium"
            echo mid_io_pause_medium="$mid_io_pause_medium"
            echo mid_io_pause_io_events="$mid_io_pause_io_events"
            echo mid_io_operation_io_events="$mid_io_operation_io_events"
            echo mid_io_pause_hlt_events="$mid_io_pause_hlt_events"
            echo mid_io_operation_hlt_events="$mid_io_operation_hlt_events"
            echo mid_io_guest_block_direct="$mid_io_guest_block_direct"
            echo suffix_segment_icount="$SEGMENT_ICOUNT"
            echo suffix_logical_horizon="$((boot_window_icount + SEGMENT_ICOUNT))"
            echo all_suffix_fingerprints_match=false
            echo boot_window_suffix_fingerprint_match="$boot_window_suffix_match"
            echo cpu_timer_suffix_fingerprint_match="$cpu_timer_suffix_match"
            echo mid_io_suffix_fingerprint_match="$mid_io_suffix_match"
            echo suffix_fingerprint_match=true
            echo suffix_stream_hash="$suffix_stream_hash"
            echo register_hash_match=true
            echo suffix_register_hash="$suffix_register_hash"
            echo ram_hash_match=true
            echo suffix_ram_hash="$suffix_ram_hash"
            echo suffix_ram_bytes="$suffix_ram_bytes"
            echo suffix_state_hash="$suffix_state_hash"
            echo device_event_hash_match=false
            echo current_vmstate_snapshot_smoke=true
            echo current_vmstate_snapshot_scope=diskless_and_cpu_timer_single_vcpu_qemu_vmstate_plus_block_pending_negative_control
            echo mid_io_burst_snapshot_exercised=true
            echo mid_io_burst_snapshot_covered=false
            echo plugin_time_control_snapshot_covered=true
            echo device_timer_snapshot_covered=true
            echo replay_oracle_fat_thin_match=false
            echo full_fat_checkpoint_complete=false
            echo crucible_owned_state_roundtrip=true
            echo ring_snapshot_restore=pass
            echo ring_live_hash="$ring_live_hash"
            echo overlay_delta_roundtrip=pass
            echo overlay_hash="$overlay_hash"
            echo rng_position_roundtrip=pass
            echo rng_next="$rng_next"
            echo thin_checkpoint_default=true
            echo fat_snapshot_default=false
            echo loadvm_branch_enabled=false
            echo fallback_adopted=thin_replay_until_full_s3
            echo risk8_status=mitigated_by_fallback_not_retired_for_fat_snapshot
            echo risk9_status=retired_thin_replay_default
            echo s3_fallback_adopted=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S3 savevm/loadvm completeness and fallback spike";
    };
  }
