{
  pkgs,
  lib,
}: let
  workloadSource = builtins.readFile ./phase0-s5-workload.c;
  pluginSource = builtins.readFile ./phase0-s5-virtual-memory-plugin.c;
  rrSwitchQuantum = 4096;

  workload = pkgs.mkDerivation {
    pname = "crucible-phase0-s5-workload";
    version = "0";
    src = null;

    workload = workloadSource;
    passAsFile = ["workload"];

    phases = [
      {
        name = "build-workload";
        script = ''
          mkdir -p "$out/bin"
          cp "$workloadPath" phase0-s5-workload.c
          cc -std=c11 -O2 -Wall -Wextra -Werror \
            phase0-s5-workload.c \
            -o "$out/bin/s5-workload"
        '';
      }
    ];
  };

  poweroffHelper = pkgs.mkDerivation {
    pname = "crucible-phase0-s5-poweroff";
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

          cc poweroff.c -o "$out/bin/s5-poweroff"
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
      pname = "crucible-phase0-s5-initramfs";
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
            ln -sfn ${poweroffHelper}/bin/s5-poweroff root/sbin/poweroff

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            echo "CRUCIBLE_S5_READY"
            test_result=0
            s5-workload || test_result=1

            if [ "$test_result" -eq 0 ]; then
              echo 'TEST_RESULT:PASS'
            else
              echo 'TEST_RESULT:FAIL'
            fi

            sync
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
        description = "Crucible Phase 0 S5 diskless initramfs";
      };
    };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s5-virtual-memory";
    version = "0";
    src = null;

    plugin = pluginSource;
    passAsFile = ["plugin"];

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

    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL = builtins.toString pkgs.linux;
    QEMU = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
    RR_SWITCH_QUANTUM = builtins.toString rrSwitchQuantum;

    phases = [
      {
        name = "build-s5-plugin";
        script = ''
          cp "$pluginPath" phase0-s5-virtual-memory-plugin.c
          cc -fPIC -shared -O2 -Wall -Wextra -Werror \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            phase0-s5-virtual-memory-plugin.c \
            -o phase0-s5-virtual-memory-plugin.so
        '';
      }
      {
        name = "run-s5-virtual-memory";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          qmp_cmd() {
            socket="$1"
            request="$2"
            response="$3"
            response_err="$response.err"

            {
              printf '{"execute":"qmp_capabilities"}\r\n'
              printf '%s\r\n' "$request"
            } | socat -T 2 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

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

          plugin="$PWD/phase0-s5-virtual-memory-plugin.so"
          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-s5-seed-v1\n' > "$seed"

          run_qemu() {
            label="$1"
            read_mode="$2"
            qmp_socket="$TMPDIR/qmp-$label.sock"
            serial="$TMPDIR/serial-$label.log"
            trace="$TMPDIR/trace-$label.jsonl"
            rm -f "$qmp_socket"

            timeout 900 "$QEMU" \
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
              -seed 0x0010c001 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
              -chardev file,id=serial0,path="$serial" \
              -serial chardev:serial0 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -plugin "$plugin",out="$trace",read="$read_mode",expected_markers=3,vcpus=1 \
              -no-shutdown \
              -no-reboot &
            qemu_pid="$!"

            wait_for_socket "$qmp_socket" || fail "$label QMP socket did not appear"
            wait_for_pause "$label" "$qmp_socket" || fail "$label did not pause after S5 markers"
            qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" || true
            wait "$qemu_pid" || fail "$label QEMU exited unsuccessfully"
            qemu_pid=""
          }

          assert_read_trace() {
            label="$1"
            jq -e -s '
              [ .[] | select(.event == "doorbell") ] as $events
              | [ .[] | select(.final == true and .pause_sample == true) ] as $finals
              | ($events | length) == 3
              and ($finals | length) == 1
              and all($events[]; (
                .register_read_ok == true
                and .read_enabled == true
                and .read_attempted == true
                and .read_success == true
                and .bytes_match == true
                and .payload_hash == .expected_hash
                and .len > 0
              ))
              and (($events | map(.kind) | sort) == [1,2,3])
              and ($events[] | select(.kind == 1 and .name == "resident" and .len == 64))
              and ($events[] | select(.kind == 2 and .name == "page_spanning" and .len == 96))
              and ($events[] | select(.kind == 3 and .name == "paged_mmap" and .len == 128))
              and all($finals[]; (
                .markers == 3
                and .read_enabled == true
                and .read_attempts == 3
                and .read_successes == 3
                and .read_failures == 0
                and .bytes_mismatches == 0
                and .sample_register_failures == 0
                and .register_read_failures == 0
                and .ram_bytes > 0
                and (.register_counts | type == "array")
                and (.register_counts | length) == 1
                and .register_counts[0] > 0
              ))
            ' "$TMPDIR/trace-$label.jsonl" >/dev/null \
              || fail "invalid S5 read trace for $label"
          }

          assert_control_trace() {
            label="$1"
            jq -e -s '
              [ .[] | select(.event == "doorbell") ] as $events
              | [ .[] | select(.final == true and .pause_sample == true) ] as $finals
              | ($events | length) == 3
              and ($finals | length) == 1
              and all($events[]; (
                .register_read_ok == true
                and .read_enabled == false
                and .read_attempted == false
                and .read_success == false
              ))
              and all($finals[]; (
                .markers == 3
                and .read_enabled == false
                and .read_attempts == 0
                and .read_successes == 0
                and .read_failures == 0
                and .bytes_mismatches == 0
                and .sample_register_failures == 0
                and .register_read_failures == 0
                and .ram_bytes > 0
              ))
            ' "$TMPDIR/trace-$label.jsonl" >/dev/null \
              || fail "invalid S5 control trace for $label"
          }

          normalize_events() {
            label="$1"
            jq -S -c '
              select(.event == "doorbell")
              | {
                  marker_index,
                  marker_icount,
                  kind,
                  name,
                  addr,
                  len,
                  payload_hash,
                  expected_hash,
                  bytes_match
                }
            ' "$TMPDIR/trace-$label.jsonl" > "$TMPDIR/events-$label.jsonl"
          }

          normalize_final() {
            label="$1"
            jq -S -c '
              select(.final == true and .pause_sample == true)
              | {
                  retired,
                  markers,
                  stream_hash,
                  register_hash,
                  ram_hash,
                  ram_bytes,
                  state_hash,
                  register_counts
                }
            ' "$TMPDIR/trace-$label.jsonl" > "$TMPDIR/final-$label.json"
          }

          run_qemu read-a on
          run_qemu read-b on
          run_qemu control off

          assert_read_trace read-a
          assert_read_trace read-b
          assert_control_trace control

          normalize_events read-a
          normalize_events read-b
          normalize_final read-a
          normalize_final read-b
          normalize_final control

          if ! diff -u "$TMPDIR/events-read-a.jsonl" "$TMPDIR/events-read-b.jsonl" > "$TMPDIR/events.diff"; then
            cat "$TMPDIR/events.diff" >&2
            fail "S5 virtual-read marker sequence is not reproducible"
          fi
          if ! diff -u "$TMPDIR/final-read-a.json" "$TMPDIR/final-read-b.json" > "$TMPDIR/final-read.diff"; then
            cat "$TMPDIR/final-read.diff" >&2
            fail "S5 read-enabled final fingerprint is not reproducible"
          fi
          if ! diff -u "$TMPDIR/final-read-a.json" "$TMPDIR/final-control.json" > "$TMPDIR/final-control.diff"; then
            cat "$TMPDIR/final-control.diff" >&2
            fail "S5 virtual-read servicing perturbed the final fingerprint"
          fi

          resident_hash=$(jq -r 'select(.event == "doorbell" and .kind == 1) | .payload_hash' "$TMPDIR/trace-read-a.jsonl")
          span_hash=$(jq -r 'select(.event == "doorbell" and .kind == 2) | .payload_hash' "$TMPDIR/trace-read-a.jsonl")
          paged_hash=$(jq -r 'select(.event == "doorbell" and .kind == 3) | .payload_hash' "$TMPDIR/trace-read-a.jsonl")
          final_hash=$(jq -r 'select(.final == true and .pause_sample == true) | .state_hash' "$TMPDIR/trace-read-a.jsonl")
          ram_hash=$(jq -r 'select(.final == true and .pause_sample == true) | .ram_hash' "$TMPDIR/trace-read-a.jsonl")
          register_hash=$(jq -r 'select(.final == true and .pause_sample == true) | .register_hash' "$TMPDIR/trace-read-a.jsonl")
          marker_icounts=$(jq -r 'select(.event == "doorbell") | .marker_icount' "$TMPDIR/trace-read-a.jsonl" | paste -sd, -)

          mkdir -p "$out"
          cp "$TMPDIR/trace-read-a.jsonl" "$out/trace-read-a.jsonl"
          cp "$TMPDIR/trace-read-b.jsonl" "$out/trace-read-b.jsonl"
          cp "$TMPDIR/trace-control.jsonl" "$out/trace-control.jsonl"
          cp "$TMPDIR/events-read-a.jsonl" "$out/events-read-a.jsonl"
          cp "$TMPDIR/final-read-a.json" "$out/final-read-a.json"
          cp phase0-s5-virtual-memory-plugin.c "$out/virtual-memory-plugin.c"
          {
            echo PASS
            echo spike=guest-virtual-memory-read
            echo check=checks.crucible.phase0.s5VirtualMemory
            echo qemu_plugin_read_memory_vaddr_available=true
            echo doorbell_surface=phase0_instruction_marker_double
            echo payload_source=register_triplet_kind_ptr_len
            echo virtual_address_read_result=pass
            echo placements=3
            echo resident_read=pass
            echo page_spanning_read=pass
            echo paged_mmap_read=pass
            echo resident_hash="$resident_hash"
            echo page_spanning_hash="$span_hash"
            echo paged_mmap_hash="$paged_hash"
            echo marker_icounts="$marker_icounts"
            echo rr_switch_quantum="$RR_SWITCH_QUANTUM"
            echo marker_icounts_reproducible=true
            echo read_bytes_match_expected=true
            echo read_hashes_reproducible=true
            echo side_effect_free_fingerprint_match=true
            echo final_state_hash="$final_hash"
            echo final_ram_hash="$ram_hash"
            echo final_register_hash="$register_hash"
            echo production_whitebox_channel_implemented=false
            echo physical_pinned_fallback_adopted=false
            echo s5_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S5 guest virtual memory read spike";
    };
  }
