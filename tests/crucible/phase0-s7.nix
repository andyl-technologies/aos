{
  pkgs,
  lib,
}: let
  pluginSource = builtins.readFile ./phase0-s7-ceiling-plugin.c;

  spinner = pkgs.mkDerivation {
    pname = "crucible-phase0-s7-spinner";
    version = "0";
    src = null;

    phases = [
      {
        name = "build-spinner";
        script = ''
          mkdir -p "$out/bin"
          cat > s7-spin.c <<'SPIN_C'
          #include <stdint.h>

          static volatile uint64_t sink;

          int main(void) {
            uint64_t state = 0x0010c0075eedULL;
            for (;;) {
              state ^= state << 7;
              state ^= state >> 9;
              state *= 0x9e3779b97f4a7c15ULL;
              sink = state;
            }
          }
          SPIN_C

          cc -std=c11 -O2 -Wall -Wextra -Werror \
            s7-spin.c \
            -o "$out/bin/s7-spin"
        '';
      }
    ];
  };

  initramfs = let
    initramfsDeps = [
      pkgs.bash
      pkgs.coreutils
      spinner
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
      pname = "crucible-phase0-s7-initramfs";
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

            cat > root/init <<'INIT'
            #!${pkgs.bash}/bin/bash
            export PATH="/bin:/sbin:${depPaths}"
            export HOME=/tmp

            echo "CRUCIBLE_S7_READY"
            s7-spin
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
        description = "Crucible Phase 0 S7 diskless initramfs";
      };
    };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s7-deadline-ceiling";
    version = "0";
    src = null;

    plugin = pluginSource;
    passAsFile = ["plugin"];

    buildDeps = [
      pkgs.coreutils
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

    phases = [
      {
        name = "build-s7-plugin";
        script = ''
          cp "$pluginPath" phase0-s7-ceiling-plugin.c
          cc -fPIC -shared -O2 -Wall -Wextra -Werror \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            phase0-s7-ceiling-plugin.c \
            -ldl \
            -o phase0-s7-ceiling-plugin.so
        '';
      }
      {
        name = "run-s7-deadline-ceiling";
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

          plugin="$PWD/phase0-s7-ceiling-plugin.so"
          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-s7-seed-v1\n' > "$seed"

          run_qemu() {
            label="$1"
            plugin_args="$2"
            qmp_socket="$TMPDIR/qmp-$label.sock"
            serial="$TMPDIR/serial-$label.log"
            trace="$TMPDIR/trace-$label.jsonl"
            rm -f "$qmp_socket"

            set -- "$QEMU" \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel sim,thread=single \
              -icount shift=0,sleep=off,align=off \
              -cpu qemu64 \
              -m 256 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c007 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -kernel "$vmlinuz" \
              -initrd "$INITRAMFS" \
              -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
              -chardev file,id=serial0,path="$serial" \
              -serial chardev:serial0 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -plugin "$plugin",out="$trace","$plugin_args" \
              -no-shutdown \
              -no-reboot

            printf '%s\n' "$@" > "$TMPDIR/qemu-args-$label.txt"
            if grep -E -q '^-drive$|^-blockdev$|^-cdrom$|^-hda$|^-hdb$|^-hdc$|^-hdd$|virtio-blk|scsi|nvme|ahci|ide-' "$TMPDIR/qemu-args-$label.txt"; then
              fail "guest $label launch is not diskless"
            fi

            timeout 900 "$@" &
            qemu_pid="$!"

            wait_for_socket "$qmp_socket" || fail "$label QMP socket did not appear"
            wait_for_pause "$label" "$qmp_socket" || fail "$label did not pause at ceiling"
            qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" || true
            wait "$qemu_pid" || fail "$label QEMU exited unsuccessfully"
            qemu_pid=""

            jq -e '
              select(.event == "final")
              | .target_selected == true
                and .stop_requested == true
                and .request_exact == true
                and .request_retired == .target
                and .exit_retired >= .target
            ' "$trace" >/dev/null \
              || fail "$label trace did not record an exact pause request"
          }

          mkdir -p "$out"

          run_qemu fixed-a "mode=fixed,target=180000000"
          run_qemu fixed-b "mode=fixed,target=180000037"
          run_qemu interior "mode=dynamic-interior,choose_after=180000000,dynamic_offset=2"

          cat "$TMPDIR"/trace-*.jsonl > "$TMPDIR/all-traces.jsonl"

          # The patch series has since landed the qemu_plugin_clock_deadline_ns
          # export, so the capability probe now reports it available; the
          # spike's throwaway probe still does not consume it, and the pause
          # surface still overshoots, so the TB-split fallback stands.
          jq -e -s '
            [ .[] | select(.event == "final") ] as $finals
            | ($finals | length) == 3
              and all($finals[]; .deadline_api_available == true)
              and all($finals[]; .deadline_exact == false)
              and all($finals[]; .request_exact == true)
              and any($finals[]; .mode == "dynamic-interior" and .target_inside_tb == true)
          ' "$TMPDIR/all-traces.jsonl" >/dev/null \
            || fail "S7 trace set failed structural assertions"

          deadline_api_available=$(jq -r 'select(.event == "final") | .deadline_api_available' "$TMPDIR/trace-fixed-a.jsonl")
          zero_overshoot_all=$(jq -r -s 'all(.[] | select(.event == "final"); .zero_overshoot == true)' "$TMPDIR/all-traces.jsonl")
          request_exact_all=$(jq -r -s 'all(.[] | select(.event == "final"); .request_exact == true)' "$TMPDIR/all-traces.jsonl")
          max_pause_overshoot=$(jq -r -s '[.[] | select(.event == "final") | .pause_overshoot] | max' "$TMPDIR/all-traces.jsonl")
          interior_pause_overshoot=$(jq -r 'select(.event == "final") | .pause_overshoot' "$TMPDIR/trace-interior.jsonl")
          interior_target=$(jq -r 'select(.event == "final") | .target' "$TMPDIR/trace-interior.jsonl")
          interior_exit_retired=$(jq -r 'select(.event == "final") | .exit_retired' "$TMPDIR/trace-interior.jsonl")
          interior_tb_index=$(jq -r 'select(.event == "final") | .target_tb_index' "$TMPDIR/trace-interior.jsonl")
          interior_tb_insns=$(jq -r 'select(.event == "final") | .target_tb_insns' "$TMPDIR/trace-interior.jsonl")
          fixed_a_target=$(jq -r 'select(.event == "final") | .target' "$TMPDIR/trace-fixed-a.jsonl")
          fixed_a_exit_retired=$(jq -r 'select(.event == "final") | .exit_retired' "$TMPDIR/trace-fixed-a.jsonl")
          fixed_a_overshoot=$(jq -r 'select(.event == "final") | .pause_overshoot' "$TMPDIR/trace-fixed-a.jsonl")
          fixed_b_target=$(jq -r 'select(.event == "final") | .target' "$TMPDIR/trace-fixed-b.jsonl")
          fixed_b_exit_retired=$(jq -r 'select(.event == "final") | .exit_retired' "$TMPDIR/trace-fixed-b.jsonl")
          fixed_b_overshoot=$(jq -r 'select(.event == "final") | .pause_overshoot' "$TMPDIR/trace-fixed-b.jsonl")

          if [ "$zero_overshoot_all" != false ] || [ "$max_pause_overshoot" -eq 0 ]; then
            fail "S7 fallback result expected current pause surface to overshoot"
          fi

          result_status=PASS_WITH_FALLBACK
          exact_next_deadline_capability=false
          max_advance_exact_capability=false
          fallback_adopted=tb_split_exact_pause_deadline_export_landed
          layer1_scheduler_fast_forward_enabled=false

          cp "$TMPDIR"/trace-fixed-a.jsonl "$out/trace-fixed-a.jsonl"
          cp "$TMPDIR"/trace-fixed-b.jsonl "$out/trace-fixed-b.jsonl"
          cp "$TMPDIR"/trace-interior.jsonl "$out/trace-interior.jsonl"
          cp "$TMPDIR"/serial-fixed-a.log "$out/serial-fixed-a.log"
          cp "$TMPDIR"/serial-fixed-b.log "$out/serial-fixed-b.log"
          cp "$TMPDIR"/serial-interior.log "$out/serial-interior.log"
          cp "$TMPDIR"/qemu-args-fixed-a.txt "$out/qemu-args-fixed-a.txt"
          cp "$TMPDIR"/qemu-args-fixed-b.txt "$out/qemu-args-fixed-b.txt"
          cp "$TMPDIR"/qemu-args-interior.txt "$out/qemu-args-interior.txt"
          cp phase0-s7-ceiling-plugin.c "$out/ceiling-plugin.c"

          {
            echo "$result_status"
            echo spike=exact-next-deadline-and-ceiling
            echo check=checks.crucible.phase0.s7DeadlineCeiling
            echo scenario=stock-linux-diskless-initramfs-ceiling-probe
            echo boot_medium=initramfs
            echo block_devices=0
            echo vcpus=1
            echo qemu_internal_seed=0x0010c007
            echo deadline_symbol=qemu_plugin_clock_deadline_ns
            echo deadline_api_available="$deadline_api_available"
            echo idle_wake_icount_reported=unavailable
            echo actual_timer_fire_icount=not_measured_spike_probe_predates_export_use
            echo exact_deadline_match=false
            echo request_exact_all="$request_exact_all"
            echo zero_overshoot_all="$zero_overshoot_all"
            echo max_pause_overshoot="$max_pause_overshoot"
            echo fixed_a_target="$fixed_a_target"
            echo fixed_a_exit_retired="$fixed_a_exit_retired"
            echo fixed_a_pause_overshoot="$fixed_a_overshoot"
            echo fixed_b_target="$fixed_b_target"
            echo fixed_b_exit_retired="$fixed_b_exit_retired"
            echo fixed_b_pause_overshoot="$fixed_b_overshoot"
            echo interior_target="$interior_target"
            echo interior_exit_retired="$interior_exit_retired"
            echo interior_pause_overshoot="$interior_pause_overshoot"
            echo interior_target_tb_index="$interior_tb_index"
            echo interior_target_tb_insns="$interior_tb_insns"
            echo interior_target_inside_tb=true
            echo exact_next_deadline_capability="$exact_next_deadline_capability"
            echo max_advance_exact_capability="$max_advance_exact_capability"
            echo layer1_scheduler_fast_forward_enabled="$layer1_scheduler_fast_forward_enabled"
            echo fallback_adopted="$fallback_adopted"
            echo s7_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S7 exact deadline and ceiling spike";
    };
  }
