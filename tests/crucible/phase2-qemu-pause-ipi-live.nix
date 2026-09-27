{
  pkgs,
  lib,
}: let
  guest = import ./phase2-qemu-live-plugin-quantum-smp-guest.nix {
    inherit pkgs;
    guestVcpus = 2;
    guestIdle = true;
    startAps = true;
  };
  pluginSource = builtins.readFile ./phase2-qemu-pause-ipi-plugin.c;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-pause-ipi-live";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.glib
      pkgs.glib.dev
      pkgs.pkg-config
      pkgs.qemu-crucible
      guest
    ];

    inherit pluginSource;
    passAsFile = ["pluginSource"];

    phases = [
      {
        name = "run-live-pause-ipi";
        script = ''
          set -eu

          cp "$pluginSourcePath" pause-ipi-plugin.c
          export PKG_CONFIG_PATH="${pkgs.glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
          cc -fPIC -shared -O2 -Wall -Wextra -Werror \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            pause-ipi-plugin.c -o pause-ipi-plugin.so

          run_once() {
            label="$1"
            events="$TMPDIR/pause-ipi-events.csv"
            serial="$TMPDIR/pause-ipi-serial.log"
            rm -f "$events" "$serial"

            set +e
            timeout 120 ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
              -L ${pkgs.qemu-crucible}/share/qemu \
              -nodefaults -no-user-config -display none \
              -machine q35 -accel sim,thread=single \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum=4096 \
              -cpu qemu64 -m 64 -smp 2 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c011 \
              -kernel ${guest}/smp-idle-guest.elf \
              -chardev file,id=serial0,path="$serial" \
              -serial chardev:serial0 \
              -plugin "$PWD/pause-ipi-plugin.so,out=$events" \
              -monitor none -no-reboot
            status="$?"
            set -e
            if [ "$status" -ne 0 ]; then
              echo "PAUSE/IPI guest $label exited with status $status" >&2
              if [ -f "$serial" ]; then
                echo "serial bytes:" >&2
                head -c 128 "$serial" | od -An -tx1 >&2
              fi
              if [ -f "$events" ]; then
                echo "event count: $(wc -l < "$events")" >&2
                echo "first event rows:" >&2
                head -80 "$events" >&2
                echo "last event rows:" >&2
                tail -40 "$events" >&2
              fi
              exit "$status"
            fi

            test "$(tr -d '\r\n' < "$serial")" = ABPR
            gawk -F, '
              $1 == "send" && $2 == 0 { send = $3; send_row = NR; sends++ }
              $1 == "ipi" && $2 == 0 {
                ipis++
                if (ipis == 1) { first_ipi = $3; first_ipi_row = NR }
              }
              $1 == "ap" && $2 == 1 { ap = $3; ap_row = NR; aps++ }
              $1 == "pause" && $2 == 0 {
                bsp_pauses++; bsp_pause = $3; bsp_pause_row = NR
              }
              $1 == "pause" && $2 == 1 {
                ap_pauses++; ap_pause = $3; ap_pause_row = NR
              }
              $1 == "hlt" && $2 == 0 { hlts++; hlt = $3; hlt_row = NR }
              $1 == "idle" { idles++; idle_row = NR }
              END {
                if (sends != 1 || ipis != 2 || aps != 1 ||
                    bsp_pauses != 1 || ap_pauses != 1 || hlts != 1 || idles != 1 ||
                    send_row >= first_ipi_row || first_ipi_row >= ap_row ||
                    first_ipi_row >= bsp_pause_row || ap_row >= ap_pause_row ||
                    bsp_pause_row >= hlt_row || ap_pause_row >= hlt_row ||
                    hlt_row >= idle_row || first_ipi >= ap ||
                    ap - first_ipi > 16384) {
                  printf "invalid PAUSE/IPI/HLT evidence: send=%s ipi=%s ap=%s " \
                         "bsp_pause=%d ap_pause=%d hlt=%d idle=%d\n", \
                         send, first_ipi, ap, bsp_pauses, ap_pauses, hlts, idles \
                         > "/dev/stderr"
                  exit 1
                }
              }
            ' "$events"

            cp "$events" "$TMPDIR/pause-ipi-events-$label.csv"
            cp "$serial" "$TMPDIR/pause-ipi-serial-$label.log"
          }

          run_once a
          run_once b
          diff -u "$TMPDIR/pause-ipi-events-a.csv" \
            "$TMPDIR/pause-ipi-events-b.csv"
          diff -u "$TMPDIR/pause-ipi-serial-a.log" \
            "$TMPDIR/pause-ipi-serial-b.log"

          mkdir -p "$out"
          cp "$TMPDIR/pause-ipi-events-a.csv" "$out/events.csv"
          {
            printf 'PASS\n'
            printf 'guest_vcpus=2\n'
            printf 'rr_switch_quantum=4096\n'
            printf 'ipi_to_ap_raw_icount_max=16384\n'
            printf 'pause_both_vcpus=true\n'
            printf 'bsp_hlt_reached=true\n'
            printf 'all_vcpus_idle_after_hlt=true\n'
            printf 'same_source_event_trace_match=true\n'
          } > "$out/result"
        '';
      }
    ];
  }
