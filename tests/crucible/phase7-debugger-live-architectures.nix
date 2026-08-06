{
  pkgs,
  lib,
  attrPath,
  taskIds,
}:
pkgs.mkDerivation {
  pname = "crucible-phase7-debugger-live-architectures";
  version = "0";
  src = null;

  buildDeps = [pkgs.gdb pkgs.qemu-crucible pkgs.coreutils pkgs.grep];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "live-debugger-architectures";
      script = ''
        set -eu
        work="$PWD/live-debugger"
        mkdir -p "$work"

        cleanup() {
          for pid_file in "$work"/*.pid; do
            if test -f "$pid_file"; then
              kill "$(cat "$pid_file")" 2>/dev/null || true
            fi
          done
        }
        trap cleanup EXIT

        wait_for_socket() {
          socket="$1"
          attempts=0
          while ! test -S "$socket"; do
            attempts=$((attempts + 1))
            test "$attempts" -le 200
            sleep 0.01
          done
        }

        run_probe() {
          architecture="$1"
          emulator="$2"
          machine="$3"
          register="$4"
          breakpoint="$5"
          socket="$work/$architecture.sock"
          pid_file="$work/$architecture.pid"

          "$emulator" \
            -machine "$machine" \
            -cpu max \
            -nodefaults \
            -display none \
            -S \
            -gdb "unix:$socket,server=on,wait=off" \
            -pidfile "$pid_file" \
            -daemonize
          wait_for_socket "$socket"

          ${pkgs.gdb}/bin/gdb --nx --batch \
            -ex "target remote $socket" \
            -ex 'maintenance packet qSupported' \
            -ex "maintenance packet Z1,$breakpoint,1" \
            -ex "maintenance packet z1,$breakpoint,1" \
            -ex "info registers $register" \
            -ex disconnect > "$work/$architecture-first.txt"
          ${pkgs.gdb}/bin/gdb --nx --batch \
            -ex "target remote $socket" \
            -ex "info registers $register" \
            -ex disconnect > "$work/$architecture-second.txt"

          grep '^received: "PacketSize=' "$work/$architecture-first.txt"
          test "$(grep "^$register " "$work/$architecture-first.txt")" = \
            "$(grep "^$register " "$work/$architecture-second.txt")"
          test "$(grep -c '^received: "OK"' "$work/$architecture-first.txt")" -eq 2
          kill "$(cat "$pid_file")"
        }

        run_probe \
          x86_64 \
          ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
          microvm \
          rip \
          fff0
        run_probe \
          aarch64 \
          ${pkgs.qemu-crucible}/bin/qemu-system-aarch64 \
          virt \
          pc \
          0

        mkdir -p "$out"
        cat > "$out/result" <<'RESULT'
        PASS
        check=${attrPath}
        tasks=${lib.concatStringsSep "," taskIds}
        execution=live-packaged-qemu-tcg
        architectures=x86_64,aarch64
        rsp_negotiation=true
        repeated_register_reads_neutral=true
        hardware_breakpoint_packets=true
        model_double=false
        raw_single_step=false
        RESULT
      '';
    }
  ];
}
