{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase6.qemuHotForkReadiness",
  taskIds ? [],
}: let
  taskList = builtins.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase6-qemu-hot-fork-readiness";
    version = "0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.jq
      pkgs.qemu
      pkgs.socat
      qemuPackage
    ];
    phases = [
      {
        name = "exercise-hot-fork-readiness";
        script = ''
          set -eu
          mkdir -p "$out"
          qemu_pid=""

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          cleanup() {
            if [ -n "''${qemu_pid:-}" ]; then
              kill "$qemu_pid" 2>/dev/null || true
              wait "$qemu_pid" 2>/dev/null || true
              qemu_pid=""
            fi
          }
          trap cleanup EXIT

          wait_for_socket() {
            socket="$1"
            attempts=0
            while [ "$attempts" -lt 300 ]; do
              [ -S "$socket" ] && return 0
              kill -0 "$qemu_pid" 2>/dev/null || return 1
              sleep 0.1
              attempts=$((attempts + 1))
            done
            return 1
          }

          qmp() {
            socket="$1"
            request="$2"
            response="$3"
            {
              printf '%s\r\n' '{"execute":"qmp_capabilities"}'
              sleep 0.1
              printf '%s\r\n' "$request"
              sleep 0.2
            } | socat -T 3 - "UNIX-CONNECT:$socket" > "$response" 2> "$response.err" || true
          }

          stock_socket="$TMPDIR/stock.qmp"
          ${pkgs.qemu}/bin/qemu-system-x86_64 \
            -machine none -nodefaults -no-user-config -display none -monitor none \
            -S -qmp "unix:$stock_socket,server=on,wait=off" \
            > "$out/stock.stdout" 2> "$out/stock.stderr" &
          qemu_pid="$!"
          wait_for_socket "$stock_socket" || fail "stock QMP socket did not appear"
          qmp "$stock_socket" \
            '{"execute":"query-crucible-hot-fork-readiness"}' \
            "$out/stock-readiness.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-readiness.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible readiness command"
          qmp "$stock_socket" '{"execute":"quit"}' "$out/stock-quit.json"
          wait "$qemu_pid"
          qemu_pid=""

          patched_socket="$TMPDIR/patched.qmp"
          ${qemuPackage}/bin/qemu-system-x86_64 \
            -machine none -nodefaults -no-user-config -display none -monitor none -serial none \
            -accel sim,thread=single \
            -icount shift=0,sleep=off,align=off,rr_switch_quantum=256 \
            -smp 1 -qmp "unix:$patched_socket,server=on,wait=off" \
            > "$out/patched.stdout" 2> "$out/patched.stderr" &
          qemu_pid="$!"
          wait_for_socket "$patched_socket" \
            || { cat "$out/patched.stderr" >&2; fail "patched QMP socket did not appear"; }

          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-readiness"}' \
            "$out/prelaunch-readiness.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 1,
              "required-proofs": 511,
              "acknowledged-proofs": 3,
              "ready": false
            }
          ' "$out/prelaunch-readiness.json" >/dev/null \
            || { cat "$out/prelaunch-readiness.json" >&2; fail "prelaunch readiness was not exact"; }

          qmp "$patched_socket" '{"execute":"stop"}' "$out/stop.json"
          jq -e -s 'all(.[]; has("error") | not)' "$out/stop.json" >/dev/null \
            || { cat "$out/stop.json" >&2; fail "ordinary QMP stop failed"; }
          qmp "$patched_socket" '{"execute":"query-status"}' "$out/paused-status.json"
          jq -e -s '[.[] | select(has("return"))][-1].return.status == "paused"' \
            "$out/paused-status.json" >/dev/null \
            || { cat "$out/paused-status.json" >&2; fail "ordinary QMP stop did not reach paused state"; }

          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-readiness"}' \
            "$out/ordinary-paused-readiness.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 1,
              "required-proofs": 511,
              "acknowledged-proofs": 3,
              "ready": false
            }
          ' "$out/ordinary-paused-readiness.json" >/dev/null \
            || { cat "$out/ordinary-paused-readiness.json" >&2; fail "ordinary pause gained an exact-boundary proof"; }

          qmp "$patched_socket" '{"execute":"quit"}' "$out/patched-quit.json"
          wait "$qemu_pid"
          qemu_pid=""

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${taskList}
          gate=gate:hot-fork-readiness
          patch=0111-crucible-hot-fork-readiness.patch
          schema_version=1
          required_proofs=511
          precise_sim_rr_proofs=3
          ordinary_paused_exact_boundary_proof=false
          incomplete_report_ready=false
          stock_command_absent=true
          RESULT
        '';
      }
    ];
  }
