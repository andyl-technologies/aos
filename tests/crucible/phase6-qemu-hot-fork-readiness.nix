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
          qmp "$stock_socket" \
            '{"execute":"query-crucible-hot-fork-thread-inventory"}' \
            "$out/stock-thread-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-thread-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible thread inventory command"
          qmp "$stock_socket" \
            '{"execute":"query-crucible-hot-fork-rcu-inventory"}' \
            "$out/stock-rcu-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-rcu-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible RCU inventory command"
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

          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-thread-inventory"}' \
            "$out/thread-inventory-1.json"
          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-thread-inventory"}' \
            "$out/thread-inventory-2.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return as $report |
            ($report | keys | sort) == [
              "complete",
              "generation",
              "overflowed",
              "schema-version",
              "threads",
              "unclassified-threads"
            ] and
            $report."schema-version" == 2 and
            ($report.generation | type) == "number" and
            ($report.complete | type) == "boolean" and
            ($report.overflowed | type) == "boolean" and
            ($report.threads | type) == "array" and
            ($report.threads | length) > 0 and
            ($report.threads | length) <= 65536 and
            ([ $report.threads[]."thread-id" ] ==
             ([ $report.threads[]."thread-id" ] | sort)) and
            ([ $report.threads[]."thread-id" ] | unique | length) ==
              ($report.threads | length) and
            all($report.threads[];
              (. | keys | sort) == [
                "disposition",
                "joinable",
                "name",
                "name-valid",
                "thread-id"
              ] and
              (."thread-id" | type) == "number" and ."thread-id" > 0 and
              (.name | type) == "string" and (.name | length) > 0 and
              (.name | length) <= 256 and
              (."name-valid" | type) == "boolean" and
              (.joinable | type) == "boolean" and
              (.disposition == "coordinator" or
               .disposition == "unclassified" or
               .disposition == "unclassified-rcu" or
               .disposition == "unclassified-aio")) and
            ([ $report.threads[] | select(.disposition == "coordinator") ] | length) == 1 and
            ([ $report.threads[] | select(.disposition != "coordinator") ] | length) ==
              $report."unclassified-threads" and
            ([ $report.threads[] |
               select(.name == "call_rcu" and .disposition == "unclassified-rcu") ] |
             length) == 1 and
            ([ $report.threads[] |
               select(.name == "IO mon_iothread" and .disposition == "unclassified-aio") ] |
             length) == 1 and
            $report.complete ==
              (($report.overflowed | not) and
               all($report.threads[]; ."name-valid") and
               ([ $report.threads[] | select(.disposition == "coordinator") ] | length) == 1)
          ' "$out/thread-inventory-1.json" >/dev/null \
            || { cat "$out/thread-inventory-1.json" >&2; fail "QEMU thread inventory was not exact"; }
          jq -e -s --slurpfile first "$out/thread-inventory-1.json" '
            [.[] | select(has("return"))][-1].return ==
              ($first | map(select(has("return"))) | .[-1].return)
          ' "$out/thread-inventory-2.json" >/dev/null \
            || { cat "$out/thread-inventory-1.json" >&2; cat "$out/thread-inventory-2.json" >&2; fail "QEMU thread inventory changed without a thread transition"; }

          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-rcu-inventory"}' \
            "$out/rcu-inventory-1.json"
          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-rcu-inventory"}' \
            "$out/rcu-inventory-2.json"
          jq -e -s --slurpfile threads "$out/thread-inventory-1.json" '
            [.[] | select(has("return"))][-1].return as $report |
            ($threads | map(select(has("return"))) | .[-1].return) as $thread_report |
            ($report | keys | sort) == [
              "active-readers",
              "complete",
              "drain-active",
              "generation",
              "overflowed",
              "pending-callbacks",
              "readers",
              "registered-readers",
              "schema-version"
            ] and
            $report."schema-version" == 1 and
            ($report.generation | type) == "number" and
            ($report.complete | type) == "boolean" and
            ($report.overflowed | type) == "boolean" and
            ($report."registered-readers" | type) == "number" and
            ($report."active-readers" | type) == "number" and
            ($report."pending-callbacks" | type) == "number" and
            ($report."drain-active" | type) == "boolean" and
            ($report.readers | type) == "array" and
            ($report.readers | length) > 0 and
            ($report.readers | length) <= 65536 and
            ($report.readers | length) == $report."registered-readers" and
            ([ $report.readers[] | select(.active) ] | length) ==
              $report."active-readers" and
            ([ $report.readers[]."thread-id" ] ==
             ([ $report.readers[]."thread-id" ] | sort)) and
            ([ $report.readers[]."thread-id" ] | unique | length) ==
              ($report.readers | length) and
            all($report.readers[];
              (. | keys | sort) == ["active", "thread-id"] and
              (."thread-id" | type) == "number" and ."thread-id" > 0 and
              (.active | type) == "boolean") and
            all($report.readers[];
              ."thread-id" as $reader_tid |
              any($thread_report.threads[];
                ."thread-id" == $reader_tid)) and
            $report.complete == ($report.overflowed | not)
          ' "$out/rcu-inventory-1.json" >/dev/null \
            || { cat "$out/rcu-inventory-1.json" >&2; fail "QEMU RCU inventory was not exact or thread-bound"; }
          jq -e -s --slurpfile first "$out/rcu-inventory-1.json" '
            [.[] | select(has("return"))][-1].return ==
              ($first | map(select(has("return"))) | .[-1].return)
          ' "$out/rcu-inventory-2.json" >/dev/null \
            || { cat "$out/rcu-inventory-1.json" >&2; cat "$out/rcu-inventory-2.json" >&2; fail "QEMU RCU inventory changed without a reader transition"; }

          qmp "$patched_socket" '{"execute":"quit"}' "$out/patched-quit.json"
          wait "$qemu_pid"
          qemu_pid=""

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${taskList}
          gate=gate:hot-fork-readiness
          patch=0113-crucible-hot-fork-rcu-inventory.patch
          schema_version=1
          required_proofs=511
          precise_sim_rr_proofs=3
          ordinary_paused_exact_boundary_proof=false
          thread_inventory_schema_version=2
          thread_inventory_bound=65536
          thread_inventory_stable=true
          thread_inventory_one_coordinator=true
          thread_inventory_rcu_owner=true
          thread_inventory_aio_owner=true
          rcu_inventory_schema_version=1
          rcu_inventory_bound=65536
          rcu_inventory_stable=true
          rcu_readers_thread_bound=true
          rcu_proof_acknowledged=false
          incomplete_report_ready=false
          stock_commands_absent=true
          RESULT
        '';
      }
    ];
  }
