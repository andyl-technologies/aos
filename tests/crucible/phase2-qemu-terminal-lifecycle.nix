{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  failures = failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource (
    if lib.hasPrefix "0064-" patchName
    then [
      {
        label = "terminal pre-exit evidence";
        needle = "CRUCIBLE_LIFECYCLE_TERMINAL_PREEXIT_VALID";
      }
      {
        label = "deferred terminal exit";
        needle = "crucible_lifecycle_terminal_exit_requested";
      }
    ]
    else if lib.hasPrefix "0065-" patchName
    then [
      {
        label = "authenticated completion command";
        needle = "crucible-complete-terminal-lifecycle";
      }
      {
        label = "action digest comparison";
        needle = "crucible_lifecycle_terminal_action_sha256";
      }
    ]
    else [
      {
        label = "immutable generation setter";
        needle = "qemu_plugin_crucible_lifecycle_set_process_generation";
      }
      {
        label = "second-set rejection";
        needle = "crucible_lifecycle_process_generation != 0";
      }
    ]
  );
in
  if failures != []
  then throw "Crucible terminal-lifecycle microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-terminal-lifecycle";
      version = "0";
      src = null;
      buildDeps = [
        pkgs.binutils
        pkgs.coreutils
        pkgs.glib
        pkgs.sed
        pkgs.jq
        pkgs.pkg-config
        pkgs.socat
        qemuPackage
        pkgs.qemu
      ];
      phases = [
        {
          name = "build-live-terminal-fixture";
          script = ''
            set -eu
            "$CC" -shared -fPIC -Wall -Wextra -Werror \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              -I${./.} \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-node-lifecycle.c} \
              -o crucible-terminal-lifecycle.so \
              $(pkg-config --libs glib-2.0)
            as --32 ${./phase2-qemu-fault-guest.S} -o fault-guest-x86.o
            ld -m elf_i386 -T ${./phase2-qemu-fault-guest.ld} \
              fault-guest-x86.o -o fault-guest-x86.elf
          '';
        }
        {
          name = "run-live-terminal-protocol";
          script = ''
            set -eu
            mkdir -p logs

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            wait_for_socket() {
              socket="$1"
              attempts=0
              while [ "$attempts" -lt 600 ]; do
                [ -S "$socket" ] && return 0
                sleep 0.1
                attempts=$((attempts + 1))
              done
              return 1
            }

            wait_for_marker() {
              marker="$1"
              log="$2"
              attempts=0
              while [ "$attempts" -lt 1200 ]; do
                grep -Fq "$marker" "$log" && return 0
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
                sleep 0.1
                printf '%s\r\n' '{"execute":"qmp_capabilities"}'
                sleep 0.1
                printf '%s\r\n' "$request"
                sleep 0.3
              } | socat -T 3 - "UNIX-CONNECT:$socket" > "$response" 2> "$response.err" || true
            }

            cleanup() {
              if [ -n "''${qemu_pid:-}" ]; then
                kill "$qemu_pid" 2>/dev/null || true
                attempts=0
                while kill -0 "$qemu_pid" 2>/dev/null && [ "$attempts" -lt 50 ]; do
                  sleep 0.1
                  attempts=$((attempts + 1))
                done
                kill -KILL "$qemu_pid" 2>/dev/null || true
                wait "$qemu_pid" 2>/dev/null || true
              fi
            }
            trap cleanup EXIT

            stock_socket="$TMPDIR/stock-qmp.sock"
            ${pkgs.qemu}/bin/qemu-system-x86_64 \
              -machine none -nodefaults -display none -S \
              -qmp "unix:$stock_socket,server=on,wait=off" \
              > logs/stock.log 2>&1 &
            qemu_pid="$!"
            wait_for_socket "$stock_socket" || fail "stock QMP socket did not appear"
            qmp "$stock_socket" '{"execute":"query-commands"}' "$TMPDIR/stock-commands.json"
            if jq -e -s 'any((.[-1].return // [])[]; .name == "crucible-complete-terminal-lifecycle")' \
                "$TMPDIR/stock-commands.json" >/dev/null; then
              fail "stock QEMU exposed the Crucible terminal authorization command"
            fi
            qmp "$stock_socket" '{"execute":"quit"}' "$TMPDIR/stock-quit.json"
            wait "$qemu_pid"
            qemu_pid=""

            socket="$TMPDIR/patched-qmp.sock"
            log="logs/patched.log"
            ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc -m 64M \
              -accel sim \
              -icount shift=0,rr_switch_quantum=256 \
              -smp 1 -nographic -serial none -monitor none \
              -qmp "unix:$socket,server=on,wait=off" \
              -kernel fault-guest-x86.elf \
              -plugin "$PWD/crucible-terminal-lifecycle.so,architecture=2,volatile_policy=1,device_policy=1,terminal=crash" \
              > "$log" 2>&1 &
            qemu_pid="$!"
            wait_for_socket "$socket" || fail "patched QMP socket did not appear"
            wait_for_marker CRUCIBLE_TERMINAL_LIFECYCLE_LIVE_PASS "$log" \
              || { cat "$log" >&2; fail "terminal lifecycle event was not published"; }
            kill -0 "$qemu_pid" 2>/dev/null \
              || { cat "$log" >&2; fail "QEMU exited before terminal authorization"; }

            marker=$(grep -F CRUCIBLE_TERMINAL_LIFECYCLE_LIVE_PASS "$log" | tail -1)
            action=$(printf '%s\n' "$marker" | sed -n 's/.*action_sha256=\([0-9a-f]\{64\}\).*/\1/p')
            evidence=$(printf '%s\n' "$marker" | sed -n 's/.*evidence_sha256=\([0-9a-f]\{64\}\).*/\1/p')
            [ "''${#action}" -eq 64 ] || fail "terminal action digest was malformed"
            [ "''${#evidence}" -eq 64 ] || fail "terminal evidence digest was malformed"

            qmp "$socket" '{"execute":"query-status"}' "$TMPDIR/patched-status.json"
            jq -e -s '[.[] | select(has("return"))][-1].return.status == "paused"' \
              "$TMPDIR/patched-status.json" >/dev/null \
              || fail "terminal decision did not stop at a QMP-responsive paused boundary"

            wrong_action="00''${action#??}"
            wrong_request=$(printf '{"execute":"crucible-complete-terminal-lifecycle","arguments":{"action-sha256":"%s","evidence-sha256":"%s","process-generation":1}}' "$wrong_action" "$evidence")
            qmp "$socket" "$wrong_request" "$TMPDIR/wrong-action.json"
            jq -e -s 'any(.[]; has("error"))' "$TMPDIR/wrong-action.json" >/dev/null \
              || fail "wrong terminal action digest was accepted"
            kill -0 "$qemu_pid" 2>/dev/null \
              || fail "wrong terminal authorization scheduled exit"

            wrong_generation=$(printf '{"execute":"crucible-complete-terminal-lifecycle","arguments":{"action-sha256":"%s","evidence-sha256":"%s","process-generation":2}}' "$action" "$evidence")
            qmp "$socket" "$wrong_generation" "$TMPDIR/wrong-generation.json"
            jq -e -s 'any(.[]; has("error"))' "$TMPDIR/wrong-generation.json" >/dev/null \
              || fail "wrong process generation was accepted"
            kill -0 "$qemu_pid" 2>/dev/null \
              || fail "wrong process generation scheduled exit"

            completion=$(printf '{"execute":"crucible-complete-terminal-lifecycle","arguments":{"action-sha256":"%s","evidence-sha256":"%s","process-generation":1}}' "$action" "$evidence")
            qmp "$socket" "$completion" "$TMPDIR/completion.json"
            jq -e -s 'all(.[]; has("error") | not) and
              ([.[] | select(has("return"))] | length == 2) and
              ([.[] | select(has("return"))][-1].return == {})' \
              "$TMPDIR/completion.json" >/dev/null \
              || { cat "$TMPDIR/completion.json" >&2; fail "terminal authorization was rejected"; }
            attempts=0
            while kill -0 "$qemu_pid" 2>/dev/null && [ "$attempts" -lt 300 ]; do
              sleep 0.1
              attempts=$((attempts + 1))
            done
            if kill -0 "$qemu_pid" 2>/dev/null; then
              qmp "$socket" '{"execute":"query-status"}' "$TMPDIR/post-completion-status.json"
              jq -c -s . "$TMPDIR/completion.json" >&2 || true
              jq -c -s . "$TMPDIR/post-completion-status.json" >&2 || true
              cat "$log" >&2
              fail "authorized terminal lifecycle did not exit within 30 seconds"
            fi
            set +e
            wait "$qemu_pid"
            exit_status="$?"
            set -e
            qemu_pid=""
            [ "$exit_status" -eq 70 ] \
              || { cat "$log" >&2; fail "authorized crash exited with $exit_status instead of 70"; }
          '';
        }
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out"
            cp -R logs "$out/"
            {
              echo PASS
              echo gate=gate:patch-microtests
              echo patch=${patchName}
              echo patched_fixture_exercised=true
              echo stock_negative_control=true
              echo qemu_package=${qemuPackage}
              echo qemu_package_version=${qemuPackage.version}
              echo backend=actual-patched-qemu
              echo terminal_boundary=event-paused-qmp-authenticated-exit
              echo process_generation=immutable-launch-binding
            } > "$out/result"
          '';
        }
      ];
    }
