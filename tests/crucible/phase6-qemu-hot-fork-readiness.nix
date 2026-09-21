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
      pkgs.python3
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
              printf '%s\r\n' '{"execute":"qmp_capabilities","arguments":{"enable":["oob"]}}'
              sleep 0.1
              printf '%s\r\n' "$request"
              sleep 0.2
            } | socat -T 3 - "UNIX-CONNECT:$socket" > "$response" 2> "$response.err" || true
          }

          qmp_pair() {
            socket="$1"
            request="$2"
            response="$3"
            {
              printf '%s\r\n' '{"execute":"qmp_capabilities","arguments":{"enable":["oob"]}}'
              sleep 0.1
              printf '%s\r\n' "$request"
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
            '{"execute":"crucible-hot-fork-block-barrier","arguments":{"action":"query"}}' \
            "$out/stock-block-barrier.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-block-barrier.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible block drain-barrier command"
          qmp "$stock_socket" \
            '{"exec-oob":"query-crucible-hot-fork-plugin-resource-inventory"}' \
            "$out/stock-plugin-resource-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-plugin-resource-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible plugin-resource inventory command"
          qmp "$stock_socket" \
            '{"exec-oob":"query-crucible-hot-fork-child-runtime"}' \
            "$out/stock-child-runtime.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-child-runtime.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible child-runtime command"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-plugin-barrier","arguments":{"action":"query"}}' \
            "$out/stock-plugin-barrier.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-plugin-barrier.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible plugin callback-barrier command"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-rcu-barrier","arguments":{"action":"query"}}' \
            "$out/stock-rcu-barrier.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-rcu-barrier.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible RCU barrier command"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-async-worker-barrier","arguments":{"action":"query"}}' \
            "$out/stock-async-worker-barrier.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-async-worker-barrier.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible asynchronous-worker barrier command"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-template","arguments":{"action":"query"}}' \
            "$out/stock-template-coordinator.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-template-coordinator.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible hot-fork template coordinator"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-private-rings","arguments":{"action":"query"}}' \
            "$out/stock-private-rings.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-private-rings.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible private-ring stage"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-child-diagnostics","arguments":{"action":"query"}}' \
            "$out/stock-child-diagnostics.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-child-diagnostics.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible child-diagnostics stage"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-child-qmp","arguments":{"action":"query"}}' \
            "$out/stock-child-qmp.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-child-qmp.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible child-QMP stage"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork","arguments":{"template-generation":0,"private-ring-generation":0,"diagnostic-generation":0,"qmp-generation":0,"console-generation":0,"monitor-generation":0,"plugin-endpoint-generation":0,"plugin-barrier-generation":0,"rcu-barrier-generation":0,"async-worker-barrier-generation":0,"block-barrier-generation":0,"parent-process-generation":0,"child-process-generation":0,"child-process-contract-generation":0,"child-files-generation":0}}' \
            "$out/stock-fork.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-fork.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible retained-template fork command"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-child-process","arguments":{"action":"query","generation":1}}' \
            "$out/stock-child-process.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-child-process.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible retained-child status command"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-child-process-contract","arguments":{"action":"query"}}' \
            "$out/stock-child-process-contract.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-child-process-contract.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible child-process contract stage"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-child-files","arguments":{"action":"query"}}' \
            "$out/stock-child-files.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-child-files.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible child-files plan stage"
          qmp "$stock_socket" \
            '{"exec-oob":"getfd","arguments":{"fdname":"crucible-oob-probe"}}' \
            "$out/stock-getfd-oob.json"
          jq -e -s 'any(.[]; (.error.desc // "") | test("does not support OOB"))' "$out/stock-getfd-oob.json" >/dev/null \
            || { cat "$out/stock-getfd-oob.json" >&2; fail "stock QEMU unexpectedly accepted out-of-band getfd"; }
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-child-console","arguments":{"action":"query"}}' \
            "$out/stock-child-console.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-child-console.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible child-console stage"
          qmp "$stock_socket" \
            '{"exec-oob":"crucible-hot-fork-plugin-endpoints","arguments":{"action":"query"}}' \
            "$out/stock-plugin-endpoints.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-plugin-endpoints.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible plugin-endpoint stage"
          qmp "$stock_socket" '{"execute":"quit"}' "$out/stock-quit.json"
          wait "$qemu_pid"
          qemu_pid=""

          truncate -s 64M "$TMPDIR/vmstate.raw"
          patched_socket="$TMPDIR/patched.qmp"
          ${qemuPackage}/bin/qemu-system-x86_64 \
            -machine none -nodefaults -no-user-config -display none -monitor none -serial none \
            -drive "if=none,id=crucible-vmstate,file=$TMPDIR/vmstate.raw,format=raw" \
            -accel sim,thread=single \
            -icount shift=0,sleep=off,align=off,rr_switch_quantum=256 \
            -smp 1 -qmp "unix:$patched_socket,server=on,wait=off" \
            > "$out/patched.stdout" 2> "$out/patched.stderr" &
          qemu_pid="$!"
          wait_for_socket "$patched_socket" \
            || { cat "$out/patched.stderr" >&2; fail "patched QMP socket did not appear"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork","arguments":{"template-generation":0,"private-ring-generation":0,"diagnostic-generation":0,"qmp-generation":0,"console-generation":0,"monitor-generation":0,"plugin-endpoint-generation":0,"plugin-barrier-generation":0,"rcu-barrier-generation":0,"async-worker-barrier-generation":0,"block-barrier-generation":0,"parent-process-generation":0,"child-process-generation":0,"child-process-contract-generation":0,"child-files-generation":0}}' \
            "$out/fork-without-template.json"
          jq -e -s 'any(.[]; has("error"))' "$out/fork-without-template.json" >/dev/null \
            || { cat "$out/fork-without-template.json" >&2; fail "retained-template fork did not fail closed without an admitted template"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-child-process","arguments":{"action":"query","generation":1}}' \
            "$out/child-process-unknown.json"
          jq -e -s 'any(.[]; has("error"))' "$out/child-process-unknown.json" >/dev/null \
            || { cat "$out/child-process-unknown.json" >&2; fail "unknown retained-child generation was accepted"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-child-process-contract","arguments":{"action":"query"}}' \
            "$out/child-process-contract-initial.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 2,
              "generation": 0,
              "template-generation": 0,
              "staged": false,
              "consumed": false,
              "cgroup-device": 0,
              "cgroup-inode": 0,
              "cgroup-procs-inode": 0,
              "cancellation-eventfd-id": 0,
              "maximum-file-bytes": 0,
              "cgroup-placement-bound": false
            }
          ' "$out/child-process-contract-initial.json" >/dev/null \
            || { cat "$out/child-process-contract-initial.json" >&2; fail "initial child-process contract state was not exact"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-child-files","arguments":{"action":"query"}}' \
            "$out/child-files-initial.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 1,
              "generation": 0,
              "template-generation": 0,
              "staged": false,
              "consumed": false,
              "maximum-bytes": 0,
              "files": []
            }
          ' "$out/child-files-initial.json" >/dev/null \
            || { cat "$out/child-files-initial.json" >&2; fail "initial child-files plan state was not exact"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-child-files","arguments":{"action":"stage","files":[{"node-name":"vmstate","fdname":"crucible-hfork-file-v1-0000000000000001","expected-device":1,"expected-inode":1}],"maximum-bytes":4096}}' \
            "$out/child-files-stage-without-template.json"
          jq -e -s 'any(.[]; has("error"))' "$out/child-files-stage-without-template.json" >/dev/null \
            || { cat "$out/child-files-stage-without-template.json" >&2; fail "child-files stage did not fail closed without a retained template"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-child-files","arguments":{"action":"release","expected-generation":0}}' \
            "$out/child-files-release-unstaged.json"
          jq -e -s 'any(.[]; has("error"))' "$out/child-files-release-unstaged.json" >/dev/null \
            || { cat "$out/child-files-release-unstaged.json" >&2; fail "child-files release did not fail closed without a staged plan"; }

          # Out-of-band descriptor transfer reaches the handlers: without an
          # SCM_RIGHTS payload getfd reports the missing descriptor, and closefd
          # reports the unknown name, instead of an OOB-not-allowed rejection.
          qmp "$patched_socket" \
            '{"exec-oob":"getfd","arguments":{"fdname":"crucible-oob-probe"}}' \
            "$out/getfd-oob.json"
          jq -e -s 'any(.[]; (.error.desc // "") | test("No file descriptor supplied"))' "$out/getfd-oob.json" >/dev/null \
            || { cat "$out/getfd-oob.json" >&2; fail "patched QEMU did not dispatch getfd out of band"; }
          qmp "$patched_socket" \
            '{"exec-oob":"closefd","arguments":{"fdname":"crucible-oob-probe"}}' \
            "$out/closefd-oob.json"
          jq -e -s 'any(.[]; (.error.desc // "") | test("not found"))' "$out/closefd-oob.json" >/dev/null \
            || { cat "$out/closefd-oob.json" >&2; fail "patched QEMU did not dispatch closefd out of band"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-child-console","arguments":{"action":"query"}}' \
            "$out/child-console-initial.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 1,
              "generation": 0,
              "template-generation": 0,
              "staged": false,
              "socket-cookie": 0,
              "retained-fd": -1,
              "resource-plan-bound": false,
              "nonblocking-unix-stream": false,
              "console-basis-bound": false,
              "reinitializer-prepared": false,
              "reinitialized": false,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            }
          ' "$out/child-console-initial.json" >/dev/null \
            || { cat "$out/child-console-initial.json" >&2; fail "initial child-console state was not exact"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-private-rings","arguments":{"action":"query"}}' \
            "$out/private-rings-initial.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 3,
              "generation": 0,
              "template-generation": 0,
              "staged": false,
              "device": 0,
              "inode": 0,
              "length": 0,
              "shrink-sealed": false,
              "source-mapping-bound": false,
              "source-start": 0,
              "source-length": 0,
              "source-offset": 0,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            }
          ' "$out/private-rings-initial.json" >/dev/null \
            || { cat "$out/private-rings-initial.json" >&2; fail "initial private-ring stage was not exact"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-child-diagnostics","arguments":{"action":"query"}}' \
            "$out/child-diagnostics-initial.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 1,
              "generation": 0,
              "template-generation": 0,
              "staged": false,
              "socket-cookie": 0,
              "source-fd": -1,
              "target-fd": -1,
              "replacement-plan-bound": false,
              "nonblocking-unix-stream": false,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            }
          ' "$out/child-diagnostics-initial.json" >/dev/null \
            || { cat "$out/child-diagnostics-initial.json" >&2; fail "initial child-diagnostics stage was not exact"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-child-qmp","arguments":{"action":"query"}}' \
            "$out/child-qmp-initial.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 8,
              "generation": 0,
              "template-generation": 0,
              "monitor-generation": 0,
              "staged": false,
              "socket-cookie": 0,
              "retained-fd": -1,
              "resource-plan-bound": false,
              "nonblocking-unix-stream": false,
              "monitor-basis-bound": false,
              "monitor-disposition-bound": false,
              "monitor-socket-resources-bound": false,
              "reinitializer-prepared": false,
              "reinitialized": false,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            }
          ' "$out/child-qmp-initial.json" >/dev/null \
            || { cat "$out/child-qmp-initial.json" >&2; fail "initial child-QMP stage was not exact"; }

          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-plugin-endpoints","arguments":{"action":"query"}}' \
            "$out/plugin-endpoints-initial.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return == {
              "schema-version": 4,
              "generation": 0,
              "template-generation": 0,
              "staged": false,
              "control-socket-cookie": 0,
              "wake-eventfd-id": 0,
              "control-source-fd": -1,
              "wake-source-fd": -1,
              "control-target-fd": -1,
              "wake-target-fd": -1,
              "private-ring-generation": 0,
              "plugin-barrier-generation": 0,
              "worker-mask": 0,
              "parent-resume-worker-mask": 0,
              "child-reinitialize-worker-mask": 0,
              "pending-worker-mask": 0,
              "worker-disposition-planned": false,
              "replacement-plan-bound": false,
              "control-unix-stream": false,
              "wake-eventfd": false,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            }
          ' "$out/plugin-endpoints-initial.json" >/dev/null \
            || { cat "$out/plugin-endpoints-initial.json" >&2; fail "initial plugin-endpoint stage was not exact"; }

          PATCHED_SOCKET="$patched_socket" PRIVATE_RING_AUDIT="$out/private-rings-live.json" \
            ${pkgs.python3}/bin/python3 <<'PY'
          import array
          import fcntl
          import json
          import os
          import socket
          import struct

          socket_path = os.environ["PATCHED_SOCKET"]
          audit_path = os.environ["PRIVATE_RING_AUDIT"]
          connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
          connection.settimeout(3.0)
          connection.connect(socket_path)
          reader = connection.makefile("rb")

          def receive():
              line = reader.readline()
              if not line:
                  raise RuntimeError("QMP closed before a complete response")
              return json.loads(line)

          def send_raw(command):
              connection.sendall(json.dumps(command, separators=(",", ":")).encode() + b"\r\n")
              return receive()

          def send(command):
              response = send_raw(command)
              if "error" in response:
                  raise RuntimeError(f"QMP command failed: {response}")
              return response

          greeting = receive()
          if "QMP" not in greeting:
              raise RuntimeError(f"missing QMP greeting: {greeting}")
          send({"execute": "qmp_capabilities", "arguments": {"enable": ["oob"]}})

          descriptor = os.memfd_create("crucible-hfork-private-rings", os.MFD_ALLOW_SEALING)
          os.ftruncate(descriptor, 4096)
          fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SHRINK)
          identity = os.fstat(descriptor)
          name = "crucible-hfork-rings-v1-live"
          getfd = json.dumps(
              {"execute": "getfd", "arguments": {"fdname": name}},
              separators=(",", ":"),
          ).encode() + b"\r\n"
          rights = array.array("i", [descriptor])
          connection.sendmsg([getfd], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
          getfd_response = receive()
          if "error" in getfd_response:
              raise RuntimeError(f"getfd failed: {getfd_response}")

          stage = send({
              "exec-oob": "crucible-hot-fork-private-rings",
              "arguments": {
                  "action": "stage",
                  "fdname": name,
                  "expected-device": identity.st_dev,
                  "expected-inode": identity.st_ino,
                  "expected-length": identity.st_size,
              },
          })
          query = send({
              "exec-oob": "crucible-hot-fork-private-rings",
              "arguments": {"action": "query"},
          })

          control_host, control_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
          wake = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
          control_cookie = struct.unpack(
              "=Q",
              control_child.getsockopt(
                  socket.SOL_SOCKET,
                  getattr(socket, "SO_COOKIE", 57),
                  8,
              ),
          )[0]
          with open(f"/proc/self/fdinfo/{wake}", "r", encoding="utf-8") as fdinfo:
              eventfd_lines = [
                  line.split(":", 1)[1].strip()
                  for line in fdinfo
                  if line.startswith("eventfd-id:")
              ]
          if len(eventfd_lines) != 1:
              raise RuntimeError(f"eventfd identity was not exact: {eventfd_lines}")
          wake_identity = int(eventfd_lines[0], 10)
          control_name = "crucible-hfork-control-v1-live"
          wake_name = "crucible-hfork-wake-v1-live"

          def transfer_fd(name, descriptor):
              request = json.dumps(
                  {"execute": "getfd", "arguments": {"fdname": name}},
                  separators=(",", ":"),
              ).encode() + b"\r\n"
              transferred = array.array("i", [descriptor])
              connection.sendmsg(
                  [request],
                  [(socket.SOL_SOCKET, socket.SCM_RIGHTS, transferred)],
              )
              response = receive()
              if "error" in response:
                  raise RuntimeError(f"endpoint getfd failed: {response}")
              return response

          control_getfd = transfer_fd(control_name, control_child.fileno())
          wake_getfd = transfer_fd(wake_name, wake)
          endpoint_stage = send({
              "exec-oob": "crucible-hot-fork-plugin-endpoints",
              "arguments": {
                  "action": "stage",
                  "control-fdname": control_name,
                  "wake-fdname": wake_name,
                  "expected-control-socket-cookie": control_cookie,
                  "expected-wake-eventfd-id": wake_identity,
              },
          })
          endpoint_query = send({
              "exec-oob": "crucible-hot-fork-plugin-endpoints",
              "arguments": {"action": "query"},
          })
          foreign_release = send_raw({
              "exec-oob": "crucible-hot-fork-private-rings",
              "arguments": {
                  "action": "release",
                  "fdname": name,
                  "expected-device": identity.st_dev,
                  "expected-inode": identity.st_ino + 1,
                  "expected-length": identity.st_size,
              },
          })
          after_rejected_release = send({
              "exec-oob": "crucible-hot-fork-private-rings",
              "arguments": {"action": "query"},
          })
          retained_ring_release = send_raw({
              "exec-oob": "crucible-hot-fork-private-rings",
              "arguments": {
                  "action": "release",
                  "fdname": name,
                  "expected-device": identity.st_dev,
                  "expected-inode": identity.st_ino,
                  "expected-length": identity.st_size,
              },
          })
          endpoint_foreign_release = send_raw({
              "exec-oob": "crucible-hot-fork-plugin-endpoints",
              "arguments": {
                  "action": "release",
                  "control-fdname": control_name,
                  "wake-fdname": wake_name,
                  "expected-control-socket-cookie": control_cookie,
                  "expected-wake-eventfd-id": wake_identity + 1,
              },
          })
          endpoint_after_rejected_release = send({
              "exec-oob": "crucible-hot-fork-plugin-endpoints",
              "arguments": {"action": "query"},
          })
          endpoint_release = send({
              "exec-oob": "crucible-hot-fork-plugin-endpoints",
              "arguments": {
                  "action": "release",
                  "control-fdname": control_name,
                  "wake-fdname": wake_name,
                  "expected-control-socket-cookie": control_cookie,
                  "expected-wake-eventfd-id": wake_identity,
              },
          })
          wake_closefd = send({"execute": "closefd", "arguments": {"fdname": wake_name}})
          control_closefd = send({
              "execute": "closefd",
              "arguments": {"fdname": control_name},
          })
          release = send({
              "exec-oob": "crucible-hot-fork-private-rings",
              "arguments": {
                  "action": "release",
                  "fdname": name,
                  "expected-device": identity.st_dev,
                  "expected-inode": identity.st_ino,
                  "expected-length": identity.st_size,
              },
          })
          closefd = send({"execute": "closefd", "arguments": {"fdname": name}})

          with open(audit_path, "w", encoding="utf-8") as audit:
              json.dump({
                  "name": name,
                  "identity": {
                      "device": identity.st_dev,
                      "inode": identity.st_ino,
                      "length": identity.st_size,
                  },
                  "stage": stage,
                  "query": query,
                  "control-name": control_name,
                  "wake-name": wake_name,
                  "control-cookie": control_cookie,
                  "wake-identity": wake_identity,
                  "control-getfd": control_getfd,
                  "wake-getfd": wake_getfd,
                  "endpoint-stage": endpoint_stage,
                  "endpoint-query": endpoint_query,
                  "foreign-release": foreign_release,
                  "after-rejected-release": after_rejected_release,
                  "retained-ring-release": retained_ring_release,
                  "endpoint-foreign-release": endpoint_foreign_release,
                  "endpoint-after-rejected-release": endpoint_after_rejected_release,
                  "endpoint-release": endpoint_release,
                  "wake-closefd": wake_closefd,
                  "control-closefd": control_closefd,
                  "release": release,
                  "closefd": closefd,
              }, audit, separators=(",", ":"))
              audit.write("\n")
          os.close(descriptor)
          os.close(wake)
          control_child.close()
          control_host.close()
          connection.close()
          PY
          jq -e '
            .identity as $identity |
            .name as $name |
            ."control-name" as $control_name |
            ."wake-name" as $wake_name |
            ."control-cookie" as $control_cookie |
            ."wake-identity" as $wake_identity |
            ."endpoint-stage".return."control-source-fd" as $control_source_fd |
            ."endpoint-stage".return."wake-source-fd" as $wake_source_fd |
            .stage.return == {
              "schema-version": 3,
              "generation": 1,
              "template-generation": 0,
              "staged": true,
              "fdname": $name,
              "device": $identity.device,
              "inode": $identity.inode,
              "length": $identity.length,
              "shrink-sealed": true,
              "source-mapping-bound": false,
              "source-start": 0,
              "source-length": 0,
              "source-offset": 0,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            } and
            .query.return == .stage.return and
            ."control-getfd".return == {} and
            ."wake-getfd".return == {} and
            ($control_source_fd | type) == "number" and
            ($wake_source_fd | type) == "number" and
            $control_source_fd >= 0 and
            $wake_source_fd >= 0 and
            $control_source_fd != $wake_source_fd and
            ."endpoint-stage".return == {
              "schema-version": 4,
              "generation": 1,
              "template-generation": 0,
              "staged": true,
              "control-fdname": $control_name,
              "wake-fdname": $wake_name,
              "control-socket-cookie": $control_cookie,
              "wake-eventfd-id": $wake_identity,
              "control-source-fd": $control_source_fd,
              "wake-source-fd": $wake_source_fd,
              "control-target-fd": -1,
              "wake-target-fd": -1,
              "private-ring-generation": 1,
              "plugin-barrier-generation": 0,
              "worker-mask": 0,
              "parent-resume-worker-mask": 0,
              "child-reinitialize-worker-mask": 0,
              "pending-worker-mask": 0,
              "worker-disposition-planned": false,
              "replacement-plan-bound": false,
              "control-unix-stream": true,
              "wake-eventfd": true,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            } and
            ."endpoint-query".return == ."endpoint-stage".return and
            (."foreign-release".error | type) == "object" and
            ."after-rejected-release".return == .stage.return and
            (."retained-ring-release".error | type) == "object" and
            (."endpoint-foreign-release".error | type) == "object" and
            ."endpoint-after-rejected-release".return == ."endpoint-stage".return and
            ."endpoint-release".return == {
              "schema-version": 4,
              "generation": 2,
              "template-generation": 0,
              "staged": false,
              "control-socket-cookie": 0,
              "wake-eventfd-id": 0,
              "control-source-fd": -1,
              "wake-source-fd": -1,
              "control-target-fd": -1,
              "wake-target-fd": -1,
              "private-ring-generation": 0,
              "plugin-barrier-generation": 0,
              "worker-mask": 0,
              "parent-resume-worker-mask": 0,
              "child-reinitialize-worker-mask": 0,
              "pending-worker-mask": 0,
              "worker-disposition-planned": false,
              "replacement-plan-bound": false,
              "control-unix-stream": false,
              "wake-eventfd": false,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            } and
            ."wake-closefd".return == {} and
            ."control-closefd".return == {} and
            .release.return == {
              "schema-version": 3,
              "generation": 2,
              "template-generation": 0,
              "staged": false,
              "device": 0,
              "inode": 0,
              "length": 0,
              "shrink-sealed": false,
              "source-mapping-bound": false,
              "source-start": 0,
              "source-length": 0,
              "source-offset": 0,
              "disposition-complete": false,
              "readiness-proof-acknowledged": false
            } and
            .closefd.return == {}
          ' "$out/private-rings-live.json" >/dev/null \
            || { cat "$out/private-rings-live.json" >&2; fail "live private-ring ownership transaction was not exact"; }

          qmp "$patched_socket" '{"execute":"stop"}' "$out/stop.json"
          jq -e -s 'all(.[]; has("error") | not)' "$out/stop.json" >/dev/null \
            || { cat "$out/stop.json" >&2; fail "ordinary QMP stop failed"; }
          qmp "$patched_socket" '{"execute":"query-status"}' "$out/paused-status.json"
          jq -e -s '[.[] | select(has("return"))][-1].return.status == "paused"' \
            "$out/paused-status.json" >/dev/null \
            || { cat "$out/paused-status.json" >&2; fail "ordinary QMP stop did not reach paused state"; }

          qmp_pair "$patched_socket" \
            '{"execute":"crucible-hot-fork-block-barrier","arguments":{"action":"query"}}' \
            "$out/block-barrier-query.json"
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("quiesced-rooted-backends"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1] and
            ($reports[0] as $report |
            ($report | keys | sort) == [
              "backend-count",
              "complete",
              "generation",
              "graph-barrier-generation",
              "graph-held",
              "graph-mutation-generation",
              "graph-owner-thread-id",
              "graph-stable",
              "graph-waiting-writers",
              "graph-writer-active",
              "held",
              "held-graph-mutation-generation",
              "in-flight",
              "owner-thread-id",
              "quiesced-rooted-backends",
              "quiescent",
              "rooted-backends",
              "schema-version",
              "snapshot-backend-generation",
              "snapshot-bound",
              "snapshot-complete",
              "snapshot-generation",
              "snapshot-graph-mutation-generation",
              "snapshot-owner-thread-id",
              "snapshot-roots",
              "snapshot-sources",
              "writable-backends",
              "writable-rooted-backends"
            ] and
            $report."schema-version" == 4 and
            $report.generation == 0 and
            $report."owner-thread-id" == 0 and
            ($report."graph-barrier-generation" | type) == "number" and
            ($report."graph-mutation-generation" | type) == "number" and
            $report."held-graph-mutation-generation" == 0 and
            $report."graph-owner-thread-id" == 0 and
            $report.held == false and
            $report."graph-held" == false and
            $report."graph-writer-active" == false and
            $report."graph-waiting-writers" == 0 and
            $report."graph-stable" == false and
            $report."snapshot-generation" == 0 and
            $report."snapshot-backend-generation" == 0 and
            $report."snapshot-graph-mutation-generation" == 0 and
            $report."snapshot-owner-thread-id" == 0 and
            $report."snapshot-bound" == false and
            $report."snapshot-complete" == false and
            $report."snapshot-roots" == [] and
            $report."snapshot-sources" == {
              "schema-version": 1,
              "frozen": false,
              "root-count": 0,
              "node-count": 0,
              "originally-writable-root-count": 0,
              "originally-writable-backend-count": 0
            } and
            $report.complete == true and
            ($report."backend-count" | type) == "number" and
            ($report."rooted-backends" | type) == "number" and
            ($report."writable-backends" | type) == "number" and
            ($report."writable-rooted-backends" | type) == "number" and
            $report."rooted-backends" <= $report."backend-count" and
            $report."writable-backends" <= $report."backend-count" and
            $report."writable-rooted-backends" <= $report."rooted-backends" and
            $report."writable-rooted-backends" <= $report."writable-backends" and
            $report."quiesced-rooted-backends" >= 0 and
            $report."quiesced-rooted-backends" <= $report."rooted-backends" and
            ($report."in-flight" | type) == "number" and
            $report."in-flight" >= 0 and
            $report.quiescent == false)
          ' "$out/block-barrier-query.json" >/dev/null \
            || { cat "$out/block-barrier-query.json" >&2; fail "QEMU released block barrier state was not exact and stable"; }
          qmp "$patched_socket" \
            '{"execute":"crucible-hot-fork-block-barrier","arguments":{"action":"hold"}}' \
            "$out/block-barrier-hold.json"
          jq -e -s 'any(.[]; has("error"))' "$out/block-barrier-hold.json" >/dev/null \
            || { cat "$out/block-barrier-hold.json" >&2; fail "QEMU held the block barrier outside the exact boundary"; }
          qmp "$patched_socket" \
            '{"execute":"crucible-hot-fork-block-barrier","arguments":{"action":"query"}}' \
            "$out/block-barrier-after-rejection.json"
          jq -e -s --slurpfile initial "$out/block-barrier-query.json" '
            [.[] | select(has("return"))][-1].return ==
              ($initial | map(select(has("return"))) | .[-1].return)
          ' "$out/block-barrier-after-rejection.json" >/dev/null \
            || { cat "$out/block-barrier-after-rejection.json" >&2; fail "QEMU retained block barrier state after a rejected hold"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"query-crucible-hot-fork-plugin-resource-inventory"}' \
            "$out/plugin-resource-inventory.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return as $report |
            ($report | keys | sort) == [
              "app-random",
              "callback-mask",
              "callback-mask-consistent",
              "complete",
              "control-fd",
              "coverage",
              "fingerprint",
              "fingerprint-worker",
              "generation",
              "node-count",
              "observed-callback-mask",
              "plugin-id",
              "process-generation",
              "registered",
              "resource-mask",
              "run-control-worker",
              "schema-version",
              "shmem-device",
              "shmem-inode",
              "shmem-length",
              "slot-index",
              "teardown-worker",
              "wake-fd",
              "whitebox",
              "worker-mask"
            ] and
            $report == {
              "schema-version": 3,
              "generation": 0,
              "registered": false,
              "complete": false,
              "process-generation": 0,
              "plugin-id": 0,
              "resource-mask": 0,
              "callback-mask": 0,
              "worker-mask": 0,
              "observed-callback-mask": 0,
              "callback-mask-consistent": true,
              "shmem-device": 0,
              "shmem-inode": 0,
              "shmem-length": 0,
              "slot-index": 0,
              "node-count": 0,
              "control-fd": 0,
              "wake-fd": 0,
              "coverage": false,
              "whitebox": false,
              "fingerprint": false,
              "run-control-worker": false,
              "teardown-worker": false,
              "fingerprint-worker": false,
              "app-random": false
            }
          ' "$out/plugin-resource-inventory.json" >/dev/null \
            || { cat "$out/plugin-resource-inventory.json" >&2; fail "QEMU unregistered plugin-resource inventory was not exact and fail-closed"; }
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("resource-mask"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1]
          ' "$out/plugin-resource-inventory.json" >/dev/null \
            || { cat "$out/plugin-resource-inventory.json" >&2; fail "QEMU plugin-resource inventory changed without registration"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"query-crucible-hot-fork-child-runtime"}' \
            "$out/child-runtime.json"
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("readiness-proof-acknowledged"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1] and
            $reports[0] == {
              "schema-version": 3,
              "generation": 0,
              "registered": false,
              "manifest-consistent": false,
              "plugin-id": 0,
              "process-generation": 0,
              "phase": "template",
              "callbacks-held": false,
              "mapping-installed": false,
              "workers-ready": false,
              "active": false,
              "failed": false,
              "parent-process-generation": 0,
              "child-process-generation": 0,
              "template-generation": 0,
              "private-ring-generation": 0,
              "plugin-endpoint-generation": 0,
              "plugin-barrier-generation": 0,
              "control-socket-cookie": 0,
              "wake-eventfd-id": 0,
              "source-mapping-start": 0,
              "source-mapping-length": 0,
              "source-mapping-offset": 0,
              "worker-mask": 0,
              "parked-worker-mask": 0,
              "pending-worker-mask": 0,
              "worker-operations-in-flight": 0,
              "readiness-proof-acknowledged": false
            }
          ' "$out/child-runtime.json" >/dev/null \
            || { cat "$out/child-runtime.json" >&2; fail "QEMU unregistered child runtime was not exact and stable"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-plugin-barrier","arguments":{"action":"query"}}' \
            "$out/plugin-barrier-query.json"
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("in-flight"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1] and
            $reports[0] == {
              "schema-version": 6,
              "generation": 0,
              "registered": false,
              "manifest-consistent": false,
              "held": false,
              "teardown-closed": false,
              "mapping-dontfork": false,
              "in-flight": 0,
              "ring-count": 0,
              "rings-held": 0,
              "ring-producers-in-flight": 0,
              "ring-consumers-in-flight": 0,
              "worker-mask": 0,
              "parked-worker-mask": 0,
              "pending-worker-mask": 0,
              "worker-operations-in-flight": 0,
              "quiescent": false
            }
          ' "$out/plugin-barrier-query.json" >/dev/null \
            || { cat "$out/plugin-barrier-query.json" >&2; fail "QEMU unregistered plugin barrier was not exact and stable"; }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-plugin-barrier","arguments":{"action":"release"}}' \
            "$out/plugin-barrier-release.json"
          jq -e -s 'any(.[]; has("error"))' "$out/plugin-barrier-release.json" >/dev/null \
            || { cat "$out/plugin-barrier-release.json" >&2; fail "QEMU released an unregistered plugin barrier"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-rcu-barrier","arguments":{"action":"query"}}' \
            "$out/rcu-barrier-query.json"
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("registered-readers"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1] and
            ($reports[0] as $report |
            ($report | keys | sort) == [
              "active-readers",
              "admissions-in-flight",
              "complete",
              "drain-active",
              "generation",
              "held",
              "owner-thread-id",
              "pending-callbacks",
              "quiescent",
              "registered-readers",
              "schema-version"
            ] and
            $report."schema-version" == 1 and
            $report.generation == 0 and
            $report."owner-thread-id" == 0 and
            $report.held == false and
            ($report.complete | type) == "boolean" and
            ($report."registered-readers" | type) == "number" and
            $report."registered-readers" > 0 and
            $report."registered-readers" <= 65536 and
            ($report."active-readers" | type) == "number" and
            $report."active-readers" >= 0 and
            $report."active-readers" <= $report."registered-readers" and
            $report."admissions-in-flight" == 0 and
            ($report."pending-callbacks" | type) == "number" and
            $report."pending-callbacks" >= 0 and
            ($report."drain-active" | type) == "boolean" and
            $report.quiescent == false)
          ' "$out/rcu-barrier-query.json" >/dev/null \
            || { cat "$out/rcu-barrier-query.json" >&2; fail "QEMU released RCU barrier state was not exact and stable"; }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-rcu-barrier","arguments":{"action":"hold"}}' \
            "$out/rcu-barrier-hold.json"
          jq -e -s 'any(.[]; has("error"))' "$out/rcu-barrier-hold.json" >/dev/null \
            || { cat "$out/rcu-barrier-hold.json" >&2; fail "QEMU held the RCU barrier outside the exact boundary"; }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-rcu-barrier","arguments":{"action":"query"}}' \
            "$out/rcu-barrier-after-rejection.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return as $report |
            $report.generation == 0 and
            $report."owner-thread-id" == 0 and
            $report.held == false and
            $report.quiescent == false
          ' "$out/rcu-barrier-after-rejection.json" >/dev/null \
            || { cat "$out/rcu-barrier-after-rejection.json" >&2; fail "QEMU retained RCU barrier state after a rejected hold"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-async-worker-barrier","arguments":{"action":"query"}}' \
            "$out/async-worker-barrier-query.json"
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("bottom-half-count"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1] and
            ($reports[0] as $report |
            ($report | keys | sort) == [
              "active-aio-dispatches",
              "active-aio-handler-callbacks",
              "active-aio-polls",
              "active-bottom-half-callbacks",
              "active-timer-callbacks",
              "admissions-in-flight",
              "aio-context-count",
              "aio-contexts-complete",
              "aio-handler-count",
              "aio-handlers-complete",
              "bottom-half-count",
              "bottom-halves-complete",
              "complete",
              "generation",
              "held",
              "owner-thread-id",
              "pending-bottom-halves",
              "pending-timers",
              "queued-coroutines",
              "quiescent",
              "scheduled-bottom-halves",
              "schema-version",
              "timers-complete"
            ] and
            $report."schema-version" == 3 and
            $report.generation == 0 and
            $report."owner-thread-id" == 0 and
            $report.held == false and
            $report.quiescent == false and
            $report."admissions-in-flight" == 0 and
            ($report."bottom-half-count" | type) == "number" and
            $report."bottom-half-count" >= 0 and
            $report."bottom-half-count" <= 65536 and
            $report."pending-bottom-halves" >= 0 and
            $report."pending-bottom-halves" <= $report."bottom-half-count" and
            $report."scheduled-bottom-halves" >= 0 and
            $report."scheduled-bottom-halves" <= $report."pending-bottom-halves" and
            $report."active-bottom-half-callbacks" >= 0 and
            $report."active-bottom-half-callbacks" <= $report."bottom-half-count" and
            $report."pending-timers" >= 0 and
            $report."pending-timers" <= 65536 and
            $report."active-timer-callbacks" >= 0 and
            $report."active-timer-callbacks" <= 65536 and
            $report."aio-context-count" >= 0 and
            $report."aio-context-count" <= 65536 and
            $report."active-aio-polls" >= 0 and
            $report."active-aio-polls" <= $report."aio-context-count" and
            $report."active-aio-dispatches" >= 0 and
            $report."active-aio-dispatches" <= $report."aio-context-count" and
            $report."queued-coroutines" >= 0 and
            $report."queued-coroutines" <=
              ($report."aio-context-count" * 4294967295) and
            $report."aio-handler-count" >= 0 and
            $report."aio-handler-count" <= 65536 and
            $report."active-aio-handler-callbacks" >= 0 and
            $report."active-aio-handler-callbacks" <=
              ($report."aio-handler-count" * 4294967295) and
            ($report."bottom-halves-complete" | type) == "boolean" and
            ($report."timers-complete" | type) == "boolean" and
            ($report."aio-contexts-complete" | type) == "boolean" and
            ($report."aio-handlers-complete" | type) == "boolean" and
            $report.complete ==
              ($report."bottom-halves-complete" and
               $report."timers-complete" and
               $report."aio-contexts-complete" and
               $report."aio-handlers-complete"))
          ' "$out/async-worker-barrier-query.json" >/dev/null \
            || { cat "$out/async-worker-barrier-query.json" >&2; fail "QEMU released asynchronous-worker barrier state was not exact and stable"; }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-async-worker-barrier","arguments":{"action":"hold"}}' \
            "$out/async-worker-barrier-hold.json"
          jq -e -s 'any(.[]; has("error"))' "$out/async-worker-barrier-hold.json" >/dev/null \
            || { cat "$out/async-worker-barrier-hold.json" >&2; fail "QEMU held the asynchronous-worker barrier outside the exact boundary"; }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-async-worker-barrier","arguments":{"action":"query"}}' \
            "$out/async-worker-barrier-after-rejection.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return as $report |
            $report.generation == 0 and
            $report."owner-thread-id" == 0 and
            $report.held == false and
            $report.quiescent == false
          ' "$out/async-worker-barrier-after-rejection.json" >/dev/null \
            || { cat "$out/async-worker-barrier-after-rejection.json" >&2; fail "QEMU retained asynchronous-worker barrier state after a rejected hold"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-template","arguments":{"action":"query"}}' \
            "$out/template-coordinator-query.json"
          jq -e -s \
            --slurpfile bh "$out/async-worker-barrier-query.json" \
            --slurpfile block "$out/block-barrier-query.json" '
            [.[] | select(has("return")) | .return |
             select(has("transaction-active"))] as $reports |
            ($bh | map(select(has("return"))) | .[-1].return) as $bh_report |
            ($block | map(select(has("return"))) | .[-1].return) as $block_report |
            ($reports | length) == 2 and $reports[0] == $reports[1] and
            ($reports[0] as $report |
            ($report | keys | sort) == [
              "acknowledged-proofs",
              "async-worker-barrier",
              "block-barrier",
              "generation",
              "missing-proofs",
              "outcome",
              "plugin-barrier",
              "rcu-barrier",
              "ready",
              "required-proofs",
              "resource-stage",
              "rollback-complete",
              "schema-version",
              "transaction-active"
            ] and
            $report."schema-version" == 27 and
            $report.generation == 0 and
            $report.outcome == "idle" and
            $report."transaction-active" == false and
            $report."required-proofs" == 127 and
            $report."acknowledged-proofs" == 3 and
            $report."missing-proofs" == 124 and
            $report."plugin-barrier" == {
              "schema-version": 6,
              "generation": 0,
              "registered": false,
              "manifest-consistent": false,
              "held": false,
              "teardown-closed": false,
              "mapping-dontfork": false,
              "in-flight": 0,
              "ring-count": 0,
              "rings-held": 0,
              "ring-producers-in-flight": 0,
              "ring-consumers-in-flight": 0,
              "worker-mask": 0,
              "parked-worker-mask": 0,
              "pending-worker-mask": 0,
              "worker-operations-in-flight": 0,
              "quiescent": false
            } and
            $report."rcu-barrier"."schema-version" == 1 and
            $report."rcu-barrier".generation == 0 and
            $report."rcu-barrier"."owner-thread-id" == 0 and
            $report."rcu-barrier".held == false and
            $report."rcu-barrier".quiescent == false and
            $report."async-worker-barrier" == $bh_report and
            $report."block-barrier" == $block_report and
            $report."resource-stage" == {
              "schema-version": 13,
              "template-generation": 0,
              "private-ring-staged": false,
              "private-ring-generation": 2,
              "diagnostics-staged": false,
              "diagnostic-generation": 0,
              "diagnostics-resource-plan-bound": false,
              "qmp-staged": false,
              "qmp-generation": 0,
              "qmp-resource-plan-bound": false,
              "console-staged": false,
              "console-generation": 0,
              "console-resource-plan-bound": false,
              "plugin-endpoints-staged": false,
              "plugin-endpoint-generation": 2,
              "plugin-private-ring-generation": 0,
              "plugin-barrier-generation": 0,
              "worker-mask": 0,
              "parent-resume-worker-mask": 0,
              "child-reinitialize-worker-mask": 0,
              "pending-worker-mask": 0,
              "worker-disposition-bound": false,
              "transaction-bound": false,
              "parent-process-generation": 0,
              "child-process-generation": 0,
              "plugin-child-plan-bound": false,
              "plugin-child-resource-plan-bound": false,
              "readiness-proof-acknowledged": false
            } and
            $report."rollback-complete" == true and
            $report.ready == false)
          ' "$out/template-coordinator-query.json" >/dev/null \
            || {
              jq -c -s '
                [.[] | select(has("return")) | .return |
                 select(has("transaction-active"))] as $reports |
                {
                  expected_schema_version: 27,
                  report_count: ($reports | length),
                  reports_stable: (($reports | length) == 2 and
                                   $reports[0] == $reports[1]),
                  schema_versions: [$reports[]."schema-version"],
                  outcomes: [$reports[].outcome],
                  report_keys: [$reports[] | keys | sort],
                  reports: $reports
                }
              ' "$out/template-coordinator-query.json" >&2 \
                || {
                  echo "unable to parse template coordinator response; raw bytes follow" >&2
                  od -An -tx1 -v "$out/template-coordinator-query.json" >&2
                }
              fail "QEMU template coordinator idle state was not exact and stable"
            }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-template","arguments":{"action":"prepare","block-snapshot-bindings":[]}}' \
            "$out/template-coordinator-prepare.json"
          jq -e -s 'any(.[]; has("error"))' "$out/template-coordinator-prepare.json" >/dev/null \
            || { cat "$out/template-coordinator-prepare.json" >&2; fail "QEMU prepared a hot-fork template outside the exact boundary"; }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-template","arguments":{"action":"query"}}' \
            "$out/template-coordinator-after-rejection.json"
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("transaction-active"))] as $reports |
            ($reports | length) == 1 and
            $reports[0].generation == 0 and
            $reports[0].outcome == "idle" and
            $reports[0]."transaction-active" == false and
            $reports[0]."rollback-complete" == true and
            $reports[0].ready == false and
            $reports[0]."plugin-barrier".held == false and
            $reports[0]."rcu-barrier".held == false and
            $reports[0]."async-worker-barrier".held == false and
            $reports[0]."block-barrier".held == false
          ' "$out/template-coordinator-after-rejection.json" >/dev/null \
            || { cat "$out/template-coordinator-after-rejection.json" >&2; fail "QEMU retained state after rejecting template preparation"; }

          qmp "$patched_socket" '{"execute":"quit"}' "$out/patched-quit.json"
          wait "$qemu_pid"
          qemu_pid=""

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${taskList}
          gate=gate:hot-fork-readiness
          patch=crucible-qemu-11.1.1.patch
          retained_template_fork_rejects_unprepared=true
          retained_child_unknown_generation_rejected=true
          child_process_contract_initially_absent=true
          child_files_initially_absent=true
          child_files_stage_rejects_without_template=true
          child_files_release_rejects_unstaged=true
          stock_getfd_rejects_out_of_band=true
          getfd_out_of_band_dispatch=true
          closefd_out_of_band_dispatch=true
          child_console_initially_absent=true
          plugin_endpoint_schema_version=4
          plugin_endpoint_source_descriptors_observed=true
          plugin_endpoint_replacement_plan_bound=false
          child_diagnostics_schema_version=1
          child_diagnostics_initially_absent=true
          child_qmp_schema_version=8
          child_qmp_initially_absent=true
          child_qmp_monitor_basis_bound=false
          child_qmp_monitor_disposition_bound=false
          child_qmp_monitor_socket_resources_bound=false
          rcu_barrier_schema_version=1
          rcu_barrier_released_stable=true
          rcu_barrier_hold_without_exact_boundary_rejected=true
          rcu_barrier_quiescence_proof_bound=true
          rcu_runtime_transaction_composed=true
          rcu_parent_registry_preserved=true
          rcu_child_registry_reconstructed=true
          rcu_child_callback_worker_restarted=true
          async_worker_barrier_schema_version=3
          async_worker_barrier_released_stable=true
          async_worker_barrier_hold_without_exact_boundary_rejected=true
          async_worker_barrier_template_bound=true
          block_barrier_schema_version=4
          block_barrier_released_stable=true
          block_barrier_hold_without_exact_boundary_rejected=true
          block_graph_writer_admission_retained=true
          block_graph_generation_bound=true
          block_snapshot_binding_argument_bound=true
          block_barrier_template_bound=true
          plugin_resource_inventory_schema_version=3
          plugin_resource_inventory_stable=true
          plugin_resource_inventory_unregistered_shape=true
          child_runtime_schema_version=3
          child_runtime_stable=true
          child_runtime_unregistered_shape=true
          child_runtime_readiness_proof_acknowledged=false
          plugin_child_runtime_adapter_one_shot=true
          plugin_barrier_schema_version=6
          plugin_barrier_stable=true
          plugin_barrier_unregistered_shape=true
          plugin_mapping_dontfork_unregistered=false
          plugin_barrier_release_unregistered_rejected=true
          plugin_worker_mask_bound=true
          plugin_worker_parking_bound=true
          plugin_worker_pending_local_bound=true
          plugin_worker_queue_cloning=false
          plugin_ring_consumer_admission_bound=true
          plugin_ring_proof_acknowledged=false
          private_ring_stage_schema_version=3
          private_ring_standalone_source_mapping_unbound=true
          private_ring_stage_initially_absent=true
          private_ring_live_descriptor_transaction=true
          private_ring_exact_identity_and_seal=true
          private_ring_foreign_release_rejected=true
          private_ring_two_layer_release=true
          private_ring_disposition_complete=false
          private_ring_readiness_proof_acknowledged=false
          plugin_endpoint_stage_schema_version=3
          plugin_endpoint_stage_initially_absent=true
          plugin_endpoint_exact_kernel_identity=true
          plugin_endpoint_private_ring_generation_bound=true
          plugin_endpoint_worker_disposition_planned=false
          plugin_endpoint_foreign_release_rejected=true
          plugin_endpoint_two_layer_release=true
          plugin_endpoint_disposition_complete=false
          plugin_endpoint_readiness_proof_acknowledged=false
          template_coordinator_schema_version=27
          plugin_child_plan_report_bound=true
          plugin_child_resource_plan_report_bound=true
          child_resource_contribution_composition=true
          sealed_child_resource_plan_application=true
          child_descriptor_replacement_composition=true
          template_resource_stage_schema_version=13
          template_worker_disposition_bound=false
          template_resource_stage_empty_after_release=true
          template_coordinator_idle_stable=true
          template_coordinator_unregistered_shape=true
          template_prepare_without_exact_boundary_rejected=true
          template_transaction_active=false
          template_ready=false
          incomplete_report_ready=false
          stock_commands_absent=true
          RESULT
        '';
      }
    ];
  }
