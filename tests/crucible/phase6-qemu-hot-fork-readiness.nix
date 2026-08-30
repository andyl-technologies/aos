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
          qmp "$stock_socket" \
            '{"execute":"query-crucible-hot-fork-aio-inventory"}' \
            "$out/stock-aio-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-aio-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible AIO inventory command"
          qmp "$stock_socket" \
            '{"exec-oob":"query-crucible-hot-fork-aio-handler-inventory"}' \
            "$out/stock-aio-handler-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-aio-handler-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible AIO-handler inventory command"
          qmp "$stock_socket" \
            '{"exec-oob":"query-crucible-hot-fork-block-backend-inventory"}' \
            "$out/stock-block-backend-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-block-backend-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible block-backend inventory command"
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
            '{"exec-oob":"crucible-hot-fork-bh-timer-barrier","arguments":{"action":"query"}}' \
            "$out/stock-bh-timer-barrier.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-bh-timer-barrier.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible bottom-half/timer barrier command"
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
            '{"exec-oob":"crucible-hot-fork-plugin-endpoints","arguments":{"action":"query"}}' \
            "$out/stock-plugin-endpoints.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-plugin-endpoints.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible plugin-endpoint stage"
          qmp "$stock_socket" \
            '{"exec-oob":"query-crucible-hot-fork-bottom-half-inventory"}' \
            "$out/stock-bottom-half-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-bottom-half-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible bottom-half inventory command"
          qmp "$stock_socket" \
            '{"execute":"query-crucible-hot-fork-mutex-inventory"}' \
            "$out/stock-mutex-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-mutex-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible mutex inventory command"
          qmp "$stock_socket" \
            '{"execute":"query-crucible-hot-fork-timer-inventory"}' \
            "$out/stock-timer-inventory.json"
          jq -e -s 'any(.[]; has("error"))' "$out/stock-timer-inventory.json" >/dev/null \
            || fail "stock QEMU unexpectedly exposed the Crucible timer inventory command"
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
              "schema-version": 2,
              "generation": 0,
              "template-generation": 0,
              "staged": false,
              "socket-cookie": 0,
              "retained-fd": -1,
              "resource-plan-bound": false,
              "nonblocking-unix-stream": false,
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

          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-aio-inventory"}' \
            "$out/aio-inventory-1.json"
          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-aio-inventory"}' \
            "$out/aio-inventory-2.json"
          jq -e -s --slurpfile threads "$out/thread-inventory-1.json" '
            [.[] | select(has("return"))][-1].return as $report |
            ($threads | map(select(has("return"))) | .[-1].return) as $thread_report |
            ($report | keys | sort) == [
              "active-bottom-halves",
              "active-dispatches",
              "active-polls",
              "assigned-contexts",
              "complete",
              "context-count",
              "contexts",
              "generation",
              "overflowed",
              "pending-bottom-halves",
              "queued-coroutines",
              "schema-version"
            ] and
            $report."schema-version" == 1 and
            ($report.generation | type) == "number" and
            ($report.complete | type) == "boolean" and
            ($report.overflowed | type) == "boolean" and
            ($report.contexts | type) == "array" and
            ($report.contexts | length) > 0 and
            ($report.contexts | length) <= 65536 and
            ($report.contexts | length) == $report."context-count" and
            ([ $report.contexts[] | select(."home-thread-id" > 0) ] | length) ==
              $report."assigned-contexts" and
            ([ $report.contexts[]."context-id" ] ==
             ([ $report.contexts[]."context-id" ] | sort)) and
            ([ $report.contexts[]."context-id" ] | unique | length) ==
              ($report.contexts | length) and
            all($report.contexts[];
              (. | keys | sort) == [
                "active-bottom-halves",
                "active-dispatches",
                "active-polls",
                "context-id",
                "home-thread-id",
                "notify-pending",
                "pending-bottom-halves",
                "queued-coroutines"
              ] and
              (."context-id" | type) == "number" and ."context-id" > 0 and
              (."home-thread-id" | type) == "number" and ."home-thread-id" >= 0 and
              (."active-polls" | type) == "number" and ."active-polls" >= 0 and
              (."active-dispatches" | type) == "number" and ."active-dispatches" >= 0 and
              (."pending-bottom-halves" | type) == "number" and ."pending-bottom-halves" >= 0 and
              (."active-bottom-halves" | type) == "number" and ."active-bottom-halves" >= 0 and
              (."queued-coroutines" | type) == "number" and ."queued-coroutines" >= 0 and
              (."notify-pending" | type) == "boolean") and
            ([ $report.contexts[]."active-polls" ] | add) == $report."active-polls" and
            ([ $report.contexts[]."active-dispatches" ] | add) == $report."active-dispatches" and
            ([ $report.contexts[]."pending-bottom-halves" ] | add) == $report."pending-bottom-halves" and
            ([ $report.contexts[]."active-bottom-halves" ] | add) == $report."active-bottom-halves" and
            ([ $report.contexts[]."queued-coroutines" ] | add) == $report."queued-coroutines" and
            all($report.contexts[] | select(."home-thread-id" > 0);
              ."home-thread-id" as $home_tid |
              any($thread_report.threads[]; ."thread-id" == $home_tid)) and
            $report.complete ==
              (($report.overflowed | not) and
               $report."assigned-contexts" == $report."context-count")
          ' "$out/aio-inventory-1.json" >/dev/null \
            || { cat "$out/aio-inventory-1.json" >&2; fail "QEMU AIO inventory was not exact or thread-bound"; }
          jq -e -s --slurpfile first "$out/aio-inventory-1.json" '
            [.[] | select(has("return"))][-1].return ==
              ($first | map(select(has("return"))) | .[-1].return)
          ' "$out/aio-inventory-2.json" >/dev/null \
            || { cat "$out/aio-inventory-1.json" >&2; cat "$out/aio-inventory-2.json" >&2; fail "QEMU AIO inventory changed without a context transition"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"query-crucible-hot-fork-aio-handler-inventory"}' \
            "$out/aio-handler-inventory.json"
          jq -e -s --slurpfile aio "$out/aio-inventory-1.json" '
            [.[] | select(has("return"))][-1].return as $report |
            ($aio | map(select(has("return"))) | .[-1].return) as $aio_report |
            ($report | keys | sort) == [
              "active-callbacks",
              "complete",
              "deleted-handlers",
              "generation",
              "handler-count",
              "handlers",
              "overflowed",
              "poll-handlers",
              "read-handlers",
              "schema-version",
              "write-handlers"
            ] and
            $report."schema-version" == 1 and
            ($report.generation | type) == "number" and
            ($report.complete | type) == "boolean" and
            ($report.overflowed | type) == "boolean" and
            ($report.handlers | type) == "array" and
            ($report.handlers | length) > 0 and
            ($report.handlers | length) <= 65536 and
            ($report.handlers | length) == $report."handler-count" and
            ([ $report.handlers[]."handler-id" ] ==
             ([ $report.handlers[]."handler-id" ] | sort)) and
            ([ $report.handlers[]."handler-id" ] | unique | length) ==
              ($report.handlers | length) and
            all($report.handlers[];
              (. | keys | sort) == [
                "active-callbacks",
                "context-id",
                "deleted",
                "fd",
                "handler-id",
                "poll-begin-callback",
                "poll-callback",
                "poll-end-callback",
                "poll-ready-callback",
                "read-callback",
                "write-callback"
              ] and
              (."handler-id" | type) == "number" and ."handler-id" > 0 and
              (."context-id" | type) == "number" and ."context-id" > 0 and
              (.fd | type) == "number" and .fd >= 0 and .fd <= 2147483647 and
              (.deleted | type) == "boolean" and
              (."read-callback" | type) == "boolean" and
              (."write-callback" | type) == "boolean" and
              (."poll-callback" | type) == "boolean" and
              (."poll-ready-callback" | type) == "boolean" and
              (."poll-begin-callback" | type) == "boolean" and
              (."poll-end-callback" | type) == "boolean" and
              (."active-callbacks" | type) == "number" and
              ."active-callbacks" >= 0 and
              (."read-callback" or ."write-callback" or ."poll-callback") and
              (."context-id" as $context_id |
               any($aio_report.contexts[]; ."context-id" == $context_id))) and
            ([ $report.handlers[] | select(."read-callback") ] | length) ==
              $report."read-handlers" and
            ([ $report.handlers[] | select(."write-callback") ] | length) ==
              $report."write-handlers" and
            ([ $report.handlers[] | select(."poll-callback") ] | length) ==
              $report."poll-handlers" and
            ([ $report.handlers[] | select(.deleted) ] | length) ==
              $report."deleted-handlers" and
            (([ $report.handlers[]."active-callbacks" ] | add) // 0) ==
              $report."active-callbacks" and
            $report.complete == ($report.overflowed | not)
          ' "$out/aio-handler-inventory.json" >/dev/null \
            || { cat "$out/aio-handler-inventory.json" >&2; fail "QEMU AIO-handler inventory was not exact or AioContext-bound"; }
          jq -r -s '
            [.[] | select(has("return"))][-1].return.handlers[] |
            select(.deleted | not) | .fd
          ' "$out/aio-handler-inventory.json" > "$out/aio-handler-live-fds"
          while IFS= read -r handler_fd; do
            [ -e "/proc/$qemu_pid/fd/$handler_fd" ] \
              || fail "QEMU AIO handler named a descriptor absent from its exact process"
          done < "$out/aio-handler-live-fds"
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("handlers"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1]
          ' "$out/aio-handler-inventory.json" >/dev/null \
            || { cat "$out/aio-handler-inventory.json" >&2; fail "QEMU AIO-handler inventory changed without a lifecycle or callback transition"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"query-crucible-hot-fork-block-backend-inventory"}' \
            "$out/block-backend-inventory.json"
          jq -e -s --slurpfile aio "$out/aio-inventory-1.json" '
            [.[] | select(has("return"))][-1].return as $report |
            ($aio | map(select(has("return"))) | .[-1].return) as $aio_report |
            ($report | keys | sort) == [
              "backend-count",
              "backends",
              "complete",
              "device-backends",
              "generation",
              "in-flight",
              "named-backends",
              "overflowed",
              "quiesced-backends",
              "rooted-backends",
              "schema-version",
              "writable-backends"
            ] and
            $report."schema-version" == 1 and
            ($report.generation | type) == "number" and
            $report.complete == true and
            $report.overflowed == false and
            ($report.backends | type) == "array" and
            ($report.backends | length) > 0 and
            ($report.backends | length) <= 65536 and
            ($report.backends | length) == $report."backend-count" and
            ([ $report.backends[]."backend-id" ] ==
             ([ $report.backends[]."backend-id" ] | sort)) and
            ([ $report.backends[]."backend-id" ] | unique | length) ==
              ($report.backends | length) and
            all($report.backends[];
              (. | keys | sort) == [
                "backend-id",
                "context-id",
                "device-attached",
                "in-flight",
                "name",
                "name-valid",
                "named",
                "permissions",
                "permissions-disabled",
                "quiesce-depth",
                "reference-count",
                "request-queuing-disabled",
                "root-present",
                "shared-permissions",
                "write-permission"
              ] and
              (."backend-id" | type) == "number" and ."backend-id" > 0 and
              (."context-id" | type) == "number" and ."context-id" > 0 and
              (."reference-count" | type) == "number" and ."reference-count" > 0 and
              (.name | type) == "string" and (.name | length) <= 255 and
              (.named | type) == "boolean" and .named == (.name != "") and
              (."name-valid" | type) == "boolean" and ."name-valid" and
              (."root-present" | type) == "boolean" and
              (."device-attached" | type) == "boolean" and
              (.permissions | type) == "number" and .permissions >= 0 and
              (."shared-permissions" | type) == "number" and ."shared-permissions" >= 0 and
              (."write-permission" | type) == "boolean" and
              ."write-permission" == ((.permissions / 2 | floor) % 2 == 1) and
              (."permissions-disabled" | type) == "boolean" and
              (."quiesce-depth" | type) == "number" and ."quiesce-depth" >= 0 and
              (."in-flight" | type) == "number" and ."in-flight" >= 0 and
              (."request-queuing-disabled" | type) == "boolean" and
              (."context-id" as $context_id |
               any($aio_report.contexts[]; ."context-id" == $context_id))) and
            ([ $report.backends[] | select(.named) ] | length) == $report."named-backends" and
            ([ $report.backends[] | select(."root-present") ] | length) == $report."rooted-backends" and
            ([ $report.backends[] | select(."device-attached") ] | length) == $report."device-backends" and
            ([ $report.backends[] | select(."write-permission") ] | length) == $report."writable-backends" and
            ([ $report.backends[] | select(."quiesce-depth" > 0) ] | length) == $report."quiesced-backends" and
            (([ $report.backends[]."in-flight" ] | add) // 0) == $report."in-flight" and
            any($report.backends[];
              .name == "crucible-vmstate" and .named and ."root-present" and
              (."in-flight" == 0))
          ' "$out/block-backend-inventory.json" >/dev/null \
            || { cat "$out/block-backend-inventory.json" >&2; fail "QEMU block-backend inventory was not exact or AioContext-bound"; }
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("backends"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1]
          ' "$out/block-backend-inventory.json" >/dev/null \
            || { cat "$out/block-backend-inventory.json" >&2; fail "QEMU block-backend inventory changed without a lifecycle or structural transition"; }

          qmp_pair "$patched_socket" \
            '{"execute":"crucible-hot-fork-block-barrier","arguments":{"action":"query"}}' \
            "$out/block-barrier-query.json"
          jq -e -s --slurpfile inventory "$out/block-backend-inventory.json" '
            [.[] | select(has("return")) | .return |
             select(has("quiesced-rooted-backends"))] as $reports |
            ($inventory | map(select(has("return"))) | .[-1].return) as $inventory_report |
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
              "writable-backends",
              "writable-rooted-backends"
            ] and
            $report."schema-version" == 3 and
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
            $report.complete == true and
            $report."backend-count" == $inventory_report."backend-count" and
            $report."rooted-backends" == $inventory_report."rooted-backends" and
            $report."writable-backends" == $inventory_report."writable-backends" and
            $report."writable-rooted-backends" ==
              ([ $inventory_report.backends[] |
                 select(."root-present" and ."write-permission") ] | length) and
            $report."quiesced-rooted-backends" >= 0 and
            $report."quiesced-rooted-backends" <= $report."rooted-backends" and
            $report."in-flight" == $inventory_report."in-flight" and
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
              "state-dump",
              "teardown-worker",
              "wake-fd",
              "whitebox",
              "worker-mask"
            ] and
            $report == {
              "schema-version": 2,
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
              "state-dump": false,
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
            '{"exec-oob":"crucible-hot-fork-bh-timer-barrier","arguments":{"action":"query"}}' \
            "$out/bh-timer-barrier-query.json"
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
            $report."schema-version" == 2 and
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
          ' "$out/bh-timer-barrier-query.json" >/dev/null \
            || { cat "$out/bh-timer-barrier-query.json" >&2; fail "QEMU released bottom-half/timer barrier state was not exact and stable"; }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-bh-timer-barrier","arguments":{"action":"hold"}}' \
            "$out/bh-timer-barrier-hold.json"
          jq -e -s 'any(.[]; has("error"))' "$out/bh-timer-barrier-hold.json" >/dev/null \
            || { cat "$out/bh-timer-barrier-hold.json" >&2; fail "QEMU held the bottom-half/timer barrier outside the exact boundary"; }
          qmp "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-bh-timer-barrier","arguments":{"action":"query"}}' \
            "$out/bh-timer-barrier-after-rejection.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return as $report |
            $report.generation == 0 and
            $report."owner-thread-id" == 0 and
            $report.held == false and
            $report.quiescent == false
          ' "$out/bh-timer-barrier-after-rejection.json" >/dev/null \
            || { cat "$out/bh-timer-barrier-after-rejection.json" >&2; fail "QEMU retained bottom-half/timer barrier state after a rejected hold"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"crucible-hot-fork-template","arguments":{"action":"query"}}' \
            "$out/template-coordinator-query.json"
          jq -e -s \
            --slurpfile bh "$out/bh-timer-barrier-query.json" \
            --slurpfile block "$out/block-barrier-query.json" '
            [.[] | select(has("return")) | .return |
             select(has("transaction-active"))] as $reports |
            ($bh | map(select(has("return"))) | .[-1].return) as $bh_report |
            ($block | map(select(has("return"))) | .[-1].return) as $block_report |
            ($reports | length) == 2 and $reports[0] == $reports[1] and
            ($reports[0] as $report |
            ($report | keys | sort) == [
              "acknowledged-proofs",
              "bh-timer-barrier",
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
            $report."schema-version" == 18 and
            $report.generation == 0 and
            $report.outcome == "idle" and
            $report."transaction-active" == false and
            $report."required-proofs" == 511 and
            $report."acknowledged-proofs" == 3 and
            $report."missing-proofs" == 508 and
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
            $report."bh-timer-barrier" == $bh_report and
            $report."block-barrier" == $block_report and
            $report."resource-stage" == {
              "schema-version": 8,
              "template-generation": 0,
              "private-ring-staged": false,
              "private-ring-generation": 2,
              "diagnostics-staged": false,
              "diagnostic-generation": 0,
              "diagnostics-resource-plan-bound": false,
              "qmp-staged": false,
              "qmp-generation": 0,
              "qmp-resource-plan-bound": false,
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
            || { cat "$out/template-coordinator-query.json" >&2; fail "QEMU template coordinator idle state was not exact and stable"; }
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
            $reports[0]."bh-timer-barrier".held == false and
            $reports[0]."block-barrier".held == false
          ' "$out/template-coordinator-after-rejection.json" >/dev/null \
            || { cat "$out/template-coordinator-after-rejection.json" >&2; fail "QEMU retained state after rejecting template preparation"; }

          qmp_pair "$patched_socket" \
            '{"exec-oob":"query-crucible-hot-fork-bottom-half-inventory"}' \
            "$out/bottom-half-inventory.json"
          jq -e -s --slurpfile aio "$out/aio-inventory-1.json" '
            [.[] | select(has("return"))][-1].return as $report |
            ($aio | map(select(has("return"))) | .[-1].return) as $aio_report |
            ($report | keys | sort) == [
              "active-callbacks",
              "bottom-half-count",
              "bottom-halves",
              "complete",
              "deleted-bottom-halves",
              "generation",
              "overflowed",
              "pending-bottom-halves",
              "scheduled-bottom-halves",
              "schema-version",
              "stable"
            ] and
            $report."schema-version" == 1 and
            ($report.generation | type) == "number" and
            ($report.complete | type) == "boolean" and
            ($report.overflowed | type) == "boolean" and
            ($report.stable | type) == "boolean" and
            ($report."bottom-halves" | type) == "array" and
            ($report."bottom-halves" | length) > 0 and
            ($report."bottom-halves" | length) <= 65536 and
            ($report."bottom-halves" | length) == $report."bottom-half-count" and
            ([ $report."bottom-halves"[]."bottom-half-id" ] ==
             ([ $report."bottom-halves"[]."bottom-half-id" ] | sort)) and
            ([ $report."bottom-halves"[]."bottom-half-id" ] | unique | length) ==
              ($report."bottom-halves" | length) and
            all($report."bottom-halves"[];
              (. | keys | sort) == [
                "active-callbacks",
                "bottom-half-id",
                "context-id",
                "deleted",
                "idle",
                "name",
                "name-valid",
                "oneshot",
                "pending",
                "scheduled"
              ] and
              (."bottom-half-id" | type) == "number" and ."bottom-half-id" > 0 and
              (."context-id" | type) == "number" and ."context-id" > 0 and
              (.name | type) == "string" and (.name | length) > 0 and
              (.name | length) <= 128 and
              (."name-valid" | type) == "boolean" and
              (.pending | type) == "boolean" and
              (.scheduled | type) == "boolean" and
              (.deleted | type) == "boolean" and
              (.oneshot | type) == "boolean" and
              (.idle | type) == "boolean" and
              (."active-callbacks" | type) == "number" and
              ."active-callbacks" >= 0 and
              (((.scheduled or .idle) | not) or .pending) and
              (."context-id" as $context_id |
               any($aio_report.contexts[]; ."context-id" == $context_id))) and
            ([ $report."bottom-halves"[] | select(.pending) ] | length) ==
              $report."pending-bottom-halves" and
            ([ $report."bottom-halves"[] | select(.scheduled) ] | length) ==
              $report."scheduled-bottom-halves" and
            ([ $report."bottom-halves"[] | select(.deleted) ] | length) ==
              $report."deleted-bottom-halves" and
            (([ $report."bottom-halves"[]."active-callbacks" ] | add) // 0) ==
              $report."active-callbacks" and
            $report.complete ==
              (($report.overflowed | not) and $report.stable and
               all($report."bottom-halves"[]; ."name-valid"))
          ' "$out/bottom-half-inventory.json" >/dev/null \
            || { cat "$out/bottom-half-inventory.json" >&2; fail "QEMU bottom-half inventory was not exact or AioContext-bound"; }
          jq -e -s '
            [.[] | select(has("return")) | .return |
             select(has("bottom-halves"))] as $reports |
            ($reports | length) == 2 and $reports[0] == $reports[1]
          ' "$out/bottom-half-inventory.json" >/dev/null \
            || { cat "$out/bottom-half-inventory.json" >&2; fail "QEMU bottom-half inventory changed without a lifecycle or state transition"; }

          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-mutex-inventory"}' \
            "$out/mutex-inventory-1.json"
          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-mutex-inventory"}' \
            "$out/mutex-inventory-2.json"
          jq -e -s --slurpfile threads "$out/thread-inventory-1.json" '
            [.[] | select(has("return"))][-1].return as $report |
            ($threads | map(select(has("return"))) | .[-1].return) as $thread_report |
            ($report | keys | sort) == [
              "acquisition-waiters",
              "complete",
              "condition-waiters",
              "generation",
              "invalid-mutexes",
              "mutex-count",
              "mutexes",
              "overflowed",
              "owned-mutexes",
              "recursive-mutexes",
              "schema-version",
              "unlock-transitions"
            ] and
            $report."schema-version" == 1 and
            ($report.generation | type) == "number" and
            ($report.complete | type) == "boolean" and
            ($report.overflowed | type) == "boolean" and
            ($report.mutexes | type) == "array" and
            ($report.mutexes | length) > 0 and
            ($report.mutexes | length) <= 65536 and
            ($report.mutexes | length) == $report."mutex-count" and
            ([ $report.mutexes[]."mutex-id" ] ==
             ([ $report.mutexes[]."mutex-id" ] | sort)) and
            ([ $report.mutexes[]."mutex-id" ] | unique | length) ==
              ($report.mutexes | length) and
            all($report.mutexes[];
              (. | keys | sort) == [
                "acquisition-waiters",
                "condition-waiters",
                "mutex-id",
                "owner-thread-id",
                "ownership-valid",
                "recursion-depth",
                "recursive",
                "unlock-active"
              ] and
              (."mutex-id" | type) == "number" and ."mutex-id" > 0 and
              (."owner-thread-id" | type) == "number" and ."owner-thread-id" >= 0 and
              (."recursion-depth" | type) == "number" and ."recursion-depth" >= 0 and
              (."acquisition-waiters" | type) == "number" and ."acquisition-waiters" >= 0 and
              (."condition-waiters" | type) == "number" and ."condition-waiters" >= 0 and
              (.recursive | type) == "boolean" and
              (."unlock-active" | type) == "boolean" and
              (."ownership-valid" | type) == "boolean" and
              ((."owner-thread-id" > 0) == (."recursion-depth" > 0)) and
              (.recursive or ."recursion-depth" <= 1)) and
            ([ $report.mutexes[] | select(.recursive) ] | length) ==
              $report."recursive-mutexes" and
            ([ $report.mutexes[] | select(."owner-thread-id" > 0) ] | length) ==
              $report."owned-mutexes" and
            (([ $report.mutexes[]."acquisition-waiters" ] | add) // 0) ==
              $report."acquisition-waiters" and
            (([ $report.mutexes[]."condition-waiters" ] | add) // 0) ==
              $report."condition-waiters" and
            ([ $report.mutexes[] | select(."unlock-active") ] | length) ==
              $report."unlock-transitions" and
            ([ $report.mutexes[] | select(."ownership-valid" | not) ] | length) ==
              $report."invalid-mutexes" and
            all($report.mutexes[] | select(."owner-thread-id" > 0);
              ."owner-thread-id" as $owner_tid |
              any($thread_report.threads[]; ."thread-id" == $owner_tid)) and
            $report.complete ==
              (($report.overflowed | not) and $report."invalid-mutexes" == 0)
          ' "$out/mutex-inventory-1.json" >/dev/null \
            || { cat "$out/mutex-inventory-1.json" >&2; fail "QEMU mutex inventory was not exact or thread-bound"; }
          jq -e -s --slurpfile first "$out/mutex-inventory-1.json" '
            [.[] | select(has("return"))][-1].return ==
              ($first | map(select(has("return"))) | .[-1].return)
          ' "$out/mutex-inventory-2.json" >/dev/null \
            || { cat "$out/mutex-inventory-1.json" >&2; cat "$out/mutex-inventory-2.json" >&2; fail "QEMU mutex inventory changed without a lifecycle or ownership transition"; }

          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-timer-inventory"}' \
            "$out/timer-inventory-1.json"
          qmp "$patched_socket" \
            '{"execute":"query-crucible-hot-fork-timer-inventory"}' \
            "$out/timer-inventory-2.json"
          jq -e -s '
            [.[] | select(has("return"))][-1].return as $report |
            ($report | keys | sort) == [
              "active-callbacks",
              "complete",
              "generation",
              "overflowed",
              "pending-timers",
              "schema-version",
              "timer-count",
              "timers"
            ] and
            $report."schema-version" == 1 and
            ($report.generation | type) == "number" and
            ($report.complete | type) == "boolean" and
            ($report.overflowed | type) == "boolean" and
            ($report.timers | type) == "array" and
            ($report.timers | length) <= 65536 and
            ($report.timers | length) == $report."timer-count" and
            ([ $report.timers[]."timer-id" ] ==
             ([ $report.timers[]."timer-id" ] | sort)) and
            ([ $report.timers[]."timer-id" ] | unique | length) ==
              ($report.timers | length) and
            all($report.timers[];
              (. | keys | sort) == [
                "attributes",
                "callback-active",
                "clock",
                "expire-time-ns",
                "pending",
                "scale",
                "timer-id",
                "timer-list-id"
              ] and
              (."timer-id" | type) == "number" and ."timer-id" > 0 and
              (."timer-list-id" | type) == "number" and ."timer-list-id" > 0 and
              (.clock == "realtime" or .clock == "virtual" or
               .clock == "host" or .clock == "virtual-realtime") and
              (."expire-time-ns" | type) == "number" and ."expire-time-ns" >= -1 and
              (.scale | type) == "number" and .scale > 0 and
              (.attributes | type) == "number" and .attributes >= 0 and
              (.pending | type) == "boolean" and
              (."callback-active" | type) == "boolean" and
              (.pending or ."callback-active") and
              (.pending == (."expire-time-ns" >= 0))) and
            ([ $report.timers[] | select(.pending) ] | length) ==
              $report."pending-timers" and
            ([ $report.timers[] | select(."callback-active") ] | length) ==
              $report."active-callbacks" and
            $report.complete == ($report.overflowed | not)
          ' "$out/timer-inventory-1.json" >/dev/null \
            || { cat "$out/timer-inventory-1.json" >&2; fail "QEMU timer inventory was not exact"; }
          jq -e -s --slurpfile first "$out/timer-inventory-1.json" '
            [.[] | select(has("return"))][-1].return ==
              ($first | map(select(has("return"))) | .[-1].return)
          ' "$out/timer-inventory-2.json" >/dev/null \
            || { cat "$out/timer-inventory-1.json" >&2; cat "$out/timer-inventory-2.json" >&2; fail "QEMU timer inventory changed without a pending or callback transition"; }

          qmp "$patched_socket" '{"execute":"quit"}' "$out/patched-quit.json"
          wait "$qemu_pid"
          qemu_pid=""

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${taskList}
          gate=gate:hot-fork-readiness
          patch=0145-crucible-exclude-source-rings-from-fork-children.patch
          patch=0146-crucible-register-hot-fork-child-runtime.patch
          patch=0147-crucible-bind-hot-fork-child-process-generation.patch
          patch=0148-crucible-expose-hot-fork-child-runtime-state.patch
          patch=0149-crucible-bind-hot-fork-endpoint-replacement-slots.patch
          patch=0150-crucible-add-fork-child-endpoint-replacement-primitive.patch
          patch=0151-crucible-authenticate-immediate-hot-fork-children.patch
          patch=0152-crucible-acknowledge-frozen-hot-fork-plugin-rings.patch
          patch=0153-crucible-close-inherited-child-descriptor-tables.patch
          patch=0154-crucible-close-fork-child-descriptor-admission.patch
          patch=0155-crucible-verify-fork-child-mapping-dispositions.patch
          patch=0156-crucible-authenticate-fork-child-shared-mapping-backings.patch
          patch=0157-crucible-compose-fork-child-resource-disposition.patch
          patch=0158-crucible-bind-hot-fork-source-mappings.patch
          patch=0159-crucible-bind-child-runtime-source-mappings.patch
          patch=0160-crucible-compose-registered-fork-child-runtime.patch
          patch=0161-crucible-bind-retained-plugin-child-plan.patch
          patch=0162-crucible-bind-plugin-child-resource-tables.patch
          patch=0163-crucible-compose-child-resource-contributions.patch
          patch=0164-crucible-consume-sealed-child-resource-plans.patch
          patch=0165-crucible-compose-child-descriptor-replacements.patch
          patch=0166-crucible-bind-branch-private-child-diagnostics.patch
          patch=0167-crucible-retain-branch-private-child-qmp.patch
          patch=0168-crucible-bind-child-qmp-reinitializer.patch
          plugin_endpoint_schema_version=4
          plugin_endpoint_source_descriptors_observed=true
          plugin_endpoint_replacement_plan_bound=false
          child_diagnostics_schema_version=1
          child_diagnostics_initially_absent=true
          child_qmp_schema_version=2
          child_qmp_initially_absent=true
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
          rcu_barrier_schema_version=1
          rcu_barrier_released_stable=true
          rcu_barrier_hold_without_exact_boundary_rejected=true
          rcu_barrier_quiescence_proof_bound=true
          bh_timer_barrier_schema_version=2
          bh_timer_barrier_released_stable=true
          bh_timer_barrier_hold_without_exact_boundary_rejected=true
          bh_timer_barrier_template_bound=true
          aio_inventory_schema_version=1
          aio_inventory_bound=65536
          aio_inventory_stable=true
          aio_contexts_thread_bound=true
          aio_proof_acknowledged=false
          aio_handler_inventory_schema_version=1
          aio_handler_inventory_bound=65536
          aio_handler_inventory_stable=true
          aio_handlers_context_bound=true
          aio_handlers_descriptor_bound=true
          block_backend_inventory_schema_version=1
          block_backend_inventory_bound=65536
          block_backend_inventory_stable=true
          block_backends_context_bound=true
          block_backends_vmstate_observed=true
          block_barrier_schema_version=3
          block_barrier_released_stable=true
          block_barrier_hold_without_exact_boundary_rejected=true
          block_graph_writer_admission_retained=true
          block_graph_generation_bound=true
          block_snapshot_proof_acknowledged=false
          block_snapshot_binding_argument_bound=true
          block_barrier_template_bound=true
          plugin_resource_inventory_schema_version=2
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
          template_coordinator_schema_version=18
          plugin_child_plan_report_bound=true
          plugin_child_resource_plan_report_bound=true
          child_resource_contribution_composition=true
          sealed_child_resource_plan_application=true
          child_descriptor_replacement_composition=true
          template_resource_stage_schema_version=8
          template_worker_disposition_bound=false
          template_resource_stage_empty_after_release=true
          template_coordinator_idle_stable=true
          template_coordinator_unregistered_shape=true
          template_prepare_without_exact_boundary_rejected=true
          template_transaction_active=false
          template_ready=false
          bottom_half_inventory_schema_version=1
          bottom_half_inventory_bound=65536
          bottom_half_inventory_stable=true
          bottom_half_inventory_exact=true
          bottom_half_contexts_aio_bound=true
          bottom_half_proof_acknowledged=false
          mutex_inventory_schema_version=1
          mutex_inventory_bound=65536
          mutex_inventory_stable=true
          mutex_owners_thread_bound=true
          mutex_proof_acknowledged=false
          timer_inventory_schema_version=1
          timer_inventory_bound=65536
          timer_inventory_stable=true
          timer_inventory_exact=true
          timer_proof_acknowledged=false
          incomplete_report_ready=false
          stock_commands_absent=true
          RESULT
        '';
      }
    ];
  }
