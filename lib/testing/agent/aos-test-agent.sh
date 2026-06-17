#!/bin/sh
# See agent-handler for the wire format (v2). LC_ALL=C: byte-
# counting parameter expansions and locale-independent printf.
#
# virtio-serial mode: $AGENT_PORT is opened ONCE on fd 3 and held
# open for the whole run — the driver (aos-test-driver, qemu
# transport) holds a single persistent connection, so the link
# never tears down between requests and the self-delimiting frame
# format streams any number of request/response pairs over it.
#
# This must NOT reopen the port per request. A close+reopen on
# every request races QEMU's virtio-serial control-queue port
# state machine: under KVM the close and reopen land within
# microseconds and QEMU can be left believing the guest port is
# closed while the agent sits blocked in read(), so the next
# command's bytes are never delivered and the agent goes silent
# mid-run. fd 3 is reopened only on a genuine EOF (host gone).
LC_ALL=C
export LC_ALL
set -u
# Test disks populate the FHS dirs (and /usr/local/bin wrappers must
# shadow everything), so those come first; the inherited PATH is kept
# as a fallback for image-boot machines, where there is no merged
# /usr/bin and the exposed aos-test-agent package unit provides the
# tool paths via Environment= (pkgs/tests/aos-test-agent.nix).
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

MAX=$((16 * 1024 * 1024))

AGENT_PORT=""
echo "aos-test-agent: probing transports..." >&2
TRIES=0
while [ -z "$AGENT_PORT" ] && [ "$TRIES" -lt 30 ]; do
  if [ -e "/dev/virtio-ports/aos.test.agent" ]; then
    AGENT_PORT="/dev/virtio-ports/aos.test.agent"
    break
  fi
  if [ -e "/dev/vport0p1" ]; then
    AGENT_PORT="/dev/vport0p1"
    break
  fi
  TRIES=$((TRIES + 1))
  sleep 0.1
done

if [ -z "$AGENT_PORT" ] && [ -e /dev/vsock ]; then
  # vsock mode (Firecracker) — listen on port 52; each host CONNECT
  # spawns a new agent-handler via socat EXEC.
  echo "aos-test-agent: vsock mode, listening on port 52" >&2
  exec socat VSOCK-LISTEN:52,reuseaddr,fork EXEC:/opt/aos-test/bin/agent-handler
fi

if [ -z "$AGENT_PORT" ]; then
  echo "aos-test-agent: no transport found (no virtio port, no /dev/vsock)" >&2
  ls /dev/vport* 2>&1 >&2 || true
  ls /dev/virtio-ports/ 2>&1 >&2 || true
  exit 1
fi
echo "aos-test-agent: virtio-serial mode, using port $AGENT_PORT" >&2

# Open the port once and hold it open for the whole run. See the
# header comment: reopening per request races QEMU's virtio-serial
# port state machine under KVM and wedges the agent mid-run.
exec 3<> "$AGENT_PORT"

while true; do
  if ! IFS= read -r len_line <&3; then
    # EOF on fd 3: the host disconnected — end of run, or the
    # driver tore the connection down after an error. Reopen and
    # wait for a fresh connection rather than spinning on EOF.
    exec 3<&-
    sleep 0.1
    exec 3<> "$AGENT_PORT"
    continue
  fi
  case "$len_line" in
    ''|*[!0-9]*)
      echo "aos-test-agent: malformed length line: '$len_line'" >&2
      continue
      ;;
  esac
  if [ "$len_line" -gt "$MAX" ]; then
    echo "aos-test-agent: request length $len_line exceeds $MAX" >&2
    continue
  fi

  head -c "$len_line" <&3 > /tmp/agent-cmd
  actual=$(stat -c %s /tmp/agent-cmd)
  if [ "$actual" -ne "$len_line" ]; then
    echo "aos-test-agent: short read ($actual / $len_line)" >&2
    continue
  fi

  cmd=$(cat /tmp/agent-cmd)
  echo "aos-test-agent: received ($len_line bytes)" >&2

  if [ "$cmd" = "PING" ]; then
    # Body is `0 0 0\n` (6 bytes); outer frame `6\n0 0 0\n`.
    printf '6\n0 0 0\n' >&3
    echo "aos-test-agent: replied (PING)" >&2
    continue
  fi
  if [ "$cmd" = "SHUTDOWN" ]; then
    printf '6\n0 0 0\n' >&3
    poweroff -f
    exit 0
  fi

  mirror_and_capture() {
    pipe="$1"
    output="$2"
    if [ -c /dev/console ]; then
      tee "$output" < "$pipe" > /dev/console
    else
      cat < "$pipe" > "$output"
    fi
  }

  rm -f /tmp/agent-stdout /tmp/agent-stderr \
    /tmp/agent-stdout.pipe /tmp/agent-stderr.pipe
  mkfifo /tmp/agent-stdout.pipe /tmp/agent-stderr.pipe
  mirror_and_capture /tmp/agent-stdout.pipe /tmp/agent-stdout &
  stdout_mirror=$!
  mirror_and_capture /tmp/agent-stderr.pipe /tmp/agent-stderr &
  stderr_mirror=$!

  # 3<&- closes the virtio-serial port in the command's process
  # tree — no apm/git/nix-store child inherits the transport fd.
  bash /tmp/agent-cmd >/tmp/agent-stdout.pipe 2>/tmp/agent-stderr.pipe 3<&-
  exit_code=$?
  wait "$stdout_mirror" 2>/dev/null || true
  wait "$stderr_mirror" 2>/dev/null || true
  rm -f /tmp/agent-stdout.pipe /tmp/agent-stderr.pipe

  stdout_size=$(stat -c %s /tmp/agent-stdout)
  stderr_size=$(stat -c %s /tmp/agent-stderr)
  header="$exit_code $stdout_size $stderr_size"
  # +1 for the newline terminating the header line.
  total=$(( ${#header} + 1 + stdout_size + stderr_size ))
  # Stage the entire frame (outer length + body) in one file then
  # emit it with a single `cat` to fd 3 — keeps the framed write
  # atomic from the agent's side regardless of payload size.
  {
    printf '%d\n' "$total"
    printf '%s\n' "$header"
    cat /tmp/agent-stdout
    cat /tmp/agent-stderr
  } > /tmp/agent-frame
  cat /tmp/agent-frame >&3
  echo "aos-test-agent: replied ($total bytes, exit $exit_code)" >&2
done
