# Invoke through the packaged `crucible-debugger-live-matrix` wrapper. This file
# deliberately has no host-shell shebang; the wrapper supplies the AOS-built bash.

set -euo pipefail

: "${CRUCIBLE_MATRIX_CRUCIBLE:?packaged Crucible path is required}"
: "${CRUCIBLE_MATRIX_GDB:?packaged GDB path is required}"
: "${CRUCIBLE_MATRIX_SSH:?packaged SSH path is required}"
: "${CRUCIBLE_MATRIX_FIXTURE_GENERATOR:?packaged fixture generator is required}"
: "${CRUCIBLE_MATRIX_BUILD_INFO:?packaged build information is required}"
: "${CRUCIBLE_MATRIX_SUPPORTED_ARCHITECTURES:?supported architectures are required}"
: "${CRUCIBLE_MATRIX_DOORBELL_INSTRUCTION_ABI_VERSION:?doorbell instruction ABI version is required}"
[[ "$CRUCIBLE_MATRIX_DOORBELL_INSTRUCTION_ABI_VERSION" == 4 ]] || {
  printf 'unsupported packaged doorbell instruction ABI: %s (expected 4)\n' \
    "$CRUCIBLE_MATRIX_DOORBELL_INSTRUCTION_ABI_VERSION" >&2
  exit 64
}

available_architectures=$CRUCIBLE_MATRIX_SUPPORTED_ARCHITECTURES
external_aarch64_kernel=${CRUCIBLE_MATRIX_EXTERNAL_KERNEL_AARCH64:-}
external_aarch64_root=${CRUCIBLE_MATRIX_EXTERNAL_ROOT_IMAGE_AARCH64:-}
external_aarch64_cmdline=${CRUCIBLE_MATRIX_EXTERNAL_KERNEL_CMDLINE_AARCH64:-}
external_aarch64_doorbell_abi=${CRUCIBLE_MATRIX_EXTERNAL_DOORBELL_INSTRUCTION_ABI_AARCH64:-}
if [[ -n "$external_aarch64_kernel" || -n "$external_aarch64_root" || -n "$external_aarch64_cmdline" || -n "$external_aarch64_doorbell_abi" ]]; then
  [[ -n "$external_aarch64_kernel" && -n "$external_aarch64_root" && -n "$external_aarch64_cmdline" && -n "$external_aarch64_doorbell_abi" ]] \
    || { printf 'external AArch64 kernel, root image, kernel command line, and doorbell ABI must be supplied together\n' >&2; exit 64; }
  [[ "$external_aarch64_doorbell_abi" == "$CRUCIBLE_MATRIX_DOORBELL_INSTRUCTION_ABI_VERSION" ]] \
    || { printf 'external AArch64 doorbell ABI %s does not match packaged ABI %s\n' "$external_aarch64_doorbell_abi" "$CRUCIBLE_MATRIX_DOORBELL_INSTRUCTION_ABI_VERSION" >&2; exit 64; }
  CRUCIBLE_MATRIX_KERNEL_AARCH64=$external_aarch64_kernel
  CRUCIBLE_MATRIX_ROOT_IMAGE_AARCH64=$external_aarch64_root
  export CRUCIBLE_KERNEL_AARCH64=$external_aarch64_kernel
  export CRUCIBLE_ROOT_IMAGE_AARCH64=$external_aarch64_root
  export CRUCIBLE_KERNEL_CMDLINE_AARCH64=$external_aarch64_cmdline
  if [[ ",$available_architectures," != *,aarch64,* ]]; then
    available_architectures="$available_architectures,aarch64"
  fi
fi

case ",$available_architectures," in
  *,x86_64,aarch64,*) default_architecture=all ;;
  *,x86_64,*) default_architecture=x86_64 ;;
  *,aarch64,*) default_architecture=aarch64 ;;
  *)
    printf 'packaged debugger matrix has no supported architecture\n' >&2
    exit 70
    ;;
esac

architecture=$default_architecture
output=
base_port=${CRUCIBLE_MATRIX_BASE_PORT:-39870}
stage_timeout_seconds=${CRUCIBLE_MATRIX_STAGE_TIMEOUT_SECONDS:-180}
rendezvous_icount=${CRUCIBLE_MATRIX_RENDEZVOUS_ICOUNT:-5000000}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --architecture)
      architecture=${2:?--architecture requires x86_64, aarch64, or all}
      shift 2
      ;;
    --output)
      output=${2:?--output requires a new directory}
      shift 2
      ;;
    --help)
      printf '%s\n' \
        'usage: crucible-debugger-live-matrix [--architecture x86_64|aarch64|all] [--output NEW-DIR]'
      printf 'available architectures: %s\n' "$available_architectures"
      printf 'packaged architectures: %s\n' "$CRUCIBLE_MATRIX_SUPPORTED_ARCHITECTURES"
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      exit 64
      ;;
  esac
done
case "$architecture" in
  x86_64)
    [[ ",$available_architectures," == *,x86_64,* ]] \
      || { printf 'x86_64 guest assets are unavailable\n' >&2; exit 64; }
    selected_architectures=x86_64
    ;;
  aarch64)
    [[ ",$available_architectures," == *,aarch64,* ]] \
      || { printf 'aarch64 guest assets are unavailable\n' >&2; exit 64; }
    selected_architectures=aarch64
    ;;
  all)
    [[ "$available_architectures" == x86_64,aarch64 ]] \
      || { printf 'the complete matrix requires x86_64 and aarch64 guest assets\n' >&2; exit 64; }
    selected_architectures='x86_64 aarch64'
    ;;
  *)
    printf 'unsupported architecture: %s\n' "$architecture" >&2
    exit 64
    ;;
esac
[[ "$base_port" =~ ^[0-9]+$ ]] || { printf 'base port must be numeric\n' >&2; exit 64; }
[[ "$stage_timeout_seconds" =~ ^[1-9][0-9]*$ ]] \
  || { printf 'stage timeout must be a positive integer\n' >&2; exit 64; }
[[ "$rendezvous_icount" =~ ^[1-9][0-9]*$ ]] \
  || { printf 'rendezvous icount must be a positive integer\n' >&2; exit 64; }

if [[ -n "$output" && ! "$output" =~ ^[A-Za-z0-9_./-]+$ ]]; then
  printf 'output path contains characters unsafe for GDB command files: %s\n' "$output" >&2
  exit 64
fi
if [[ -z "$output" ]]; then
  temporary_root=${TMPDIR:-/tmp}
  [[ "$temporary_root" =~ ^[A-Za-z0-9_./-]+$ ]] \
    || { printf 'TMPDIR contains characters unsafe for GDB command files\n' >&2; exit 64; }
  output=$(mktemp -d "$temporary_root/crucible-debugger-live-matrix.XXXXXX")
elif [[ -e "$output" ]]; then
  printf 'output path already exists: %s\n' "$output" >&2
  exit 64
else
  mkdir -p "$output"
fi
[[ "$output" =~ ^[A-Za-z0-9_./-]+$ ]] \
  || { printf 'final output path is unsafe for GDB command files\n' >&2; exit 64; }
cp "$CRUCIBLE_MATRIX_BUILD_INFO" "$output/crucible-build-info"
printf 'crucible debugger live evidence: %s\n' "$output"

daemon_pid=
run_pid=
relay_pid=
gdb_pid=
channel_pid=
gdb_probe_writer_pid=
run_fd_open=false
gdb_fd_open=false
channel_fd_open=false
progress_file="$output/progress.log"

progress() {
  printf 'stage=%s\n' "$*" | tee -a "$progress_file" >&2
}

terminate_group() {
  local process_id=$1
  local attempts=0
  [[ -n "$process_id" ]] || return 0
  if kill -0 "$process_id" 2>/dev/null || kill -0 -- "-$process_id" 2>/dev/null; then
    kill -TERM -- "-$process_id" 2>/dev/null || kill -TERM "$process_id" 2>/dev/null || true
  fi
  while kill -0 "$process_id" 2>/dev/null || kill -0 -- "-$process_id" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [[ $attempts -ge 50 ]]; then
      kill -KILL -- "-$process_id" 2>/dev/null || kill -KILL "$process_id" 2>/dev/null || true
      break
    fi
    sleep 0.1
  done
  kill -KILL -- "-$process_id" 2>/dev/null || true
  wait "$process_id" 2>/dev/null || true
}

cleanup_processes() {
  if [[ "$channel_fd_open" == true ]]; then exec 4>&- || true; channel_fd_open=false; fi
  if [[ "$gdb_fd_open" == true ]]; then exec 5>&- || true; gdb_fd_open=false; fi
  if [[ "$run_fd_open" == true ]]; then exec 3>&- || true; run_fd_open=false; fi
  if [[ -n "$gdb_probe_writer_pid" ]]; then
    kill -TERM "$gdb_probe_writer_pid" 2>/dev/null || true
    wait "$gdb_probe_writer_pid" 2>/dev/null || true
    gdb_probe_writer_pid=
  fi
  terminate_group "$channel_pid"
  terminate_group "$gdb_pid"
  terminate_group "$relay_pid"
  terminate_group "$run_pid"
  terminate_group "$daemon_pid"
}
trap cleanup_processes EXIT

fail() {
  printf 'live debugger matrix failed: %s\n' "$*" >&2
  exit 1
}

wait_for_pattern() {
  local file=$1
  local pattern=$2
  local process_id=$3
  local attempts=0
  local maximum_attempts=$((stage_timeout_seconds * 10))
  until grep -Fq "$pattern" "$file" 2>/dev/null; do
    if ! kill -0 "$process_id" 2>/dev/null; then
      fail "process $process_id exited before '$pattern' appeared in $file"
    fi
    attempts=$((attempts + 1))
    [[ $attempts -le $maximum_attempts ]] \
      || fail "timed out after ${stage_timeout_seconds}s waiting for '$pattern' in $file"
    sleep 0.1
  done
}

wait_for_count() {
  local file=$1
  local pattern=$2
  local expected=$3
  local process_id=$4
  local diagnostic_file=${5:-}
  local attempts=0
  local maximum_attempts=$((stage_timeout_seconds * 10))
  while [[ $(grep -Fc "$pattern" "$file" 2>/dev/null || true) -lt $expected ]]; do
    if ! kill -0 "$process_id" 2>/dev/null; then
      if [[ -n "$diagnostic_file" && -s "$diagnostic_file" ]]; then
        printf 'process diagnostic from %s:\n' "$diagnostic_file" >&2
        sed -n '1,160p' "$diagnostic_file" >&2
      fi
      fail "process $process_id exited before $expected '$pattern' records appeared in $file"
    fi
    attempts=$((attempts + 1))
    [[ $attempts -le $maximum_attempts ]] \
      || fail "timed out after ${stage_timeout_seconds}s waiting for $expected '$pattern' records"
    sleep 0.1
  done
}

wait_for_exit() {
  local process_id=$1
  local attempts=0
  local maximum_attempts=$((stage_timeout_seconds * 10))
  while kill -0 "$process_id" 2>/dev/null; do
    attempts=$((attempts + 1))
    [[ $attempts -le $maximum_attempts ]] \
      || fail "process $process_id did not exit within ${stage_timeout_seconds}s"
    sleep 0.1
  done
  wait "$process_id"
}

field_value() {
  local file=$1
  local field=$2
  sed -n "s/^${field}=//p" "$file" | tail -n 1
}

files_equal() {
  [[ "$(sha256sum <"$1")" == "$(sha256sum <"$2")" ]]
}

landed_tuple() {
  local file=$1
  grep '^landed-' "$file"
}

require_landed_evidence() {
  local file=$1
  local label=$2
  local field
  for field in configuration runtime-state virtual-time schedule-prefix event-log-prefix \
    event-log-bytes event-log-events node-icount.debuggee; do
    [[ -n "$(field_value "$file" "landed-$field")" ]] \
      || fail "$label omitted landed-$field"
  done
  [[ "$(field_value "$file" retired-world-cleanup)" == reaped ]] \
    || fail "$label did not prove retired-world cleanup"
}

debug_command() {
  local endpoint=$1
  local session=$2
  shift 2
  timeout -k 5s "$stage_timeout_seconds" "$CRUCIBLE_MATRIX_CRUCIBLE" \
    --daemon "$endpoint" \
    --trusted-unauthenticated-daemon \
    debug --session "$session" --node debuggee "$@"
}

run_ssh_client() {
  local directory=$1
  local ssh_pid ssh_status
  shift
  if "$CRUCIBLE_MATRIX_SSH" -G -F /dev/null root@crucible-guest >/dev/null 2>&1; then
    setsid timeout -k 5s "$stage_timeout_seconds" "$CRUCIBLE_MATRIX_SSH" "$@" &
    ssh_pid=$!
  else
    # Some remote builders obtain their account through network NSS while the
    # hermetic OpenSSH client reads only /etc/passwd. Give that client a private
    # user/mount namespace with a minimal local identity; the network namespace
    # and the SSH/Crucible transport remain unchanged.
    local passwd_file="$directory/ssh-client.passwd"
    printf 'root:x:0:0:root:/tmp:/bin/false\n' >"$passwd_file"
    setsid timeout -k 5s "$stage_timeout_seconds" \
      unshare --user --map-root-user --mount "$BASH" -c \
        'mount --bind "$1" /etc/passwd; shift; exec "$@"' \
        crucible-ssh-userns "$passwd_file" "$CRUCIBLE_MATRIX_SSH" "$@" &
    ssh_pid=$!
  fi

  if wait "$ssh_pid"; then
    ssh_status=0
  else
    ssh_status=$?
  fi
  # OpenSSH may leave ProxyCommand alive after a bounded remote command exits.
  # Terminate that private process group so its guest channel cannot leak into
  # the following reposition exercise or append an expected closure to ssh.err.
  terminate_group "$ssh_pid"
  return "$ssh_status"
}

gdb_window_is_clean() {
  local file=$1
  local label=$2
  if grep -Eiq \
    'Remote replied unexpectedly|Remote connection closed|Ignoring packet error|Timed out|protocol error|Remote communication error|received: "E[0-9a-f]+"|received: ""|not supported' \
    "$file"; then
    fail "$label observed a GDB/RSP transport error"
  fi
}

gdb_replacement_window_is_stable() {
  local file=$1
  local label=$2
  if grep -Eiq \
    'Remote replied unexpectedly|Remote connection closed|Timed out|protocol error|Remote communication error|received: "E[0-9a-f]+"|received: ""|not supported' \
    "$file"; then
    fail "$label observed a fatal GDB/RSP transport error"
  fi
  local retries
  retries=$(grep -Fc 'Ignoring packet error, continuing...' "$file" || true)
  ((retries <= 1)) || fail "$label required more than one RSP retransmission"
}

start_gdb_replacement_probe() {
  local label=$1
  local begin="CRUCIBLE_REPLACE_${label}_BEGIN"
  local end="CRUCIBLE_REPLACE_${label}_END"
  printf 'echo %s\\n\n' "$begin" >&5
  wait_for_pattern "$gdb_output" "$begin" "$gdb_pid"
  {
    local request expected attempts prior_errors prior_responses
    local baseline
    baseline=$(grep -Ec 'received: "[0-9a-fA-F]{128,}"' "$gdb_output" || true)
    for ((request = 1; request <= 128; request++)); do
      expected=$((baseline + request))
      attempts=0
      while [[ $(grep -Ec 'received: "[0-9a-fA-F]{128,}"' "$gdb_output" || true) -lt $expected ]]; do
        prior_errors=$(grep -Fc 'Ignoring packet error, continuing...' "$gdb_output" || true)
        prior_responses=$(grep -Fc 'received: "' "$gdb_output" || true)
        printf 'maintenance packet g\n'
        while [[ $(grep -Ec 'received: "[0-9a-fA-F]{128,}"' "$gdb_output" || true) -lt $expected ]] \
          && [[ $(grep -Fc 'Ignoring packet error, continuing...' "$gdb_output" || true) -le $prior_errors ]] \
          && [[ $(grep -Fc 'received: "' "$gdb_output" || true) -le $prior_responses ]]; do
          kill -0 "$gdb_pid" 2>/dev/null || exit 1
          attempts=$((attempts + 1))
          [[ $attempts -le $((stage_timeout_seconds * 10)) ]] || exit 1
          sleep 0.1
        done
        kill -0 "$gdb_pid" 2>/dev/null || exit 1
      done
    done
    printf 'echo %s\\n\n' "$end"
  } >&5 &
  gdb_probe_writer_pid=$!
}

finish_gdb_replacement_probe() {
  local label=$1
  local begin="CRUCIBLE_REPLACE_${label}_BEGIN"
  local end="CRUCIBLE_REPLACE_${label}_END"
  wait "$gdb_probe_writer_pid" || fail "$label GDB probe writer failed"
  gdb_probe_writer_pid=
  wait_for_pattern "$gdb_output" "$end" "$gdb_pid"
  sed -n "/$begin/,/$end/p" "$gdb_output" >"$gdb_output.$label"
  gdb_replacement_window_is_stable "$gdb_output.$label" "$label replacement"
  [[ $(grep -Ec 'received: "[0-9a-fA-F]{128,}"' "$gdb_output.$label") -ge 128 ]] \
    || fail "$label replacement barrier did not return sustained valid register payloads"
}

start_relay() {
  local endpoint=$1
  local session=$2
  local port=$3
  local prefix=$4
  setsid "$CRUCIBLE_MATRIX_CRUCIBLE" \
    --daemon "$endpoint" \
    --trusted-unauthenticated-daemon \
    debug --session "$session" --node debuggee \
    --gdb-listen "127.0.0.1:$port" attach-gdb \
    >"$prefix.relay.out" 2>"$prefix.relay.err" &
  relay_pid=$!
  wait_for_pattern "$prefix.relay.out" "remote GDB relay listening at 127.0.0.1:$port" "$relay_pid"
}

start_gdb() {
  local port=$1
  local prefix=$2
  local fifo="$prefix.gdb.in"
  mkfifo "$fifo"
  setsid "$CRUCIBLE_MATRIX_GDB" --nx --quiet \
    <"$fifo" >"$prefix.gdb.out" 2>"$prefix.gdb.err" &
  gdb_pid=$!
  exec 5>"$fifo"
  gdb_fd_open=true
  printf 'set pagination off\nset confirm off\nset remotetimeout %s\ntarget remote 127.0.0.1:%s\n' \
    "$stage_timeout_seconds" "$port" >&5
  printf 'maintenance packet qSupported\necho CRUCIBLE_GDB_CONNECTED\\n\n' >&5
  wait_for_pattern "$prefix.gdb.out" CRUCIBLE_GDB_CONNECTED "$gdb_pid"
  grep -Fq 'received: "PacketSize=' "$prefix.gdb.out" \
    || fail "GDB did not negotiate RSP"
}

gdb_snapshot() {
  local snapshot_file=$1
  local registers=$2
  local marker=$3
  printf 'set logging file %s\n' "$snapshot_file" >&5
  printf 'set logging overwrite on\nset logging redirect on\nset logging enabled on\n' >&5
  printf 'info threads\ninfo registers %s\ninfo breakpoints\n' "$registers" >&5
  printf 'set logging enabled off\necho %s\\n\n' "$marker" >&5
  wait_for_pattern "$gdb_output" "$marker" "$gdb_pid"
  grep -Eq '^\*?[[:space:]]*[0-9]+[[:space:]]' "$snapshot_file" \
    || fail "GDB snapshot omitted thread state"
}

stop_gdb() {
  printf 'disconnect\nquit\n' >&5
  exec 5>&-
  gdb_fd_open=false
  wait_for_exit "$gdb_pid" || fail "GDB exited unsuccessfully"
  gdb_pid=
  wait_for_exit "$relay_pid" || fail "GDB relay exited unsuccessfully"
  relay_pid=
}

run_scheduler_control() {
  local output_file=$1
  local continue_packet_log="$output_file.continue-packets"
  local packet_log="$output_file.stepi-packets"
  printf 'set logging file %s\n' "$continue_packet_log" >&5
  printf 'set logging overwrite on\nset logging debugredirect on\nset logging enabled on\n' >&5
  printf 'set debug remote 1\necho CRUCIBLE_CONTINUE_BEGIN\\n\ncontinue\n' >&5
  wait_for_pattern "$continue_packet_log" 'Sending packet: $vCont;c' "$gdb_pid"
  kill -INT "$gdb_pid"
  wait_for_pattern "$continue_packet_log" 'Packet received: T02' "$gdb_pid"
  printf 'echo CRUCIBLE_CONTINUE_END\\n\n' >&5
  wait_for_pattern "$continue_packet_log" CRUCIBLE_CONTINUE_END "$gdb_pid"
  printf 'set debug remote 0\nset logging enabled off\necho CRUCIBLE_CONTINUE_TRACE_END\\n\n' >&5
  wait_for_pattern "$output_file" CRUCIBLE_CONTINUE_TRACE_END "$gdb_pid"
  sed -n '/CRUCIBLE_CONTINUE_BEGIN/,/CRUCIBLE_CONTINUE_END/p' "$continue_packet_log" \
    >"$output_file.continue"
  gdb_window_is_clean "$output_file.continue" "GDB continue"
  grep -Fq 'vCont;c' "$continue_packet_log" \
    || fail "GDB continue did not use scheduler-mediated vCont;c"
  grep -Eq 'Packet received: T0?2|Packet received: S0?2' "$continue_packet_log" \
    || fail "GDB interrupt produced no correlated scheduler stop"

  printf 'maintenance packet vCont?\necho CRUCIBLE_VCONT_QUERY_END\\n\n' >&5
  wait_for_pattern "$output_file" CRUCIBLE_VCONT_QUERY_END "$gdb_pid"
  grep -Fq 'received: "vCont' "$output_file" || fail "vCont capability was not reported"

  printf 'set logging file %s\n' "$packet_log" >&5
  printf 'set logging overwrite on\nset logging debugredirect on\nset logging enabled on\n' >&5
  printf 'set debug remote 1\necho CRUCIBLE_STEPI_BEGIN\\n\nstepi\necho CRUCIBLE_STEPI_END\\n\n' >&5
  printf 'set debug remote 0\nset logging enabled off\necho CRUCIBLE_STEPI_TRACE_END\\n\n' >&5
  wait_for_pattern "$packet_log" CRUCIBLE_STEPI_END "$gdb_pid"
  wait_for_pattern "$output_file" CRUCIBLE_STEPI_TRACE_END "$gdb_pid"
  sed -n '/CRUCIBLE_STEPI_BEGIN/,/CRUCIBLE_STEPI_END/p' "$packet_log" \
    >"$output_file.stepi"
  gdb_window_is_clean "$output_file.stepi" "GDB stepi"
  grep -Eq '0x[0-9a-f]+|Program received signal' "$output_file.stepi" \
    || fail "GDB stepi produced no correlated stop"
  grep -Fq 'vCont;s' "$packet_log" \
    || fail "GDB stepi did not use scheduler-mediated vCont;s"
  grep -Eq 'Packet received: T0?5|Packet received: S0?5' "$packet_log" \
    || fail "vCont;s produced no correlated scheduler stop"
}

run_architecture() {
  local guest_architecture=$1
  local expected_uname=$2
  local port_offset=$3
  local directory="$output/$guest_architecture"
  local daemon_port=$((base_port + port_offset))
  local relay_port=$((daemon_port + 1))
  local endpoint="http://127.0.0.1:$daemon_port"
  local registers='pc sp x29 x0'
  local kernel root_image kernel_cmdline
  if [[ "$guest_architecture" == x86_64 ]]; then
    registers='rip rsp rbp rax'
    kernel=${CRUCIBLE_MATRIX_KERNEL_X86_64:?x86_64 kernel is not packaged}
    root_image=${CRUCIBLE_MATRIX_ROOT_IMAGE_X86_64:?x86_64 root image is not packaged}
    kernel_cmdline=${CRUCIBLE_MATRIX_KERNEL_CMDLINE_X86_64:?x86_64 kernel command line is not packaged}
  else
    kernel=${CRUCIBLE_MATRIX_KERNEL_AARCH64:?AArch64 kernel is not packaged}
    root_image=${CRUCIBLE_MATRIX_ROOT_IMAGE_AARCH64:?AArch64 root image is not packaged}
    kernel_cmdline=${CRUCIBLE_KERNEL_CMDLINE_AARCH64:?AArch64 kernel command line is not packaged}
  fi
  mkdir -p "$directory"
  local fixture="$directory/scenario.toml"
  progress "$guest_architecture:generate-fixture"
  timeout -k 5s "$stage_timeout_seconds" "$CRUCIBLE_MATRIX_FIXTURE_GENERATOR" \
    "$guest_architecture" "$kernel" "$root_image" "$kernel_cmdline" "$fixture"
  grep '^kernel = "blake3:' "$fixture" >"$directory/asset-identities"
  grep '^root_image = "blake3:' "$fixture" >>"$directory/asset-identities"
  grep '^cmdline = ' "$fixture" >>"$directory/asset-identities"
  printf 'doorbell_instruction_abi=%s\n' \
    "$CRUCIBLE_MATRIX_DOORBELL_INSTRUCTION_ABI_VERSION" >>"$directory/asset-identities"

  progress "$guest_architecture:start-daemon"
  setsid "$CRUCIBLE_MATRIX_CRUCIBLE" serve \
    --listen "127.0.0.1:$daemon_port" \
    --trusted-unauthenticated-bind \
    --production-qemu \
    --qemu-rendezvous-icount "$rendezvous_icount" \
    >"$directory/daemon.out" 2>"$directory/daemon.err" &
  daemon_pid=$!
  wait_for_pattern "$directory/daemon.out" "serving API daemon at $endpoint" "$daemon_pid"

  local fifo="$directory/run.in"
  mkfifo "$fifo"
  setsid "$CRUCIBLE_MATRIX_CRUCIBLE" \
    --daemon "$endpoint" \
    --trusted-unauthenticated-daemon \
    --seed 0x060d \
    --backend qemu \
    --format table \
    run "$fixture" --interactive --max-quanta 768 \
    <"$fifo" >"$directory/run.out" 2>"$directory/run.err" &
  run_pid=$!
  exec 3>"$fifo"
  run_fd_open=true
  wait_for_pattern "$directory/run.err" "crucible: live-session" "$run_pid"
  local session
  session=$(sed -n 's/.*ref=//p' "$directory/run.err" | head -n 1)
  [[ -n "$session" ]] || fail "live session reference was not reported"

  progress "$guest_architecture:build-live-history"
  printf 'query\n' >&3
  for ((step_index = 0; step_index < 64; step_index++)); do
    printf 'step\n' >&3
  done
  printf 'query\n' >&3
  wait_for_count "$directory/run.out" interactive-ack 66 "$run_pid" "$directory/run.err"

  debug_command "$endpoint" "$session" --read-only reverse-step quantum \
    >"$directory/reverse-baseline.out" 2>"$directory/reverse-baseline.err"
  require_landed_evidence "$directory/reverse-baseline.out" "baseline reverse"
  local baseline_events baseline_generation baseline_sequence
  baseline_events=$(field_value "$directory/reverse-baseline.out" landed-event-log-events)
  baseline_generation=$(field_value "$directory/reverse-baseline.out" gateway-generation)
  baseline_sequence=$(field_value "$directory/reverse-baseline.out" target-event-sequence)
  [[ "$baseline_events" =~ ^[1-9][0-9]*$ ]] \
    || fail "baseline reverse history was empty"

  progress "$guest_architecture:attach-stable-gdb"
  start_relay "$endpoint" "$session" "$relay_port" "$directory/stable"
  gdb_output="$directory/stable.gdb.out"
  start_gdb "$relay_port" "$directory/stable"
  # `$pc` is evaluated by GDB, not this shell.
  # shellcheck disable=SC2016
  printf 'hbreak *$pc\necho CRUCIBLE_BREAKPOINT_INSTALLED\\n\n' >&5
  wait_for_pattern "$gdb_output" CRUCIBLE_BREAKPOINT_INSTALLED "$gdb_pid"
  grep -Fq 'Hardware assisted breakpoint 1' "$gdb_output" \
    || fail "architecture-correct hardware breakpoint was not installed"

  gdb_snapshot "$directory/read-only-before.gdb" "$registers" CRUCIBLE_READ_ONLY_BEFORE
  gdb_snapshot "$directory/read-only-after.gdb" "$registers" CRUCIBLE_READ_ONLY_AFTER
  files_equal "$directory/read-only-before.gdb" "$directory/read-only-after.gdb" \
    || fail "read-only GDB inspection changed thread, register, or breakpoint state"

  progress "$guest_architecture:reverse-with-live-gdb"
  start_gdb_replacement_probe REVERSE
  debug_command "$endpoint" "$session" --read-only reverse-step quantum \
    >"$directory/reverse-earlier.out" 2>"$directory/reverse-earlier.err"
  finish_gdb_replacement_probe REVERSE
  require_landed_evidence "$directory/reverse-earlier.out" "earlier reverse"
  local earlier_events earlier_time earlier_generation earlier_sequence
  earlier_events=$(field_value "$directory/reverse-earlier.out" landed-event-log-events)
  earlier_time=$(field_value "$directory/reverse-earlier.out" landed-virtual-time)
  earlier_generation=$(field_value "$directory/reverse-earlier.out" gateway-generation)
  earlier_sequence=$(field_value "$directory/reverse-earlier.out" target-event-sequence)
  [[ "$earlier_events" =~ ^[0-9]+$ ]] || fail "earlier reverse event prefix was invalid"
  ((earlier_events < baseline_events)) || fail "reverse event prefix did not decrease"
  ((earlier_generation > baseline_generation)) || fail "reverse gateway generation did not advance"
  kill -0 "$gdb_pid" 2>/dev/null || fail "GDB connection did not survive reverse replacement"
  gdb_snapshot "$directory/reverse-earlier.gdb" "$registers" CRUCIBLE_REVERSE_EARLIER

  start_gdb_replacement_probe GOTO_EARLIER
  debug_command "$endpoint" "$session" --read-only goto "event:$earlier_sequence" \
    >"$directory/goto-earlier.out" 2>"$directory/goto-earlier.err"
  finish_gdb_replacement_probe GOTO_EARLIER
  require_landed_evidence "$directory/goto-earlier.out" "repeated earlier goto"
  landed_tuple "$directory/reverse-earlier.out" >"$directory/reverse-earlier.tuple"
  landed_tuple "$directory/goto-earlier.out" >"$directory/goto-earlier.tuple"
  files_equal "$directory/reverse-earlier.tuple" "$directory/goto-earlier.tuple" \
    || fail "repeated coordinate did not reproduce the complete landed tuple"
  local repeated_generation
  repeated_generation=$(field_value "$directory/goto-earlier.out" gateway-generation)
  ((repeated_generation > earlier_generation)) \
    || fail "repeated goto gateway generation did not advance"
  gdb_snapshot "$directory/goto-earlier.gdb" "$registers" CRUCIBLE_GOTO_EARLIER
  files_equal "$directory/reverse-earlier.gdb" "$directory/goto-earlier.gdb" \
    || fail "repeated coordinate changed GDB thread/register/breakpoint state"

  start_gdb_replacement_probe GOTO_BASELINE
  debug_command "$endpoint" "$session" --read-only goto "event:$baseline_sequence" \
    >"$directory/goto-baseline.out" 2>"$directory/goto-baseline.err"
  finish_gdb_replacement_probe GOTO_BASELINE
  require_landed_evidence "$directory/goto-baseline.out" "baseline goto"
  landed_tuple "$directory/reverse-baseline.out" >"$directory/reverse-baseline.tuple"
  landed_tuple "$directory/goto-baseline.out" >"$directory/goto-baseline.tuple"
  files_equal "$directory/reverse-baseline.tuple" "$directory/goto-baseline.tuple" \
    || fail "forward replay did not reproduce the baseline landed tuple"
  gdb_snapshot "$directory/goto-baseline.gdb" "$registers" CRUCIBLE_GOTO_BASELINE

  progress "$guest_architecture:fork-and-run-control"
  start_gdb_replacement_probe FORK
  debug_command "$endpoint" "$session" --allow-mutate fork-debug \
    >"$directory/fork-debug.out" 2>"$directory/fork-debug.err"
  finish_gdb_replacement_probe FORK
  grep -Fq 'argv-exec=true pty=true resize=true ssh-bridge=true' "$directory/fork-debug.out" \
    || fail "fork-time guest feature negotiation was incomplete"
  kill -0 "$gdb_pid" 2>/dev/null || fail "GDB connection did not survive fork replacement"
  gdb_snapshot "$directory/post-fork.gdb" "$registers" CRUCIBLE_POST_FORK
  grep -Eq '^1[[:space:]]+hw breakpoint[[:space:]]+keep[[:space:]]+y' "$directory/post-fork.gdb" \
    || fail "hardware breakpoint state was not retained across replacement"
  printf 'delete 1\necho CRUCIBLE_RETAINED_BREAKPOINT_REMOVED\\n\n' >&5
  wait_for_pattern "$gdb_output" CRUCIBLE_RETAINED_BREAKPOINT_REMOVED "$gdb_pid"
  run_scheduler_control "$gdb_output"
  printf 'info breakpoints\necho CRUCIBLE_BREAKPOINT_REMOVED\\n\n' >&5
  wait_for_pattern "$gdb_output" CRUCIBLE_BREAKPOINT_REMOVED "$gdb_pid"
  tail -n 20 "$gdb_output" | grep -Fq 'No breakpoints' \
    || fail "hardware breakpoint removal was not acknowledged"

  progress "$guest_architecture:guest-exec-pty-ssh"
  debug_command "$endpoint" "$session" --allow-mutate \
    --record-transcript "$directory/exec.crgt" --guest-idle-timeout 120s \
    exec -- /bin/uname -m >"$directory/exec.out" 2>"$directory/exec.err"
  grep -Fxq "$expected_uname" "$directory/exec.out" \
    || fail "guest exec reported the wrong architecture"

  printf '' | debug_command "$endpoint" "$session" --allow-mutate \
    --record-transcript "$directory/pty.crgt" --guest-idle-timeout 120s \
    pty --columns 100 --rows 30 -- /bin/sh -c '/bin/echo CRUCIBLE_PTY_OK' \
    >"$directory/pty.out" 2>"$directory/pty.err"
  grep -Fq CRUCIBLE_PTY_OK "$directory/pty.out" || fail "guest PTY output was not preserved"

  local proxy_command
  proxy_command="$CRUCIBLE_MATRIX_CRUCIBLE --daemon $endpoint --trusted-unauthenticated-daemon debug --session $session --node debuggee --allow-mutate --record-transcript $directory/ssh.crgt --guest-idle-timeout 120s ssh"
  run_ssh_client "$directory" -F /dev/null \
    -o BatchMode=yes \
    -o KexAlgorithms=curve25519-sha256 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o "ProxyCommand=$proxy_command" \
    root@crucible-guest /bin/uname -m \
    >"$directory/ssh.out" 2>"$directory/ssh.err"
  grep -Fxq "$expected_uname" "$directory/ssh.out" \
    || fail "guest SSH bridge reported the wrong architecture"
  [[ $(wc -c <"$directory/ssh.crgt") -gt 8 ]] \
    || fail "guest SSH transcript omitted protocol records"

  progress "$guest_architecture:reposition-stream-closure"
  local channel_fifo="$directory/channel.in"
  mkfifo "$channel_fifo"
  setsid "$CRUCIBLE_MATRIX_CRUCIBLE" \
    --daemon "$endpoint" \
    --trusted-unauthenticated-daemon \
    debug --session "$session" --node debuggee --allow-mutate \
    --record-transcript "$directory/reposition-close.crgt" --guest-idle-timeout 180s \
    pty -- /bin/sh -c '/bin/echo CRUCIBLE_CHANNEL_READY; while :; do :; done' \
    <"$channel_fifo" >"$directory/reposition-close.out" 2>"$directory/reposition-close.err" &
  channel_pid=$!
  exec 4>"$channel_fifo"
  channel_fd_open=true
  wait_for_pattern "$directory/reposition-close.out" CRUCIBLE_CHANNEL_READY "$channel_pid"
  # A virtual time can name more than one scheduler boundary after fork-time
  # run control. Use the already-proven event coordinate so this exercise tests
  # stream closure, rather than the CLI's intentional ambiguous-time rejection.
  debug_command "$endpoint" "$session" --allow-mutate goto "event:$baseline_sequence" \
    >"$directory/reposition-stream.out" 2>"$directory/reposition-stream.err"
  exec 4>&-
  channel_fd_open=false
  if wait_for_exit "$channel_pid"; then
    fail "repositioned guest PTY unexpectedly reported success"
  fi
  channel_pid=
  grep -Eiq 'closed.*reposition|reposition.*closed' \
    "$directory/reposition-close.err" "$directory/reposition-close.out" \
    || fail "guest PTY did not report typed reposition closure"

  stop_gdb
  printf 'stop\n' >&3
  exec 3>&-
  run_fd_open=false
  wait_for_exit "$run_pid" || fail "interactive run exited unsuccessfully"
  run_pid=
  terminate_group "$daemon_pid"
  daemon_pid=

  cat >"$directory/result" <<RESULT
PASS
architecture=$guest_architecture
reverse_baseline_event_prefix=$baseline_events
reverse_earlier_event_prefix=$earlier_events
landed_virtual_time=$earlier_time
gateway_generation_baseline=$baseline_generation
gateway_generation_reverse=$earlier_generation
gateway_generation_repeat=$repeated_generation
read_only_neutrality=true
complete_landed_tuple_repeat=true
stable_gdb_across_replacement=true
replacement_rsp_retries=$(grep -Fc 'Ignoring packet error, continuing...' "$gdb_output" || true)
hardware_breakpoint_retained=true
scheduler_run_control=true
guest_exec=true
guest_pty=true
guest_ssh=true
stream_reposition_close=true
RESULT
  printf 'PASS %s\n' "$guest_architecture"
}

for selected in $selected_architectures; do
  case "$selected" in
    x86_64) run_architecture x86_64 x86_64 0 ;;
    aarch64) run_architecture aarch64 aarch64 10 ;;
  esac
done

{
  printf '%s\n' PASS
  printf 'architectures=%s\n' "${selected_architectures// /,}"
  printf 'available_architectures=%s\n' "$available_architectures"
  printf 'packaged_architectures=%s\n' "$CRUCIBLE_MATRIX_SUPPORTED_ARCHITECTURES"
  printf 'doorbell_instruction_abi=%s\n' "$CRUCIBLE_MATRIX_DOORBELL_INSTRUCTION_ABI_VERSION"
  printf 'build_info=crucible-build-info\n'
  for selected in $selected_architectures; do
    printf 'evidence.%s=%s/result\n' "$selected" "$selected"
    sed "s/^/asset.$selected./" "$output/$selected/asset-identities"
  done
} >"$output/result"
progress complete
