#!@bash@/bin/bash
# Streams bounded completed-stage diagnostics while retaining the full libtest log.
set -u

if [ "$#" -lt 2 ]; then
  printf 'usage: packaged-maintenance-stage-runner LOG COMMAND [ARG...]\n' >&2
  exit 64
fi

flight_log=$1
shift
stage_directory=$(@coreutils@/bin/mktemp -d "${flight_log}.stages.XXXXXX") || exit 1
stage_pipe="$stage_directory/rows"
flight_pid=
tail_pid=
filter_pid=

# Only these direct children belong to this diagnostic runner. A row/byte cap
# never closes the reader early or changes the original flight's exit status.
cleanup_stages() {
  if [ -n "$flight_pid" ]; then
    kill -TERM "$flight_pid" 2>/dev/null || true
    wait "$flight_pid" 2>/dev/null || true
  fi
  for reader_pid in "$tail_pid" "$filter_pid"; do
    if [ -n "$reader_pid" ]; then
      kill -TERM "$reader_pid" 2>/dev/null || true
    fi
  done
  for reader_pid in "$tail_pid" "$filter_pid"; do
    if [ -n "$reader_pid" ]; then
      wait "$reader_pid" 2>/dev/null || true
    fi
  done
  @coreutils@/bin/rm -f "$stage_pipe"
  @coreutils@/bin/rmdir "$stage_directory"
}

trap cleanup_stages EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

@coreutils@/bin/mkfifo "$stage_pipe" || exit 1
: > "$flight_log"
"$@" > "$flight_log" 2>&1 &
flight_pid=$!
@coreutils@/bin/tail --pid="$flight_pid" -n +1 -F "$flight_log" \
  > "$stage_pipe" 2>/dev/null &
tail_pid=$!
@gawk@/bin/awk '
  /^CRUCIBLE-PACKAGED-STAGE-V1 diagnostic_only=true stage=[a-z0-9-]+$/ {
    if (length($0) <= 127 && emitted_rows < 32) {
      print
      fflush()
      emitted_rows++
    }
  }
' < "$stage_pipe" &
filter_pid=$!

flight_status=0
wait "$flight_pid" || flight_status=$?
flight_pid=
# tail observes the reaped flight and closes the FIFO; the filter drains it.
# The capped filter keeps reading until EOF, so it cannot strand its producer.
wait "$tail_pid" || true
tail_pid=
wait "$filter_pid" || true
filter_pid=
exit "$flight_status"
