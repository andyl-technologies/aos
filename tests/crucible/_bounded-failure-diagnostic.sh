# Bounded artifact dump for QEMU gate failures.

CRUCIBLE_DIAGNOSTIC_MAX_BYTES=65536
CRUCIBLE_DIAGNOSTIC_MAX_LINES=256
CRUCIBLE_DIAGNOSTIC_READ_TIMEOUT_SECONDS=2

crucible_failure_diagnostic_file() {
  cfd_role="$1"
  cfd_path="$2"

  printf 'artifact=%s\n' "$cfd_role"
  if [ -L "$cfd_path" ]; then
    printf 'state=symlink-rejected\n'
    return 0
  fi
  if [ ! -e "$cfd_path" ]; then
    printf 'state=missing\n'
    return 0
  fi
  if [ ! -f "$cfd_path" ]; then
    printf 'state=non-regular-rejected\n'
    return 0
  fi

  cfd_size=$(stat -c '%s' "$cfd_path" 2>/dev/null || true)
  case "$cfd_size" in
    '' | *[!0-9]*)
      printf 'state=stat-failed\n'
      return 0
      ;;
  esac
  printf 'state=bounded-tail size_bytes=%s max_bytes=%s max_lines=%s\n' \
    "$cfd_size" "$CRUCIBLE_DIAGNOSTIC_MAX_BYTES" "$CRUCIBLE_DIAGNOSTIC_MAX_LINES"

  cfd_copy="$TMPDIR/crucible-failure-diagnostic-$$-$cfd_role.tmp"
  rm -f "$cfd_copy"
  if timeout "$CRUCIBLE_DIAGNOSTIC_READ_TIMEOUT_SECONDS" \
    tail -c "$CRUCIBLE_DIAGNOSTIC_MAX_BYTES" "$cfd_path" > "$cfd_copy"; then
    tail -n "$CRUCIBLE_DIAGNOSTIC_MAX_LINES" "$cfd_copy"
  else
    printf 'state=read-failed-or-timed-out\n'
  fi
  rm -f "$cfd_copy"
}

crucible_failure_diagnostic() {
  cfd_label="$1"
  cfd_args="$2"
  cfd_serial="$3"
  cfd_trace="$4"
  cfd_qmp_status="$5"

  {
    printf 'CRUCIBLE_FAILURE_DIAGNOSTIC_BEGIN label=%s consistency=independent-bounded-file-observations\n' \
      "$cfd_label"
    crucible_failure_diagnostic_file qemu-arguments "$cfd_args"
    crucible_failure_diagnostic_file serial "$cfd_serial"
    crucible_failure_diagnostic_file trace "$cfd_trace"
    crucible_failure_diagnostic_file qmp-status "$cfd_qmp_status"
    printf 'CRUCIBLE_FAILURE_DIAGNOSTIC_END label=%s\n' "$cfd_label"
  } >&2
}
