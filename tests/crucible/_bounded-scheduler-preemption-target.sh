# This file is invoked with the AOS builder shell; it deliberately has no
# host-dependent shebang.  Recording the shell PID before exec gives the test
# harness a stable identity for the actual QEMU process, even when COMMAND is a
# short-lived argument-validation launcher that subsequently execs QEMU.
set -eu

pid_file="$1"
working_directory="$2"
shift 2

if [ "$working_directory" != "-" ]; then
  cd "$working_directory"
fi

pid_file_tmp="$pid_file.tmp.$$"
printf '%s\n' "$$" > "$pid_file_tmp"
mv "$pid_file_tmp" "$pid_file"
exec "$@"
