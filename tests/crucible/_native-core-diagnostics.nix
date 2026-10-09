# Failure-only inspection of kernel-produced cores in the disposable test VM.
{pkgs}: let
  commands = pkgs.writeTextFile {
    name = "crucible-native-core-inspect";
    destination = "/share/crucible/native-core-inspect.gdb";
    text = ''
      set pagination off
      set print frame-arguments none
      set print elements 16
      set width 0
      python
      import gdb
      expected_pid = int(gdb.parse_and_eval("$expected_pid"))
      expected_tid = int(gdb.parse_and_eval("$expected_tid"))
      inferior = gdb.selected_inferior()
      thread = gdb.selected_thread()
      mappings = gdb.execute("info proc mappings", to_string=True)
      executable = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64"
      glib = "${pkgs.glib}/lib/libglib-2.0.so.0.8200.4"

      if inferior.pid != expected_pid or thread.ptid[1] != expected_tid:
          raise gdb.GdbError("kernel core identity mismatch: expected PID/TID %d/%d, observed %d/%d" % (expected_pid, expected_tid, inferior.pid, thread.ptid[1]))
      if executable not in mappings or glib not in mappings:
          raise gdb.GdbError("kernel NT_FILE mappings omit selected executable=%s or GLib=%s" % (executable, glib))

      print("native_core_pid=%d native_core_fault_tid=%d" % (inferior.pid, thread.ptid[1]))
      for line in mappings.splitlines():
          if executable in line or glib in line:
              print("native_core_mapping=" + line)
      gdb.execute("info registers rbp rsp rip")
      gdb.execute("bt 24")
      end
    '';
  };
in {
  rootfsDeps = [pkgs.gdb commands];

  setup = ''
    # The volume bounds allocated core data together; sparse logical file
    # lengths can be larger. Private RAM and thread stacks stay
    # eligible for dumping; a truncated core is reported rather than repaired.
    native_core_directory=/tmp/crucible-native-cores
    setup_step native-core-directory mkdir -m 1777 "$native_core_directory"
    setup_step native-core-volume ${pkgs.util-linux}/bin/mount \
      -t tmpfs -o size=512m,nr_inodes=16,mode=1777 tmpfs "$native_core_directory"
    printf '%s\n' '/tmp/crucible-native-cores/core.%P.%I' > /proc/sys/kernel/core_pattern \
      || setup_failure "$?" native-core-pattern
    # /init runs Bash as sh; POSIX ulimit sizes are 512-byte blocks.
    ulimit -S -c 1048576 || setup_failure "$?" native-core-soft-limit
    ulimit -H -c 1048576 || setup_failure "$?" native-core-hard-limit
    printf '%s\n' '0x33' > /proc/self/coredump_filter \
      || setup_failure "$?" native-core-filter
    printf '%s\n' 'native_core_setup=enabled core_write_limit_bytes=536870912 total_storage_limit_bytes=536870912 filter=0x33'

    inspect_native_cores() {
      native_core_count=0
      for native_core_file in "$native_core_directory"/core.*.*; do
        [ -f "$native_core_file" ] || continue
        native_core_name=''${native_core_file##*/}
        if [[ ! "$native_core_name" =~ ^core\.[0-9]+\.[0-9]+$ ]]; then
          printf '%s\n' 'native_core_read_status=unexpected-filename'
          continue
        fi
        if [ "$native_core_count" -ge 8 ]; then
          printf '%s\n' 'native_core_read_status=record-limit'
          break
        fi
        native_core_count=$((native_core_count + 1))

        printf 'native_core_file=%s\n' "$native_core_name"
        native_core_identity=''${native_core_name#core.}
        native_core_pid=''${native_core_identity%%.*}
        native_core_tid=''${native_core_identity##*.}
        ${pkgs.coreutils}/bin/stat -c 'native_core_logical_bytes=%s allocated_blocks=%b block_unit_bytes=%B owner_uid=%u mode=%a' "$native_core_file" || true
        ${pkgs.coreutils}/bin/sha256sum "$native_core_file" || true
        native_core_gdb_status=0
        (
          # This limit applies only to debugger output, not the campaign.
          ulimit -c 0 || exit 1
          ulimit -S -f 256 || exit 1
          ulimit -H -f 256 || exit 1
          ${pkgs.coreutils}/bin/timeout -k 2 15 ${pkgs.gdb}/bin/gdb \
          -nx -nh -batch -iex 'set auto-load off' \
          -iex 'set debuginfod enabled off' \
          --se=${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
          --core="$native_core_file" \
          -ex "set \$expected_pid=$native_core_pid" \
          -ex "set \$expected_tid=$native_core_tid" -x ${commands}/share/crucible/native-core-inspect.gdb \
        ) > /tmp/crucible-native-core-report.txt 2>&1 || native_core_gdb_status=$?
        native_core_report_bytes=$(${pkgs.coreutils}/bin/wc -c < /tmp/crucible-native-core-report.txt)
        printf 'native_core_gdb_status=%s report_bytes=%s report_file_limit=131072 emitted_tail_limit=16384\n' \
          "$native_core_gdb_status" "$native_core_report_bytes"
        ${pkgs.coreutils}/bin/tail -c 16384 /tmp/crucible-native-core-report.txt || true
      done
      printf 'native_core_files_inspected=%s\n' "$native_core_count"
    }
  '';
}
