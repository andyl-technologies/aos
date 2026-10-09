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
      import hashlib
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
      def report_command(command):
          try:
              gdb.execute(command)
          except gdb.error as error:
              print("native_core_read=inconclusive command=%s error=%s" % (command, error))

      def read_unsigned(address, size):
          if address < 0 or size <= 0 or address > (1 << 64) - size:
              raise gdb.GdbError("core address range exceeds 64-bit pointers")
          return int.from_bytes(inferior.read_memory(address, size).tobytes(), "little")

      def report_sources(context):
          # Only the source-list links and public source/function fields are read.
          # Callback data and source names may already have been released.
          bucket_link = read_unsigned(context + 0xc0, 8)
          seen_buckets = set()
          seen_sources = set()
          sources_read = 0

          for bucket_index in range(4):
              if bucket_link == 0:
                  print("native_core_sources_status=complete sources_read=%d" % sources_read)
                  return
              if bucket_link in seen_buckets:
                  print("native_core_sources_status=inconclusive reason=bucket-cycle")
                  return
              seen_buckets.add(bucket_link)
              bucket = read_unsigned(bucket_link, 8)
              next_bucket = read_unsigned(bucket_link + 8, 8)
              source = read_unsigned(bucket + 0x18, 8)

              while source != 0:
                  if sources_read >= 8:
                      print("native_core_sources_status=inconclusive reason=total-source-limit")
                      return
                  if source in seen_sources:
                      print("native_core_sources_status=inconclusive reason=source-cycle")
                      return
                  seen_sources.add(source)
                  sources_read += 1

                  ref_count = read_unsigned(source + 0x18, 4)
                  source_context = read_unsigned(source + 0x20, 8)
                  flags = read_unsigned(source + 0x2c, 4)
                  print("native_core_source_candidate=%d source=%#x ref_count=%d context=%#x context_matches=%s flags=%#x in_call=%s" %
                        (sources_read, source, ref_count, source_context, source_context == context, flags, bool(flags & 2)))
                  if ref_count == 0 or source_context != context:
                      print("native_core_sources_status=inconclusive reason=invalid-source-context-or-refcount")
                      return

                  source_funcs = read_unsigned(source + 0x10, 8)
                  dispatch = read_unsigned(source_funcs + 0x10, 8)
                  print("native_core_source_dispatch source=%#x source_funcs=%#x dispatch=%#x" %
                        (source, source_funcs, dispatch))
                  source = read_unsigned(source + 0x48, 8)
              bucket_link = next_bucket

          if bucket_link == 0:
              print("native_core_sources_status=complete sources_read=%d" % sources_read)
          else:
              print("native_core_sources_status=inconclusive reason=bucket-limit sources_read=%d" % sources_read)

      report_command("info registers rbx rbp r12 r13 r14 r15 rsp rip")
      report_command("x/56gx $rsp-0x100")
      report_command("bt 24")
      report_command("info threads")

      # This decoder is specific to the retained ELF instruction and layout.
      # NT_FILE offsets printed by GDB are bytes; this ELF's text VMA matches
      # its file offset. A path alone is insufficient to select the decoder.
      known_layout_elf = False
      try:
          digest = hashlib.sha256()
          with open(glib, "rb") as library:
              while True:
                  chunk = library.read(65536)
                  if not chunk:
                      break
                  digest.update(chunk)
          library_sha256 = digest.hexdigest()
          known_layout_elf = library_sha256 == "46983b8cc5ccd46970ed71bc95df2fa1a0aea56a7a6784517aa5385afd22e3f4"
          print("native_core_glib_sha256=%s layout_elf_supported=%s" % (library_sha256, known_layout_elf))
      except OSError as error:
          print("native_core_glib_identity=inconclusive error=%s" % error)

      rip = int(gdb.parse_and_eval("$rip"))
      fault_mappings = []
      malformed_mapping = False
      for line in mappings.splitlines():
          parts = line.split()
          if not parts or parts[-1] != glib:
              continue
          try:
              start, end, file_offset = (int(parts[index], 16) for index in (0, 1, 3))
          except (ValueError, IndexError):
              malformed_mapping = True
              continue
          if start <= rip < end:
              fault_mappings.append(file_offset + rip - start)

      if not known_layout_elf or malformed_mapping or fault_mappings != [0x66f11]:
          print("native_core_glib_layout=inconclusive reason=unverified-elf-or-fault-mapping matching_offsets=%s malformed=%s" %
                (fault_mappings, malformed_mapping))
      else:
          print("native_core_glib_layout=glib-2.82.4-j172 fault_elf_offset=0x66f11")
          rsp = int(gdb.parse_and_eval("$rsp"))
          context = int(gdb.parse_and_eval("$r14"))
          print("native_core_dispatch_context=%#x" % context)
          try:
              callback = read_unsigned(rsp + 0x30, 8)
              userdata = read_unsigned(rsp + 0x28, 8)
              print("native_core_dispatch_callback=%#x userdata=%#x raw_addresses_only=true" % (callback, userdata))
          except gdb.error as error:
              print("native_core_dispatch_arguments=inconclusive error=%s" % error)
          try:
              report_sources(context)
          except gdb.error as error:
              print("native_core_sources_status=inconclusive reason=inaccessible-core-memory error=%s" % error)
      end
    '';
  };
  stackReferences = ./_native-core-stack-references.py;
in {
  rootfsDeps = [pkgs.gdb pkgs.python3 commands];

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

        native_core_scan_status=0
        (
          ulimit -c 0 || exit 1
          ulimit -S -f 512 || exit 1
          ulimit -H -f 512 || exit 1
          ${pkgs.coreutils}/bin/timeout -k 2 120 ${pkgs.python3}/bin/python3 -I -S \
            ${stackReferences} "$native_core_file" "$native_core_tid"
        ) > /tmp/crucible-native-core-stack-references.txt 2>&1 || native_core_scan_status=$?
        native_core_scan_bytes=$(${pkgs.coreutils}/bin/wc -c < /tmp/crucible-native-core-stack-references.txt)
        printf 'native_core_stack_scan_status=%s report_bytes=%s report_file_limit=262144 emitted_head_limit=65536\n' \
          "$native_core_scan_status" "$native_core_scan_bytes"
        ${pkgs.coreutils}/bin/head -c 65536 /tmp/crucible-native-core-stack-references.txt || true
      done
      printf 'native_core_files_inspected=%s\n' "$native_core_count"
    }
  '';
}
