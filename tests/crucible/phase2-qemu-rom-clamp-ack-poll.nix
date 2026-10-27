# Controlled host ACK-poll comparison; both fresh processes use one binary,
# unchanged firmware/native inputs, and the original per-flight watchdog.
{
  pkgs,
  flight,
  firmwareGuest,
}: {
  rootfsDeps = [pkgs.python3 "${./qemu-rom-clamp-ack-poll.py}"];
  buildDeps = [pkgs.python3];
  testScript = ''
    export CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS=256
    for mode in baseline ack-poll-100us; do
      mkdir -m 700 "/tmp/attempts/$mode"
      if ${pkgs.coreutils}/bin/timeout -k 15 180 \
        ${flight}/bin/crucible-qemu-rom-clamp-stress \
        ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${firmwareGuest}/whitebox-bios.bin \
        /sys/fs/cgroup/crucible "/tmp/attempts/$mode" "$mode" \
        > "/tmp/$mode.result" 2> "/tmp/$mode.log"; then
        :
      else
        status=$?
        tail -c 16384 "/tmp/$mode.result" >&2 || true
        tail -c 65536 "/tmp/$mode.log" >&2 || true
        exit "$status"
      fi
      echo "CRUCIBLE_ACK_POLL_RESULT_BEGIN $mode"
      cat "/tmp/$mode.result"
      echo "CRUCIBLE_ACK_POLL_RESULT_END $mode"
      # Existing diagnostics are sampled, not a whole-run timing distribution.
      grep '^CRUCIBLE-HOST-QUANTUM-PERF-V1 ' "/tmp/$mode.log" \
        > "/tmp/$mode.perf" || true
      head -c 65536 "/tmp/$mode.perf"
      if test "$(wc -c < "/tmp/$mode.perf")" -gt 65536; then
        echo "ACK_POLL_SAMPLES_TRUNCATED $mode"
      fi
    done
    ${pkgs.python3}/bin/python3 ${./qemu-rom-clamp-ack-poll.py} \
      /tmp/baseline.result /tmp/ack-poll-100us.result
  '';
  retainScript = ''
    ${pkgs.python3}/bin/python3 ${./qemu-rom-clamp-ack-poll.py} \
      --serial "$out/vm-serial.log" "$out"
  '';
}
