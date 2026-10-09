# Diagnostic stack samples of the campaign service during a long Envoy run.
#
# The service binary is built unstripped for this option, so a periodic
# debugger attach names the host functions that dominate wall time between
# backend RUNs. Samples perturb the service while it is stopped; they explain
# throughput and are never evidence for an assertion or a deadline.
{pkgs}: let
  commands = pkgs.writeTextFile {
    name = "crucible-host-stack-sample";
    destination = "/share/crucible/host-stack-sample.gdb";
    text = ''
      set pagination off
      set print frame-arguments none
      set width 0
      python
      import gdb

      # Threads parked in these waits are idle; their stacks are omitted.
      idle_markers = ("futex", "epoll", "poll", "nanosleep", "park", "wait4",
                      "waitid", "accept", "recvmsg", "__libc_read", "pthread_cond")
      busy = 0
      for thread in gdb.selected_inferior().threads():
          thread.switch()
          frame = gdb.newest_frame()
          names = []
          while frame is not None and len(names) < 48:
              names.append(frame.name() or "??")
              frame = frame.older()
          if any(marker in name for name in names[:4] for marker in idle_markers):
              continue
          busy += 1
          print("host_stack_thread lwp=%d frames=%d" % (thread.ptid[1], len(names)))
          for index, name in enumerate(names):
              print("  #%d %s" % (index, name))
      print("host_stack_busy_threads=%d" % busy)
      end
    '';
  };
in {
  rootfsDeps = [pkgs.gdb commands];

  # Starts a bounded background sampler for the service owned by this flight.
  start = flightBinary: ''
    (
      ${pkgs.coreutils}/bin/sleep 300
      for host_stack_sample in 1 2 3 4 5 6 7 8 9 10; do
        host_stack_pid=
        for host_stack_proc in /proc/[0-9]*; do
          # The service is the flight's CLI binary running `serve`.
          host_stack_argv=$(${pkgs.coreutils}/bin/tr '\0' ' ' < "$host_stack_proc/cmdline" 2>/dev/null || true)
          case "$host_stack_argv" in
            "${flightBinary} serve "*) host_stack_pid=''${host_stack_proc#/proc/}; break ;;
          esac
        done
        printf 'host_stack_sample=%s pid=%s uptime=%s\n' "$host_stack_sample" \
          "''${host_stack_pid:-none}" "$(${pkgs.coreutils}/bin/cut -d' ' -f1 /proc/uptime)"
        if [ -n "$host_stack_pid" ]; then
          ${pkgs.coreutils}/bin/timeout -k 2 40 ${pkgs.gdb}/bin/gdb -nx -nh -batch \
            -iex 'set auto-load off' -iex 'set debuginfod enabled off' \
            -p "$host_stack_pid" -x ${commands}/share/crucible/host-stack-sample.gdb \
            2>&1 | ${pkgs.grep}/bin/grep -E '^(host_stack|  #)' \
            | ${pkgs.coreutils}/bin/head -c 24576
        fi
        ${pkgs.coreutils}/bin/sleep 25
      done
    ) > /tmp/crucible-host-stack-samples.txt 2>&1 &
  '';

  report = ''
    printf '%s\n' 'host-stack-samples-begin max_bytes=262144'
    ${pkgs.coreutils}/bin/head -c 262144 /tmp/crucible-host-stack-samples.txt 2>/dev/null || true
    printf '%s\n' 'host-stack-samples-end'
  '';
}
