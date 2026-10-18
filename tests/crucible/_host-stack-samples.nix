# Diagnostic stack samples of the campaign service during a long Envoy run.
#
# The service binary is built unstripped for this option, so a periodic
# debugger attach names the host functions that dominate wall time between
# backend RUNs. Samples perturb the service while it is stopped; they explain
# throughput and are never evidence for an assertion or a deadline.
{pkgs}: let
  serviceStderrDir = "/tmp/campaign-service-stderr";
  stallStopFile = "/tmp/crucible-qemu-stall-stop";

  # One host sample prints at most this many stack bytes before its footer.
  # The cap bounds the 180-sample file (about 11 MiB) while leaving room for
  # every busy service thread; the footer itself is printed outside the cap.
  hostSampleStackBytes = 61440;
  # The shell cut is a backstop above the in-process cap and its footer.
  hostSampleCutBytes = 65536;
  # Full QEMU backtraces are unfiltered, so one process can exceed 16 KiB.
  # Three rounds over five guests stay within about 1 MiB.
  qemuStallCutBytes = 65536;
  qemuStallReportBytes = 1048576;

  commands = pkgs.writeTextFile {
    name = "crucible-host-stack-sample";
    destination = "/share/crucible/host-stack-sample.gdb";
    text = ''
      set pagination off
      set print frame-arguments none
      set width 0
      python
      import gdb

      # Threads parked in these waits are idle; their stacks are omitted. Only
      # the two innermost frames are matched, so host functions whose names
      # merely contain a marker, such as repoll loops, still count as busy.
      # "recv" covers recv, recvfrom, and recvmsg; "epoll" covers epoll_wait
      # and epoll_pwait; "poll" covers poll and ppoll.
      idle_markers = ("futex", "epoll", "poll", "pselect", "__select", "nanosleep",
                      "park", "wait4", "waitid", "sigtimedwait", "sigwait",
                      "accept", "recv", "__libc_read", "pthread_cond")
      stack_budget = ${toString hostSampleStackBytes}
      busy = 0
      omitted = 0
      for thread in gdb.selected_inferior().threads():
          thread.switch()
          frame = gdb.newest_frame()
          names = []
          while frame is not None and len(names) < 48:
              names.append(frame.name() or "??")
              frame = frame.older()
          if any(marker in name for name in names[:2] for marker in idle_markers):
              continue
          busy += 1
          lines = ["host_stack_thread lwp=%d frames=%d" % (thread.ptid[1], len(names))]
          lines.extend("  #%d %s" % (index, name) for index, name in enumerate(names))
          text = "\n".join(lines)
          # Busy threads are still counted once the budget is spent, so the
          # footer stays exact even when their stacks are omitted.
          if len(text) + 1 > stack_budget:
              omitted += 1
              continue
          stack_budget -= len(text) + 1
          print(text)
      print("host_stack_omitted_threads=%d" % omitted)
      print("host_stack_busy_threads=%d" % busy)
      end
    '';
  };
in {
  rootfsDeps = [pkgs.gdb commands];

  # Starts a bounded background sampler for the service owned by this flight.
  start = flightBinary: ''
    (
      # Sample through the whole flight: the slowest attempts run last, long
      # after boot, and a sparse early window cannot attribute their cost.
      ${pkgs.coreutils}/bin/sleep 300
      host_stack_sample=0
      while [ "$host_stack_sample" -lt 180 ]; do
        host_stack_sample=$((host_stack_sample + 1))
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
            | ${pkgs.coreutils}/bin/head -c ${toString hostSampleCutBytes}
        fi
        ${pkgs.coreutils}/bin/sleep 10
      done
    ) > /tmp/crucible-host-stack-samples.txt 2>&1 &
  '';

  # The flight harness links each campaign service's live stderr here.
  inherit serviceStderrDir;

  # Samples every QEMU thread while the host reports a pending-advance stall.
  #
  # Host wait rows go only to the service's stderr. The bounded test log
  # receives a tail of it after QEMU is gone, so the sampler watches the live
  # per-service links instead. Attaching stops a QEMU child, which can perturb
  # host wall-clock deadlines, so nothing attaches until the service has
  # already waited on an advance. Each round needs a newer wait row and rounds
  # stay at least 15 seconds apart, so a wait that recovered cannot spend the
  # whole budget. Thread stacks are not filtered: a stalled vCPU is itself a
  # parked waiter.
  startQemuStall = ''
    ${pkgs.coreutils}/bin/rm -f ${stallStopFile}
    (
      qemu_stall_seen=0
      qemu_stall_round=0
      qemu_stall_idle=0
      while [ "$qemu_stall_round" -lt 3 ] && [ "$qemu_stall_idle" -lt 3600 ] &&
        [ ! -e ${stallStopFile} ]; do
        qemu_stall_rows=$(${pkgs.coreutils}/bin/cat ${serviceStderrDir}/campaign-service-*.stderr 2>/dev/null \
          | ${pkgs.grep}/bin/grep -c '^CRUCIBLE-HOST-WAIT-V1 phase=advance-pending ' || true)
        if [ "''${qemu_stall_rows:-0}" -le "$qemu_stall_seen" ]; then
          ${pkgs.coreutils}/bin/sleep 1
          qemu_stall_idle=$((qemu_stall_idle + 1))
          continue
        fi
        qemu_stall_seen=$qemu_stall_rows
        qemu_stall_round=$((qemu_stall_round + 1))
        for qemu_stall_proc in /proc/[0-9]*; do
          qemu_stall_argv=$(${pkgs.coreutils}/bin/tr '\0' ' ' < "$qemu_stall_proc/cmdline" 2>/dev/null || true)
          case "$qemu_stall_argv" in
            *qemu-system*) ;;
            *) continue ;;
          esac
          qemu_stall_pid=''${qemu_stall_proc#/proc/}
          printf 'qemu_stall_sample=%s pid=%s wait_rows=%s uptime=%s\n' "$qemu_stall_round" \
            "$qemu_stall_pid" "$qemu_stall_rows" "$(${pkgs.coreutils}/bin/cut -d' ' -f1 /proc/uptime)"
          ${pkgs.coreutils}/bin/timeout -k 2 40 ${pkgs.gdb}/bin/gdb -nx -nh -batch \
            -iex 'set auto-load off' -iex 'set debuginfod enabled off' \
            -ex 'set pagination off' -ex 'set print frame-arguments none' \
            -ex 'thread apply all bt 32' -p "$qemu_stall_pid" 2>&1 \
            | ${pkgs.grep}/bin/grep -E '^(Thread |#)' \
            | ${pkgs.coreutils}/bin/head -c ${toString qemuStallCutBytes}
        done
        qemu_stall_pause=0
        while [ "$qemu_stall_pause" -lt 15 ] && [ ! -e ${stallStopFile} ]; do
          ${pkgs.coreutils}/bin/sleep 1
          qemu_stall_pause=$((qemu_stall_pause + 1))
        done
      done
    ) > /tmp/crucible-qemu-stall-stacks.txt 2>&1 &
    qemu_stall_sampler=$!
  '';

  report = ''
    # Stop the stall sampler and let a round in progress finish its samples.
    : > ${stallStopFile}
    if [ -n "''${qemu_stall_sampler:-}" ]; then
      wait "$qemu_stall_sampler" 2>/dev/null || true
    fi
    # The newest samples cover the slowest, final attempts, so keep the tail.
    printf '%s\n' 'host-stack-samples-begin max_bytes=1048576'
    ${pkgs.coreutils}/bin/tail -c 1048576 /tmp/crucible-host-stack-samples.txt 2>/dev/null || true
    printf '%s\n' 'host-stack-samples-end'
    printf '%s\n' 'qemu-stall-stacks-begin max_bytes=${toString qemuStallReportBytes}'
    ${pkgs.coreutils}/bin/head -c ${toString qemuStallReportBytes} /tmp/crucible-qemu-stall-stacks.txt 2>/dev/null || true
    printf '%s\n' 'qemu-stall-stacks-end'
  '';
}
