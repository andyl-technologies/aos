"""Retains bounded, read-only observations before a failed startup VM exits."""

from contextlib import contextmanager
import shlex


@contextmanager
def startup_diagnostics(machine, *units):
    """Preserves the original failure even when a diagnostic command fails."""
    try:
        yield
    except Exception:
        selected_units = " ".join(f"--unit={shlex.quote(unit)}" for unit in units)
        journal_lines = 80 if units else 160
        # Preserve the audit tail before status queries add their own denials.
        # Serial audit backlogs can overflow before the startup assertion fails.
        commands = (
            # Repeated diagnostic execs can crowd early owner and bus denials
            # out of the raw tail. Select both from the retained audit file.
            "LC_ALL=C grep -E '^type=(AVC|SELINUX_ERR) ' /var/log/audit/audit.log "
            "| grep -E 'aos_|system_dbusd_t' | tail -n 80 | head -c 32768",
            "tail -c 65536 /var/log/audit/audit.log",
            f"journalctl --boot=0 {selected_units} --lines={journal_lines} --no-pager",
            "systemctl --failed --no-pager",
            # A pending oneshot can hold boot without entering failed state.
            "systemctl list-jobs --no-pager",
            "stat -c '%a %u:%g %d:%i %C %F %n' -- "
            "/run /run/aos /run/aos/sandbox-policy-cache-recovery "
            "/var /var/lib /var/lib/aos /var/lib/aos/sandbox "
            "/var/lib/aos/sandbox/policy-compiler",
            # Stop producers at the process bound. Piping an unbounded loop
            # into head leaves every later subprocess reporting broken pipes.
            # Use the image's existing shell/Coreutils; Procps is optional.
            "count=0; for process in /proc/[0-9]*; do "
            "[ \"$count\" -lt 64 ] || break; "
            "[ -r \"$process/status\" ] || continue; "
            "count=$((count + 1)); "
            "printf '\\n%s\\n' \"$process\"; "
            "head -n 8 \"$process/status\"; "
            "cat \"$process/wchan\"; done",
        )

        for command in commands:
            try:
                status, stdout, stderr = machine.execute(command, timeout=15)
                output = (stdout + stderr).decode("utf-8", errors="replace")
                print(f"Startup diagnostic: {command} (exit {status})", flush=True)
                print(output, flush=True)
            except Exception as diagnostic_error:
                print(f"Startup diagnostic unavailable: {diagnostic_error}", flush=True)

        raise
