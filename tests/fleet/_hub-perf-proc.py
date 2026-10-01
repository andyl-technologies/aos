"""Read bounded counters for the fleet's exact Node parent and workerd child.

The script reads no command line, environment, config, credential or log. Boundary
snapshots include driver/collection latency and describe the complete workload
window; they cannot attribute CPU or queue time to one page request.
"""

import argparse
import json
import os
from pathlib import Path
import time


def bounded_text(path, maximum=8192):
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("process counter exceeds bounds")
    return data.decode("ascii")


def read_scheduler(path):
    values = [int(value) for value in bounded_text(path).split()]
    if len(values) != 3 or any(value < 0 for value in values):
        raise ValueError("invalid process scheduler counters")
    return {"runtime_ns": values[0], "runqueue_ns": values[1], "timeslices": values[2]}


def read_io(path):
    io = {}
    allowed = {
        "rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes",
        "cancelled_write_bytes",
    }
    for line in bounded_text(path).splitlines():
        key, separator, value = line.partition(":")
        if key in allowed and separator:
            io[key] = int(value.strip())
    if set(io) != allowed or any(value < 0 for value in io.values()):
        raise ValueError("invalid process I/O counters")
    return io


def optional_counters(path, reader):
    """Report absent/unreadable optional counters without inventing zero values."""
    try:
        return reader(path), {"status": "available"}
    except FileNotFoundError:
        reason = "not_supported"
    except PermissionError:
        reason = "permission_denied"
    except OSError:
        reason = "read_error"
    except (ValueError, UnicodeError):
        reason = "invalid_counters"
    return None, {"status": "unavailable", "reason": reason}


def read_stat(proc, pid):
    stat = bounded_text(proc / str(pid) / "stat")
    prefix, separator, tail = stat.rpartition(") ")
    if not separator or not prefix.startswith(f"{pid} ("):
        raise ValueError("invalid process stat identity")
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError("incomplete process stat counters")
    if int(fields[1]) < 0 or int(fields[19]) < 0:
        raise ValueError("invalid process lifetime identity")
    return fields


def runtime_children(proc, node_pid):
    """Use bounded parent-stat discovery when the kernel omits proc children."""
    path = proc / str(node_pid) / "task" / str(node_pid) / "children"
    try:
        children = bounded_text(path).split()
        method = "proc_task_children"
    except FileNotFoundError:
        children = []
        count = 0
        for entry in proc.iterdir():
            if not entry.name.isdecimal():
                continue
            count += 1
            if count > 4096:
                raise ValueError("process discovery exceeds bounds")
            try:
                fields = read_stat(proc, int(entry.name))
            except FileNotFoundError:
                # Unrelated processes may exit while bounded discovery runs.
                continue
            if int(fields[1]) == node_pid:
                children.append(entry.name)
                if len(children) > 32:
                    raise ValueError("runtime child set exceeds bounds")
        method = "bounded_proc_parent_scan"
    if len(children) > 32 or not all(value.isdecimal() and int(value) > 0 for value in children):
        raise ValueError("invalid runtime child set")
    return children, method


def read_process(proc, pid, expected_exe):
    directory = proc / str(pid)
    exe = str((directory / "exe").resolve(strict=True))
    if exe != str(expected_exe.resolve(strict=True)):
        raise ValueError("unexpected process executable identity")
    fields = read_stat(proc, pid)
    sched, sched_status = optional_counters(directory / "schedstat", read_scheduler)
    io, io_status = optional_counters(directory / "io", read_io)
    record = {
        "pid": pid, "ppid": int(fields[1]), "exe": exe,
        "start_ticks": int(fields[19]),
        "cpu_ticks": {"user": int(fields[11]), "system": int(fields[12])},
        "schedstat": sched,
        "optional_counter_status": {"schedstat": sched_status, "io": io_status},
        "io": io,
    }
    if any(value < 0 for value in record["cpu_ticks"].values()) or record["start_ticks"] < 0:
        raise ValueError("invalid process lifetime counters")
    return record


def snapshot(proc, node_pid, node_exe, workerd_exe):
    started = time.monotonic_ns()
    node = read_process(proc, node_pid, node_exe)
    children, discovery = runtime_children(proc, node_pid)
    expected = str(workerd_exe.resolve(strict=True))
    matches = [int(value) for value in children
               if str((proc / value / "exe").resolve(strict=True)) == expected]
    if len(matches) != 1:
        raise ValueError("expected exactly one source-built workerd child")
    workerd = read_process(proc, matches[0], workerd_exe)
    if workerd["ppid"] != node_pid:
        raise ValueError("runtime parent identity changed")
    # Reread lifetime identity to reject a process replacement during collection.
    final_node = read_process(proc, node_pid, node_exe)
    final_worker = read_process(proc, matches[0], workerd_exe)
    if (node["start_ticks"] != final_node["start_ticks"]
            or workerd["start_ticks"] != final_worker["start_ticks"]
            or final_worker["ppid"] != node_pid):
        raise ValueError("process identity changed during collection")
    return {
        "monotonic_started_ns": started, "monotonic_finished_ns": time.monotonic_ns(),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "coverage": "boundary-only complete workload; not per-request CPU attribution",
        "counter_scope": "CPU and IO process-wide; schedstat main thread only",
        "child_discovery": discovery,
        "processes": {"node": node, "workerd": workerd},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid-file", type=Path, required=True)
    parser.add_argument("--node-exe", type=Path, required=True)
    parser.add_argument("--workerd-exe", type=Path, required=True)
    options = parser.parse_args()
    raw_pid = bounded_text(options.pid_file, 32).strip()
    if not raw_pid.isdecimal() or int(raw_pid) <= 0:
        raise ValueError("invalid fleet runtime parent identity")
    observation = snapshot(Path("/proc"), int(raw_pid), options.node_exe, options.workerd_exe)
    print(json.dumps(observation, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError):
        raise SystemExit("fleet process counter snapshot failed") from None
