//! Draining and diagnosing project-quota usage that outlives an emptied run
//! directory.
//!
//! Reaping the last process that held a project file does not settle the
//! project's accounted usage synchronously: the kernel may finish the final
//! file release and inode eviction on deferred work shortly afterwards. Release
//! therefore re-reads the kernel's own usage counters until both reach zero or
//! a fixed number of short pauses is spent. The wait observes only that
//! signal; it never deletes, closes, or repeats anything, and usage still held
//! at the bound fails the release closed.
//!
//! When usage remains, a bounded `/proc` scan names processes that hold
//! deleted files on the run directory's filesystem, and processes whose
//! descriptor tables it could not read. Because a kernel can also keep a file
//! alive with no descriptor or mapping in any table, the scan additionally
//! names exiting tasks and unix sockets with unread queued bytes. The scan
//! never influences the release decision.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::thread;
use std::time::Duration;

use rustix::process::{Pid, PidfdFlags, PidfdGetfdFlags};

/// Most `/proc` descriptor and mapping entries inspected by one scan.
const MAX_SCANNED_ENTRIES: usize = 65_536;

/// Most holders named in one diagnostic.
const MAX_REPORTED_HOLDERS: usize = 8;

/// Linux `PF_EXITING` task flag from `/proc/<pid>/stat`.
const PF_EXITING: u64 = 0x4;

/// Most pauses release takes while waiting for released usage to reach zero.
///
/// With [`RELEASED_USAGE_READ_INTERVAL`] this bounds the wait to about one
/// second without reading a host clock. Deferred kernel release settles within
/// milliseconds of the reap; the bound only keeps a genuinely held project
/// from stalling release indefinitely.
const RELEASED_USAGE_DRAIN_PAUSES: usize = 1_000;

/// Pause between project-usage reads while waiting for the drain.
const RELEASED_USAGE_READ_INTERVAL: Duration = Duration::from_millis(1);

/// Project usage observed by [`await_released_usage_drain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleasedUsage {
    /// Both accounted counters read zero.
    Drained,
    /// Usage was still accounted when the pause budget ran out.
    Held {
        /// Last observed accounted bytes.
        bytes: u64,
        /// Last observed accounted inode count.
        inodes: u64,
    },
}

/// Waits a fixed bounded number of read intervals for released usage to drain.
///
/// # Errors
///
/// Returns the first error from `read_usage`.
pub(super) fn drain_released_usage<E>(
    read_usage: impl FnMut() -> Result<(u64, u64), E>,
) -> Result<ReleasedUsage, E> {
    await_released_usage_drain(
        read_usage,
        sleeping_pauses(RELEASED_USAGE_DRAIN_PAUSES, RELEASED_USAGE_READ_INTERVAL),
    )
}

/// Reads released project usage until it drains or `pause` declines to wait.
///
/// `read_usage` returns accounted `(bytes, inodes)`. Usage is read at least
/// once and once more after every accepted pause, so the final answer always
/// reflects a read taken after the last wait. A read error ends the wait
/// immediately and is returned unchanged, because release cannot prove an
/// unreadable project is empty.
fn await_released_usage_drain<E>(
    mut read_usage: impl FnMut() -> Result<(u64, u64), E>,
    mut pause: impl FnMut() -> bool,
) -> Result<ReleasedUsage, E> {
    loop {
        let (bytes, inodes) = read_usage()?;
        if bytes == 0 && inodes == 0 {
            return Ok(ReleasedUsage::Drained);
        }
        if !pause() {
            return Ok(ReleasedUsage::Held { bytes, inodes });
        }
    }
}

/// Returns a pause that sleeps `interval` at most `budget` times.
fn sleeping_pauses(mut budget: usize, interval: Duration) -> impl FnMut() -> bool {
    move || {
        let Some(remaining) = budget.checked_sub(1) else {
            return false;
        };
        budget = remaining;
        thread::sleep(interval);
        true
    }
}

/// Scans for deleted-file holders, then re-reads the project usage.
///
/// The second read shows whether usage was only transient: the scan itself
/// takes long enough for a kernel release that trails the reap to land.
pub(super) fn diagnose_released_usage<E: std::fmt::Display>(
    directory: &Path,
    reread_usage: impl FnOnce() -> Result<(u64, u64), E>,
) -> String {
    let holders = deleted_file_holders(directory);
    let kernel_held = kernel_held_candidates();
    match reread_usage() {
        Ok((bytes, inodes)) => {
            format!("{holders}; {kernel_held}; usage after scan: {bytes} bytes, {inodes} inodes")
        }
        Err(source) => {
            format!("{holders}; {kernel_held}; usage after scan unavailable: {source}")
        }
    }
}

/// Describes processes holding deleted files on `directory`'s filesystem.
///
/// Holders are matched by device and a zero link count rather than by path,
/// so a process that names the file through another path is still found.
/// The result is diagnostic text that also names processes whose descriptor
/// or mapping tables were unreadable, because those can hide holders.
pub(super) fn deleted_file_holders(directory: &Path) -> String {
    deleted_file_holders_among(directory, |_pid| true)
}

/// Runs [`deleted_file_holders`] over the processes `include` selects.
fn deleted_file_holders_among(directory: &Path, include: impl Fn(u32) -> bool) -> String {
    let device = match fs::metadata(directory) {
        Ok(metadata) => metadata.dev(),
        Err(source) => return format!("unavailable: run directory metadata: {source}"),
    };
    let Ok(processes) = fs::read_dir("/proc") else {
        return String::from("unavailable: /proc is unreadable");
    };

    let mut holders = Vec::new();
    let mut scanned_processes = 0_usize;
    let mut unreadable = Vec::new();
    let mut scanned = 0_usize;
    let mut truncated = false;

    'processes: for process in processes.flatten() {
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if !include(pid) {
            continue;
        }
        scanned_processes += 1;
        let command = fs::read_to_string(process.path().join("comm"))
            .map(|command| command.trim().to_owned())
            .unwrap_or_default();

        // Descriptors and mappings are both magic links whose metadata is
        // the referenced inode, even after its last name was removed.
        for (kind, table) in [("fd", "fd"), ("map", "map_files")] {
            let Ok(entries) = fs::read_dir(process.path().join(table)) else {
                if unreadable.len() < MAX_REPORTED_HOLDERS {
                    unreadable.push(format!("{pid} ({command}) {table}"));
                }
                continue;
            };
            for entry in entries.flatten() {
                scanned += 1;
                if scanned > MAX_SCANNED_ENTRIES {
                    truncated = true;
                    break 'processes;
                }
                let Ok(metadata) = fs::metadata(entry.path()) else {
                    continue;
                };
                if metadata.dev() != device || metadata.nlink() != 0 {
                    continue;
                }
                let target = fs::read_link(entry.path())
                    .map(|target| target.to_string_lossy().into_owned())
                    .unwrap_or_default();
                holders.push(format!(
                    "pid {pid} ({command}) {kind} {} inode {} bytes {} -> {target}",
                    entry.file_name().to_string_lossy(),
                    metadata.ino(),
                    metadata.len(),
                ));
                if kind == "map" {
                    // One mapping per process is enough to name the holder.
                    break;
                }
            }
        }

        if holders.len() >= MAX_REPORTED_HOLDERS {
            truncated = true;
            break;
        }
    }

    let mut report = if holders.is_empty() {
        String::from("none found")
    } else {
        holders.join("; ")
    };
    report.push_str(&format!(
        " (processes {scanned_processes}, unreadable [{}]",
        unreadable.join(", ")
    ));
    if truncated {
        report.push_str(", truncated");
    }
    report.push(')');
    report
}

/// Names exiting tasks and unix sockets that still queue unread bytes.
///
/// Neither shows a deleted file in a descriptor table. An exiting task has
/// detached its table while the final release of its files can still be
/// pending, and a descriptor sent with `SCM_RIGHTS` but never received is
/// owned by the receiving socket's queue rather than by any process. A
/// queued socket is therefore a candidate holder, not proof of one.
pub(super) fn kernel_held_candidates() -> String {
    kernel_held_candidates_among(|_pid| true)
}

/// Runs [`kernel_held_candidates`] over the processes `include` selects.
fn kernel_held_candidates_among(include: impl Fn(i32) -> bool) -> String {
    let Ok(processes) = fs::read_dir("/proc") else {
        return String::from("kernel-held candidates unavailable: /proc is unreadable");
    };

    let mut exiting = Vec::new();
    let mut queued = Vec::new();
    let mut inspected_sockets = 0_usize;
    let mut socket_errors = 0_usize;
    let mut first_socket_error = None;

    for process in processes.flatten() {
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .filter(|pid| include(*pid))
        else {
            continue;
        };
        let command = fs::read_to_string(process.path().join("comm"))
            .map(|command| command.trim().to_owned())
            .unwrap_or_default();

        if let Some((state, flags)) = task_state(&process.path())
            && (flags & PF_EXITING != 0 || matches!(state, 'D' | 'X' | 'Z'))
            && exiting.len() < MAX_REPORTED_HOLDERS
        {
            exiting.push(format!("{pid} ({command}) state {state} flags {flags:#x}"));
        }

        let Ok(entries) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        let mut pidfd = None;
        for entry in entries.flatten() {
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy().into_owned();
            let Some(descriptor) = target
                .starts_with("socket:")
                .then(|| entry.file_name().to_str()?.parse::<i32>().ok())
                .flatten()
            else {
                continue;
            };
            inspected_sockets += 1;

            match queued_socket_bytes(pid, &mut pidfd, descriptor) {
                Ok(0) => {}
                Ok(bytes) => {
                    if queued.len() < MAX_REPORTED_HOLDERS {
                        queued.push(format!(
                            "pid {pid} ({command}) fd {descriptor} {target} queued {bytes}"
                        ));
                    }
                }
                Err(source) => {
                    socket_errors += 1;
                    first_socket_error
                        .get_or_insert_with(|| format!("pid {pid} fd {descriptor}: {source}"));
                }
            }
        }
    }

    format!(
        "exiting tasks [{}]; queued unix sockets [{}] (inspected {inspected_sockets}, errors {socket_errors}{})",
        exiting.join(", "),
        queued.join("; "),
        first_socket_error
            .map(|error| format!(", first {error}"))
            .unwrap_or_default(),
    )
}

/// Reads a task's state letter and kernel flags from `/proc/<pid>/stat`.
fn task_state(process: &Path) -> Option<(char, u64)> {
    let stat = fs::read_to_string(process.join("stat")).ok()?;
    // The command field may contain spaces and parentheses; fields resume
    // after its final closing parenthesis.
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let flags = fields.nth(5)?.parse().ok()?;
    Some((state, flags))
}

/// Duplicates one socket descriptor from `pid` and returns its unread bytes.
///
/// The duplicate refers to the same open socket and is closed on return, so
/// the inspected process keeps its descriptor unchanged.
fn queued_socket_bytes(
    pid: i32,
    pidfd: &mut Option<rustix::fd::OwnedFd>,
    descriptor: i32,
) -> rustix::io::Result<u64> {
    let pidfd = match pidfd {
        Some(pidfd) => pidfd,
        None => {
            let process = Pid::from_raw(pid).ok_or(rustix::io::Errno::SRCH)?;
            pidfd.insert(rustix::process::pidfd_open(process, PidfdFlags::empty())?)
        }
    };
    let socket = rustix::process::pidfd_getfd(&*pidfd, descriptor, PidfdGetfdFlags::empty())?;
    rustix::io::ioctl_fionread(&socket)
}

#[cfg(test)]
#[path = "released_usage_tests.rs"]
mod tests;
