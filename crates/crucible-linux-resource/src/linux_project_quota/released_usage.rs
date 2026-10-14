//! Diagnostics for project-quota usage that outlives an emptied run directory.
//!
//! When release still finds accounted usage, a bounded `/proc` scan names
//! processes that hold deleted files on the run directory's filesystem, and
//! processes whose descriptor tables it could not read. The scan never
//! influences the release decision.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// Most `/proc` descriptor and mapping entries inspected by one scan.
const MAX_SCANNED_ENTRIES: usize = 65_536;

/// Most holders named in one diagnostic.
const MAX_REPORTED_HOLDERS: usize = 8;

/// Scans for deleted-file holders, then re-reads the project usage.
///
/// The second read shows whether usage was only transient: the scan itself
/// takes long enough for a kernel release that trails the reap to land.
pub(super) fn diagnose_released_usage<E: std::fmt::Display>(
    directory: &Path,
    reread_usage: impl FnOnce() -> Result<(u64, u64), E>,
) -> String {
    let holders = deleted_file_holders(directory);
    match reread_usage() {
        Ok((bytes, inodes)) => {
            format!("{holders}; usage after scan: {bytes} bytes, {inodes} inodes")
        }
        Err(source) => format!("{holders}; usage after scan unavailable: {source}"),
    }
}

/// Describes processes holding deleted files on `directory`'s filesystem.
///
/// Holders are matched by device and a zero link count rather than by path,
/// so a process that names the file through another path is still found.
/// The result is diagnostic text that also names processes whose descriptor
/// or mapping tables were unreadable, because those can hide holders.
pub(super) fn deleted_file_holders(directory: &Path) -> String {
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

#[cfg(test)]
#[path = "released_usage_tests.rs"]
mod tests;
