//! Bounded diagnostic scan for processes that keep deleted project files alive.
//!
//! An emptied run directory can still account project-quota usage when a
//! process holds an unlinked file open or mapped. The scan reads `/proc` once,
//! reports a few holders by PID, command, and kind, and never influences the
//! release decision itself.

use std::fs;
use std::path::Path;

/// Most `/proc` descriptor and mapping entries inspected by one scan.
const MAX_SCANNED_ENTRIES: usize = 65_536;

/// Most holders named in one diagnostic.
const MAX_REPORTED_HOLDERS: usize = 8;

const DELETED_SUFFIX: &str = " (deleted)";

/// Describes processes holding deleted files that were created under `directory`.
///
/// The result is diagnostic text: `none found`, a semicolon-separated holder
/// list, or a note that `/proc` could not be read. A truncated scan says so.
pub(super) fn deleted_file_holders(directory: &Path) -> String {
    let Ok(processes) = fs::read_dir("/proc") else {
        return String::from("unavailable: /proc is unreadable");
    };
    let prefix = format!("{}/", directory.display());
    let mut holders = Vec::new();
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
        let command = fs::read_to_string(process.path().join("comm"))
            .map(|command| command.trim().to_owned())
            .unwrap_or_default();

        let descriptors = fs::read_dir(process.path().join("fd"))
            .into_iter()
            .flatten();
        for descriptor in descriptors.flatten() {
            scanned += 1;
            if scanned > MAX_SCANNED_ENTRIES {
                truncated = true;
                break 'processes;
            }
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if is_deleted_under(&target, &prefix) {
                holders.push(format!(
                    "pid {pid} ({command}) fd {} -> {target}",
                    descriptor.file_name().to_string_lossy()
                ));
            }
        }

        let maps = fs::read_to_string(process.path().join("maps")).unwrap_or_default();
        for mapping in maps.lines() {
            scanned += 1;
            if scanned > MAX_SCANNED_ENTRIES {
                truncated = true;
                break 'processes;
            }
            // The pathname is the line's last field and may itself contain
            // spaces, including the deleted suffix; the prefix is absolute.
            let Some(start) = mapping.find(prefix.as_str()) else {
                continue;
            };
            let path = &mapping[start..];
            if is_deleted_under(path, &prefix) {
                holders.push(format!("pid {pid} ({command}) map {path}"));
                // One mapping per process is enough to name the holder.
                break;
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
    if truncated {
        report.push_str("; scan truncated");
    }
    report
}

fn is_deleted_under(target: &str, prefix: &str) -> bool {
    target.ends_with(DELETED_SUFFIX) && target.starts_with(prefix)
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- focused fixtures use exact panic messages.
    #![allow(clippy::expect_used)]

    use std::io::Write as _;
    use std::path::PathBuf;

    use super::*;

    /// Owns one fresh scan directory and removes it when dropped.
    struct ScanDirectory(PathBuf);

    impl ScanDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "crucible-deleted-holders-{name}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("scan directory");
            Self(path)
        }
    }

    impl Drop for ScanDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn names_this_process_for_an_unlinked_open_file() {
        let directory = ScanDirectory::new("unlinked");
        let path = directory.0.join("retained");
        let mut file = fs::File::create(&path).expect("retained file");
        file.write_all(b"held").expect("retained bytes");
        fs::remove_file(&path).expect("unlink retained file");

        let report = deleted_file_holders(&directory.0);

        assert!(
            report.contains(&format!("pid {} ", std::process::id())),
            "{report}"
        );
        assert!(report.contains("retained (deleted)"), "{report}");
        drop(file);
    }

    #[test]
    fn reports_none_for_a_directory_without_deleted_files() {
        let directory = ScanDirectory::new("live");
        fs::write(directory.0.join("present"), b"live").expect("live file");

        assert_eq!(deleted_file_holders(&directory.0), "none found");
    }
}
