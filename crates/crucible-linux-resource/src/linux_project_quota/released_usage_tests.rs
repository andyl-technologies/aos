//! Deleted-file holder diagnostics for released project-quota usage.

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
            "crucible-released-usage-{name}-{}",
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
fn reports_no_holder_for_live_files() {
    let directory = ScanDirectory::new("live");
    fs::write(directory.0.join("present"), b"live").expect("live file");
    let _open = fs::File::open(directory.0.join("present")).expect("open live file");

    let report = deleted_file_holders(&directory.0);

    // Other deleted files on the same filesystem may be reported.
    assert!(!report.contains("present"), "{report}");
    assert!(report.contains("(processes "), "{report}");
}
