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

    // Concurrent processes on the filesystem may fill the bounded report;
    // inspect only this one.
    let own_process = std::process::id();
    let report = deleted_file_holders_among(&directory.0, |pid| pid == own_process);

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

#[test]
fn names_a_socket_whose_queue_holds_unread_bytes() {
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().expect("socket pair");
    (&sender).write_all(b"unread").expect("queue bytes");

    // Other processes on the host may queue bytes too; inspect only this one.
    let own_process = i32::try_from(std::process::id()).expect("process id");
    let report = kernel_held_candidates_among(|pid| pid == own_process);

    let receiver_descriptor = std::os::fd::AsRawFd::as_raw_fd(&receiver);
    assert!(
        report.contains(&format!(
            "pid {} ({}) fd {receiver_descriptor} socket:",
            std::process::id(),
            fs::read_to_string("/proc/self/comm")
                .expect("own command")
                .trim()
        )),
        "{report}"
    );
    assert!(report.contains("queued 6"), "{report}");
}

/// Replays scripted usage reads and counts the pauses the drain requests.
struct ScriptedUsage {
    reads: std::collections::VecDeque<Result<(u64, u64), &'static str>>,
    pauses: usize,
}

impl ScriptedUsage {
    fn new(reads: impl IntoIterator<Item = Result<(u64, u64), &'static str>>) -> Self {
        Self {
            reads: reads.into_iter().collect(),
            pauses: 0,
        }
    }

    fn drain(&mut self, pause_budget: usize) -> Result<ReleasedUsage, &'static str> {
        let reads = &mut self.reads;
        let pauses = &mut self.pauses;
        await_released_usage_drain(
            || reads.pop_front().expect("drain read past the script"),
            || {
                if *pauses == pause_budget {
                    return false;
                }
                *pauses += 1;
                true
            },
        )
    }
}

#[test]
fn drain_releases_immediately_when_usage_is_already_zero() {
    let mut usage = ScriptedUsage::new([Ok((0, 0))]);

    assert_eq!(usage.drain(4), Ok(ReleasedUsage::Drained));
    assert_eq!(usage.pauses, 0);
}

#[test]
fn drain_waits_for_deferred_release_to_settle() {
    let mut usage = ScriptedUsage::new([Ok((200_704, 1)), Ok((4_096, 1)), Ok((0, 0))]);

    assert_eq!(usage.drain(4), Ok(ReleasedUsage::Drained));
    assert_eq!(usage.pauses, 2);
    assert!(usage.reads.is_empty());
}

#[test]
fn drain_reports_the_last_read_when_usage_outlives_the_budget() {
    let mut usage = ScriptedUsage::new([Ok((8_192, 2)), Ok((8_192, 2)), Ok((4_096, 1))]);

    assert_eq!(
        usage.drain(2),
        Ok(ReleasedUsage::Held {
            bytes: 4_096,
            inodes: 1
        })
    );
    assert_eq!(usage.pauses, 2);
}

#[test]
fn drain_treats_nonzero_inodes_alone_as_held() {
    let mut usage = ScriptedUsage::new([Ok((0, 1))]);

    assert_eq!(
        usage.drain(0),
        Ok(ReleasedUsage::Held {
            bytes: 0,
            inodes: 1
        })
    );
}

#[test]
fn drain_stops_at_the_first_unreadable_usage() {
    let mut usage = ScriptedUsage::new([Ok((4_096, 1)), Err("quotactl refused")]);

    assert_eq!(usage.drain(4), Err("quotactl refused"));
    assert_eq!(usage.pauses, 1);
}

#[test]
fn sleeping_pauses_stop_after_their_budget() {
    let mut pause = sleeping_pauses(2, Duration::ZERO);

    assert!(pause());
    assert!(pause());
    assert!(!pause());
    assert!(!pause());
}

#[test]
fn sleeping_pauses_without_a_budget_decline_at_once() {
    let mut pause = sleeping_pauses(0, Duration::ZERO);

    assert!(!pause());
}
