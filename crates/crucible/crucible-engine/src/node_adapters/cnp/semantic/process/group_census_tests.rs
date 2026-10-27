//! Exercises incomplete kernel census reads without assuming group reclamation.

use super::{GroupStatFile, complete_group_stat_read, group_stat_group, open_group_stat};
use crucible_node_transport::ProviderError;
use std::{
    fs::File,
    io::{Error, ErrorKind, Read},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
};

#[test]
fn a_task_reaped_after_stat_open_requires_another_complete_census()
-> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "node_adapters::cnp::semantic::tests::process::generic_owned_process",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()?;
    let path = format!("/proc/{}/stat", child.id());
    let opened = File::open(&path);
    let mut live_bytes = Vec::new();
    let live_read =
        File::open(&path).and_then(|file| file.take(65_537).read_to_end(&mut live_bytes));

    // Close only this original child's pipe and reap it before asserting. The
    // open stat descriptor remains bound to the exited task across PID reuse.
    drop(child.stdin.take());
    let status = child.wait();
    let file = opened?;
    assert!(status?.success());
    assert!(complete_group_stat_read(live_read)?);
    assert!(!live_bytes.is_empty());

    let mut departed_bytes = Vec::new();
    let departed_read = file.take(65_537).read_to_end(&mut departed_bytes);
    assert_eq!(
        departed_read
            .as_ref()
            .err()
            .ok_or("departed task stat unexpectedly remained readable")?
            .raw_os_error(),
        Some(rustix::io::Errno::SRCH.raw_os_error()),
    );
    assert!(!complete_group_stat_read(departed_read)?);
    Ok(())
}

#[test]
fn other_stat_read_failures_cannot_become_reclamation_evidence() {
    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::InvalidData,
        ErrorKind::UnexpectedEof,
        ErrorKind::NotFound,
    ] {
        assert!(matches!(
            complete_group_stat_read(Err(Error::from(kind))),
            Err(ProviderError::Io(error)) if error.kind() == kind
        ));
    }
}

#[test]
fn a_task_reaped_before_stat_open_requires_another_complete_census()
-> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "node_adapters::cnp::semantic::tests::process::generic_owned_process",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()?;
    let path = format!("/proc/{}", child.id());
    let directory = File::open(&path);
    let live = open_group_stat(&std::path::Path::new(&path).join("stat"));

    // Hold the actual proc directory across reaping. This reproduces a task
    // disappearing between pathname lookup and opening its stat entry.
    drop(child.stdin.take());
    let status = child.wait();
    let directory = directory?;
    assert!(status?.success());
    assert!(matches!(live?, GroupStatFile::Present(_)));
    let departed = format!("/proc/self/fd/{}/stat", directory.as_raw_fd());

    assert!(matches!(
        open_group_stat(std::path::Path::new(&departed))?,
        GroupStatFile::Departed,
    ));
    Ok(())
}

#[test]
fn absent_proc_rows_remain_distinct_from_other_open_errors()
-> Result<(), Box<dyn std::error::Error>> {
    // PID zero has no task directory, independently of process allocation.
    assert!(matches!(
        open_group_stat(std::path::Path::new("/proc/0/stat"))?,
        GroupStatFile::Absent,
    ));
    assert!(matches!(
        open_group_stat(std::path::Path::new("/proc/self/stat/child")),
        Err(ProviderError::Io(error)) if error.kind() == ErrorKind::NotADirectory,
    ));
    Ok(())
}

#[test]
fn a_kernel_unavailable_group_row_requires_another_complete_census() {
    // do_task_stat's literal -1 is a kernel sentinel, not a reclamation proof.
    // Spaces and parenthesis in comm do not change the group field's position.
    let row = b"123 (departing task (worker)) X 1 -1 -1 0 -1 0\n";
    assert_eq!(group_stat_group(row).unwrap(), None);
    for group in [0, 1, 123, u32::MAX] {
        let row = format!("123 (live task (worker)) S 1 {group} 1 0 -1 0\n");
        assert_eq!(group_stat_group(row.as_bytes()).unwrap(), Some(group));
    }
}

#[test]
fn malformed_kernel_group_rows_still_refuse_reclamation() {
    for row in [
        b"123 missing-comm S 1 123 1".as_slice(),
        b"123 (task) S 1",
        b"123 (task) S 1 -2 1",
        b"123 (task) S 1 -01 1",
        b"123 (task) S 1 4294967296 1",
        b"123 (task) S 1 invalid 1",
        b"123 (task) S 1 12\xff 1",
    ] {
        assert!(group_stat_group(row).is_err(), "{row:?}");
    }
}
