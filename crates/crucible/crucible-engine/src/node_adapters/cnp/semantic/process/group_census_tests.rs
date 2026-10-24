//! Exercises incomplete kernel census reads without assuming group reclamation.

use super::complete_group_stat_read;
use crucible_node_transport::ProviderError;
use std::{
    fs::File,
    io::{Error, ErrorKind, Read},
    os::unix::process::CommandExt,
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
