//! Checks worker handle validation before irreversible process confinement.

#![cfg(target_os = "linux")]

use std::{fs::File, io, os::fd::AsFd, os::unix::net::UnixStream, process::Command};

#[test]
fn worker_network_refuses_non_fuse_handles_before_confining_the_caller()
-> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let regular = File::open(&executable)?;
    let null = File::options().read(true).write(true).open("/dev/null")?;
    let (socket, _peer) = UnixStream::pair()?;

    for descriptor in [regular.as_fd(), null.as_fd(), socket.as_fd()] {
        let error = terrane_linux::quota_confinement::install_worker_network(descriptor)
            .err()
            .ok_or("non-FUSE handle was accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    let output = Command::new(executable).arg("--list").output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    Ok(())
}
