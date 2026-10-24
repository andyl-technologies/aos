//! Exercises actual publisher confinement in fresh empty-capability guest actors.
//!
//! Sockets are unbound kernel objects. These controls send no traffic and use
//! no external endpoint. They construct no cache or serving proof.

use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
use std::{fs, io};
use terrane_linux::quota_confinement;

/// Runs a real kernel installation or refusal control before cache resources exist.
///
/// # Errors
/// Refuses another identity, capabilities, missing unconfined socket support,
/// unexpected confinement results or an installation that failed kernel checks.
pub(super) fn run(mode: &str) -> io::Result<()> {
    require_identity()?;
    match mode {
        "publisher-confinement" => {
            // Empty capabilities alone do not deny ordinary Internet sockets.
            // Close this positive control before auditing the role bootstrap.
            drop(internet_socket()?);
            let installed = quota_confinement::install_publisher()?;
            installed.check_current()?;
            match internet_socket() {
                Err(error) if error.raw_os_error() == Some(libc::EPERM) => {}
                Err(error) => return Err(error),
                Ok(_) => return Err(io::Error::other("publisher Internet socket was allowed")),
            }
            println!(
                "PASS actual publisher kernel denies Internet sockets and permits Unix transport; no Ready"
            );
        }
        "publisher-reject-descriptor" => {
            let socket = internet_socket()?;
            require_refusal("publisher inherited an undeclared descriptor")?;
            drop(socket);
            println!("PASS actual publisher rejects an undeclared preexisting network descriptor");
        }
        "publisher-reject-stdio" => {
            require_refusal("publisher inherited unsupported standard I/O")?;
            println!("PASS actual publisher rejects a network socket inherited as standard input");
        }
        _ => return Err(io::Error::other("unknown publisher confinement selector")),
    }
    require_identity()
}

fn internet_socket() -> io::Result<std::os::fd::OwnedFd> {
    Ok(net::socket_with(
        AddressFamily::INET,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

fn require_refusal(expected: &str) -> io::Result<()> {
    let error = quota_confinement::install_publisher()
        .err()
        .ok_or_else(|| io::Error::other("publisher accepted unsupported inherited descriptors"))?;
    if error.kind() != io::ErrorKind::PermissionDenied || error.to_string() != expected {
        return Err(io::Error::other(format!(
            "unexpected publisher refusal: {error}"
        )));
    }
    Ok(())
}

fn require_identity() -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 841 {
        return Err(io::Error::other(
            "publisher confinement actor UID must be 841",
        ));
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let expected = format!("{field}:\t0000000000000000");
        if !status.lines().any(|line| line == expected) {
            return Err(io::Error::other(
                "publisher confinement actor has capabilities",
            ));
        }
    }
    Ok(())
}
