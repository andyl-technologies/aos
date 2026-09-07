//! Exact systemd socket-activation descriptor adoption.

use std::os::fd::{FromRawFd as _, OwnedFd};

use crate::transport::ActivatedSeqpacketListener;
use crate::{HostError, Result};

const ACTIVATION_FD: i32 = 3;
const EXPECTED_FD_NAME: &str = "aos-sandbox-host";

/// Adopts the sole listener described by systemd's activation environment.
///
/// `LISTEN_PID` must name this exact process, `LISTEN_FDS` must be one, and an
/// optional `LISTEN_FDNAMES` must equal `aos-sandbox-host`. The descriptor is
/// then validated as a listening `SOCK_SEQPACKET` by
/// [`ActivatedSeqpacketListener`].
///
/// This function must run before the process creates any threads or closes FD
/// 3. It does not mutate the environment, so later child construction must use
/// an explicit sanitized environment rather than inheriting activation state.
///
/// # Errors
///
/// Returns an error for a missing/malformed/mismatched activation environment
/// or an invalid inherited descriptor.
pub fn take_systemd_listener() -> Result<ActivatedSeqpacketListener> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| HostError::State("current PID does not fit u32".to_owned()))?;
    if listen_pid != current_pid {
        return Err(HostError::State(
            "LISTEN_PID does not name this host broker".to_owned(),
        ));
    }
    if environment_u32("LISTEN_FDS")? != 1 {
        return Err(HostError::State(
            "host broker requires exactly one activated descriptor".to_owned(),
        ));
    }
    if let Some(names) = std::env::var_os("LISTEN_FDNAMES")
        && names != EXPECTED_FD_NAME
    {
        return Err(HostError::State(
            "activated descriptor has the wrong systemd name".to_owned(),
        ));
    }

    // SAFETY: systemd's validated LISTEN_PID/LISTEN_FDS contract transfers
    // unique ownership of descriptor 3 to this process. The typed listener
    // constructor immediately verifies the descriptor's kernel socket type,
    // listening state, and close-on-exec flag.
    let fd = unsafe { OwnedFd::from_raw_fd(ACTIVATION_FD) };
    ActivatedSeqpacketListener::from_owned(fd)
}

fn environment_u32(name: &'static str) -> Result<u32> {
    std::env::var(name)
        .map_err(|_| HostError::State(format!("{name} is absent")))?
        .parse()
        .map_err(|_| HostError::State(format!("{name} is not a decimal u32")))
}
