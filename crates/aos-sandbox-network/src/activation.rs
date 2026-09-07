//! Exact systemd record-subject socket activation for `aos-netd`.

use std::os::fd::{FromRawFd as _, OwnedFd};

use aos_sandbox_linux::seqpacket::RecordSubjectListener;

use crate::service::NetworkServiceError;

const ACTIVATION_FD: i32 = 3;
const EXPECTED_FD_NAME: &str = "aos-netd";

/// Adopts the sole record-subject listener supplied by systemd.
///
/// `LISTEN_PID` must name this exact process, `LISTEN_FDS` must be one, and
/// `LISTEN_FDNAMES` must equal `aos-netd`. The listener must already be a Unix
/// `SOCK_SEQPACKET` listener with `SO_PASSCRED` and `SO_PASSPIDFD` enabled.
/// This function must run before any thread or unrelated descriptor is created.
///
/// # Errors
///
/// Returns [`NetworkServiceError`] when activation metadata is absent,
/// malformed, or mismatched, or descriptor 3 violates the listener contract.
pub fn take_systemd_listener() -> Result<RecordSubjectListener, NetworkServiceError> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| activation_error("current PID does not fit u32"))?;
    if listen_pid != current_pid {
        return Err(activation_error("LISTEN_PID does not name this process"));
    }
    if environment_u32("LISTEN_FDS")? != 1 {
        return Err(activation_error(
            "exactly one activated descriptor is required",
        ));
    }
    if std::env::var_os("LISTEN_FDNAMES").as_deref() != Some(EXPECTED_FD_NAME.as_ref()) {
        return Err(activation_error(
            "activated descriptor has the wrong systemd name",
        ));
    }

    // SAFETY: the validated systemd LISTEN_PID/LISTEN_FDS contract transfers
    // unique ownership of descriptor 3 to this single-threaded startup path.
    // The typed constructor immediately verifies its socket and identity flags.
    let fd = unsafe { OwnedFd::from_raw_fd(ACTIVATION_FD) };
    RecordSubjectListener::from_owned(fd).map_err(Into::into)
}

fn environment_u32(name: &'static str) -> Result<u32, NetworkServiceError> {
    std::env::var(name)
        .map_err(|_| activation_error(format!("{name} is absent")))?
        .parse()
        .map_err(|_| activation_error(format!("{name} is not a decimal u32")))
}

fn activation_error(message: impl Into<String>) -> NetworkServiceError {
    NetworkServiceError::Activation(message.into())
}
