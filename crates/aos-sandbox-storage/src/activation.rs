//! Exact systemd record-subject socket activation for `aos-storaged`.

use aos_sandbox_linux::inherited_fd::duplicate_inherited_descriptor;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;

use crate::service::StorageServiceError;

const ACTIVATION_FD: i32 = 3;
const EXPECTED_FD_NAME: &str = "aos-storaged";

/// Duplicates and adopts the sole listener supplied by systemd.
///
/// `LISTEN_PID` must name this exact process, `LISTEN_FDS` must be one, and
/// `LISTEN_FDNAMES` must equal `aos-storaged`. The inherited listener must
/// already be a Unix `SOCK_SEQPACKET` listener with `SO_PASSCRED` and
/// `SO_PASSPIDFD` enabled before any child could be queued.
///
/// This function must run before the process creates threads or allocates an
/// unrelated descriptor. It safely duplicates descriptor 3 rather than
/// constructing a second owner for an untyped numeric descriptor.
///
/// # Errors
///
/// Returns [`StorageServiceError`] when activation metadata is absent,
/// malformed, or mismatched, descriptor duplication fails, or the listener
/// violates the record-subject contract.
pub fn take_systemd_listener() -> Result<RecordSubjectListener, StorageServiceError> {
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

    let fd = duplicate_inherited_descriptor(ACTIVATION_FD)?;
    RecordSubjectListener::from_owned(fd).map_err(Into::into)
}

fn environment_u32(name: &'static str) -> Result<u32, StorageServiceError> {
    std::env::var(name)
        .map_err(|_| activation_error(format!("{name} is absent")))?
        .parse()
        .map_err(|_| activation_error(format!("{name} is not a decimal u32")))
}

fn activation_error(message: impl Into<String>) -> StorageServiceError {
    StorageServiceError::Activation(message.into())
}
