//! Exact systemd record-subject socket activation for `aos-storaged`.

use aos_sandbox_linux::inherited_fd::duplicate_inherited_descriptor;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;

use crate::service::StorageServiceError;

const ACTIVATION_FD: i32 = 3;
const EXPECTED_FD_NAME: &str = "aos-storaged";
const EXPORT_FD_NAME: &str = "aos-storaged-root-export";

/// Adopts the controller and Host root-export listeners from one service activation.
///
/// # Errors
///
/// Rejects wrong PID, count, names, descriptor type, or missing record subjects.
pub fn take_systemd_listeners()
-> Result<(RecordSubjectListener, RecordSubjectListener), StorageServiceError> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| activation_error("current PID does not fit u32"))?;
    if listen_pid != current_pid || environment_u32("LISTEN_FDS")? != 2 {
        return Err(activation_error(
            "exactly two listeners for this process are required",
        ));
    }

    let names = std::env::var("LISTEN_FDNAMES")
        .map_err(|_| activation_error("activated descriptor names are absent"))?;
    let names: Vec<_> = names.split(':').collect();
    if names.len() != 2 || !names.contains(&EXPECTED_FD_NAME) || !names.contains(&EXPORT_FD_NAME) {
        return Err(activation_error("activated descriptor names are invalid"));
    }

    // Duplicate both inherited entries before a new descriptor can reuse either slot.
    let first = duplicate_inherited_descriptor(ACTIVATION_FD)?;
    let second = duplicate_inherited_descriptor(ACTIVATION_FD + 1)?;
    let (controller, export) = if names[0] == EXPECTED_FD_NAME {
        (first, second)
    } else {
        (second, first)
    };
    let controller = RecordSubjectListener::from_owned(controller)?;
    let export = RecordSubjectListener::from_owned(export)?;
    controller.require_local_filesystem_path(std::path::Path::new(
        "/run/aos/sandbox-storage/control.sock",
    ))?;
    export.require_local_filesystem_path(std::path::Path::new(
        "/run/aos/sandbox-storage/root-export.sock",
    ))?;
    Ok((controller, export))
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
