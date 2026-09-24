//! Exact systemd record-subject socket activation for `aos-storaged`.

use aos_sandbox_linux::inherited_fd::duplicate_inherited_descriptor;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_protocol::operator_storage_repair_transport_v2::OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V2;

use crate::service::StorageServiceError;

const ACTIVATION_FD: i32 = 3;
const EXPECTED_FD_NAME: &str = "aos-storaged";
const EXPORT_FD_NAME: &str = "aos-storaged-root-export";
const LIVE_EXPORT_FD_NAME: &str = "aos-storaged-live-export-request";
const OPERATOR_REPAIR_FD_NAME: &str = "aos-storaged-operator-repair";

/// Adopts the required listeners and an optional closed Provider request listener.
///
/// # Errors
///
/// Rejects wrong PID, count, names, descriptor type, or missing record subjects.
pub fn take_systemd_listeners() -> Result<
    (
        RecordSubjectListener,
        RecordSubjectListener,
        Option<RecordSubjectListener>,
        Option<RecordSubjectListener>,
    ),
    StorageServiceError,
> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| activation_error("current PID does not fit u32"))?;
    let descriptor_count = environment_u32("LISTEN_FDS")?;
    if listen_pid != current_pid || !(2..=4).contains(&descriptor_count) {
        return Err(activation_error("two to four named listeners are required"));
    }

    let names = std::env::var("LISTEN_FDNAMES")
        .map_err(|_| activation_error("activated descriptor names are absent"))?;
    let names: Vec<_> = names.split(':').collect();
    if !valid_listener_names(&names, descriptor_count) {
        return Err(activation_error("activated descriptor names are invalid"));
    }

    // Duplicate every inherited entry before a new descriptor can reuse a slot.
    let first = duplicate_inherited_descriptor(ACTIVATION_FD)?;
    let second = duplicate_inherited_descriptor(ACTIVATION_FD + 1)?;
    let third = if descriptor_count >= 3 {
        Some(duplicate_inherited_descriptor(ACTIVATION_FD + 2)?)
    } else {
        None
    };
    let fourth = if descriptor_count == 4 {
        Some(duplicate_inherited_descriptor(ACTIVATION_FD + 3)?)
    } else {
        None
    };
    let mut controller = None;
    let mut export = None;
    let mut live_export = None;
    let mut operator_repair = None;
    for (name, descriptor) in names
        .into_iter()
        .zip([Some(first), Some(second), third, fourth])
    {
        let descriptor =
            descriptor.ok_or_else(|| activation_error("activation descriptor is absent"))?;
        match name {
            EXPECTED_FD_NAME => controller = Some(descriptor),
            EXPORT_FD_NAME => export = Some(descriptor),
            LIVE_EXPORT_FD_NAME => live_export = Some(descriptor),
            OPERATOR_REPAIR_FD_NAME => operator_repair = Some(descriptor),
            _ => return Err(activation_error("activated descriptor name is unknown")),
        }
    }
    let controller = controller.ok_or_else(|| activation_error("controller listener is absent"))?;
    let export = export.ok_or_else(|| activation_error("root-export listener is absent"))?;
    let controller = RecordSubjectListener::from_owned(controller)?;
    let export = RecordSubjectListener::from_owned(export)?;
    let live_export = live_export
        .map(RecordSubjectListener::from_owned)
        .transpose()?;
    let operator_repair = operator_repair
        .map(RecordSubjectListener::from_owned)
        .transpose()?;
    controller.require_local_filesystem_path(std::path::Path::new(
        "/run/aos/sandbox-storage/control.sock",
    ))?;
    export.require_local_filesystem_path(std::path::Path::new(
        "/run/aos/sandbox-storage/root-export.sock",
    ))?;
    if let Some(listener) = &live_export {
        listener.require_local_filesystem_path(std::path::Path::new(
            "/run/aos/sandbox-storage/live-export-request.sock",
        ))?;
    }
    if let Some(listener) = &operator_repair {
        listener.require_local_filesystem_path(std::path::Path::new(
            OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V2,
        ))?;
    }
    Ok((controller, export, live_export, operator_repair))
}

fn valid_listener_names(names: &[&str], descriptor_count: u32) -> bool {
    (2..=4).contains(&descriptor_count)
        && names.len() == descriptor_count as usize
        && names.contains(&EXPECTED_FD_NAME)
        && names.contains(&EXPORT_FD_NAME)
        && names
            .iter()
            .filter(|name| **name == EXPECTED_FD_NAME)
            .count()
            == 1
        && names.iter().filter(|name| **name == EXPORT_FD_NAME).count() == 1
        && names
            .iter()
            .filter(|name| **name == LIVE_EXPORT_FD_NAME)
            .count()
            <= 1
        && names
            .iter()
            .filter(|name| **name == OPERATOR_REPAIR_FD_NAME)
            .count()
            <= 1
        && names.iter().all(|name| {
            matches!(
                *name,
                EXPECTED_FD_NAME | EXPORT_FD_NAME | LIVE_EXPORT_FD_NAME | OPERATOR_REPAIR_FD_NAME
            )
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_accepts_only_exact_named_tables() {
        assert!(valid_listener_names(&[EXPECTED_FD_NAME, EXPORT_FD_NAME], 2));
        assert!(valid_listener_names(
            &[LIVE_EXPORT_FD_NAME, EXPECTED_FD_NAME, EXPORT_FD_NAME],
            3,
        ));
        assert!(valid_listener_names(
            &[OPERATOR_REPAIR_FD_NAME, EXPECTED_FD_NAME, EXPORT_FD_NAME],
            3,
        ));
        assert!(valid_listener_names(
            &[
                OPERATOR_REPAIR_FD_NAME,
                LIVE_EXPORT_FD_NAME,
                EXPECTED_FD_NAME,
                EXPORT_FD_NAME,
            ],
            4,
        ));
        assert!(!valid_listener_names(
            &[EXPECTED_FD_NAME, LIVE_EXPORT_FD_NAME],
            2
        ));
        assert!(!valid_listener_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, EXPORT_FD_NAME],
            3,
        ));
        assert!(!valid_listener_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, "foreign"],
            3,
        ));
    }
}
