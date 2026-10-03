//! Exact systemd record-subject socket activation for `aos-storaged`.

mod original_worker;

pub(crate) use original_worker::StorageOriginalWorkerStartupCauseV3;
pub use original_worker::{StorageOriginalWorkerStartupErrorV3, StorageOriginalWorkerStartupV3};

use std::os::fd::OwnedFd;

use aos_sandbox_linux::inherited_fd::duplicate_initial_activation_table;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_protocol::operator_storage_repair_transport_v3::OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V3;

use crate::service::StorageServiceError;

const EXPECTED_FD_NAME: &str = "aos-storaged";
const EXPORT_FD_NAME: &str = "aos-storaged-root-export";
const LIVE_EXPORT_FD_NAME: &str = "aos-storaged-live-export-request";
const ZFS_HOLD_FD_NAME: &str = "aos-storaged-zfs-hold-request";
const OPERATOR_REPAIR_FD_NAME: &str = "aos-storaged-operator-repair";
const EXISTING_OUTPUT_FD_NAME: &str = "aos-storaged-existing-output";

/// Names the parent-only original PID 1 image delivered by fixed-unit OpenFile.
pub const PID1_LAUNCH_IMAGE_FD_NAME: &str = "aos-method46-pid1-image";

/// The fixed Storage listener roles, without any TPM or image authorization.
pub type StorageSystemdListenersV1 = (
    RecordSubjectListener,
    RecordSubjectListener,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
);

/// Owns an observed complete startup table, not authenticated image custody.
pub struct CapturedStorageStartupV1 {
    listeners: StorageSystemdListenersV1,
    pid1_image: Option<OwnedFd>,
}

impl CapturedStorageStartupV1 {
    /// Returns observed listener roles and an unverified original launch image.
    #[must_use]
    pub fn into_parts(self) -> (StorageSystemdListenersV1, Option<OwnedFd>) {
        (self.listeners, self.pid1_image)
    }

    /// Admits worker startup custody from this one complete actual capture.
    ///
    /// The same original image remains available to the separate Security
    /// owner. Absence returns `None`, never an admitted empty image or grant.
    /// The returned opaque owner conveys no floor or backend readiness.
    ///
    /// # Errors
    ///
    /// Rejects changed actual process, unit, image, or confinement. Admission
    /// failure owns the original table and any partial retained observations.
    pub fn into_original_worker_parts(
        self,
    ) -> Result<
        (
            StorageSystemdListenersV1,
            Option<OwnedFd>,
            Option<StorageOriginalWorkerStartupV3>,
        ),
        StorageOriginalWorkerStartupErrorV3,
    > {
        original_worker::admit_captured(self)
    }
}

/// Adopts the required listeners and an optional closed Provider request listener.
///
/// # Errors
///
/// Rejects wrong PID, count, names, descriptor type, or missing record subjects.
pub fn take_systemd_listeners() -> Result<StorageSystemdListenersV1, StorageServiceError> {
    let (listeners, image) = take_systemd_startup()?.into_parts();
    if image.is_some() {
        return Err(activation_error(
            "legacy listener adoption cannot consume a PID 1 image",
        ));
    }
    Ok(listeners)
}

/// Captures fixed listeners and at most one observed parent-only image FD.
///
/// Every numeric entry is copied before opening any other retained descriptor.
/// Names and environment are correlation hints only. The security owner must
/// independently authenticate the fixed unit, image mode, and actual image.
///
/// # Errors
///
/// Rejects malformed names/counts, a nonclosed startup table, invalid listeners,
/// or an unknown descriptor. This single-shot operation cannot be retried.
pub fn take_systemd_startup() -> Result<CapturedStorageStartupV1, StorageServiceError> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| activation_error("current PID does not fit u32"))?;
    let descriptor_count = environment_u32("LISTEN_FDS")?;
    if listen_pid != current_pid || !(2..=7).contains(&descriptor_count) {
        return Err(activation_error(
            "two to seven named startup entries are required",
        ));
    }

    let names = std::env::var("LISTEN_FDNAMES")
        .map_err(|_| activation_error("activated descriptor names are absent"))?;
    if names.len() > 7 * 256
        || !names.is_ascii()
        || names.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(activation_error(
            "activated descriptor names exceed fixed bounds",
        ));
    }
    let names: Vec<_> = names.split(':').collect();
    if !valid_startup_names(&names, descriptor_count) {
        return Err(activation_error("activated descriptor names are invalid"));
    }

    // Duplicate every inherited entry before a new descriptor can reuse a slot.
    let descriptors = duplicate_initial_activation_table(descriptor_count as usize)?;
    let mut controller = None;
    let mut export = None;
    let mut live_export = None;
    let mut zfs_hold = None;
    let mut operator_repair = None;
    let mut existing_output = None;
    let mut pid1_image = None;
    for (name, descriptor) in names.into_iter().zip(descriptors) {
        match name {
            EXPECTED_FD_NAME => controller = Some(descriptor),
            EXPORT_FD_NAME => export = Some(descriptor),
            LIVE_EXPORT_FD_NAME => live_export = Some(descriptor),
            ZFS_HOLD_FD_NAME => zfs_hold = Some(descriptor),
            OPERATOR_REPAIR_FD_NAME => operator_repair = Some(descriptor),
            EXISTING_OUTPUT_FD_NAME => existing_output = Some(descriptor),
            PID1_LAUNCH_IMAGE_FD_NAME => pid1_image = Some(descriptor),
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
    let zfs_hold = zfs_hold
        .map(RecordSubjectListener::from_owned)
        .transpose()?;
    let operator_repair = operator_repair
        .map(RecordSubjectListener::from_owned)
        .transpose()?;
    let existing_output = existing_output
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
    if let Some(listener) = &zfs_hold {
        listener.require_local_filesystem_path(std::path::Path::new(
            "/run/aos/sandbox-storage/zfs-hold-request.sock",
        ))?;
    }
    if let Some(listener) = &operator_repair {
        listener.require_local_filesystem_path(std::path::Path::new(
            OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V3,
        ))?;
    }
    if let Some(listener) = &existing_output {
        listener.require_local_filesystem_path(std::path::Path::new(
            "/run/aos/sandbox-storage/existing-output.sock",
        ))?;
    }
    Ok(CapturedStorageStartupV1 {
        listeners: (
            controller,
            export,
            live_export,
            zfs_hold,
            operator_repair,
            existing_output,
        ),
        pid1_image,
    })
}

fn valid_startup_names(names: &[&str], descriptor_count: u32) -> bool {
    let images = names
        .iter()
        .filter(|name| **name == PID1_LAUNCH_IMAGE_FD_NAME)
        .count();
    let listeners = names
        .iter()
        .copied()
        .filter(|name| *name != PID1_LAUNCH_IMAGE_FD_NAME)
        .collect::<Vec<_>>();
    (2..=7).contains(&descriptor_count)
        && names.len() == descriptor_count as usize
        && images <= 1
        && valid_listener_names(&listeners, descriptor_count - images as u32)
}

fn valid_listener_names(names: &[&str], descriptor_count: u32) -> bool {
    (2..=6).contains(&descriptor_count)
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
            .filter(|name| **name == ZFS_HOLD_FD_NAME)
            .count()
            <= 1
        && names
            .iter()
            .filter(|name| **name == OPERATOR_REPAIR_FD_NAME)
            .count()
            <= 1
        && names
            .iter()
            .filter(|name| **name == EXISTING_OUTPUT_FD_NAME)
            .count()
            <= 1
        && names.iter().all(|name| {
            matches!(
                *name,
                EXPECTED_FD_NAME
                    | EXPORT_FD_NAME
                    | LIVE_EXPORT_FD_NAME
                    | ZFS_HOLD_FD_NAME
                    | OPERATOR_REPAIR_FD_NAME
                    | EXISTING_OUTPUT_FD_NAME
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
            &[ZFS_HOLD_FD_NAME, EXPECTED_FD_NAME, EXPORT_FD_NAME],
            3,
        ));
        assert!(!valid_listener_names(
            &[
                ZFS_HOLD_FD_NAME,
                ZFS_HOLD_FD_NAME,
                EXPECTED_FD_NAME,
                EXPORT_FD_NAME
            ],
            4,
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
        assert!(valid_listener_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, EXISTING_OUTPUT_FD_NAME],
            3,
        ));
        assert!(!valid_listener_names(
            &[
                EXPECTED_FD_NAME,
                EXPORT_FD_NAME,
                EXISTING_OUTPUT_FD_NAME,
                EXISTING_OUTPUT_FD_NAME
            ],
            4,
        ));
    }

    #[test]
    fn activation_pid1_image_is_unique_and_separate_from_listener_roles() {
        assert!(valid_startup_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, PID1_LAUNCH_IMAGE_FD_NAME],
            3
        ));
        assert!(valid_startup_names(&[EXPECTED_FD_NAME, EXPORT_FD_NAME], 2));
        assert!(!valid_listener_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, PID1_LAUNCH_IMAGE_FD_NAME],
            3
        ));
        assert!(!valid_startup_names(
            &[
                EXPECTED_FD_NAME,
                EXPORT_FD_NAME,
                PID1_LAUNCH_IMAGE_FD_NAME,
                PID1_LAUNCH_IMAGE_FD_NAME
            ],
            4
        ));
        assert!(!valid_startup_names(
            &[EXPECTED_FD_NAME, PID1_LAUNCH_IMAGE_FD_NAME],
            2
        ));
        assert!(!valid_startup_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, "wrong-image"],
            3
        ));
    }
}
