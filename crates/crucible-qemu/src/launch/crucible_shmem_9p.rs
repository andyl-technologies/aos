//! Crucible-shmem 9p device attachment for deterministic QEMU launches.
//!
//! A [`CrucibleShmem9pDevice`] attaches a stock virtio-9p device to a launched
//! guest. The carried QEMU patch series (`0019-crucible-9p-shmem`) intercepts
//! the *stock* virtio-9p transport: when the plugin has registered its 9p
//! callbacks (`crucible_9p_callbacks_ready()`), every 9p PDU the guest submits is
//! forwarded over the `SLOT_9P_IO` shared-memory rings to the host servicer
//! instead of being handled by QEMU's fsdev backend. There is therefore no
//! bespoke crucible fsdev driver (unlike the block device's
//! `-drive driver=crucible-shmem`); the `-fsdev` backend is a launch formality
//! the plugin bypasses.
//!
//! The default backend is [`synth`](CrucibleShmem9pFsdevBackend::Synth), a
//! hermetic synthetic filesystem that consults no host path. A
//! [`local`](CrucibleShmem9pFsdevBackend::Local) passthrough backend is offered
//! only as a fallback for a QEMU build that lacks the synth fsdev; it names a
//! host directory and is therefore non-hermetic.
//!
//! Argv layout (emitted only when a device is attached; a launch without one is
//! byte-identical to a launch that never knew about this type):
//!
//! ```text
//! -fsdev synth,id=<fsdev_id>
//! -device virtio-9p-pci,fsdev=<fsdev_id>,mount_tag=<mount_tag>,id=<device_id>
//! ```
//!
//! or, with the local fallback backend:
//!
//! ```text
//! -fsdev local,id=<fsdev_id>,path=<host_path>,security_model=none
//! -device virtio-9p-pci,fsdev=<fsdev_id>,mount_tag=<mount_tag>,id=<device_id>
//! ```

use super::QemuLaunchCommandError;

/// Default `-fsdev` identifier bound to the crucible-shmem 9p device.
pub const DEFAULT_CRUCIBLE_SHMEM_9P_FSDEV_ID: &str = "crucible-9p-fsdev0";

/// Default `-device` identifier for the attached virtio-9p front-end.
pub const DEFAULT_CRUCIBLE_SHMEM_9P_DEVICE_ID: &str = "crucible-9p-device0";

/// Default 9p mount tag the guest uses to mount the crucible filesystem.
pub const DEFAULT_CRUCIBLE_SHMEM_9P_MOUNT_TAG: &str = "crucible";

/// The `-fsdev` backend the crucible-shmem 9p device is launched with.
///
/// The plugin intercepts 9p PDUs before the backend is consulted, so the backend
/// choice never affects the data a crucible-serviced 9p op observes. It only
/// determines which fsdev QEMU registers to satisfy the `-device` reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrucibleShmem9pFsdevBackend {
    /// Hermetic synthetic backend (`-fsdev synth`); no host path. Preferred: the
    /// crucible plugin forwards every PDU over `SLOT_9P_IO`, so the synth tree is
    /// never read and the launch stays hermetic.
    Synth,
    /// Host-directory passthrough backend (`-fsdev local`), a non-hermetic
    /// fallback for a QEMU build without the synth fsdev. The named directory is
    /// never actually read on the crucible path, but naming a host path makes the
    /// launch non-hermetic, so this variant is used only when synth is absent.
    Local {
        /// Host directory path passed to the local fsdev backend.
        path: String,
    },
}

/// A crucible-shmem 9p device attached to a launched guest.
///
/// The device is a stock virtio-9p front-end whose PDUs are intercepted by the
/// carried QEMU patch and forwarded to the host 9p servicer over the
/// `SLOT_9P_IO` shared-memory rings. Every field contributes to deterministic
/// launch identity like every other launch input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleShmem9pDevice {
    /// `-fsdev` identifier bound to the (bypassed) fsdev backend.
    fsdev_id: String,
    /// `-device` identifier for the virtio-9p front-end.
    device_id: String,
    /// 9p mount tag the guest addresses the filesystem by.
    mount_tag: String,
    /// The fsdev backend QEMU registers to satisfy the device reference.
    backend: CrucibleShmem9pFsdevBackend,
}

impl CrucibleShmem9pDevice {
    /// Builds a crucible-shmem 9p device with default ids and the synth backend.
    ///
    /// Identifiers and the mount tag are validated only when the enclosing launch
    /// config is validated; construction itself never fails.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fsdev_id: DEFAULT_CRUCIBLE_SHMEM_9P_FSDEV_ID.to_owned(),
            device_id: DEFAULT_CRUCIBLE_SHMEM_9P_DEVICE_ID.to_owned(),
            mount_tag: DEFAULT_CRUCIBLE_SHMEM_9P_MOUNT_TAG.to_owned(),
            backend: CrucibleShmem9pFsdevBackend::Synth,
        }
    }

    /// Returns the device with explicit `-fsdev` and `-device` identifiers.
    #[must_use]
    pub fn with_ids(mut self, fsdev_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        self.fsdev_id = fsdev_id.into();
        self.device_id = device_id.into();
        self
    }

    /// Returns the device with an explicit 9p mount tag.
    #[must_use]
    pub fn with_mount_tag(mut self, mount_tag: impl Into<String>) -> Self {
        self.mount_tag = mount_tag.into();
        self
    }

    /// Returns the device with an explicit fsdev backend.
    #[must_use]
    pub fn with_backend(mut self, backend: CrucibleShmem9pFsdevBackend) -> Self {
        self.backend = backend;
        self
    }

    /// Returns the `-fsdev` identifier bound to the fsdev backend.
    #[must_use]
    pub fn fsdev_id(&self) -> &str {
        &self.fsdev_id
    }

    /// Returns the `-device` identifier for the virtio-9p front-end.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Returns the 9p mount tag the guest addresses the filesystem by.
    #[must_use]
    pub fn mount_tag(&self) -> &str {
        &self.mount_tag
    }

    /// Returns the fsdev backend the device is launched with.
    #[must_use]
    pub const fn backend(&self) -> &CrucibleShmem9pFsdevBackend {
        &self.backend
    }

    /// Appends the `-fsdev`/`-device` argument pair for this device.
    pub(crate) fn append_qemu_args(&self, args: &mut Vec<String>) {
        args.push("-fsdev".to_owned());
        match &self.backend {
            CrucibleShmem9pFsdevBackend::Synth => {
                args.push(format!("synth,id={}", self.fsdev_id));
            }
            CrucibleShmem9pFsdevBackend::Local { path } => {
                args.push(format!(
                    "local,id={},path={},security_model=none",
                    self.fsdev_id, path
                ));
            }
        }
        args.push("-device".to_owned());
        args.push(format!(
            "virtio-9p-pci,fsdev={},mount_tag={},id={}",
            self.fsdev_id, self.mount_tag, self.device_id
        ));
    }

    /// Appends canonical launch-identity lines describing this device.
    pub(super) fn append_hash_material(&self, lines: &mut Vec<String>) {
        lines.push("crucible_shmem_9p=present".to_owned());
        lines.push(format!("crucible_shmem_9p_fsdev_id={}", self.fsdev_id));
        lines.push(format!("crucible_shmem_9p_device_id={}", self.device_id));
        lines.push(format!("crucible_shmem_9p_mount_tag={}", self.mount_tag));
        match &self.backend {
            CrucibleShmem9pFsdevBackend::Synth => {
                lines.push("crucible_shmem_9p_backend=synth".to_owned());
            }
            CrucibleShmem9pFsdevBackend::Local { path } => {
                lines.push("crucible_shmem_9p_backend=local".to_owned());
                lines.push(format!("crucible_shmem_9p_backend_path={path}"));
            }
        }
    }

    /// Validates the identifiers, mount tag, and backend of this device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError::InvalidLaunchText`] when an identifier,
    /// the mount tag, or a local backend path is empty or contains a newline, NUL
    /// byte, comma, or `=` (any of which would corrupt the comma-separated QEMU
    /// option it is spliced into). A local backend path may contain neither a
    /// comma nor an `=`, so it must not embed those characters.
    pub(crate) fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        validate_option_token("crucible_shmem_9p_fsdev_id", &self.fsdev_id)?;
        validate_option_token("crucible_shmem_9p_device_id", &self.device_id)?;
        validate_option_token("crucible_shmem_9p_mount_tag", &self.mount_tag)?;
        if let CrucibleShmem9pFsdevBackend::Local { path } = &self.backend {
            validate_option_token("crucible_shmem_9p_backend_path", path)?;
        }
        Ok(())
    }
}

impl Default for CrucibleShmem9pDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates one token spliced into a comma-separated QEMU option string.
///
/// # Errors
///
/// Returns [`QemuLaunchCommandError::InvalidLaunchText`] when `value` is empty
/// or carries a newline, NUL byte, comma, or `=`.
fn validate_option_token(field: &'static str, value: &str) -> Result<(), QemuLaunchCommandError> {
    super::validate_launch_text(field, value)?;
    if value.contains(',') || value.contains('=') {
        return Err(QemuLaunchCommandError::InvalidLaunchText { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ids_and_synth_backend_apply() {
        let device = CrucibleShmem9pDevice::new();
        assert_eq!(device.fsdev_id(), DEFAULT_CRUCIBLE_SHMEM_9P_FSDEV_ID);
        assert_eq!(device.device_id(), DEFAULT_CRUCIBLE_SHMEM_9P_DEVICE_ID);
        assert_eq!(device.mount_tag(), DEFAULT_CRUCIBLE_SHMEM_9P_MOUNT_TAG);
        assert_eq!(device.backend(), &CrucibleShmem9pFsdevBackend::Synth);
    }

    #[test]
    fn args_use_synth_fsdev_and_virtio_9p_pci() {
        let device = CrucibleShmem9pDevice::new();
        let mut args = Vec::new();
        device.append_qemu_args(&mut args);
        assert_eq!(
            args,
            vec![
                "-fsdev".to_owned(),
                "synth,id=crucible-9p-fsdev0".to_owned(),
                "-device".to_owned(),
                "virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0"
                    .to_owned(),
            ]
        );
    }

    #[test]
    fn args_use_local_backend_when_selected() {
        let device =
            CrucibleShmem9pDevice::new().with_backend(CrucibleShmem9pFsdevBackend::Local {
                path: "/scratch/9p".to_owned(),
            });
        let mut args = Vec::new();
        device.append_qemu_args(&mut args);
        assert_eq!(
            args,
            vec![
                "-fsdev".to_owned(),
                "local,id=crucible-9p-fsdev0,path=/scratch/9p,security_model=none".to_owned(),
                "-device".to_owned(),
                "virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0"
                    .to_owned(),
            ]
        );
    }

    #[test]
    fn hash_material_is_present_marker_plus_fields() {
        let device = CrucibleShmem9pDevice::new()
            .with_ids("fs-a", "fs-a-device")
            .with_mount_tag("tag-a");
        let mut lines = Vec::new();
        device.append_hash_material(&mut lines);
        assert_eq!(
            lines,
            vec![
                "crucible_shmem_9p=present".to_owned(),
                "crucible_shmem_9p_fsdev_id=fs-a".to_owned(),
                "crucible_shmem_9p_device_id=fs-a-device".to_owned(),
                "crucible_shmem_9p_mount_tag=tag-a".to_owned(),
                "crucible_shmem_9p_backend=synth".to_owned(),
            ]
        );
    }

    #[test]
    fn hash_material_records_local_backend_path() {
        let device =
            CrucibleShmem9pDevice::new().with_backend(CrucibleShmem9pFsdevBackend::Local {
                path: "/scratch/9p".to_owned(),
            });
        let mut lines = Vec::new();
        device.append_hash_material(&mut lines);
        assert!(lines.contains(&"crucible_shmem_9p_backend=local".to_owned()));
        assert!(lines.contains(&"crucible_shmem_9p_backend_path=/scratch/9p".to_owned()));
    }

    #[test]
    fn validate_accepts_defaults() {
        assert!(CrucibleShmem9pDevice::new().validate().is_ok());
    }

    #[test]
    fn validate_rejects_comma_in_mount_tag() {
        assert!(matches!(
            CrucibleShmem9pDevice::new()
                .with_mount_tag("bad,tag")
                .validate(),
            Err(QemuLaunchCommandError::InvalidLaunchText {
                field: "crucible_shmem_9p_mount_tag"
            })
        ));
    }

    #[test]
    fn validate_rejects_equals_in_device_id() {
        assert!(matches!(
            CrucibleShmem9pDevice::new()
                .with_ids(DEFAULT_CRUCIBLE_SHMEM_9P_FSDEV_ID, "bad=id")
                .validate(),
            Err(QemuLaunchCommandError::InvalidLaunchText {
                field: "crucible_shmem_9p_device_id"
            })
        ));
    }

    #[test]
    fn validate_rejects_empty_fsdev_id() {
        assert!(matches!(
            CrucibleShmem9pDevice::new()
                .with_ids("", DEFAULT_CRUCIBLE_SHMEM_9P_DEVICE_ID)
                .validate(),
            Err(QemuLaunchCommandError::InvalidLaunchText { .. })
        ));
    }

    #[test]
    fn validate_rejects_comma_in_local_path() {
        assert!(matches!(
            CrucibleShmem9pDevice::new()
                .with_backend(CrucibleShmem9pFsdevBackend::Local {
                    path: "/bad,path".to_owned()
                })
                .validate(),
            Err(QemuLaunchCommandError::InvalidLaunchText {
                field: "crucible_shmem_9p_backend_path"
            })
        ));
    }
}
