//! Crucible-shmem block device attachment for deterministic QEMU launches.
//!
//! A [`CrucibleShmemBlockDevice`] attaches the patched-QEMU `crucible-shmem`
//! block driver to a launched guest as a virtio-blk device. The device's
//! backend is the host I/O sub-node that services the `SLOT_BLK_IO`
//! shared-memory rings; the guest reaches it as an ordinary virtio-blk disk.
//!
//! The driver is opened through the legacy `-drive driver=<name>` interface,
//! which resolves the driver by name against QEMU's runtime-registered block
//! driver list. That path deliberately does not require a `BlockdevDriver` QAPI
//! enum entry, so the carried QEMU patch series needs no schema change to make
//! the device openable. The modern `-blockdev driver=crucible-shmem` spelling
//! would require such an enum entry and is intentionally not used here.
//!
//! Argv layout (emitted only when a device is attached; a launch without one is
//! byte-identical to a launch that never knew about this type):
//!
//! ```text
//! -drive driver=crucible-shmem,if=none,id=<drive_id>,size=<size_bytes>
//! -device virtio-blk-pci,drive=<drive_id>,id=<device_id>
//! ```

use super::QemuLaunchCommandError;

/// Sector size, in bytes, that a crucible-shmem device length must be a whole
/// multiple of so virtio-blk reports an integral sector count.
const CRUCIBLE_SHMEM_BLOCK_SECTOR_BYTES: u64 = 512;

/// Upper bound, in bytes, on a modeled crucible-shmem device length. The bound
/// guards against accidental unit typos rather than any storage limit.
const CRUCIBLE_SHMEM_BLOCK_MAX_BYTES: u64 = 1 << 40;

/// Default `-drive` identifier bound to the crucible-shmem block backend.
pub const DEFAULT_CRUCIBLE_SHMEM_DRIVE_ID: &str = "crucible-blk0";

/// Default `-device` identifier for the attached virtio-blk front-end.
pub const DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID: &str = "crucible-blk-device0";

/// A crucible-shmem block device attached to a launched guest.
///
/// The device is backed by the host I/O sub-node over the `SLOT_BLK_IO`
/// shared-memory rings; the fixed `size_bytes` length is reported to the guest
/// without consulting any host file, so it contributes to deterministic launch
/// identity like every other launch input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleShmemBlockDevice {
    /// `-drive` identifier bound to the crucible-shmem backend.
    drive_id: String,
    /// `-device` identifier for the virtio-blk front-end.
    device_id: String,
    /// Fixed device length in bytes, a whole multiple of the sector size.
    size_bytes: u64,
}

impl CrucibleShmemBlockDevice {
    /// Builds a crucible-shmem block device of `size_bytes` with default ids.
    ///
    /// The length is validated only when the enclosing launch config is
    /// validated; construction itself never fails.
    #[must_use]
    pub fn new(size_bytes: u64) -> Self {
        Self {
            drive_id: DEFAULT_CRUCIBLE_SHMEM_DRIVE_ID.to_owned(),
            device_id: DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID.to_owned(),
            size_bytes,
        }
    }

    /// Returns the device with explicit `-drive` and `-device` identifiers.
    #[must_use]
    pub fn with_ids(mut self, drive_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        self.drive_id = drive_id.into();
        self.device_id = device_id.into();
        self
    }

    /// Returns the fixed device length in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Returns the `-drive` identifier bound to the crucible-shmem backend.
    #[must_use]
    pub fn drive_id(&self) -> &str {
        &self.drive_id
    }

    /// Returns the `-device` identifier for the virtio-blk front-end.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Appends the `-drive`/`-device` argument pair for this device.
    pub(crate) fn append_qemu_args(&self, args: &mut Vec<String>) {
        args.push("-drive".to_owned());
        args.push(format!(
            "driver=crucible-shmem,if=none,id={},size={}",
            self.drive_id, self.size_bytes
        ));
        args.push("-device".to_owned());
        args.push(format!(
            "virtio-blk-pci,drive={},id={}",
            self.drive_id, self.device_id
        ));
    }

    /// Appends canonical launch-identity lines describing this device.
    pub(super) fn append_hash_material(&self, lines: &mut Vec<String>) {
        lines.push("crucible_shmem_block=present".to_owned());
        lines.push(format!("crucible_shmem_block_drive_id={}", self.drive_id));
        lines.push(format!("crucible_shmem_block_device_id={}", self.device_id));
        lines.push(format!(
            "crucible_shmem_block_size_bytes={}",
            self.size_bytes
        ));
    }

    /// Validates the identifiers and length of this device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError::InvalidLaunchText`] when an identifier
    /// is empty or contains a newline, NUL byte, comma, or `=` (any of which
    /// would corrupt the comma-separated QEMU option it is spliced into), and
    /// [`QemuLaunchCommandError::InvalidCrucibleShmemBlockSize`] when the length
    /// is zero, not a whole multiple of the sector size, or above the modeled
    /// maximum.
    pub(crate) fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        validate_option_token("crucible_shmem_block_drive_id", &self.drive_id)?;
        validate_option_token("crucible_shmem_block_device_id", &self.device_id)?;
        if self.size_bytes == 0
            || !self
                .size_bytes
                .is_multiple_of(CRUCIBLE_SHMEM_BLOCK_SECTOR_BYTES)
            || self.size_bytes > CRUCIBLE_SHMEM_BLOCK_MAX_BYTES
        {
            return Err(QemuLaunchCommandError::InvalidCrucibleShmemBlockSize {
                size: self.size_bytes,
            });
        }
        Ok(())
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

    const ONE_MIB: u64 = 1 << 20;

    #[test]
    fn default_ids_apply() {
        let device = CrucibleShmemBlockDevice::new(ONE_MIB);
        assert_eq!(device.drive_id(), DEFAULT_CRUCIBLE_SHMEM_DRIVE_ID);
        assert_eq!(device.device_id(), DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID);
        assert_eq!(device.size_bytes(), ONE_MIB);
    }

    #[test]
    fn args_use_legacy_drive_driver_path() {
        let device = CrucibleShmemBlockDevice::new(ONE_MIB);
        let mut args = Vec::new();
        device.append_qemu_args(&mut args);
        assert_eq!(
            args,
            vec![
                "-drive".to_owned(),
                "driver=crucible-shmem,if=none,id=crucible-blk0,size=1048576".to_owned(),
                "-device".to_owned(),
                "virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0".to_owned(),
            ]
        );
    }

    #[test]
    fn hash_material_is_present_marker_plus_fields() {
        let device = CrucibleShmemBlockDevice::new(ONE_MIB).with_ids("blk-a", "blk-a-device");
        let mut lines = Vec::new();
        device.append_hash_material(&mut lines);
        assert_eq!(
            lines,
            vec![
                "crucible_shmem_block=present".to_owned(),
                "crucible_shmem_block_drive_id=blk-a".to_owned(),
                "crucible_shmem_block_device_id=blk-a-device".to_owned(),
                "crucible_shmem_block_size_bytes=1048576".to_owned(),
            ]
        );
    }

    #[test]
    fn validate_accepts_sector_multiple() {
        assert!(CrucibleShmemBlockDevice::new(ONE_MIB).validate().is_ok());
        assert!(
            CrucibleShmemBlockDevice::new(CRUCIBLE_SHMEM_BLOCK_SECTOR_BYTES)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_rejects_zero_length() {
        assert!(matches!(
            CrucibleShmemBlockDevice::new(0).validate(),
            Err(QemuLaunchCommandError::InvalidCrucibleShmemBlockSize { size: 0 })
        ));
    }

    #[test]
    fn validate_rejects_non_sector_multiple() {
        assert!(matches!(
            CrucibleShmemBlockDevice::new(ONE_MIB + 1).validate(),
            Err(QemuLaunchCommandError::InvalidCrucibleShmemBlockSize { .. })
        ));
    }

    #[test]
    fn validate_rejects_oversize_length() {
        assert!(matches!(
            CrucibleShmemBlockDevice::new(CRUCIBLE_SHMEM_BLOCK_MAX_BYTES + ONE_MIB).validate(),
            Err(QemuLaunchCommandError::InvalidCrucibleShmemBlockSize { .. })
        ));
    }

    #[test]
    fn validate_rejects_comma_in_id() {
        assert!(matches!(
            CrucibleShmemBlockDevice::new(ONE_MIB)
                .with_ids("bad,id", DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID)
                .validate(),
            Err(QemuLaunchCommandError::InvalidLaunchText {
                field: "crucible_shmem_block_drive_id"
            })
        ));
    }

    #[test]
    fn validate_rejects_equals_in_device_id() {
        assert!(matches!(
            CrucibleShmemBlockDevice::new(ONE_MIB)
                .with_ids(DEFAULT_CRUCIBLE_SHMEM_DRIVE_ID, "bad=id")
                .validate(),
            Err(QemuLaunchCommandError::InvalidLaunchText {
                field: "crucible_shmem_block_device_id"
            })
        ));
    }

    #[test]
    fn validate_rejects_empty_id() {
        assert!(matches!(
            CrucibleShmemBlockDevice::new(ONE_MIB)
                .with_ids("", DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID)
                .validate(),
            Err(QemuLaunchCommandError::InvalidLaunchText { .. })
        ));
    }
}
