//! Deterministic virtio Crucible accelerator attachment.
//!
//! ```text
//! -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on
//! ```

use super::QemuLaunchCommandError;

/// Default QEMU identity for the co-simulation accelerator.
pub const DEFAULT_CRUCIBLE_ACCELERATOR_DEVICE_ID: &str = "crucible-accelerator0";

/// A deterministic GPU/TPU/FPGA co-simulation device attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleAcceleratorDevice {
    device_id: String,
}

impl CrucibleAcceleratorDevice {
    /// Builds an accelerator attachment with the stable default identity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            device_id: DEFAULT_CRUCIBLE_ACCELERATOR_DEVICE_ID.to_owned(),
        }
    }

    /// Returns the attachment with a different stable QEMU identity.
    #[must_use]
    pub fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = device_id.into();
        self
    }

    /// Returns the QEMU device identity.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub(super) fn append_qemu_args(&self, args: &mut Vec<String>) {
        args.extend([
            "-device".to_owned(),
            format!(
                "virtio-crucible-accelerator-pci,id={},disable-legacy=on",
                self.device_id
            ),
        ]);
    }

    pub(super) fn append_hash_material(&self, lines: &mut Vec<String>) {
        lines.extend([
            "crucible_accelerator=present".to_owned(),
            "crucible_accelerator_protocol=1".to_owned(),
            "crucible_accelerator_transport=modern-only".to_owned(),
            format!("crucible_accelerator_device_id={}", self.device_id),
        ]);
    }

    pub(super) fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        super::validate_launch_text("crucible_accelerator_device_id", &self.device_id)?;
        if self.device_id.contains(',') || self.device_id.contains('=') {
            return Err(QemuLaunchCommandError::InvalidLaunchText {
                field: "crucible_accelerator_device_id",
            });
        }
        Ok(())
    }
}

impl Default for CrucibleAcceleratorDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_arguments_require_the_modern_only_transport() {
        let mut arguments = Vec::new();
        CrucibleAcceleratorDevice::new().append_qemu_args(&mut arguments);

        assert_eq!(
            arguments,
            [
                "-device",
                "virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on",
            ]
        );
    }

    #[test]
    fn launch_identity_attests_the_transport_mode() {
        let mut material = Vec::new();
        CrucibleAcceleratorDevice::new().append_hash_material(&mut material);

        assert!(
            material
                .iter()
                .any(|line| line == "crucible_accelerator_transport=modern-only")
        );
    }
}
