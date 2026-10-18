//! Fixed q35 device placement and immutable root-image formats.

pub(super) const QEMU_PCI_BUS: &str = "pcie.0";
pub(super) const QEMU_RNG_PCI_ADDRESS: &str = "0x1";
pub(super) const QEMU_ROOT_PCI_ADDRESS: &str = "0x2";
pub(super) const QEMU_SHMEM_BLOCK_PCI_ADDRESS: &str = "0x3";
pub(super) const QEMU_NINEP_PCI_ADDRESS: &str = "0x4";
pub(super) const QEMU_NETWORK_PCI_ADDRESS: &str = "0x5";
pub(super) const QEMU_ACCELERATOR_PCI_ADDRESS: &str = "0x6";
pub(super) const QEMU_DEBUG_SERIAL_PCI_ADDRESS: &str = "0x7";

/// On-disk format of an immutable root-image backing artifact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QemuRootImageFormat {
    /// The backing artifact is a QCOW2 image.
    #[default]
    Qcow2,
    /// The backing artifact is a raw disk or filesystem image.
    Raw,
}

impl QemuRootImageFormat {
    pub(super) const fn qemu_driver(self) -> &'static str {
        match self {
            Self::Qcow2 => "qcow2",
            Self::Raw => "raw",
        }
    }
}
