//! Retains SDK registration/publication component demand as passive DATA.
//!
//! The operation tag prevents exchanging the two saved component rows. Neither
//! a row nor a progress flag supplies private Source signing or receipt authority.

/// Preserves independent SDK, containment and original guard demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeImport18BootstrapSdkRowData {
    pub(crate) axes: [usize; 3],
    pub(crate) publication: bool,
}

impl PacketNativeImport18BootstrapSdkRowData {
    /// Returns retained, simultaneous transient and fixed-control requested bytes.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }
}
