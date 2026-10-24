//! Retains independently quoted Controller request-materialization components.
//!
//! This fixed DATA row contains no serialized identity, native permission or
//! Source credit. The defining Controller authenticates its original operands
//! before constructing it and separately retains it before entering the attempt.

use super::PacketNativeImport18BootstrapSealingRowData;

/// Preserves actual materializer demand together with its enclosing guard work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeImport18BootstrapMaterializationRowData {
    pub(crate) component: PacketNativeImport18BootstrapSealingRowData,
    pub(crate) axes: [usize; 3],
}

impl PacketNativeImport18BootstrapMaterializationRowData {
    /// Returns retained, simultaneous transient and fixed-control requested bytes.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }
}
