//! Retains independently quoted typed decoding and actual SDK request settlement.
//!
//! This passive row supplies neither Source receipt verification nor completion.

use super::PacketNativeImport18BootstrapResponseDecodeRowData;

/// Preserves the decoder component beside actual moved SDK and guard demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeImport18BootstrapSdkSettlementRowData {
    pub(crate) component: PacketNativeImport18BootstrapResponseDecodeRowData,
    pub(crate) axes: [usize; 3],
}

impl PacketNativeImport18BootstrapSdkSettlementRowData {
    /// Returns retained, simultaneous transient and fixed-control requested bytes.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }

    /// Returns the independently derived closed typed decoder component.
    pub const fn decoder_component_data(
        self,
    ) -> PacketNativeImport18BootstrapResponseDecodeRowData {
        self.component
    }
}
