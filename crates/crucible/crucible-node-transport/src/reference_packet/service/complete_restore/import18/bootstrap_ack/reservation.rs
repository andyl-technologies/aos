//! Retains independently quoted original literal reservation component DATA.
//!
//! The actual Controller authenticates unchanged typed custody, original Hello
//! and unused SDK before entering the quoted operation. The row supplies no
//! Source funding, slot, proof or publication permission.

/// Binds derived reservation demand without allocating a frame or an incident.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PacketNativeImport18BootstrapReservationRowData {
    pub(crate) axes: [usize; 3],
    pub(crate) maximum_payload_bytes: usize,
}

impl PacketNativeImport18BootstrapReservationRowData {
    /// Returns retained, simultaneous transient and fixed-control component demand.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }

    /// Returns the closed sealed-request payload bound, excluding its frame header.
    pub const fn maximum_payload_bytes_data(self) -> usize {
        self.maximum_payload_bytes
    }
}
