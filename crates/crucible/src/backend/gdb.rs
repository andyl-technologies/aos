//! Mediated debugger endpoint validation and attach metadata.

use super::*;

impl GdbAttachInfo {
    /// Builds a report for a mediated out-of-band gdbstub attach.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Rejected`] when `qemu_endpoint` is not stable
    /// endpoint text.
    pub fn new(
        node: NodeId,
        qemu_endpoint: impl Into<String>,
        operator_listen: GdbListen,
    ) -> Result<Self, BackendError> {
        let qemu_endpoint = qemu_endpoint.into();
        validate_gdb_endpoint("qemu_gdbstub", &qemu_endpoint)?;
        Ok(Self {
            node,
            qemu_endpoint,
            operator_listen,
            mediated_by_crucible: true,
            out_of_band: true,
            carries_per_quantum_timing: false,
            carries_frame_data: false,
        })
    }

    /// Returns whether the channel is a read-only out-of-band debug proxy.
    #[must_use]
    pub const fn is_out_of_band_debug_proxy(&self) -> bool {
        self.mediated_by_crucible
            && self.out_of_band
            && !self.carries_per_quantum_timing
            && !self.carries_frame_data
    }
}

pub(super) fn validate_gdb_endpoint(field: &'static str, value: &str) -> Result<(), BackendError> {
    if value.is_empty() || value.chars().any(|ch| matches!(ch, '\n' | '\0')) {
        return Err(BackendError::Rejected {
            message: format!("{field} endpoint is invalid"),
        });
    }
    Ok(())
}
