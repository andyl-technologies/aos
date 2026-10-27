//! Borrows the original endpoint handshake, operational cut and service roots.
//!
//! This input view creates no registration, callback, deadline or native right.
//! The five concrete action functions remain independent dispatch operands.

use crate::client::ExchangeDeadline;
use crate::handshake::Handshake;
use crate::reference_packet::service::OriginalNativeServiceCaptureContext;
use std::mem::size_of;

/// Groups the same borrowed registration and service context for one step.
pub(super) struct OriginalEndpointContextData<'loan, 'context> {
    /// Borrows the ordinary handshake and its existing exchange deadline.
    pub(super) context: Option<(&'loan Handshake, &'loan ExchangeDeadline)>,
    /// Borrows the original selected service's existing operational cut.
    pub(super) selected_deadline: Option<&'loan ExchangeDeadline>,
    /// Borrows the actual retained native service roots, when selected.
    pub(super) service_context: Option<&'loan OriginalNativeServiceCaptureContext<'context>>,
}

/// Counts the endpoint and nested Control views at each funded dispatch boundary.
pub(crate) const fn original_endpoint_context_counter_scratch_data() -> usize {
    2 * size_of::<OriginalEndpointContextData<'static, 'static>>()
        + size_of::<usize>()
        + crate::reference_packet::control::original_control_permissions_counter_scratch_data()
}
