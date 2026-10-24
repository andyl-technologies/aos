//! Lends the actual Node's Controller history for funded Source quotation.
//!
//! The Node view retains its original concrete supervisor by reference and only
//! the Controller's actual identity. Each method receives the current Controller
//! loan, checks that identity and lets the SDK check its original supervisor and
//! Session parent. No identity pointer is dereferenced, serialized or accepted as
//! a read, execution, restoration or completion grant.

use super::OriginalRestoredSettledNodeHistoryView;
use crate::node_contract::RuntimeError;
use crucible_node_transport::{
    ProviderError,
    client::{CnpController, ControllerSettledHistoryData},
    connection::OriginalRetainedSupervisor,
};
use std::mem::size_of;

impl OriginalRestoredSettledNodeHistoryView<'_> {
    fn authenticate_controller_identity_data(
        &self,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.controller_identity, controller) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Borrows the defining Controller history under its actual Node supervisor.
    ///
    /// The borrowed serializer allocates no output and owns only fixed SDK
    /// views. Its literal/Hello loans must end before any mutable SDK operation.
    /// The caller admits the defining scratch and serialization temporary first,
    /// then separately prices its canonical output and DOM constructor banks.
    ///
    /// # Errors
    /// Refuses another Controller, absent or conflicting SDK owners, unsupported
    /// historical fields, or a changed original supervisor/Session/codec parent.
    pub(crate) fn original_controller_history_data<'borrow>(
        &'borrow self,
        controller: &'borrow CnpController,
    ) -> Result<ControllerSettledHistoryData<'borrow>, RuntimeError> {
        self.authenticate_controller_identity_data(controller)?;
        controller
            .borrowed_settled_history_data(self.supervisor)
            .map_err(|_| RuntimeError::UnsupportedFacet)
    }

    /// Prices actual Controller serialization temporaries without output copies.
    ///
    /// The defining SDK walk checks the same retained supervisor. This demand is
    /// separate from existing Controller backing and from future output banks;
    /// it neither reserves bytes nor mutates metadata or alias-bank decisions.
    ///
    /// # Errors
    /// Refuses another Controller or supervisor parent, an unsupported metadata
    /// owner, or checked traversal and temporary-byte overflow.
    pub(crate) fn original_controller_history_serialization_transient_data(
        &self,
        controller: &CnpController,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_controller_identity_data(controller)?;
        controller
            .settled_history_serialization_transient_bytes_data(self.supervisor)
            .map_err(|_| RuntimeError::ResourceLimit)
    }

    /// Counts these borrowed control headers and the defining SDK history views.
    pub(crate) fn original_controller_history_counter_scratch_data() -> usize {
        CnpController::settled_history_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CnpController>()
            + size_of::<*const CnpController>()
            + size_of::<&OriginalRetainedSupervisor>()
            + size_of::<Option<&OriginalRetainedSupervisor>>()
            + size_of::<Result<&OriginalRetainedSupervisor, RuntimeError>>()
            + size_of::<Option<&CnpController>>()
            + size_of::<Result<&CnpController, RuntimeError>>()
            + size_of::<Result<ControllerSettledHistoryData<'static>, RuntimeError>>()
            + size_of::<Result<ControllerSettledHistoryData<'static>, ProviderError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
