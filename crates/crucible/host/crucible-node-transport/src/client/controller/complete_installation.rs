//! Retains both verified archived graphs after the actual completed restore RPC.
//!
//! This is the mechanical ownership step. The source caller separately verifies
//! the keyed original receipt, signed complete journal and Core target context.
//! Fresh live authority and active correlation/literal banks are retained; no
//! archived descriptor or historical proof becomes a new registrar or key.

use super::*;
use crate::protocol_snapshot::{
    PreparedArchivedProtocolMapping,
    owned11::{
        native::outer::{HistoricalNativeState, SealedHistoricalNativeState},
        outer::{HistoricalControllerState, SealedHistoricalControllerState},
    },
};
use std::rc::Rc;

/// Owns exact verified archived data beside the independently enrolled fresh controller.
///
/// This owner is not a live authority and has no public data constructor. It
/// remains in the target controller across source wrapper failure or unwind.
pub struct InstalledArchivedProtocolState {
    mapping_identity: Rc<crate::protocol_snapshot::ArchivedProtocolMappingIdentity>,
    host: Option<SealedHistoricalControllerState>,
    native: Option<SealedHistoricalNativeState>,
    complete: bool,
}

impl InstalledArchivedProtocolState {
    /// Borrows the exact decoder-produced archived controller graph.
    ///
    /// # Errors
    /// Refuses partial ownership transfer or an incomplete decoded graph.
    pub fn host(&self) -> Result<&HistoricalControllerState, ProviderError> {
        if !self.complete {
            return Err(refused());
        }
        self.host.as_ref().ok_or_else(refused)?.historical()
    }

    /// Borrows the exact decoder-produced archived native graph.
    ///
    /// # Errors
    /// Refuses partial ownership transfer or an incomplete decoded graph.
    pub fn native(&self) -> Result<&HistoricalNativeState, ProviderError> {
        if !self.complete {
            return Err(refused());
        }
        self.native.as_ref().ok_or_else(refused)?.historical()
    }

    /// Reports actual retained encoded bank capacities without original-size credit.
    pub fn encoded_capacities(&self) -> (usize, usize) {
        (
            self.host
                .as_ref()
                .map_or(0, SealedHistoricalControllerState::encoded_capacity),
            self.native
                .as_ref()
                .map_or(0, SealedHistoricalNativeState::encoded_capacity),
        )
    }
}

impl CnpController {
    /// Transfers both exact archived owners after the same original restore completes.
    ///
    /// The source performs its private Core/journal/receipt-MAC conjunction before
    /// invoking this mechanical data transfer. This method does not enroll a live
    /// source, replace the fresh codec or assert native model/Control completion.
    ///
    /// # Errors
    /// Refuses another mapping/body, unselected or stale controller, incomplete
    /// original RPC, occupied target or partial inputs. Every refusal before the
    /// transfer retains both input slots; after transfer the target retains both.
    pub fn install_original_completed_complete_restore_into(
        &mut self,
        mapping: &PreparedArchivedProtocolMapping,
        host: &mut Option<SealedHistoricalControllerState>,
        native: &mut Option<SealedHistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.authenticate_archived_protocol_mapping(mapping)?;
        if self.installed_complete_restore.is_some()
            || self.original_native5_complete_restore_selection()? != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedOwned11) {
            return Err(refused());
        }
        let state = self
            .original_complete_restore
            .as_ref()
            .ok_or_else(refused)?;
        state.validate_owned_snapshot()?;
        mapping.authenticate_identity(&state.mapping_identity)?;
        if state.nonce != *mapping.nonce() {
            return Err(refused());
        }
        crate::connection::CompleteRestoreProjection::from_envelope(&state.original)?;
        let response = state.response.as_ref().ok_or_else(refused)?;
        crate::connection::CompleteRestoreProjection::from_envelope(response)?;
        state.original.matches_response(response)?;
        let host_ref = host.as_ref().ok_or_else(refused)?;
        let native_ref = native.as_ref().ok_or_else(refused)?;
        if host_ref.body_reference() != mapping.archive_protocol()
            || native_ref.body_reference() != mapping.native_protocol()
        {
            return Err(refused());
        }
        host_ref.historical()?.require_complete_reader_state()?;
        native_ref
            .historical()?
            .authenticate_capture_correspondence()?;

        // Store the target owner before moving either input. There is no fallible
        // callback, allocation, decoding or I/O between these ownership effects.
        self.installed_complete_restore = Some(InstalledArchivedProtocolState {
            mapping_identity: mapping.retain_identity(),
            host: None,
            native: None,
            complete: false,
        });
        let installed = self
            .installed_complete_restore
            .as_mut()
            .ok_or_else(refused)?;
        installed.host = host.take();
        installed.native = native.take();
        installed.complete = true;
        Ok(())
    }

    /// Borrows the actual installed owner under the same current target and mapping.
    ///
    /// # Errors
    /// Refuses a changed target/mapping, absent owner or partial ownership transfer.
    pub fn original_installed_complete_restore(
        &self,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<&InstalledArchivedProtocolState, ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.authenticate_archived_protocol_mapping(mapping)?;
        let installed = self
            .installed_complete_restore
            .as_ref()
            .ok_or_else(refused)?;
        mapping.authenticate_identity(&installed.mapping_identity)?;
        if !installed.complete {
            return Err(refused());
        }
        Ok(installed)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original completed complete restore owner differs")
}
