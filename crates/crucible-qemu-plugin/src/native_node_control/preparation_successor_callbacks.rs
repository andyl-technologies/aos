//! Native Applied callback capture and nonsemantic cached successor recovery.
//!
//! The source itself chooses the immutable post-HOME object. A reader can recover
//! only its retained canonical bytes after the actual initialization ACK. This
//! extension changes no legacy observation and grants no modeled dispatch.

use super::NativeNodeControl;
use crate::native_node_control::{
    preparation_successor_abi, preparation_successor_custody::PreparationSuccessorCustody,
};
use crucible_protocol::node_control::{
    NativeCommandError, NativeFrame, NativeInitializationReceipt, NativePreparationSuccessorQuery,
};

impl NativeNodeControl {
    /// Pins source-only successor observation before native callback registration.
    ///
    /// # Errors
    /// Refuses missing original phase/initialization or source exports, a second
    /// installation, prior execution, or poisoned actual journal custody.
    pub(crate) fn with_preparation_successor(mut self) -> Result<Self, NativeCommandError> {
        if self.preparation_successor.is_some()
            || self.initialization.is_none()
            || self.phase_projection.is_none()
        {
            return Err(NativeCommandError::Conflict);
        }
        {
            let state = self
                .state
                .lock()
                .map_err(|_| NativeCommandError::Conflict)?;
            if state.quarantined || !state.journal.is_pristine() {
                return Err(NativeCommandError::Conflict);
            }
        }
        let query = preparation_successor_abi::resolve_query_preparation_successor().ok_or(
            NativeCommandError::Invalid("native preparation successor query unavailable"),
        )?;
        let read = preparation_successor_abi::resolve_read_preparation_successor().ok_or(
            NativeCommandError::Invalid("native preparation successor read unavailable"),
        )?;
        self.preparation_successor = Some(std::sync::Arc::new(PreparationSuccessorCustody::new(
            query, read,
        )));
        Ok(self)
    }

    /// Retains only the genuine original native initialization Applied seam.
    ///
    /// # Errors
    /// Refuses changed source observations or incomplete bounded custody. Legacy
    /// configurations without this extension preserve their original behavior.
    pub(crate) fn observe_preparation_successor(
        &self,
        receipt: &NativeInitializationReceipt,
    ) -> Result<(), NativeCommandError> {
        match &self.preparation_successor {
            Some(successor) => successor.observe_after_applied(receipt),
            None => Ok(()),
        }
    }

    pub(crate) fn send_preparation_successor_chunk(
        &self,
        query: &NativePreparationSuccessorQuery,
    ) -> Result<(), NativeCommandError> {
        let successor = self
            .preparation_successor
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        let initialization = self
            .initialization
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        let chunk = successor.acknowledged_original_chunk(initialization, query)?;
        let channel = self.channel.as_ref().ok_or(NativeCommandError::Conflict)?;
        // A full datagram socket keeps the original immutable object and ACK.
        // An identical query can recover the same slice without source sampling.
        let _sent = channel
            .send(&NativeFrame::PreparationSuccessorChunk(Box::new(chunk)))
            .map_err(|_| NativeCommandError::Conflict)?;
        Ok(())
    }
}
