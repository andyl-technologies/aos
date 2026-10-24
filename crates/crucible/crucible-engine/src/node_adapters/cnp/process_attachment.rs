//! Adopts original negotiated control without dropping a rejected owner.
//!
//! The caller keeps the controller and registrar in its preowned preparation
//! holder until every check passes. Adoption moves them directly into the same
//! Child capsule; it creates no process, session, custody slot or authority.

use crucible_node_transport::{ProviderError, client::ReferenceController, handshake::Handshake};

use super::{CnpLaunchGuard, CnpRegistrar};

impl CnpLaunchGuard {
    /// Adopts the same negotiated controller while preserving rejected inputs.
    ///
    /// Both caller slots remain unchanged on refusal. Success transfers both
    /// originals directly into this guard after all validation. The caller's
    /// owning preparation holder must remain live across refusal and cleanup.
    /// No control request or native work occurs during this transition.
    ///
    /// # Errors
    /// Refuses absent originals, an occupied or transferred native capsule, a
    /// controller belonging to another Child, or a typed-extension controller
    /// requiring its distinct registrar attachment route.
    pub fn attach_original(
        &mut self,
        controller: &mut Option<ReferenceController>,
        handshake: &mut Option<Handshake>,
    ) -> Result<(), ProviderError> {
        let custody = self.custody.as_mut().ok_or(ProviderError::Correlation(
            "CNP original native custody transferred",
        ))?;
        let original = controller
            .as_ref()
            .ok_or(ProviderError::Correlation("CNP original controller absent"))?;
        if handshake.is_none()
            || custody.controller.is_some()
            || custody.handshake.is_some()
            || original.peer_pid() != custody.child.id()
            || original.selected_extensions().is_some()
        {
            return Err(ProviderError::Correlation(
                "CNP original attachment differs from retained Child",
            ));
        }

        // These exclusive caller slots were checked above. There are no
        // callbacks or fallible operations between taking and installing them.
        custody.handshake = handshake.take().map(CnpRegistrar::Legacy);
        custody.controller = controller.take();
        Ok(())
    }
}
