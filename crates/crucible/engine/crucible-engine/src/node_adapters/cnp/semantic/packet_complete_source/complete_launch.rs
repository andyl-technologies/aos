//! Selects original complete-byte executable custody before native launch.
//!
//! Only the concrete complete Source supplies this factory path. It does not
//! alter ordinary connected sources or convert any existing lease/Child. Full
//! current executable validation remains separate from readiness and is never
//! claimed to be an atomic check-to-exec exclusion.

use super::*;
use crate::node_adapters::cnp::{CnpSemanticLaunchReservation, CnpSemanticProcessSlot};
use std::path::PathBuf;

impl PacketCompleteSemanticSource {
    /// Reserves this original complete peer with executable byte validation.
    ///
    /// Matches the exact declared executable before the slot identity callback,
    /// selects the no-worker path before Child birth and spends this Source's
    /// reservation once. A callback failure cannot retrofit a second reservation.
    /// The actual private launcher must still authenticate path/directory/full
    /// launch bytes and use the returned original reservation for that Child.
    ///
    /// The complete measurement byte buffer and positional/hash temporaries
    /// remain separate whole-action allocation terms; choosing this path does
    /// not manufacture an allocation admission or an atomic exec guarantee.
    ///
    /// # Errors
    /// Refuses another creator, invalid complete declaration, another executable,
    /// a previous reservation, retained native/preconstruction association or a
    /// busy original holder. No Child is created by this method.
    ///
    /// # Panics
    /// Propagates a trusted slot identity callback panic before Child creation;
    /// the Source reservation choice remains spent.
    pub fn reserve_original_complete_bytes_launch(
        &self,
        directory: PathBuf,
        executable: ContentRef,
        slot: Box<dyn CnpSemanticProcessSlot>,
    ) -> Result<CnpSemanticLaunchReservation, OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_registration()?;
        let mut artifacts = self
            .installation()
            .provider
            .implementation
            .artifacts
            .iter()
            .filter(|artifact| artifact.role.as_str() == "executable");
        if artifacts
            .next()
            .is_none_or(|artifact| artifact.content != executable)
            || artifacts.next().is_some()
        {
            return Err(refused(
                "complete-byte launch executable differs from original declaration",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound()?,
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound()?,
        };
        if !unbound
            || self
                .preconstruction
                .try_borrow()
                .map_err(|_| refused("complete-byte launch preconstruction already borrowed"))?
                .is_some()
        {
            return Err(refused(
                "complete-byte launch follows original native association",
            ));
        }
        {
            let association = self
                .ack_peer_association
                .try_borrow()
                .map_err(|_| refused("complete-byte launch association already borrowed"))?;
            if let Some(association) = association.as_ref() {
                // Genuine private birth owns these empty banks before Hello.
                // Present associated/failed data cannot reopen launch custody.
                association.authenticate_reserved_prebirth_data()?;
                let birth = self
                    .ack_peer_birth
                    .try_borrow()
                    .map_err(|_| refused("complete-byte launch private birth already borrowed"))?;
                birth
                    .as_ref()
                    .ok_or_else(|| {
                        refused("complete-byte launch reserved banks lack original birth")
                    })?
                    .authenticate_reserved_launch_data(self)?;
            }
        }
        if self.complete_bytes_launch_reserved.replace(true) {
            return Err(refused(
                "complete-byte Source launch reservation was already spent",
            ));
        }
        Ok(
            CnpSemanticLaunchReservation::reserve_complete_original_child(
                directory, executable, slot,
            ),
        )
    }
}
