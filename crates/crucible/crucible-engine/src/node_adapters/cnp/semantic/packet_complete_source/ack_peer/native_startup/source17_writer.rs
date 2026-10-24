//! Joins Source17 output to its actual completed native startup owner.
//!
//! Old suffix16 launch and declaration checks remain unchanged. These distinct
//! Source17 DATA lenders require the real completed settled startup member and
//! authenticate its complete wrapper8 identity before lending any writer facts.

use super::*;

impl PacketCompleteSemanticSource {
    /// Authenticates the exact canonical launch retained by completed startup17.
    ///
    /// This comparison does not prove native receipt or issue a SourceRead,
    /// Window claim, current checkpoint or Capture permit.
    ///
    /// # Errors
    /// Refuses another selection, Source/member, typed or raw launch, purpose,
    /// reservation, incomplete actual wire or changed complete wrapper identity.
    pub(crate) fn authenticate_original_restored_settled_source17_launch_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_launch_data(launch)?;
        if !self.is_original_restored_settled_capture_declaration_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.authenticate_original_initial_lifecycle_data()?;
        let state = birth
            .native_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !state.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        state.member.authenticate_boot_ready(self)?;
        let purpose = state
            .original_invocation_data()?
            .ok_or(RuntimeError::OwnerUnavailable)?;
        purpose
            .authenticate_target_data(launch)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let suffix = state
            .member
            .suffix
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let settled = suffix
            .settled_data(self)?
            .ok_or(RuntimeError::OwnerUnavailable)?;
        settled.authenticate_completed_wire_data()?;
        let reservation = suffix.reservation_data();
        let existing = settled.storage_data().existing_rows_data();
        if existing.suffix != reservation {
            return Err(RuntimeError::InvalidReceipt);
        }
        let actual = crucible_node_transport::reference_packet::service::native_startup::original_native_settled_launch_identity_data(
            &purpose, canonical_launch5, &reservation, existing, settled.carrier_data(),
        ).map_err(|_| RuntimeError::ForeignAuthority)?;
        if actual != settled.launch_identity_data() || actual.encoded_bytes > 1024 * 1024 {
            return Err(RuntimeError::ForeignAuthority);
        }
        state.member.authenticate_boot_ready(self)?;
        settled.authenticate_completed_wire_data()?;
        self.storage_origin_with_error::<RuntimeError>()
    }

    /// Returns THIS completed startup17's underlying suffix Boot capacity.
    ///
    /// Capture's separately funded carrier maximum is not this native journal
    /// capacity. Neither value renews the original generic/Producer lifetime cap.
    ///
    /// # Errors
    /// Refuses unavailable or partial actual startup17 custody, invalid original
    /// rows, or a quantity outside the current platform's checked usize range.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_restored_settled_source17_boot_original_limit_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.with_original_completed_restored_settled_startup_data(|storage| {
            let reservation = &storage.existing_rows_data().suffix;
            reservation
                .requested_bytes_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            usize::try_from(reservation.maximum_originals.get())
                .map_err(|_| RuntimeError::ResourceLimit)
        })
    }
}
