//! Owns one original Source mapping occurrence and every failed constructor prefix.
//!
//! A fresh Source starts at generation zero. Its only permitted transition
//! increments that local counter once, before fallible work; repeated attempts
//! neither increment nor clear it. A separately born Source has a fresh private
//! key and nonce. Target World/owner generations are independent epochs.
//!
//! This noncloneable custody creates no native allocation, escrow or phase claim.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_format::U64;
use crucible_node_transport::reference_packet::service::complete_restore::import18::native_import18_mapping_lease_identity_data;

/// Retains the Source-local once transition and every original mapping prefix.
pub(super) struct OriginalMappingLeaseAttempt {
    started: bool,
    failed: bool,
    generation: U64,
    nonce: Option<[u8; 32]>,
    identity: Option<[u8; 32]>,
}

/// Copies complete mapping-attempt history without recreating current custody.
#[derive(Clone, Copy)]
pub(crate) struct MappingLeaseHistoryData {
    /// Records the original attempt even when construction failed.
    pub(crate) started: bool,
    /// Keeps a failed or incomplete attempt spent.
    pub(crate) failed: bool,
    /// Names the original Source-local occurrence generation.
    pub(crate) generation: U64,
    /// Retains the actual challenge when its derivation completed.
    pub(crate) nonce: Option<[u8; 32]>,
    /// Retains the commitment when its construction completed.
    pub(crate) identity: Option<[u8; 32]>,
}

impl OriginalMappingLeaseAttempt {
    /// Constructs only an unused inline slot without issuing custody.
    pub(super) fn empty() -> Self {
        Self {
            started: false,
            failed: false,
            generation: U64::new(0),
            nonce: None,
            identity: None,
        }
    }

    fn authenticate_unused(&self) -> Result<(), RuntimeError> {
        if self.started
            || self.failed
            || self.generation.get() != 0
            || self.nonce.is_some()
            || self.identity.is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    fn begin(&mut self) -> Result<(), RuntimeError> {
        self.authenticate_unused()?;
        self.started = true;
        self.failed = true;
        self.generation = U64::new(
            self.generation
                .get()
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?,
        );
        Ok(())
    }

    /// Visits each fixed history field without reconstructing a live owner.
    ///
    /// # Errors
    /// Refuses checked traversal-work overflow while preserving history.
    pub(super) fn record_retained_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            started,
            failed,
            generation,
            nonce,
            identity,
        } = self;
        census.observe_inline_data(started)?;
        census.observe_inline_data(failed)?;
        census.observe_inline_data(generation)?;
        census.observe_inline_data(nonce)?;
        census.observe_inline_data(identity)
    }

    /// Names the actual fixed roster references and result controls.
    pub(super) fn retained_capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(&bool, &bool, &U64, &Option<[u8; 32]>, &Option<[u8; 32]>)>()
            + size_of::<Result<(), RuntimeError>>()
    }

    /// Copies inert history without renewing or transferring the once owner.
    pub(super) fn history_data(&self) -> MappingLeaseHistoryData {
        MappingLeaseHistoryData {
            started: self.started,
            failed: self.failed,
            generation: self.generation,
            nonce: self.nonce,
            identity: self.identity,
        }
    }
}

impl Import18RecipeOwner {
    /// Checks an unused mapping slot before the original constructor begins.
    ///
    /// # Errors
    /// Refuses any spent, failed, occupied or already selected recipe state.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn authenticate_unused_mapping_data(
        &self,
    ) -> Result<(), RuntimeError> {
        if self.started
            || self.completed
            || self.failed
            || self.recipe.is_some()
            || self.initial.is_some()
            || self.launch.is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.mapping.authenticate_unused()
    }

    /// Spends the original mapping attempt before fallible constructor work.
    ///
    /// # Errors
    /// Refuses occupied/spent state or a generation increment that overflows.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn begin_mapping_attempt(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.authenticate_unused_mapping_data()?;
        self.mapping.begin()
    }

    /// Keeps the guarded Birth's challenge in the already spent attempt.
    ///
    /// # Errors
    /// Refuses an absent attempt, completed state or an already occupied prefix.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn retain_mapping_nonce(
        &mut self,
        nonce: [u8; 32],
    ) -> Result<(), RuntimeError> {
        if !self.mapping.started || !self.mapping.failed || self.mapping.nonce.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.mapping.nonce = Some(nonce);
        Ok(())
    }

    /// Retains the genuine launch and its same-occurrence commitment.
    ///
    /// # Errors
    /// Refuses an absent, completed or occupied prefix, missing nonce or invalid DATA.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn retain_mapping_identity(
        &mut self,
        launch: PacketNativeImport18LaunchIdentityData,
    ) -> Result<(), RuntimeError> {
        if !self.mapping.started
            || !self.mapping.failed
            || self.mapping.identity.is_some()
            || self.launch.is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.launch = Some(launch);
        let nonce = self
            .mapping
            .nonce
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let identity =
            native_import18_mapping_lease_identity_data(&launch, nonce, self.mapping.generation)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.mapping.identity = Some(identity);
        Ok(())
    }

    /// Completes original mapping custody after the terminal Source/Birth guard.
    ///
    /// # Errors
    /// Refuses duplicate completion or any absent, zero-generation or partial slot.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn complete_mapping_attempt(
        &mut self,
    ) -> Result<(), RuntimeError> {
        if !self.mapping.failed {
            return Err(RuntimeError::DuplicateOperation);
        }
        if !self.mapping.started
            || self.mapping.generation.get() == 0
            || self.mapping.nonce.is_none()
            || self.mapping.identity.is_none()
            || self.launch.is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.mapping.failed = false;
        Ok(())
    }

    /// Copies only the retained complete original mapping occurrence DATA.
    ///
    /// # Errors
    /// Refuses absent, failed or partial original mapping/recipe custody.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn original_mapping_data(
        &self,
    ) -> Result<([u8; 32], U64, [u8; 32]), RuntimeError> {
        if !self.mapping.started || self.mapping.failed || self.failed || self.launch.is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok((
            self.mapping.nonce.ok_or(RuntimeError::OwnerUnavailable)?,
            self.mapping.generation,
            self.mapping
                .identity
                .ok_or(RuntimeError::OwnerUnavailable)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_mapping_prefix_is_spent_without_renewing_generation() {
        let mut attempt = OriginalMappingLeaseAttempt::empty();
        attempt.begin().unwrap();
        // This models retained DATA after a refused constructor, not a live
        // Source lease or a completed native/recipe result.
        attempt.nonce = Some([17; 32]);
        let before = attempt.history_data();

        assert!(matches!(
            attempt.begin(),
            Err(RuntimeError::DuplicateOperation)
        ));
        let after = attempt.history_data();
        assert!(after.started && after.failed);
        assert_eq!(after.generation, U64::new(1));
        assert_eq!(after.generation, before.generation);
        assert_eq!(after.nonce, before.nonce);
        assert!(after.identity.is_none());
    }
}
