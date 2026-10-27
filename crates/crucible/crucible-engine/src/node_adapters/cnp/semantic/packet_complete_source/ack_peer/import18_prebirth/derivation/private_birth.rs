//! Assembles a private Birth from the original completed job and retained seed.
//!
//! The completion keeps its original banks. Two separately admitted byte copies
//! become the Birth's mutable startup banks, without decoding or reserializing
//! them. Neither construction nor storage observation grants native readiness.

use super::*;
use std::mem::size_of;

impl PacketCompleteSemanticSource {
    /// Quotes the startup-bank copies from the current original completion.
    ///
    /// The original job and seed remain charged by their existing owning rows.
    /// The caller must admit this additional row before construction, under the
    /// same deployment reservation used for the original derivation.
    ///
    /// # Errors
    /// Refuses missing, changed, cancelled or already-spent original custody,
    /// absent private inputs, overflow or an axis above `maximum`.
    pub fn native_import18_private_birth_construction_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        self.authenticate_isolated_private_birth_inputs()?;
        let (source, registration) = self.native_import18_derived_banks_data()?;
        let retained = source
            .len()
            .checked_add(registration.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        let transient = retained
            .checked_add(size_of::<birth::OriginalAckPeerBirth>())
            .and_then(|bytes| bytes.checked_add(size_of::<Option<birth::OriginalAckPeerBirth>>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = Self::native_import18_private_birth_counter_scratch_data();
        let row = [retained, transient, scratch];
        if row.into_iter().any(|bytes| bytes > maximum) {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(row)
    }

    /// Retains the private Birth using accepted banks and the original File/key.
    ///
    /// This once-only construction copies bytes directly from the sealed
    /// completion into separately funded startup banks. It preserves the seed's
    /// executable descriptor and signing identity. Native startup finalization,
    /// Initial/Recipe construction and world activation remain independent.
    /// Failed allocation prefixes and the original completion stay owned.
    ///
    /// # Errors
    /// Refuses foreign, cancelled, absent or repeated custody, actual allocation
    /// failure, changed executable identity or an occupied Birth destination.
    pub fn prepare_native_import18_private_birth_into(&mut self) -> Result<(), RuntimeError> {
        self.authenticate_isolated_private_birth_inputs()?;
        self.ack_birth_attempted = true;
        self.native_import18_derivation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .private_birth_started = true;

        let result = self.assemble_isolated_private_birth();
        // Reauthenticate the completion after both successful and failed
        // construction, while all allocated prefixes are still retained.
        let current = self
            .native_import18_derived_banks_data()
            .map(|_| ())
            .and_then(|()| self.authenticate_isolated_private_birth_original());
        if let Err(error) = result.and(current) {
            if let Some(birth) = self.ack_peer_birth.get_mut() {
                birth.revoke_isolated_construction();
            }
            let state = self
                .native_import18_derivation
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            state.stage = DerivationStage::Failed;
            if let Some(job) = &mut state.job {
                job.refuse_runtime(error);
            }
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }

    /// Names the direct copy/transfer controls in addition to the original job.
    ///
    /// Opaque allocation and IO resources remain under the separately retained
    /// deployment reservation; this reports explicit userspace workspace only.
    pub fn native_import18_private_birth_counter_scratch_data() -> usize {
        Self::isolated_derivation_counter_scratch_data()
            + birth::OriginalImport18PrivateSeed::birth_transfer_counter_scratch_data()
            + size_of::<&mut Self>()
            + size_of::<&NativeImport18DerivationState>()
            + size_of::<&mut NativeImport18DerivationState>()
            + size_of::<(&[u8], &[u8])>()
            + size_of::<&mut Vec<u8>>() * 2
            + size_of::<std::collections::TryReserveError>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<(), RuntimeError>>() * 3
            + size_of::<[usize; 3]>()
    }

    /// Checks the original construction phase without requiring successful work.
    ///
    /// # Errors
    /// Refuses foreign or missing derivation custody, a busy Birth, or startup
    /// effects beyond this construction-only storage observer's scope.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_isolated_private_birth_storage_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.authenticate_isolated_derivation_storage_custody()?;
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if let Some(birth) = slot.as_ref() {
            if !state.private_birth_started {
                return Err(RuntimeError::ForeignAuthority);
            }
            birth.authenticate_isolated_construction_storage_data()?;
        }
        Ok(())
    }

    fn authenticate_isolated_private_birth_inputs(&self) -> Result<(), RuntimeError> {
        self.native_import18_derived_banks_data()?;
        self.authenticate_isolated_private_birth_original()?;
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.private_birth_started
            || self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        state
            .private_seed
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate()
    }

    fn authenticate_isolated_private_birth_original(&self) -> Result<(), RuntimeError> {
        let original = self
            .native_import18_derivation
            .as_ref()
            .and_then(|state| state.original_launch.as_ref())
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.authenticate_import18_birth_source_data(original.original())
    }

    fn assemble_isolated_private_birth(&mut self) -> Result<(), RuntimeError> {
        let state = self
            .native_import18_derivation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let [source_range, registration_range] =
            state.banks.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let bytes = state
            .job
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .stdout()?;
        copy_bank(
            bytes
                .get(source_range.clone())
                .ok_or(RuntimeError::InvalidReceipt)?,
            &mut state.source_bank,
        )?;
        copy_bank(
            bytes
                .get(registration_range.clone())
                .ok_or(RuntimeError::InvalidReceipt)?,
            &mut state.registration_bank,
        )?;
        state
            .private_seed
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .retain_birth_into(
                &mut state.source_bank,
                &mut state.registration_bank,
                self.ack_peer_birth.get_mut(),
            )
    }
}

fn copy_bank(original: &[u8], destination: &mut Vec<u8>) -> Result<(), RuntimeError> {
    if original.is_empty() || !destination.is_empty() {
        return Err(RuntimeError::InvalidReceipt);
    }
    destination
        .try_reserve_exact(original.len())
        .map_err(|_| RuntimeError::ResourceLimit)?;
    destination.extend_from_slice(original);
    Ok(())
}
