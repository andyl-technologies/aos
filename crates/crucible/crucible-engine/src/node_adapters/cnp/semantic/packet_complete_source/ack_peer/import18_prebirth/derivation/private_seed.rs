//! Connects accepted original banks to bank-free retained private inputs.
//!
//! The expected host reference is the original input operand, independently
//! measured by the parent. Its private commitment prevents later rebinding; it
//! never approves a replacement executable identity or produces native credit.
//! Fresh derivations also retain the same immutable launch in both the Source
//! association and its original Job; those owners outlive every seed loan.

use super::super::birth::OriginalImport18PrivateSeed;
use super::*;

struct PrivateSeedLoan<'a> {
    source_birth: &'a [u8],
    registration: &'a [u8],
    seed: &'a OriginalImport18PrivateSeed,
}

impl PacketCompleteSemanticSource {
    /// Quotes the operational seed from the same accepted original operands.
    ///
    /// This is requested-storage DATA. The parent separately observes/adopts the
    /// actual row before entering construction; no Initial or native row follows.
    ///
    /// # Errors
    /// Refuses absent/cancelled/foreign accepted banks, a changed expected host,
    /// repeated seed, currentness, overflow or the supplied restriction.
    pub fn native_import18_private_seed_construction_data(
        &self,
        expected_host: &ContentRef,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        self.authenticate_private_seed_operands(expected_host)?;
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.private_seed.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        OriginalImport18PrivateSeed::construction_data(
            expected_host,
            state
                .private_launch
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            maximum,
        )
    }

    /// Prepares original File/key inputs beside the unchanged Completion owner once.
    ///
    /// The caller has admitted the actual quoted seed row and the same original
    /// deployment before this synchronous loan. Planned bytes remain slices of
    /// Completion; no bank Vec, legacy Birth, mapping lease or native member is
    /// constructed. Every failed clone/File/key prefix stays in the Source.
    ///
    /// # Errors
    /// Refuses changed/repeated/foreign operands or real clone/File/entropy work.
    /// A started failure remains spent and revokes further bank acceptance.
    pub fn prepare_native_import18_private_seed_into(
        &mut self,
        expected_host: &ContentRef,
    ) -> Result<(), RuntimeError> {
        self.authenticate_private_seed_operands(expected_host)?;
        let state = self
            .native_import18_derivation
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.private_seed.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        state.private_seed = Some(OriginalImport18PrivateSeed::empty());
        let result = state
            .private_seed
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .prepare(
                expected_host,
                state
                    .private_launch
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            );
        // Recheck the same Source/Job/mechanism after every constructor return,
        // including a failed File/entropy prefix. Both results remain rooted.
        let original = self.native_import18_derived_banks_data().map(|_| ());
        let result = result.and(original);
        let result = result.and_then(|()| {
            self.with_private_seed(|loan| {
                if loan.source_birth.is_empty() || loan.registration.is_empty() {
                    return Err(RuntimeError::InvalidReceipt);
                }
                // The original opaque seed is borrowed, never adopted from DATA.
                let _original = loan.seed;
                Ok(())
            })
        });
        if let Err(error) = result {
            if let Some(state) = &mut self.native_import18_derivation {
                state.stage = DerivationStage::Failed;
                if let Some(job) = &mut state.job {
                    job.refuse_runtime(error);
                }
            }
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }

    /// Names actual seed clone/stream and new fixed wrapper workspace only.
    ///
    /// Opaque runtime/IO remains in its same original deployment domain. This
    /// does not certify a full native constructor or convert a ceiling to bytes.
    pub fn native_import18_private_seed_counter_scratch_data() -> usize {
        OriginalImport18PrivateSeed::counter_scratch_data()
            + std::mem::size_of::<&Self>()
            + std::mem::size_of::<&mut Self>()
            + std::mem::size_of::<PrivateSeedLoan<'static>>() * 2
            + std::mem::size_of::<&ContentRef>()
            + std::mem::size_of::<blake3::Hasher>()
            + std::mem::size_of::<[u8; 32]>() * 2
            + std::mem::size_of::<Result<(), RuntimeError>>() * 2
    }

    fn authenticate_private_seed_operands(
        &self,
        expected_host: &ContentRef,
    ) -> Result<(), RuntimeError> {
        self.native_import18_derived_banks_data()?;
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.host_reference != Some(host_reference_identity(expected_host)?) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    fn with_private_seed<R>(
        &self,
        inspect: impl FnOnce(&PrivateSeedLoan<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        let (source_birth, registration) = self.native_import18_derived_banks_data()?;
        let seed = self
            .native_import18_derivation
            .as_ref()
            .and_then(|state| state.private_seed.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        seed.authenticate()?;
        let result = inspect(&PrivateSeedLoan {
            source_birth,
            registration,
            seed,
        });
        seed.authenticate()?;
        self.native_import18_derived_banks_data()?;
        result
    }
}

pub(super) fn host_reference_identity(reference: &ContentRef) -> Result<[u8; 32], RuntimeError> {
    // Commits the exact existing input reference. This is neither a newly
    // measured ContentRef nor permission to select a different executable.
    let mut hash = blake3::Hasher::new_derive_key("crucible.source-birth.host-operand/1");
    for text in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ] {
        let length = u64::try_from(text.len()).map_err(|_| RuntimeError::ResourceLimit)?;
        hash.update(&length.to_be_bytes());
        hash.update(text.as_bytes());
    }
    hash.update(&reference.length.get().to_be_bytes());
    Ok(*hash.finalize().as_bytes())
}

#[cfg(test)]
#[path = "private_seed/tests.rs"]
mod tests;
