//! Retained ownership-header credit for immutable transport byte bodies.

use super::*;
use owned_decode::{DecodeBudget, DecodeScratch};

struct WireOwner<T> {
    body: AdmittedOutput<T>,
    _owner_loan: DecodeScratch,
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for WireOwner<T> {
    fn as_ref(&self) -> &[u8] {
        self.body.as_ref()
    }
}

impl<T: AsRef<[u8]> + Send + 'static> AdmittedOutput<T> {
    /// Transfers admitted bytes to a shared transport owner with an admitted header.
    ///
    /// # Errors
    /// Refuses missing or failed original authority, layout overflow, or exhausted credit.
    pub(crate) fn into_wire_bytes(
        self,
    ) -> Result<bytes::Bytes, owned_decode::DecodeAdmissionError> {
        let _scope = self
            .enter_original_scope()
            .ok_or_else(|| owned_decode::DecodeAdmissionError::new(MissingWireAuthority))?;
        let budget = owned_decode::current_budget()
            .ok_or_else(|| owned_decode::DecodeAdmissionError::new(MissingWireAuthority))?;
        budget.check()?;
        let loan = reserve_owner::<WireOwner<T>>(&budget)?;
        Ok(bytes::Bytes::from_owner(WireOwner {
            body: self,
            _owner_loan: loan,
        }))
    }
}

/// Reserves the concrete ownership header used by the pinned byte implementation.
///
/// # Errors
/// Refuses layout overflow or exhaustion of the original resource account.
pub(crate) fn reserve_owner<T>(
    budget: &DecodeBudget,
) -> Result<DecodeScratch, owned_decode::DecodeAdmissionError> {
    // Pinned bytes1.11.1 allocates repr(C) Owned<T>: one AtomicUsize reference
    // count followed by T. Its vtable is static and allocates no header storage.
    let (layout, _) = std::alloc::Layout::new::<std::sync::atomic::AtomicUsize>()
        .extend(std::alloc::Layout::new::<T>())
        .map_err(owned_decode::DecodeAdmissionError::new)?;
    budget.reserve_scratch_bytes(layout.pad_to_align().size() as u64)
}

#[derive(Debug, thiserror::Error)]
#[error("transport byte ownership requires its retained original resource authority")]
struct MissingWireAuthority;
