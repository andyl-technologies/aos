//! Borrows one in-process page completion while its original owners remain live.
//!
//! This view carries no resource admission or authentication authority. The
//! consumer verifies the separately trusted root before using its bytes. Its
//! references never appear in a wire encoding or shared-memory region.

use crate::PageProof;

#[cfg(feature = "test-support")]
use crate::RamError;

/// Retains a membership proof with its inseparable canonical encoding.
///
/// The caller admits the proof's existing allocations and encoding capacity
/// before constructing this owner, then retains that original custody until
/// this value closes. It creates the same single encoding allocation as
/// [`PageProof::encode`]; it acquires no resources or authentication authority.
pub struct EncodedPageProof {
    proof: PageProof,
    encoded: Vec<u8>,
}

impl EncodedPageProof {
    /// Encodes an existing proof once under the caller's original admission.
    ///
    /// Moving the proof preserves its allocations. Private fields and immutable
    /// getters prevent a response from pairing the proof with unrelated bytes.
    pub fn new(proof: PageProof) -> Self {
        let encoded = proof.encode();
        Self { proof, encoded }
    }

    /// Borrows the membership proof committed by the encoding.
    #[must_use]
    pub fn proof(&self) -> &PageProof {
        &self.proof
    }

    /// Borrows the proof's inseparable canonical encoding.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns the capacity of the existing encoding allocation.
    #[must_use]
    pub fn encoding_capacity(&self) -> usize {
        self.encoded.capacity()
    }
}

/// Borrows page bytes, their membership proof, and its existing encoding.
///
/// The producer retains every allocation and its original resource custody
/// throughout consumption. Constructing this view neither authenticates the
/// page nor allocates, copies, encodes, or acquires resources.
///
/// An independently supplied wire proof cannot be substituted for the sealed
/// owner's encoding:
///
/// ```compile_fail
/// use crucible_ram::{BorrowedPageResponse, EncodedPageProof};
///
/// fn mismatched_wire<'a>(
///     page: &'a mut [u8],
///     proof: &'a EncodedPageProof,
///     unrelated_wire: &'a [u8],
/// ) -> BorrowedPageResponse<'a> {
///     BorrowedPageResponse::new(page, proof, unrelated_wire)
/// }
/// ```
pub struct BorrowedPageResponse<'a> {
    page: &'a mut [u8],
    proof: &'a EncodedPageProof,
}

impl<'a> BorrowedPageResponse<'a> {
    /// Borrows an existing completion under the producer's original custody.
    pub fn new(page: &'a mut [u8], proof: &'a EncodedPageProof) -> Self {
        Self { page, proof }
    }

    /// Borrows the completion's page bytes for independent verification.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.page
    }

    /// Borrows the existing membership proof.
    #[must_use]
    pub fn proof(&self) -> &PageProof {
        self.proof.proof()
    }

    /// Borrows the producer's existing canonical proof encoding.
    #[must_use]
    pub fn encoded_proof(&self) -> &[u8] {
        self.proof.encoded()
    }

    /// Changes the first page byte without replacing its allocation or proof.
    ///
    /// # Errors
    /// Returns an error when the borrowed page is empty.
    #[cfg(feature = "test-support")]
    pub fn with_flipped_first_byte_for_test(self) -> Result<Self, RamError> {
        let Some(first) = self.page.first_mut() else {
            return Err(RamError::InvalidLength);
        };
        *first ^= 1;
        Ok(self)
    }

    /// Shortens the visible page while retaining its original allocation.
    ///
    /// The producer still owns the complete allocation. Only this untrusted
    /// completion view loses its last byte; the proof stays unchanged.
    ///
    /// # Errors
    /// Returns an error when the borrowed page is empty.
    #[cfg(feature = "test-support")]
    pub fn with_truncated_page_for_test(self) -> Result<Self, RamError> {
        let Some(length) = self.page.len().checked_sub(1) else {
            return Err(RamError::InvalidLength);
        };
        let (page, _) = self.page.split_at_mut(length);
        Ok(Self {
            page,
            proof: self.proof,
        })
    }
}
