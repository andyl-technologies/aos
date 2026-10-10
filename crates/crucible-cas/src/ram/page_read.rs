//! Linear page and proof owners retaining their original allocation custody.

use std::ops::Deref;

use crucible_ram::{NodeDigest, PageProof};

use crate::owned_decode::{DecodeBudget, DecodeScratch};

use super::RamStoreError;
use super::codec_ownership::OwnedEnvelope;

#[cfg(any(test, feature = "test-support"))]
use super::logical;

const PAGE_PREFIX_BYTES: usize = 32 + 4;

/// Retains authenticated page bytes in their original decoded envelope.
///
/// Borrowing exposes only the canonical valid page bytes. The envelope and its
/// decoder custody stay together until this linear owner closes.
pub struct RamPageBytes {
    envelope: OwnedEnvelope,
}

impl RamPageBytes {
    pub(super) fn new(envelope: OwnedEnvelope) -> Self {
        Self { envelope }
    }

    /// Borrows the authenticated canonical page bytes without copying them.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        // Construction follows complete envelope, length and digest validation.
        &self.envelope.body()[PAGE_PREFIX_BYTES..]
    }
}

impl Deref for RamPageBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}

impl AsRef<[u8]> for RamPageBytes {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for RamPageBytes {
    fn eq(&self, other: &T) -> bool {
        self.bytes() == other.as_ref()
    }
}

impl Eq for RamPageBytes {}

impl std::fmt::Debug for RamPageBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RamPageBytes")
            .field("length", &self.len())
            .finish_non_exhaustive()
    }
}

/// Retains one page, its portable proof, and its canonical proof encoding.
///
/// The response sender borrows these fields while their original resource
/// owners remain live. This owner cannot detach an unaccounted vector or proof.
pub struct RamPageRead {
    page: RamPageBytes,
    proof: crucible_ram::EncodedPageProof,
    // All proof allocations close before their original refundable reservation.
    _credit: DecodeScratch,
}

impl RamPageRead {
    pub(super) fn new(page: RamPageBytes, proof: PageProof, credit: DecodeScratch) -> Self {
        let proof = crucible_ram::EncodedPageProof::new(proof);
        Self {
            page,
            proof,
            _credit: credit,
        }
    }

    pub(super) fn into_page(self) -> RamPageBytes {
        self.page
    }

    /// Borrows the existing completion while retaining all original custody.
    ///
    /// The producer keeps this owner live through response validation and send
    /// completion. This view adds no allocation, account clone, reservation,
    /// encoding, or copy; it grants no independent authentication authority.
    pub fn borrow_response(&mut self) -> crucible_ram::BorrowedPageResponse<'_> {
        crucible_ram::BorrowedPageResponse::new(
            &mut self.page.envelope.body_mut()[PAGE_PREFIX_BYTES..],
            &self.proof,
        )
    }

    /// Borrows the authenticated canonical valid page bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.page.bytes()
    }

    /// Borrows the page's authenticated portable membership proof.
    #[must_use]
    pub fn proof(&self) -> &PageProof {
        self.proof.proof()
    }

    /// Borrows the canonical proof encoding for a bounded response.
    #[must_use]
    pub fn encoded_proof(&self) -> &[u8] {
        self.proof.encoded()
    }

    /// Flips the first page byte while retaining its original proof and custody.
    ///
    /// The returned page is intentionally untrusted. This consuming test helper
    /// preserves every allocation and resource owner so the response consumer
    /// must detect the changed content through its normal proof validation.
    ///
    /// # Errors
    /// Returns an error when the page contains no byte to change.
    #[cfg(feature = "test-support")]
    pub fn with_flipped_first_byte_for_test(mut self) -> Result<Self, RamStoreError> {
        if !self
            .page
            .envelope
            .flip_body_byte_for_test(PAGE_PREFIX_BYTES)
        {
            return Err(RamStoreError::Invalid("empty test page completion"));
        }
        Ok(self)
    }

    /// Removes the final page byte while retaining its original proof and custody.
    ///
    /// The returned page is intentionally untrusted. Its unchanged proof and
    /// resource owners allow the response consumer to reject the shortened
    /// completion without reconstructing or copying the original envelope.
    ///
    /// # Errors
    /// Returns an error when the page contains no byte to remove.
    #[cfg(feature = "test-support")]
    pub fn with_truncated_page_for_test(mut self) -> Result<Self, RamStoreError> {
        if self.bytes().is_empty() || !self.page.envelope.remove_last_body_byte_for_test() {
            return Err(RamStoreError::Invalid("empty test page completion"));
        }
        Ok(self)
    }

    /// Copies modeled page values into independently admitted test ownership.
    ///
    /// This helper checks the page identity committed by the proof. It grants
    /// neither physical storage authentication nor root membership; the modeled
    /// source and response consumer still verify the separately trusted root.
    /// Incoming fixture allocations remain the fixture's responsibility.
    ///
    /// # Errors
    /// Returns original resource refusal, allocation bounds, or mismatched page
    /// length or digest. Admission precedes every copied allocation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_page_for_test(
        original: &DecodeBudget,
        bytes: &[u8],
        proof: &PageProof,
    ) -> Result<Self, RamStoreError> {
        use std::collections::BTreeSet;

        use crate::content_envelope::ContentEnvelope;

        original
            .verify_live()
            .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
        if bytes.len() != proof.valid_length() as usize
            || crucible_ram::PageDigest::hash(bytes).map_err(logical)? != proof.page_digest()
        {
            return Err(RamStoreError::Invalid("modeled page identity"));
        }

        let credit = proof_credit(original, proof.region_id(), proof.siblings().len())?;
        let account = original
            .child()
            .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
        let body_length = PAGE_PREFIX_BYTES
            .checked_add(bytes.len())
            .ok_or(RamStoreError::Limit("page response allocation"))?;
        account
            .charge_bytes((body_length + super::codec::PAGE_SCHEMA.len()) as u64)
            .map_err(|error| crate::content_store::batch::admission_under(&account, error))?;

        let mut body = Vec::with_capacity(body_length);
        body.extend_from_slice(proof.page_digest().as_bytes());
        body.extend_from_slice(&proof.valid_length().to_be_bytes());
        body.extend_from_slice(bytes);
        let envelope = ContentEnvelope::new(
            super::codec::PAGE_SCHEMA,
            super::codec::SCHEMA_VERSION,
            BTreeSet::new(),
            body,
        )?;
        let page = RamPageBytes::new(OwnedEnvelope::new(envelope, &account));
        let proof = PageProof::new(
            proof.region_id(),
            proof.page_index(),
            proof.valid_length(),
            proof.page_digest(),
            proof.siblings().to_vec(),
        )
        .map_err(logical)?;
        Ok(Self::new(page, proof, credit))
    }
}

impl Deref for RamPageRead {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}

impl std::fmt::Debug for RamPageRead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RamPageRead")
            .field("length", &self.bytes().len())
            .field("proof", &self.proof())
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use std::sync::Arc;

    use crate::content_store::{StoreError, StorePhysicalQuotaGuard};
    use crate::owned_decode::ResourceLoan;

    use super::*;

    struct CompletionResources(crate::content_store::test_resources::FixtureResourceBudget);

    impl StorePhysicalQuotaGuard for CompletionResources {
        fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
            Ok(1024 * 1024)
        }

        fn verify(&self) -> Result<(), StoreError> {
            Ok(())
        }

        fn reserve_resources(
            &self,
            descriptors: u64,
            resident_bytes: u64,
        ) -> Result<ResourceLoan, StoreError> {
            self.0.reserve(descriptors, resident_bytes)
        }
    }

    #[test]
    fn page_completion_faults_retain_the_original_allocations_proof_and_custody() {
        for truncate in [false, true] {
            let resources = Arc::new(CompletionResources(
                crate::content_store::test_resources::FixtureResourceBudget::new(8, 1024 * 1024),
            ));
            let original = DecodeBudget::for_store(resources.clone())
                .unwrap_or_else(|error| panic!("finite completion account: {error}"));
            let bytes = [1, 2, 3, 4];
            let digest = crucible_ram::PageDigest::hash(&bytes)
                .unwrap_or_else(|error| panic!("original page digest: {error}"));
            let proof = PageProof::new("main", 0, 4, digest, Vec::new())
                .unwrap_or_else(|error| panic!("original page proof: {error}"));
            let page = RamPageRead::from_page_for_test(&original, &bytes, &proof)
                .unwrap_or_else(|error| panic!("admitted page owner: {error}"));
            let page_address = page.bytes().as_ptr();
            let proof_address = page.encoded_proof().as_ptr();
            let proof_capacity = page.proof.encoding_capacity();
            let original_credit = resources
                .0
                .usage()
                .unwrap_or_else(|error| panic!("original completion credit: {error}"));

            let page = if truncate {
                page.with_truncated_page_for_test()
            } else {
                page.with_flipped_first_byte_for_test()
            }
            .unwrap_or_else(|error| panic!("damage original completion: {error}"));

            assert_eq!(page.bytes().as_ptr(), page_address);
            assert_eq!(page.encoded_proof().as_ptr(), proof_address);
            assert_eq!(page.proof.encoding_capacity(), proof_capacity);
            assert_eq!(page.encoded_proof(), proof.encode());
            assert_eq!(page.proof().page_digest(), digest);
            assert_eq!(page.proof().valid_length(), 4);
            assert_ne!(page.bytes(), bytes);
            assert_eq!(page.bytes().len(), if truncate { 3 } else { 4 });
            assert_eq!(
                resources
                    .0
                    .usage()
                    .unwrap_or_else(|error| panic!("retained credit: {error}")),
                original_credit,
            );

            drop(original);
            assert_eq!(
                resources
                    .0
                    .usage()
                    .unwrap_or_else(|error| panic!("owner-only credit: {error}")),
                original_credit,
            );
            drop(page);
            assert_eq!(
                resources
                    .0
                    .usage()
                    .unwrap_or_else(|error| panic!("closed completion credit: {error}")),
                (0, 0),
            );
        }
    }
}

pub(super) fn proof_credit(
    original: &DecodeBudget,
    region_id: &str,
    height: usize,
) -> Result<DecodeScratch, RamStoreError> {
    let siblings = height
        .checked_mul(std::mem::size_of::<NodeDigest>())
        .ok_or(RamStoreError::Limit("page proof allocation"))?;
    // PageProof::encode reserves exactly this capacity in the pinned codec.
    let encoding = 64_usize
        .checked_add(region_id.len())
        .and_then(|bytes| bytes.checked_add(siblings))
        .ok_or(RamStoreError::Limit("page proof allocation"))?;
    let total = region_id
        .len()
        .checked_add(siblings)
        .and_then(|bytes| bytes.checked_add(encoding))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RamStoreError::Limit("page proof allocation"))?;
    original
        .reserve_scratch_bytes(total)
        .map_err(|error| crate::content_store::batch::admission_under(original, error).into())
}
