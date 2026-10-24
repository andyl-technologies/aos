//! Restores encoded chunk reads from independently verified sealed residences.
//!
//! The portable wrapper verifies returned chunk bytes. The native binding owns
//! publisher-adopted descriptors, manifest witnesses, domain-root evidence and
//! durable pins; implementing this trait alone establishes none of those facts.

use super::{DomainHostLayout, HostReadOnlyContent};
use crate::{
    bucket::BucketBinding,
    store::{
        ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, ContentValidator,
        CorruptSubject, IdentityPrefix, InvalidReason, LocalFs, StoreErrorKind, StoreFailure,
    },
};
use std::collections::BTreeMap;
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};

/// Carries one plaintext span and its verified manifest boundary context.
///
/// This is untrusted data to the portable verifier, never a native seal,
/// reservation, domain binding or authorization receipt.
pub struct ResidenceChunk {
    /// Plaintext bytes extracted from the claimed chunk's exact residence.
    pub plaintext: Vec<u8>,
    /// Whether the verified containing manifest places this chunk last.
    pub final_chunk: bool,
}

/// Supplies fixed residence reads from a trusted host I/O composition.
///
/// Native implementations retain actual adopted read-only publisher handles,
/// verified canonical manifests, genuine domain bindings and durable pins for
/// each operation. They check configured allocation limits before reading or
/// enumerating. Callers cannot select paths, file descriptors or callbacks.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait HostResidenceReader: BucketBinding {
    /// Reads a verified residence within the supplied plaintext allocation cap.
    ///
    /// Missing residence returns `None`. An existing corrupt or unadopted
    /// residence returns an error rather than silently becoming a cache miss.
    ///
    /// # Errors
    /// Rejects another domain/root, invalid manifest/range/seal, absent durable
    /// pin custody, native failures and capacity above `max_plaintext_bytes`.
    async fn read_chunk(
        &self,
        layout: &DomainHostLayout,
        identity: &Identity,
        max_plaintext_bytes: usize,
    ) -> Result<Option<ResidenceChunk>, StoreFailure>;

    /// Enumerates candidate chunk identities without exceeding the entry cap.
    ///
    /// Candidates are independently read and verified before being advertised.
    /// The binding bounds its allocation before constructing the returned vector.
    ///
    /// # Errors
    /// Returns capacity when the inventory exceeds `max_entries`, or domain,
    /// manifest, recovery and native I/O errors. Size alone is never corruption.
    async fn chunk_identities(
        &self,
        layout: &DomainHostLayout,
        max_entries: usize,
    ) -> Result<Vec<Identity>, StoreFailure>;
}

/// Adds verified sealed-residence fallback to an ordinary encoded cache reader.
///
/// Only an ordinary chunk miss consults residences. Corrupt ordinary content
/// remains an error for the owning quarantine/refetch policy. Manifest identities
/// always address retained canonical metadata, never sealed plaintext.
pub struct HostResidentContent<F, V, R> {
    ordinary: HostReadOnlyContent<F, V>,
    residences: R,
    max_inventory_entries: usize,
}

impl<F: LocalFs + BucketBinding, V: ContentValidator + BucketBinding> HostReadOnlyContent<F, V> {
    /// Adds a trusted residence I/O binding and finite inventory policy.
    ///
    /// The inventory cap bounds retained ordinary and residence identities;
    /// underlying `LocalFs::read_dir` allocation remains the binding's concern.
    /// This composition is not evidence that native admission, seals, quota or
    /// domain authorization are qualified. Those belong to the concrete binding.
    ///
    /// # Errors
    /// Returns capacity when `max_inventory_entries` is zero.
    pub fn with_residences<R: HostResidenceReader>(
        self,
        residences: R,
        max_inventory_entries: usize,
    ) -> Result<HostResidentContent<F, V, R>, StoreFailure> {
        if max_inventory_entries == 0 {
            return Err(capacity());
        }
        Ok(HostResidentContent {
            ordinary: self,
            residences,
            max_inventory_entries,
        })
    }
}

impl<F: LocalFs + BucketBinding, V: ContentValidator + BucketBinding, R>
    HostResidentContent<F, V, R>
{
    /// Returns the immutable routing layout of the ordinary and residence views.
    pub fn layout(&self) -> &DomainHostLayout {
        self.ordinary.layout()
    }

    /// Returns the ordinary reader's observed root device and inode.
    pub fn directory_identity(&self) -> (u64, u64) {
        self.ordinary.directory_identity()
    }
}

impl<F, V, R> CapabilityReport for HostResidentContent<F, V, R> {
    fn capabilities(&self) -> &Capabilities {
        self.ordinary.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, V, R> ContentStore for HostResidentContent<F, V, R>
where
    F: LocalFs + BucketBinding,
    V: ContentValidator + BucketBinding,
    R: HostResidenceReader,
{
    async fn put(&self, _upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        let absence = match self.ordinary.get(identity, range).await {
            Ok(bytes) => return Ok(bytes),
            Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => error,
            Err(error) => return Err(error),
        };
        if identity.kind() != IdentityKind::Chunk {
            return Err(absence);
        }
        let limit = self
            .ordinary
            .read_limits()
            .max_allocation_bytes
            .saturating_sub(1)
            .min(self.layout().chunk_profile().maximum());
        let Some(chunk) = self
            .residences
            .read_chunk(self.layout(), identity, limit)
            .await?
        else {
            return Err(absence);
        };
        if chunk.plaintext.len() > limit {
            return Err(capacity());
        }
        // Codec zero is the registered raw envelope. Chunk identities name
        // plaintext, so a residence need not preserve its former compression.
        let mut encoded = Vec::with_capacity(chunk.plaintext.len() + 1);
        encoded.push(0);
        encoded.extend_from_slice(&chunk.plaintext);
        crate::codec::decode_verified(
            &encoded,
            chunk.plaintext.len(),
            self.layout().chunk_profile(),
            chunk.final_chunk,
            identity,
            None,
        )
        .map_err(|error| {
            StoreFailure::with_source(
                StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
                error,
            )
        })?;
        slice_encoded(encoded, range)
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        let mut present = Vec::with_capacity(identities.len());
        for identity in identities {
            match self.get(identity, None).await {
                Ok(_) => present.push(true),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {
                    present.push(false)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(present)
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        let ordinary = self
            .ordinary
            .list_bounded(prefix, self.max_inventory_entries)
            .await?;
        if ordinary.len() > self.max_inventory_entries {
            return Err(capacity());
        }
        let mut identities: BTreeMap<Vec<u8>, Identity> = ordinary
            .into_iter()
            .map(|identity| (identity.digest().to_vec(), identity))
            .collect();
        if prefix.kind == IdentityKind::Chunk {
            let candidates = self
                .residences
                .chunk_identities(self.layout(), self.max_inventory_entries)
                .await?;
            if candidates.len() > self.max_inventory_entries {
                return Err(capacity());
            }
            for identity in candidates {
                if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name()
                {
                    return Err(StoreFailure::new(StoreErrorKind::Invalid(
                        InvalidReason::MalformedRequest,
                    )));
                }
                if !identity.digest().starts_with(&prefix.digest_prefix) {
                    continue;
                }
                self.get(&identity, None).await?;
                if !identities.contains_key(identity.digest())
                    && identities.len() >= self.max_inventory_entries
                {
                    return Err(capacity());
                }
                identities.insert(identity.digest().to_vec(), identity);
            }
        }
        Ok(identities.into_values().collect())
    }
}

fn slice_encoded(bytes: Vec<u8>, range: Option<ByteRange>) -> Result<Vec<u8>, StoreFailure> {
    let Some(range) = range else {
        return Ok(bytes);
    };
    let invalid = || StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Range(range)));
    let start = usize::try_from(range.start).map_err(|_| invalid())?;
    let length = usize::try_from(range.length).map_err(|_| invalid())?;
    let end = start.checked_add(length).ok_or_else(invalid)?;
    bytes
        .get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(invalid)
}

fn capacity() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Capacity)
}
