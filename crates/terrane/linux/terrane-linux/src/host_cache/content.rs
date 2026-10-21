//! Exposes verified chunk and canonical metadata operations on a running native cache.
//!
//! Reads acquire the physical owner's actual consumer grants. Writes validate
//! the complete offered context before deduplication, then hand genuine completed
//! admissions into cache custody. No catalog row, decoded policy or guessed size
//! substitutes for a native source. This host-local adapter grants no ref writes
//! or guest authorization; callers apply their repository guard separately.

mod driver;
mod object;
mod prepared;
mod presentation;
mod validation;

pub use driver::{NativeReadDriver, NativeReadPolicy};
pub use object::{NativeChunkedObject, NativeChunkedReader};
pub use prepared::{NativePreparedObject, NativeSealedObject};
pub use presentation::NativeObjectPresentation;

use super::{NativeConsumerLease, NativeReady};
use std::{
    io,
    time::{Duration, UNIX_EPOCH},
};
use terrane_format::identity::{Identity, IdentityKind};
use terrane_sdk::{
    repository::MetadataValidator,
    store::{
        ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload, Durability,
        IdentityPrefix, InvalidReason, RangeCapability, RefCapability, StoreErrorKind,
        StoreFailure, TokioClock,
    },
};

/// Implements host-local content operations over genuine running cache custody.
///
/// Only an actual [`NativeReady`] supplies the owner. Every chunk read retains
/// its original native backing through verification and releases its durable
/// consumer grant afterward. Cancellation leaves accepted physical work and
/// durable leases with the owner until reconciliation or expiry.
///
/// Container-pack upload is currently unavailable through this adapter.
/// Canonical metadata uploads are stored as genuine ordinary metadata pack/index
/// pairs; chunks retain their offered verified encoding. Advisory listing covers
/// ordinary content and may omit sealed-only chunk residences.
pub struct NativeContentStore {
    ready: NativeReady,
    capabilities: Capabilities,
    validator: MetadataValidator,
    lease_duration: Duration,
    max_allocation_bytes: usize,
    max_requests: usize,
}

impl NativeContentStore {
    /// Binds content operations to the original recovered native owner.
    ///
    /// The finite lease duration bounds abandoned read and validation grants.
    /// It must be between one and 300 whole seconds. Request bounds come from
    /// the native owner's validated configuration, never upload declarations.
    ///
    /// # Errors
    /// Refuses a zero, fractional or overlong lease duration.
    pub fn new(ready: NativeReady, lease_duration: Duration) -> Result<Self, StoreFailure> {
        if !(1..=300).contains(&lease_duration.as_secs()) || lease_duration.subsec_nanos() != 0 {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::MalformedRequest,
            )));
        }
        let (max_allocation_bytes, max_requests) = ready.request_bounds();
        let capabilities = Capabilities {
            refs: RefCapability::None,
            ranges: RangeCapability::Ranges,
            presign: false,
            locality: ready.locality().clone(),
            durability: Durability::Local,
            sealed: true,
        };
        let validator = MetadataValidator::new(ready.layout().layout().chunk_profile().clone());
        Ok(Self {
            ready,
            capabilities,
            validator,
            lease_duration,
            max_allocation_bytes,
            max_requests,
        })
    }

    /// Borrows the original native owner composition for explicit cache maintenance.
    pub fn ready(&self) -> &NativeReady {
        &self.ready
    }

    fn consumer_deadline(&self) -> Result<u64, StoreFailure> {
        TokioClock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
            })?
            .as_secs()
            .checked_add(self.lease_duration.as_secs())
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Capacity))
    }

    async fn pin(&self, identity: &Identity) -> Result<NativeConsumerLease, StoreFailure> {
        let expires = self.consumer_deadline()?;
        self.ready
            .owner()
            .pin_resident_chunk(identity.clone(), expires)
            .await
            .map_err(|error| native_failure(error, identity))
    }

    async fn finish<T>(
        &self,
        result: Result<T, StoreFailure>,
        leases: Vec<NativeConsumerLease>,
    ) -> Result<T, StoreFailure> {
        let mut release_error = None;
        for lease in leases {
            if let Err(error) = self.ready.owner().release_consumer_lease(&lease).await {
                release_error.get_or_insert_with(|| native_failure(error, lease.identity()));
            }
        }
        match result {
            Err(error) => Err(error),
            Ok(value) => release_error.map_or(Ok(value), Err),
        }
    }
}

impl CapabilityReport for NativeContentStore {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl ContentStore for NativeContentStore {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        match upload {
            ContentUpload::Chunk(upload) => self.put_chunk(upload).await,
            ContentUpload::Meta(upload) => self.put_meta(upload).await,
        }
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if identity.profile() != terrane_format::identity::TERRANE_V1.name()
            || identity.kind() == IdentityKind::Pack
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let bytes = if identity == &validation::empty_chunk()? {
            vec![0]
        } else if identity.kind() == IdentityKind::Chunk {
            let lease = self.pin(identity).await?;
            let result = lease
                .read_encoded()
                .map_err(|error| native_failure(error, identity));
            self.finish(result, vec![lease]).await?
        } else {
            let lease = self
                .ready
                .owner()
                .pin_cached_metadata(identity.clone(), self.consumer_deadline()?)
                .await
                .map_err(|error| native_failure(error, identity))?;
            match lease {
                Some(lease) => {
                    let result = lease
                        .read_encoded()
                        .map_err(|error| native_failure(error, identity));
                    self.finish(result, vec![lease]).await?
                }
                None => return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone()))),
            }
        };
        match range {
            None => Ok(bytes),
            Some(range) => {
                let start = usize::try_from(range.start).ok();
                let end = range
                    .start
                    .checked_add(range.length)
                    .and_then(|end| usize::try_from(end).ok());
                match start
                    .zip(end)
                    .and_then(|(start, end)| bytes.get(start..end))
                {
                    Some(selected) => Ok(selected.to_vec()),
                    None => Err(StoreFailure::new(StoreErrorKind::Invalid(
                        InvalidReason::Range(range),
                    ))),
                }
            }
        }
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        if identities.len() > self.max_requests {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        let mut result = Vec::with_capacity(identities.len());
        for identity in identities {
            match self.get(identity, None).await {
                Ok(_) => result.push(true),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {
                    result.push(false)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(result)
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.ready
            .metadata()
            .list_candidates(prefix, self.max_requests)
            .await
    }
}

pub(in crate::host_cache) fn native_failure(error: io::Error, identity: &Identity) -> StoreFailure {
    // Native policy preserves its typed store refusal inside the I/O boundary.
    // In particular, an exhausted durable-state budget is still Capacity.
    if let Some(failure) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<StoreFailure>())
    {
        return StoreFailure::with_source(failure.kind().clone(), error);
    }

    let kind = match error.kind() {
        io::ErrorKind::NotFound => StoreErrorKind::Absent(identity.clone()),
        io::ErrorKind::InvalidData => StoreErrorKind::Corrupt(
            terrane_sdk::store::CorruptSubject::Identity(identity.clone()),
        ),
        io::ErrorKind::OutOfMemory | io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => {
            StoreErrorKind::Capacity
        }
        io::ErrorKind::Unsupported => StoreErrorKind::Unsupported,
        _ => StoreErrorKind::Unavailable { retry_after: None },
    };
    StoreFailure::with_source(kind, error)
}
