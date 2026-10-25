//! Serves verified resident content and warms native custody from a bounded lower read.
//!
//! The original repository remains the reference and authorization authority.
//! This driver accepts only an already running native store, obtains original
//! consumer grants on hits, and submits real native admissions after fully
//! verifying a lower body. Failed admission never invalidates verified lower
//! bytes and never releases rejected original custody or funding.

use super::NativeContentStore;
use std::{sync::Arc, time::Duration};
use terrane_format::{
    codec::{Codec, parse_envelope},
    identity::{Identity, IdentityKind, TERRANE_V1},
};
use terrane_sdk::{
    bucket::BucketBinding,
    host::cache::{CircuitBreaker, FetchRequirement},
    store::{
        ByteRange, Capabilities, CapabilityReport, ChunkPosition, ChunkUpload, Clock, ContentStore,
        ContentUpload, IdentityPrefix, InvalidReason, MetaUpload, StoreErrorKind, StoreFailure,
        TokioClock,
    },
};
use tokio::{
    sync::Mutex,
    time::{Instant, timeout_at},
};

/// Owns validated finite lower-read and circuit policy without native authority.
pub struct NativeReadPolicy {
    budget: Duration,
    circuit: CircuitBreaker,
}

impl NativeReadPolicy {
    /// Validates an explicit deadline, consecutive-failure threshold and probe interval.
    ///
    /// # Errors
    /// Refuses zero or fractional-millisecond intervals, intervals above 300
    /// seconds, and thresholds outside one through 1000 consecutive failures.
    pub fn new(budget: Duration, failures: u32, probe: Duration) -> Result<Self, StoreFailure> {
        let finite = |value: Duration| {
            !value.is_zero()
                && value <= Duration::from_secs(300)
                && value.subsec_nanos().is_multiple_of(1_000_000)
        };
        if !finite(budget) || !finite(probe) || !(1..=1000).contains(&failures) {
            return Err(invalid());
        }
        Ok(Self {
            budget,
            circuit: CircuitBreaker::new(failures, probe)?,
        })
    }
}

/// Retains a genuine native owner and a trusted same-domain original lower store.
///
/// Resident reads remain available with an open lower circuit. Misses use one
/// total deadline, including the circuit wait, dictionary fetch and optional
/// native admission. Every lower body is verified before a successful circuit
/// result or admission. Complete repository guards still authorize each request.
/// Clones share the same physical owner, lower store and circuit state; cloning
/// never restarts recovery, creates custody or resets a failed lower circuit.
pub struct NativeReadDriver<S> {
    native: Arc<NativeContentStore>,
    lower: Arc<S>,
    circuit: Arc<Mutex<CircuitBreaker>>,
    budget: Duration,
}

impl<S> Clone for NativeReadDriver<S> {
    fn clone(&self) -> Self {
        Self {
            native: Arc::clone(&self.native),
            lower: Arc::clone(&self.lower),
            circuit: Arc::clone(&self.circuit),
            budget: self.budget,
        }
    }
}

impl NativeContentStore {
    /// Transfers the original running owner into bounded same-domain read-through routing.
    ///
    /// Trusted composition supplies the genuine original lower store and an
    /// already validated policy. No initialization, recovery or authority is
    /// inferred from the lower store, its bytes or this configuration.
    pub fn with_lower<S>(self, lower: S, policy: NativeReadPolicy) -> NativeReadDriver<S> {
        NativeReadDriver {
            native: Arc::new(self),
            lower: Arc::new(lower),
            circuit: Arc::new(Mutex::new(policy.circuit)),
            budget: policy.budget,
        }
    }
}

impl<S> NativeReadDriver<S> {
    /// Borrows the original running native content and maintenance owner.
    pub fn native(&self) -> &NativeContentStore {
        &self.native
    }
}

struct Dictionary {
    identity: Identity,
    encoded: Vec<u8>,
    plaintext: Vec<u8>,
}

struct Fetched {
    encoded: Vec<u8>,
    length: Option<usize>,
    dictionary: Option<Dictionary>,
}

impl<S: ContentStore + BucketBinding> NativeReadDriver<S> {
    async fn fetch(&self, identity: &Identity) -> Result<Vec<u8>, StoreFailure> {
        let deadline = Instant::now() + self.budget;
        let mut circuit = timeout_at(deadline, self.circuit.lock())
            .await
            .map_err(|_| unavailable())?;
        if !circuit.allow(TokioClock.monotonic()) {
            return Err(unavailable());
        }
        let fetched = timeout_at(deadline, self.fetch_verified(identity))
            .await
            .map_err(|_| unavailable())
            .and_then(|result| result);
        let fetched = if Instant::now() >= deadline {
            Err(unavailable())
        } else {
            fetched
        };
        let fetched = match fetched {
            Ok(fetched) => {
                circuit.success();
                fetched
            }
            Err(error) => {
                if !matches!(error.kind(), StoreErrorKind::Absent(_)) {
                    circuit.failure(TokioClock.monotonic());
                }
                return Err(error);
            }
        };
        drop(circuit);

        // Cache admission is separate from the verified lower result. Timeout
        // or cancellation leaves accepted native work with its physical owner.
        if Instant::now() >= deadline
            || (fetched.length.is_none() && identity.kind() != IdentityKind::Manifest)
        {
            // Control/history metadata remains verified lower content. Warming
            // arbitrary graph records would consume bounded durable consumer
            // state before this request's object chunks can enter custody.
            return Ok(fetched.encoded);
        }
        if let Some(dictionary) = &fetched.dictionary {
            let upload = ChunkUpload {
                encoded: &dictionary.encoded,
                identity: &dictionary.identity,
                declared_plaintext_len: dictionary.plaintext.len(),
                position: ChunkPosition::Final,
                profile: self.native.ready.layout().layout().chunk_profile(),
            };
            let _ = timeout_at(deadline, self.native.put(ContentUpload::Chunk(upload))).await;
        }
        if Instant::now() >= deadline {
            return Ok(fetched.encoded);
        }
        let upload = match fetched.length {
            Some(length) => ContentUpload::Chunk(ChunkUpload {
                encoded: &fetched.encoded,
                identity,
                declared_plaintext_len: length,
                position: ChunkPosition::Final,
                profile: self.native.ready.layout().layout().chunk_profile(),
            }),
            None => ContentUpload::Meta(MetaUpload::new(identity.kind(), &fetched.encoded)?),
        };
        let _ = timeout_at(deadline, self.native.put(upload)).await;
        Ok(fetched.encoded)
    }

    async fn fetch_verified(&self, identity: &Identity) -> Result<Fetched, StoreFailure> {
        let encoded = self.lower.get(identity, None).await?;
        if encoded.len() > self.native.max_allocation_bytes {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        if identity.kind() != IdentityKind::Chunk {
            FetchRequirement::Metadata { identity }.verify(&encoded, &self.native.validator)?;
            return Ok(Fetched {
                encoded,
                length: None,
                dictionary: None,
            });
        }
        let profile = self.native.ready.layout().layout().chunk_profile();
        let length = terrane_sdk::codec::encoded_plaintext_len(&encoded, profile.maximum())
            .map_err(|error| corrupt(identity, error))?;
        if length > self.native.max_allocation_bytes {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        let envelope = parse_envelope(&encoded).map_err(|error| corrupt(identity, error))?;
        let dictionary = if let Codec::ZstdDictionary(digest) = envelope.codec {
            let id = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .map_err(|error| corrupt(identity, error))?;
            if id == *identity {
                return Err(invalid());
            }
            let bytes = match self.native.get(&id, None).await {
                Ok(bytes) => bytes,
                Err(error) if retryable(&error) => self.lower.get(&id, None).await?,
                Err(error) => return Err(error),
            };
            if bytes.len() > self.native.max_allocation_bytes {
                return Err(StoreFailure::new(StoreErrorKind::Capacity));
            }
            let size = terrane_sdk::codec::encoded_plaintext_len(&bytes, profile.maximum())
                .map_err(|error| corrupt(&id, error))?;
            if size > self.native.max_allocation_bytes {
                return Err(StoreFailure::new(StoreErrorKind::Capacity));
            }
            let plaintext =
                terrane_sdk::codec::decode_verified(&bytes, size, profile, true, &id, None)
                    .map_err(|error| corrupt(&id, error))?
                    .plaintext()
                    .to_vec();
            Some(Dictionary {
                identity: id,
                encoded: bytes,
                plaintext,
            })
        } else {
            None
        };
        // Standalone cache admission accepts a final boundary; each actual
        // object reader independently enforces its declared length and position.
        FetchRequirement::Chunk {
            identity,
            length,
            profile,
            final_chunk: true,
            dictionary: dictionary.as_ref().map(|value| value.plaintext.as_slice()),
        }
        .verify(&encoded, &self.native.validator)?;
        Ok(Fetched {
            encoded,
            length: Some(length),
            dictionary,
        })
    }
}

impl<S> CapabilityReport for NativeReadDriver<S> {
    fn capabilities(&self) -> &Capabilities {
        self.native.capabilities()
    }
}

#[async_trait::async_trait]
impl<S: ContentStore + BucketBinding> ContentStore for NativeReadDriver<S> {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        let bytes = match self.native.get(identity, None).await {
            Ok(bytes) => bytes,
            Err(error) if retryable(&error) => self.fetch(identity).await?,
            Err(error) => return Err(error),
        };
        match range {
            None => Ok(bytes),
            Some(range) => {
                let bounds = usize::try_from(range.start).ok().zip(
                    range
                        .start
                        .checked_add(range.length)
                        .and_then(|value| usize::try_from(value).ok()),
                );
                bounds
                    .and_then(|(start, end)| bytes.get(start..end))
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| {
                        StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Range(range)))
                    })
            }
        }
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        if identities.len() > self.native.max_requests {
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
        // This is advisory resident inventory, never original reachability.
        self.native.list(prefix).await
    }
}

fn retryable(error: &StoreFailure) -> bool {
    matches!(
        error.kind(),
        StoreErrorKind::Absent(_)
            | StoreErrorKind::Corrupt(_)
            | StoreErrorKind::Unavailable { .. }
            | StoreErrorKind::Capacity
    )
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}

fn invalid() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
}

fn corrupt(
    identity: &Identity,
    error: impl std::error::Error + Send + Sync + 'static,
) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Corrupt(terrane_sdk::store::CorruptSubject::Identity(
            identity.clone(),
        )),
        error,
    )
}
