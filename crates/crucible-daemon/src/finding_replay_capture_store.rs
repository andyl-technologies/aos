//! Chunked immutable storage for portable finding replay captures.
//!
//! A complete capture is split into deterministic chunks no larger than 64
//! MiB. A small versioned [`ContentEnvelope`] records the capture hash, total
//! length, and ordered chunk children. Four role-specific manifests form one
//! finding capture set; preparation deduplicates equal chunk identities across
//! all roles before enforcing the 512 MiB finding allowance.
//!
//! ```text
//! manifest body := "CRUCFRCM", capture-hash[32], total-length:u64,
//!                  ordered-chunk-count:u32
//! children      := chunk-00000000, chunk-00000001, ...
//! ```

use crucible::ContentHash;
use crucible_campaign::{
    CampaignExecutorPublicationGuard, FindingReplayCaptureEvidenceId,
    FindingReplayCaptureIncomplete, FindingReplayCaptureReference, FindingReplayCaptureSet,
    MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES,
};
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope, ContentEnvelopeError};
use crucible_cas::content_store::{BlobHandle, ContentId, ObjectKind, PutReceipt, StoreError};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const CAPTURE_MANIFEST_SCHEMA: &str = "crucible.executor.finding-replay-capture-manifest";
const CAPTURE_MANIFEST_SCHEMA_VERSION: u32 = 1;
const CAPTURE_CHUNK_SCHEMA_VERSION: u32 = 1;
const CAPTURE_MANIFEST_MAGIC: &[u8; 8] = b"CRUCFRCM";
const MAX_CAPTURE_CHUNK_BYTES: usize = 64 * 1024 * 1024;
const MAX_CAPTURE_MANIFEST_BYTES: usize = 4 * 1024;
const MAX_CAPTURE_CHUNKS: usize =
    MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES as usize / MAX_CAPTURE_CHUNK_BYTES;

/// One transient complete or durable-incomplete capture outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingReplayCaptureInput {
    /// Canonical path-free capture bytes and their independently derived hash.
    Complete {
        /// Canonical capture bytes.
        bytes: Vec<u8>,
        /// Hash returned by the capture producer for these exact bytes.
        content_hash: ContentHash,
    },
    /// Stable reason this role has no complete capture.
    Incomplete(FindingReplayCaptureIncomplete),
}

/// No-write preparation of one four-role chunked capture closure.
#[derive(Clone)]
pub struct PreparedFindingReplayCaptureSet {
    references: FindingReplayCaptureSet,
    manifests: BTreeMap<ContentId, BlobHandle>,
    chunks: BTreeMap<ContentId, BlobHandle>,
    unique_chunk_bytes: u64,
}

impl PreparedFindingReplayCaptureSet {
    /// Returns the four small manifest roots or durable incomplete reasons.
    #[must_use]
    pub const fn references(&self) -> FindingReplayCaptureSet {
        self.references
    }

    /// Returns aggregate bytes charged after cross-role chunk deduplication.
    #[must_use]
    pub const fn unique_chunk_bytes(&self) -> u64 {
        self.unique_chunk_bytes
    }
}

/// Complete authenticated bytes loaded for one durable capture outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadedFindingReplayCapture {
    /// Reassembled canonical capture bytes and their authenticated hash.
    Complete {
        /// Canonical capture bytes.
        bytes: Vec<u8>,
        /// Hash committed by the authenticated manifest.
        content_hash: ContentHash,
    },
    /// Stable reason this role has no complete capture.
    Incomplete(FindingReplayCaptureIncomplete),
}

/// Durable immutable store operations for portable finding replay captures.
pub struct FindingReplayCaptureStore;

impl FindingReplayCaptureStore {
    /// Derives all chunk and manifest identities without repository writes.
    ///
    /// Equal chunks are stored once across the four fixed roles. A complete
    /// role that would exceed the remaining aggregate allowance is represented
    /// by [`FindingReplayCaptureIncomplete::PublicationLimitExceeded`].
    ///
    /// # Errors
    ///
    /// Returns an error when complete bytes are empty, disagree with their
    /// producer hash, or cannot be represented by the bounded manifest format.
    pub fn prepare_set(
        inputs: [FindingReplayCaptureInput; 4],
    ) -> Result<PreparedFindingReplayCaptureSet, FindingReplayCaptureStoreError> {
        let mut manifests = BTreeMap::new();
        let mut chunks = BTreeMap::new();
        let mut unique_chunk_bytes = 0_u64;
        let mut references = Vec::with_capacity(4);

        for input in inputs {
            let FindingReplayCaptureInput::Complete {
                bytes,
                content_hash,
            } = input
            else {
                let FindingReplayCaptureInput::Incomplete(reason) = input else {
                    unreachable!();
                };
                references.push(FindingReplayCaptureReference::Incomplete(reason));
                continue;
            };

            let prepared = match prepare_capture(bytes, content_hash) {
                Ok(prepared) => prepared,
                Err(FindingReplayCaptureStoreError::LimitExceeded {
                    limit: "finding-replay-capture-bytes",
                }) => {
                    references.push(FindingReplayCaptureReference::Incomplete(
                        FindingReplayCaptureIncomplete::PublicationLimitExceeded,
                    ));
                    continue;
                }
                Err(source) => return Err(source),
            };
            let additional_bytes = prepared
                .chunks
                .iter()
                .filter(|(id, _)| !chunks.contains_key(*id))
                .try_fold(0_u64, |total, (_, source)| {
                    total.checked_add(source.logical_length()).ok_or(
                        FindingReplayCaptureStoreError::LimitExceeded {
                            limit: "finding-replay-capture-unique-chunk-bytes",
                        },
                    )
                })?;
            if unique_chunk_bytes
                .checked_add(additional_bytes)
                .is_none_or(|total| total > MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES)
            {
                references.push(FindingReplayCaptureReference::Incomplete(
                    FindingReplayCaptureIncomplete::PublicationLimitExceeded,
                ));
                continue;
            }

            unique_chunk_bytes += additional_bytes;
            chunks.extend(prepared.chunks);
            manifests
                .entry(prepared.root.content_id())
                .or_insert(prepared.manifest);
            references.push(FindingReplayCaptureReference::Complete(prepared.root));
        }

        let references: [FindingReplayCaptureReference; 4] =
            references
                .try_into()
                .map_err(|_| FindingReplayCaptureStoreError::InvalidManifest {
                    reason: "capture role count",
                })?;
        Ok(PreparedFindingReplayCaptureSet {
            references: FindingReplayCaptureSet::new(
                references[0],
                references[1],
                references[2],
                references[3],
            ),
            manifests,
            chunks,
            unique_chunk_bytes,
        })
    }

    /// Publishes chunks first and manifest roots last.
    ///
    /// Exact retry is idempotent. The caller must hold repository GC exclusion
    /// from before the first chunk write through the operational Publishing
    /// transition that retains every complete manifest root. The hidden
    /// prepared-result journal is written before that transition and becomes
    /// visible only after the transition succeeds.
    ///
    /// # Errors
    ///
    /// Returns a backend or durable-receipt error. Earlier successful writes
    /// are unreachable immutable objects until the caller stages the roots.
    pub fn publish_set(
        guard: &CampaignExecutorPublicationGuard<'_>,
        prepared: &PreparedFindingReplayCaptureSet,
    ) -> Result<(), FindingReplayCaptureStoreError> {
        for (id, source) in &prepared.chunks {
            require_durable_receipt(
                guard.put_finding_replay_capture_object(*id, source)?,
                *id,
                source,
            )?;
        }
        for (id, source) in &prepared.manifests {
            require_durable_receipt(
                guard.put_finding_replay_capture_object(*id, source)?,
                *id,
                source,
            )?;
        }
        Ok(())
    }

    /// Loads and authenticates all four manifest/chunk closures.
    ///
    /// The returned array preserves the canonical role order used by
    /// [`FindingReplayCaptureSet::references`].
    ///
    /// # Errors
    ///
    /// Returns an error when a manifest or chunk is absent, corrupt,
    /// oversized, out of order, or inconsistent with the committed capture
    /// length and hash.
    pub fn load_set(
        guard: &CampaignExecutorPublicationGuard<'_>,
        references: FindingReplayCaptureSet,
    ) -> Result<[LoadedFindingReplayCapture; 4], FindingReplayCaptureStoreError> {
        Self::preflight_set(guard, references)?;

        let mut loaded = Vec::with_capacity(4);
        for reference in references.references() {
            match reference {
                FindingReplayCaptureReference::Complete(root) => {
                    loaded.push(Self::load_capture(guard, root)?);
                }
                FindingReplayCaptureReference::Incomplete(reason) => {
                    loaded.push(LoadedFindingReplayCapture::Incomplete(reason));
                }
            }
        }
        loaded
            .try_into()
            .map_err(|_| FindingReplayCaptureStoreError::InvalidManifest {
                reason: "capture role count",
            })
    }

    fn preflight_set(
        guard: &CampaignExecutorPublicationGuard<'_>,
        references: FindingReplayCaptureSet,
    ) -> Result<(), FindingReplayCaptureStoreError> {
        let mut unique_chunks = BTreeMap::new();
        let mut unique_chunk_bytes = 0_u64;

        for root in references
            .references()
            .into_iter()
            .filter_map(FindingReplayCaptureReference::evidence)
        {
            let (manifest, descriptor) = Self::load_manifest(guard, root)?;
            for (index, child) in manifest.children().iter().enumerate() {
                validate_chunk_child(index, child)?;
                let consumed = (index as u64)
                    .checked_mul(MAX_CAPTURE_CHUNK_BYTES as u64)
                    .ok_or(FindingReplayCaptureStoreError::LimitExceeded {
                        limit: "finding-replay-capture-chunk-bytes",
                    })?;
                let expected = descriptor
                    .total_length
                    .checked_sub(consumed)
                    .ok_or(FindingReplayCaptureStoreError::InvalidManifest {
                        reason: "chunk position",
                    })?
                    .min(MAX_CAPTURE_CHUNK_BYTES as u64);
                match unique_chunks.entry(child.id()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        unique_chunk_bytes = unique_chunk_bytes.checked_add(expected).ok_or(
                            FindingReplayCaptureStoreError::LimitExceeded {
                                limit: "finding-replay-capture-unique-chunk-bytes",
                            },
                        )?;
                        if unique_chunk_bytes > MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES {
                            return Err(FindingReplayCaptureStoreError::LimitExceeded {
                                limit: "finding-replay-capture-unique-chunk-bytes",
                            });
                        }
                        entry.insert(expected);
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if *entry.get() == expected => {}
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(FindingReplayCaptureStoreError::InvalidManifest {
                            reason: "shared chunk length",
                        });
                    }
                }
            }
        }

        // Authenticate presence and declared size for the complete unique
        // inventory before any role-specific reconstruction allocates its
        // capture-sized output buffer. Full reads below authenticate bytes.
        for (id, expected) in unique_chunks {
            let source = guard.read_finding_replay_capture_object(id)?;
            if source.logical_length() != expected {
                return Err(FindingReplayCaptureStoreError::InvalidManifest {
                    reason: "chunk declared length",
                });
            }
        }
        Ok(())
    }

    fn load_manifest(
        guard: &CampaignExecutorPublicationGuard<'_>,
        root: FindingReplayCaptureEvidenceId,
    ) -> Result<(ContentEnvelope, CaptureManifestDescriptor), FindingReplayCaptureStoreError> {
        let root_id = root.content_id();
        let manifest_bytes = guard
            .read_finding_replay_capture_object(root_id)?
            .read_all(MAX_CAPTURE_MANIFEST_BYTES as u64)?;
        let manifest = ContentEnvelope::from_canonical_bytes(&manifest_bytes)?;
        if manifest.content_id(ObjectKind::ExactManifest) != root_id
            || manifest.schema_name() != CAPTURE_MANIFEST_SCHEMA
            || manifest.schema_version() != CAPTURE_MANIFEST_SCHEMA_VERSION
        {
            return Err(FindingReplayCaptureStoreError::InvalidManifest {
                reason: "manifest identity or schema",
            });
        }
        let descriptor = decode_manifest(&manifest)?;
        Ok((manifest, descriptor))
    }

    fn load_capture(
        guard: &CampaignExecutorPublicationGuard<'_>,
        root: FindingReplayCaptureEvidenceId,
    ) -> Result<LoadedFindingReplayCapture, FindingReplayCaptureStoreError> {
        let (manifest, descriptor) = Self::load_manifest(guard, root)?;
        let capacity = usize::try_from(descriptor.total_length).map_err(|_| {
            FindingReplayCaptureStoreError::LimitExceeded {
                limit: "finding-replay-capture-bytes",
            }
        })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| StoreError::Quota)?;

        for (index, child) in manifest.children().iter().enumerate() {
            validate_chunk_child(index, child)?;
            let remaining = descriptor.total_length.saturating_sub(bytes.len() as u64);
            let expected = remaining.min(MAX_CAPTURE_CHUNK_BYTES as u64);
            let chunk = guard
                .read_finding_replay_capture_object(child.id())?
                .read_all(expected)?;
            if chunk.len() as u64 != expected {
                return Err(FindingReplayCaptureStoreError::InvalidManifest {
                    reason: "chunk length",
                });
            }
            bytes.extend_from_slice(&chunk);
        }

        if bytes.len() as u64 != descriptor.total_length
            || ContentHash::from_bytes(&bytes) != descriptor.content_hash
        {
            return Err(FindingReplayCaptureStoreError::CaptureHashMismatch);
        }
        Ok(LoadedFindingReplayCapture::Complete {
            bytes,
            content_hash: descriptor.content_hash,
        })
    }
}

struct PreparedCapture {
    root: FindingReplayCaptureEvidenceId,
    manifest: BlobHandle,
    chunks: BTreeMap<ContentId, BlobHandle>,
}

fn prepare_capture(
    bytes: Vec<u8>,
    content_hash: ContentHash,
) -> Result<PreparedCapture, FindingReplayCaptureStoreError> {
    if bytes.is_empty() {
        return Err(FindingReplayCaptureStoreError::InvalidCapture);
    }
    if ContentHash::from_bytes(&bytes) != content_hash {
        return Err(FindingReplayCaptureStoreError::CaptureHashMismatch);
    }
    if bytes.len() as u64 > MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES {
        return Err(FindingReplayCaptureStoreError::LimitExceeded {
            limit: "finding-replay-capture-bytes",
        });
    }

    let mut children = BTreeSet::new();
    let mut chunks = BTreeMap::new();
    for (index, chunk) in bytes.chunks(MAX_CAPTURE_CHUNK_BYTES).enumerate() {
        if index >= MAX_CAPTURE_CHUNKS {
            return Err(FindingReplayCaptureStoreError::LimitExceeded {
                limit: "finding-replay-capture-chunk-count",
            });
        }
        let id = ContentId::for_bytes(ObjectKind::Trace, CAPTURE_CHUNK_SCHEMA_VERSION, chunk);
        children.insert(ContentChild::new(chunk_role(index), id)?);
        chunks
            .entry(id)
            .or_insert_with(|| BlobHandle::from_bytes(chunk.to_vec()));
    }
    let body = encode_manifest(content_hash, bytes.len() as u64, children.len())?;
    let envelope = ContentEnvelope::new(
        CAPTURE_MANIFEST_SCHEMA,
        CAPTURE_MANIFEST_SCHEMA_VERSION,
        children,
        body,
    )?;
    let manifest_bytes = envelope.canonical_bytes();
    if manifest_bytes.len() > MAX_CAPTURE_MANIFEST_BYTES {
        return Err(FindingReplayCaptureStoreError::LimitExceeded {
            limit: "finding-replay-capture-manifest-bytes",
        });
    }
    let root = FindingReplayCaptureEvidenceId::from_manifest_content_id(
        envelope.content_id(ObjectKind::ExactManifest),
    )?;
    Ok(PreparedCapture {
        root,
        manifest: BlobHandle::from_bytes(manifest_bytes),
        chunks,
    })
}

#[derive(Clone, Copy)]
struct CaptureManifestDescriptor {
    content_hash: ContentHash,
    total_length: u64,
}

fn encode_manifest(
    content_hash: ContentHash,
    total_length: u64,
    chunk_count: usize,
) -> Result<Vec<u8>, FindingReplayCaptureStoreError> {
    let chunk_count =
        u32::try_from(chunk_count).map_err(|_| FindingReplayCaptureStoreError::LimitExceeded {
            limit: "finding-replay-capture-chunk-count",
        })?;
    let mut body = Vec::with_capacity(52);
    body.extend_from_slice(CAPTURE_MANIFEST_MAGIC);
    body.extend_from_slice(&content_hash.bytes);
    body.extend_from_slice(&total_length.to_be_bytes());
    body.extend_from_slice(&chunk_count.to_be_bytes());
    Ok(body)
}

fn decode_manifest(
    envelope: &ContentEnvelope,
) -> Result<CaptureManifestDescriptor, FindingReplayCaptureStoreError> {
    let body = envelope.body();
    if body.len() != 52 || &body[..8] != CAPTURE_MANIFEST_MAGIC {
        return Err(FindingReplayCaptureStoreError::InvalidManifest {
            reason: "manifest body framing",
        });
    }
    let content_hash = ContentHash {
        bytes: body[8..40].try_into().map_err(|_| {
            FindingReplayCaptureStoreError::InvalidManifest {
                reason: "capture hash",
            }
        })?,
    };
    let total_length = u64::from_be_bytes(body[40..48].try_into().map_err(|_| {
        FindingReplayCaptureStoreError::InvalidManifest {
            reason: "capture length",
        }
    })?);
    let chunk_count = u32::from_be_bytes(body[48..52].try_into().map_err(|_| {
        FindingReplayCaptureStoreError::InvalidManifest {
            reason: "chunk count",
        }
    })?) as usize;
    let expected_chunks = usize::try_from(total_length)
        .ok()
        .map(|length| length.div_ceil(MAX_CAPTURE_CHUNK_BYTES));
    if total_length == 0
        || total_length > MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES
        || chunk_count == 0
        || chunk_count > MAX_CAPTURE_CHUNKS
        || Some(chunk_count) != expected_chunks
        || envelope.children().len() != chunk_count
    {
        return Err(FindingReplayCaptureStoreError::InvalidManifest {
            reason: "capture length or chunk count",
        });
    }
    Ok(CaptureManifestDescriptor {
        content_hash,
        total_length,
    })
}

fn chunk_role(index: usize) -> String {
    format!("chunk-{index:08x}")
}

fn validate_chunk_child(
    index: usize,
    child: &ContentChild,
) -> Result<(), FindingReplayCaptureStoreError> {
    if child.role() != chunk_role(index)
        || child.id().kind() != ObjectKind::Trace
        || child.id().schema_version() != CAPTURE_CHUNK_SCHEMA_VERSION
    {
        return Err(FindingReplayCaptureStoreError::InvalidManifest {
            reason: "chunk child",
        });
    }
    Ok(())
}

fn require_durable_receipt(
    receipt: PutReceipt,
    expected: ContentId,
    source: &BlobHandle,
) -> Result<(), FindingReplayCaptureStoreError> {
    let exact = receipt.id == expected
        && receipt.is_durable()
        && receipt
            .placements
            .iter()
            .filter(|placement| placement.durable)
            .all(|placement| placement.logical_length == source.logical_length());
    if exact {
        Ok(())
    } else {
        Err(FindingReplayCaptureStoreError::InvalidReceipt { id: expected })
    }
}

/// Failure to prepare, publish, or load a portable capture closure.
#[derive(Debug, Error)]
pub enum FindingReplayCaptureStoreError {
    /// Complete capture bytes are empty.
    #[error("finding replay capture is empty")]
    InvalidCapture,
    /// A manifest is malformed or inconsistent with its children.
    #[error("finding replay capture manifest has invalid {reason}")]
    InvalidManifest {
        /// Stable rejected field or relationship.
        reason: &'static str,
    },
    /// Capture bytes disagree with the producer or manifest hash.
    #[error("finding replay capture content hash mismatch")]
    CaptureHashMismatch,
    /// A bounded representation or aggregate allowance was exceeded.
    #[error("finding replay capture exceeded {limit}")]
    LimitExceeded {
        /// Stable bound name.
        limit: &'static str,
    },
    /// The immutable backend failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A manifest envelope was malformed or oversized.
    #[error(transparent)]
    Envelope(#[from] ContentEnvelopeError),
    /// A typed campaign identity rejected the manifest content ID.
    #[error(transparent)]
    Campaign(#[from] crucible_campaign::CampaignCodecError),
    /// The campaign repository rejected guarded capture-object access.
    #[error(transparent)]
    Repository(#[from] crucible_campaign::CampaignRepositoryError),
    /// A backend reported a non-durable or inconsistent placement.
    #[error("finding replay capture backend returned an invalid receipt for {id}")]
    InvalidReceipt {
        /// Expected immutable identity.
        id: ContentId,
    },
}

impl FindingReplayCaptureStoreError {
    /// Returns whether the same immutable handoff can be retried unchanged.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Repository(error)
                if error.executor_rejection()
                    == crucible_campaign::ExecutorRejection::UnavailableInput
        )
    }
}

#[cfg(test)]
mod tests;
