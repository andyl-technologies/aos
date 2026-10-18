//! Content-addressed immutable storage for portable finding replay captures.
//!
//! A capture is one manifest envelope whose children are its leaves
//! ([`FindingProductionReplayCapture::prepare_objects`]). Four role-specific
//! manifests form one finding capture set. Preparation shares equal leaves
//! across all roles and charges each distinct leaf once against one of two
//! per-finding allowances:
//!
//! ```text
//! static allowance   manifests, model reproductions, replay-closure roots,
//!                    guest assets, lifecycle objects
//!                    <= MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES
//! segment allowance  side-log attempt segments, side-trace segments, and
//!                    replay-closure frames (run-length evidence)
//!                    <= MAX_FINDING_REPLAY_PUBLICATION_SEGMENT_BYTES
//! ```
//!
//! A complete role that would exceed either allowance is recorded as
//! [`FindingReplayCaptureIncomplete::PublicationLimitExceeded`]. Publication
//! copies leaves one at a time before any manifest, and loading obtains one
//! handle per child after charging the same allowances, so neither direction
//! builds a buffer the size of a capture.
//!
//! [`FindingProductionReplayCapture::prepare_objects`]: crate::FindingProductionReplayCapture::prepare_objects

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use crucible_campaign::{
    CampaignExecutorPublicationGuard, CampaignRepository, CampaignRepositoryError,
    FindingReplayCaptureEvidenceId, FindingReplayCaptureIncomplete, FindingReplayCaptureReference,
    FindingReplayCaptureSet, MAX_FINDING_REPLAY_PUBLICATION_SEGMENT_BYTES,
    MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES,
};
use crucible_cas::content_store::{BlobHandle, ContentId, ObjectKind, PutReceipt, StoreError};
use thiserror::Error;

use crate::finding_production_replay::{
    FindingProductionReplayCaptureError, FindingProductionReplayCaptureObjects,
    FindingProductionReplayLeafRole, MAX_FINDING_PRODUCTION_REPLAY_MANIFEST_BYTES,
    decode_finding_production_replay_manifest,
};

/// One transient complete or durable-incomplete capture outcome.
#[derive(Clone, Debug)]
pub enum FindingReplayCaptureInput {
    /// The manifest and leaves of one complete capture.
    Complete(Box<FindingProductionReplayCaptureObjects>),
    /// Stable reason this role has no complete capture.
    Incomplete(FindingReplayCaptureIncomplete),
}

/// No-write preparation of one four-role capture closure.
#[derive(Clone)]
pub struct PreparedFindingReplayCaptureSet {
    references: FindingReplayCaptureSet,
    manifests: BTreeMap<ContentId, BlobHandle>,
    leaves: BTreeMap<ContentId, BlobHandle>,
    charges: CaptureCharges,
}

impl PreparedFindingReplayCaptureSet {
    /// Returns the four small manifest roots or durable incomplete reasons.
    #[must_use]
    pub const fn references(&self) -> FindingReplayCaptureSet {
        self.references
    }

    /// Returns manifest and static leaf bytes charged after sharing.
    #[must_use]
    pub const fn unique_static_bytes(&self) -> u64 {
        self.charges.static_bytes
    }

    /// Returns side-log segment bytes charged after sharing.
    #[must_use]
    pub const fn unique_segment_bytes(&self) -> u64 {
        self.charges.segment_bytes
    }
}

/// The authenticated objects of one durable complete capture.
///
/// The manifest's identity, schema, and children have been checked, every
/// child has a handle whose declared length was charged to the finding's
/// allowances, and no leaf has been read yet.
/// [`crate::FindingProductionReplayCapture::from_objects`] decodes it.
#[derive(Clone)]
pub struct LoadedFindingReplayCaptureObjects {
    root: FindingReplayCaptureEvidenceId,
    manifest: Vec<u8>,
    leaves: BTreeMap<ContentId, BlobHandle>,
}

impl std::fmt::Debug for LoadedFindingReplayCaptureObjects {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedFindingReplayCaptureObjects")
            .field("root", &self.root)
            .field("manifest_bytes", &self.manifest.len())
            .field("leaves", &self.leaves.len())
            .finish()
    }
}

impl LoadedFindingReplayCaptureObjects {
    /// Returns the manifest identity that names the capture.
    #[must_use]
    pub const fn root(&self) -> FindingReplayCaptureEvidenceId {
        self.root
    }

    /// Returns the canonical manifest envelope bytes.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// Returns one unread handle per manifest child, by identity.
    #[must_use]
    pub const fn leaves(&self) -> &BTreeMap<ContentId, BlobHandle> {
        &self.leaves
    }
}

/// One durable capture outcome loaded from a capture set.
#[derive(Clone, Debug)]
pub enum LoadedFindingReplayCapture {
    /// The authenticated objects of a complete capture.
    Complete(Box<LoadedFindingReplayCaptureObjects>),
    /// Stable reason this role has no complete capture.
    Incomplete(FindingReplayCaptureIncomplete),
}

/// Durable immutable store operations for portable finding replay captures.
pub struct FindingReplayCaptureStore;

impl FindingReplayCaptureStore {
    /// Derives the four-role publication closure without repository writes.
    ///
    /// Equal leaves and manifests are stored once across the four fixed
    /// roles. A complete role that would exceed the remaining static or
    /// segment allowance is represented by
    /// [`FindingReplayCaptureIncomplete::PublicationLimitExceeded`].
    ///
    /// # Errors
    ///
    /// Returns an error when the role count cannot form a capture set.
    pub fn prepare_set(
        inputs: [FindingReplayCaptureInput; 4],
    ) -> Result<PreparedFindingReplayCaptureSet, FindingReplayCaptureStoreError> {
        let mut manifests = BTreeMap::new();
        let mut leaves = BTreeMap::new();
        let mut charges = CaptureCharges::default();
        let mut references = Vec::with_capacity(4);

        for input in inputs {
            let objects = match input {
                FindingReplayCaptureInput::Complete(objects) => objects,
                FindingReplayCaptureInput::Incomplete(reason) => {
                    references.push(FindingReplayCaptureReference::Incomplete(reason));
                    continue;
                }
            };

            // Charge only what this role adds, so a role that does not fit
            // leaves the earlier roles' charges untouched.
            let root = objects.root().content_id();
            let mut role_charges = charges;
            if !manifests.contains_key(&root) {
                role_charges.charge_static(objects.manifest_bytes().len() as u64);
            }
            for (id, leaf) in objects.leaves() {
                if !leaves.contains_key(id) {
                    role_charges.charge(leaf.role(), leaf.length());
                }
            }
            if !role_charges.within_allowances() {
                references.push(FindingReplayCaptureReference::Incomplete(
                    FindingReplayCaptureIncomplete::PublicationLimitExceeded,
                ));
                continue;
            }

            charges = role_charges;
            manifests
                .entry(root)
                .or_insert_with(|| objects.manifest_source());
            for (id, leaf) in objects.leaves() {
                leaves.entry(*id).or_insert_with(|| leaf.source().clone());
            }
            references.push(FindingReplayCaptureReference::Complete(objects.root()));
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
            leaves,
            charges,
        })
    }

    /// Publishes leaves first and manifest roots last.
    ///
    /// Each leaf is copied from its source by the backend, one at a time.
    /// Exact retry is idempotent. The caller must hold repository GC exclusion
    /// from before the first leaf write through the operational Publishing
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
        for (id, source) in prepared.leaves.iter().chain(&prepared.manifests) {
            require_durable_receipt(
                guard.put_finding_replay_capture_object(*id, source)?,
                *id,
                source,
            )?;
        }
        Ok(())
    }

    /// Loads and authenticates all four manifests and their child handles.
    ///
    /// The returned array preserves the canonical role order used by
    /// [`FindingReplayCaptureSet::references`].
    ///
    /// # Errors
    ///
    /// Returns an error when a manifest is absent, corrupt, oversized, or of
    /// another schema, a child is absent or of another kind, or the distinct
    /// declared bytes exceed either per-finding allowance.
    pub fn load_set(
        guard: &CampaignExecutorPublicationGuard<'_>,
        references: FindingReplayCaptureSet,
    ) -> Result<[LoadedFindingReplayCapture; 4], FindingReplayCaptureStoreError> {
        Self::load_set_with_reader(
            &|id| guard.read_finding_replay_capture_object(id),
            references,
        )
    }

    /// Loads a retained capture set from an authenticated imported repository.
    ///
    /// The caller must first prove the finding's membership in a complete
    /// archive. This reader uses the same bounded manifest and child checks
    /// as live publication, without requiring write or GC-exclusion authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent, corrupt, oversized, or inconsistent
    /// capture object or four-role set.
    pub fn load_set_from_repository(
        repository: &CampaignRepository,
        references: FindingReplayCaptureSet,
    ) -> Result<[LoadedFindingReplayCapture; 4], FindingReplayCaptureStoreError> {
        Self::load_set_with_reader(
            &|id| repository.read_finding_replay_capture_object(id),
            references,
        )
    }

    fn load_set_with_reader<F>(
        read: &F,
        references: FindingReplayCaptureSet,
    ) -> Result<[LoadedFindingReplayCapture; 4], FindingReplayCaptureStoreError>
    where
        F: Fn(ContentId) -> Result<BlobHandle, CampaignRepositoryError>,
    {
        let mut charged = BTreeMap::new();
        let mut charges = CaptureCharges::default();
        let mut loaded = Vec::with_capacity(4);

        for reference in references.references() {
            match reference {
                FindingReplayCaptureReference::Complete(root) => {
                    let objects = Self::load_capture(read, root, &mut charged, &mut charges)?;
                    loaded.push(LoadedFindingReplayCapture::Complete(Box::new(objects)));
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

    /// Reads one manifest and one handle per child, charging new objects.
    ///
    /// Presence and declared length are authenticated for every child before
    /// any leaf byte is read; leaf bytes are authenticated when decoded.
    fn load_capture<F>(
        read: &F,
        root: FindingReplayCaptureEvidenceId,
        charged: &mut BTreeMap<ContentId, u64>,
        charges: &mut CaptureCharges,
    ) -> Result<LoadedFindingReplayCaptureObjects, FindingReplayCaptureStoreError>
    where
        F: Fn(ContentId) -> Result<BlobHandle, CampaignRepositoryError>,
    {
        let root_id = root.content_id();
        let manifest = read(root_id)?.read_all(MAX_FINDING_PRODUCTION_REPLAY_MANIFEST_BYTES)?;
        let envelope = decode_finding_production_replay_manifest(root, &manifest)?;
        if let Entry::Vacant(entry) = charged.entry(root_id) {
            charges.charge_static(manifest.len() as u64);
            entry.insert(manifest.len() as u64);
        }

        let mut leaves = BTreeMap::new();
        for child in envelope.children() {
            let role = FindingProductionReplayLeafRole::from_role(child.role()).ok_or(
                FindingReplayCaptureStoreError::InvalidManifest {
                    reason: "child role",
                },
            )?;
            let id = child.id();
            if id.kind() != ObjectKind::Trace || id.schema_version() != 1 {
                return Err(FindingReplayCaptureStoreError::InvalidManifest {
                    reason: "child identity",
                });
            }
            if leaves.contains_key(&id) {
                continue;
            }

            let handle = read(id)?;
            match charged.get(&id) {
                Some(length) if *length != handle.logical_length() => {
                    return Err(FindingReplayCaptureStoreError::InvalidManifest {
                        reason: "shared leaf length",
                    });
                }
                Some(_) => {}
                None => {
                    charges.charge(role, handle.logical_length());
                    charged.insert(id, handle.logical_length());
                }
            }
            leaves.insert(id, handle);
        }
        if !charges.within_allowances() {
            return Err(FindingReplayCaptureStoreError::LimitExceeded {
                limit: "finding-replay-capture-unique-bytes",
            });
        }

        Ok(LoadedFindingReplayCaptureObjects {
            root,
            manifest,
            leaves,
        })
    }
}

/// Distinct bytes charged to one finding's two capture allowances.
///
/// Sums saturate, and a saturated sum exceeds either allowance.
#[derive(Clone, Copy, Debug, Default)]
struct CaptureCharges {
    static_bytes: u64,
    segment_bytes: u64,
}

impl CaptureCharges {
    fn charge(&mut self, role: FindingProductionReplayLeafRole, length: u64) {
        if role.is_run_length() {
            self.segment_bytes = self.segment_bytes.saturating_add(length);
        } else {
            self.charge_static(length);
        }
    }

    fn charge_static(&mut self, length: u64) {
        self.static_bytes = self.static_bytes.saturating_add(length);
    }

    const fn within_allowances(&self) -> bool {
        self.static_bytes <= MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES
            && self.segment_bytes <= MAX_FINDING_REPLAY_PUBLICATION_SEGMENT_BYTES
    }
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
    /// A manifest is malformed or inconsistent with its children.
    #[error("finding replay capture manifest has invalid {reason}")]
    InvalidManifest {
        /// Stable rejected field or relationship.
        reason: &'static str,
    },
    /// A bounded representation or aggregate allowance was exceeded.
    #[error("finding replay capture exceeded {limit}")]
    LimitExceeded {
        /// Stable bound name.
        limit: &'static str,
    },
    /// The manifest envelope failed capture authentication.
    #[error(transparent)]
    Capture(#[from] FindingProductionReplayCaptureError),
    /// The immutable backend failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The campaign repository rejected guarded capture-object access.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
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
