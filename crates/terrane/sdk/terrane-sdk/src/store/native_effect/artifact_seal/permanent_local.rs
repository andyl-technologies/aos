//! Owns fixed local observations and effects beneath selected permanent ownership.
//!
//! The producer supplies complete current owner, lease, Original and serving
//! predicates. Native receipts retain actual physical instances and exclusions;
//! they never create first-owner permission or permit old-key readmission.

#[path = "permanent_local/physical.rs"]
mod physical;

#[path = "permanent_local/recipes.rs"]
mod recipes;

#[path = "permanent_local/walk.rs"]
mod walk;

#[path = "permanent_local/observation.rs"]
pub(crate) mod observation;

#[path = "permanent_local/effects.rs"]
pub(crate) mod effects;

#[path = "permanent_local/publication.rs"]
pub(crate) mod publication;

use super::{NativeExclusion, PathBuf};
use std::sync::Arc;

/// Retains actual family observations from the closed current native worker.
pub(crate) struct NativePermanentObservation {
    root: PathBuf,
    control: PathBuf,
    pack: [u8; 16],
    operation_key: String,
    operation_bytes: Vec<u8>,
    leaves: Vec<physical::Leaf>,
    exclusions: Arc<[NativeExclusion]>,
    extraction: Option<ExtractedPair>,
    walk: Option<walk::CandidateWalk>,
}

/// Retains raw collector-only bytes; complete content admission remains independent.
pub(crate) struct ExtractedPair {
    pack: Vec<u8>,
    index: Vec<u8>,
    pack_metadata: std::fs::Metadata,
    index_metadata: std::fs::Metadata,
}

impl NativePermanentObservation {
    /// Refreshes the actual retained candidate walk before progress handoffs.
    ///
    /// Current owner, whole lease, DATA and consumed Original controls remain
    /// independent submitting-Frame predicates. This physical check neither
    /// grants deletion permission nor treats prior traversal as current absence.
    ///
    /// # Errors
    /// Refuses missing discovery, changed canonical candidates, unsafe current
    /// directories, descriptor/name/ancestry discontinuity or lost absence.
    pub(crate) fn recheck_candidate_walk(&self) -> Result<(), super::NativeEffectFailure> {
        self.walk
            .as_ref()
            .ok_or_else(|| std::io::Error::other("native candidate traversal absent"))?
            .check_physical()
            .map_err(Into::into)
    }

    /// Rechecks original candidate directories during unselected proposal staging.
    ///
    /// Full enumeration remains required before progress selection and through
    /// acknowledgment. Current authority and exclusions remain Frame predicates.
    ///
    /// # Errors
    /// Refuses missing discovery, changed original directory recipes or absence.
    pub(crate) fn recheck_candidate_continuity(&self) -> Result<(), super::NativeEffectFailure> {
        self.walk
            .as_ref()
            .ok_or_else(|| std::io::Error::other("native candidate traversal absent"))?
            .check_continuity()
            .map_err(Into::into)
    }

    /// Refreshes actual source descriptors and namespace continuity only.
    ///
    /// Full source bytes and current permission remain separate Frame predicates.
    /// This check neither validates content nor samples old selection caches.
    ///
    /// # Errors
    /// Refuses absent extraction, changed leaves, names, ancestry or exclusions.
    pub(crate) fn recheck_source(&self) -> Result<(), super::NativeEffectFailure> {
        if self.extraction.is_none() || self.leaves.len() != 2 {
            return Err(
                std::io::Error::other("native permanent source extraction unavailable").into(),
            );
        }
        for leaf in &self.leaves {
            leaf.check_source(&self.exclusions)?;
        }
        Ok(())
    }

    /// Checks the exact namespace and selected operation attached by the worker.
    pub(crate) fn matches_selected(
        &self,
        root: &std::path::Path,
        control: &std::path::Path,
        key: &str,
        bytes: &[u8],
    ) -> bool {
        self.root == root
            && self.control == control
            && self.operation_key == key
            && self.operation_bytes == bytes
    }

    /// Derives fixed unversioned progress from actual worker-observed family leaves.
    ///
    /// # Errors
    /// Refuses unknown family paths or changed retained physical observations.
    pub(crate) fn progress(
        &self,
    ) -> Result<Vec<terrane_format::gc::retirement::RequestObservation>, super::NativeEffectFailure>
    {
        use terrane_format::gc::retirement::{
            ObservationState, ObservedArtifact, ObservedInstance, RequestObservation,
        };
        let id = crate::pack::PackId::from_random_bytes(self.pack);
        let mut rows = Vec::new();
        for leaf in &self.leaves {
            leaf.check(&self.exclusions)?;
            let artifact = if leaf.path() == self.root.join(id.pack_key()) {
                ObservedArtifact::Pack
            } else if leaf.path() == self.root.join(id.index_key()) {
                ObservedArtifact::Index
            } else {
                let relative = leaf
                    .path()
                    .strip_prefix(&self.root)
                    .map_err(|_| std::io::Error::other("permanent progress root differs"))?;
                let parts: Vec<_> = relative.components().collect();
                if parts.len() != 3
                    || parts[0].as_os_str() != "trash"
                    || parts[2].as_os_str() != id.to_string().as_str()
                {
                    return Err(std::io::Error::other("permanent progress family differs").into());
                }
                let cycle = parts[1]
                    .as_os_str()
                    .to_str()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| std::io::Error::other("permanent progress cycle differs"))?;
                if leaf.path() != self.root.join(format!("trash/{cycle}/{id}")) {
                    return Err(
                        std::io::Error::other("permanent progress cycle is noncanonical").into(),
                    );
                }
                ObservedArtifact::Trash(cycle)
            };
            rows.push(RequestObservation {
                artifact,
                instance: ObservedInstance::Unversioned,
                state: if leaf.is_present() {
                    ObservationState::Planned
                } else {
                    ObservationState::ConfirmedAbsent
                },
            });
        }
        Ok(rows)
    }

    /// Reports a completed fixed discovery traversal, never universal family absence.
    pub(crate) fn candidate_traversal_completed(&self) -> bool {
        self.walk
            .as_ref()
            .is_some_and(walk::CandidateWalk::complete)
    }

    /// Revalidates the retained native traversal before progress acknowledgment.
    ///
    /// # Errors
    /// Refuses missing complete discovery, changed actual directories or current inputs.
    pub(super) fn recheck_traversal(
        &self,
        worker: &super::Worker,
    ) -> Result<(), super::NativeEffectFailure> {
        self.walk
            .as_ref()
            .ok_or_else(|| std::io::Error::other("complete candidate walk absent"))?
            .check(worker)
    }

    /// Borrows the physically observed family paths without deletion permission.
    pub(crate) fn paths(&self) -> impl Iterator<Item = &std::path::Path> {
        self.leaves.iter().map(physical::Leaf::path)
    }

    /// Returns the permanently owned family, not a content serving identity.
    pub(crate) fn pack(&self) -> [u8; 16] {
        self.pack
    }

    /// Borrows the actual extracted pair without admitting or serving its bytes.
    pub(crate) fn extraction(&self) -> Option<&ExtractedPair> {
        self.extraction.as_ref()
    }
}

impl ExtractedPair {
    /// Borrows actual pack bytes and metadata from the same no-follow descriptor.
    pub(crate) fn pack(&self) -> (&[u8], &std::fs::Metadata) {
        (&self.pack, &self.pack_metadata)
    }

    /// Borrows actual detached-index bytes and their matching descriptor metadata.
    pub(crate) fn index(&self) -> (&[u8], &std::fs::Metadata) {
        (&self.index, &self.index_metadata)
    }
}
