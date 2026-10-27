//! Publishes unreferenced signed overlay inputs and publishes their ordinary materialization.
//!
//! Layers retain independent protected Original authority. Ordered signed inputs
//! are reauthenticated by the Guard before their output uses the ordinary durable
//! ref publication path; no layer is selected as an ordinary serving head.

use terrane_format::identity::Digest;
use terrane_format::refs::RefRecord;

use super::{Error, Repository};
use crate::guard::OverlayInput;
use crate::ref_advance::{CommitRequest, WriterSession};
use crate::store::{Clock, LocalFs, Store};

/// Reports an opt-in test boundary without exposing publication identities.
///
/// # Panics
/// Panics if enabled diagnostics cannot write to standard error.
#[cfg(test)]
fn trace_overlay_repository(phase: &'static str) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!("overlay-repository-subphase phase={phase}");
    }
}

/// Identifies a signed input layer published for authenticated materialization.
///
/// An unreferenced input remains subject to the existing collection and grace
/// rules. Publishing an ordinary output with this input in its signed ancestry
/// establishes reachability; Original authentication alone supplies no GC root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedOverlayLayer {
    /// Exact newly signed input commit.
    pub commit: Digest,
    /// Canonical root of the authenticated input layer.
    pub root: Digest,
}

impl<S, C, F> Repository<S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Publishes an unreferenced signed layer under current Commit authority.
    ///
    /// The layer keeps its introducing and attribute-producing history. Its
    /// immutable identity is an overlay operand; the current ref remains the
    /// independent ordinary policy authority for subsequent Read checks.
    ///
    /// This publication creates no collection root. The ordinary garbage-collection
    /// grace applies until an acknowledged materialization roots the input through
    /// signed ancestry. A later consumer refuses missing collected metadata.
    ///
    /// # Errors
    /// Preserves invalid canonical metadata, denied current authority, missing
    /// protected Original evidence, failed durable writes and unchanged deadline errors.
    pub async fn publish_overlay_layer(
        &self,
        session: &mut WriterSession,
        request: CommitRequest,
    ) -> Result<PublishedOverlayLayer, Error> {
        #[cfg(test)]
        trace_overlay_repository("layer.retain-baseline");
        self.retain_baseline(session).await?;

        #[cfg(test)]
        trace_overlay_repository("layer.prepare");
        let prepared = self
            .coordinator
            .prepare_algebra(
                session,
                request,
                crate::ref_advance::overlay::AlgebraPreparation::Layer,
            )
            .await
            .map_err(Error::Advance)?;
        #[cfg(test)]
        trace_overlay_repository("layer.retain-candidate");
        let retention = self.local_retention.as_ref().ok_or(Error::Denied)?;
        let original = retention
            .retain_candidate(self.coordinator.guard(), self.coordinator.fs(), &prepared)
            .await?;
        #[cfg(test)]
        trace_overlay_repository("layer.publish");
        let (commit, root) = self
            .coordinator
            .publish_unreferenced_layer(session, &prepared, &original)
            .await
            .map_err(Error::Advance)?;
        #[cfg(test)]
        trace_overlay_repository("layer.complete");
        Ok(PublishedOverlayLayer { commit, root })
    }

    /// Materializes ordered authenticated inputs and publishes an ordinary namespace.
    ///
    /// Input order binds the recipe independently of the destination baseline.
    /// Every current input Read decision and the destination's Commit decision
    /// remain mandatory through the final durable ref publication.
    ///
    /// # Errors
    /// Preserves signed history, Original scope, current authorization, canonical
    /// recomputation, index, durability, fencing and publication deadline errors.
    pub async fn overlay(
        &self,
        session: &mut WriterSession,
        inputs: &[OverlayInput],
        request: CommitRequest,
    ) -> Result<RefRecord, Error> {
        #[cfg(test)]
        trace_overlay_repository("output.retain-baseline");
        self.retain_baseline(session).await?;

        #[cfg(test)]
        trace_overlay_repository("output.prepare");
        let prepared = self
            .coordinator
            .prepare_algebra(
                session,
                request,
                crate::ref_advance::overlay::AlgebraPreparation::Overlay(inputs),
            )
            .await
            .map_err(Error::Advance)?;
        #[cfg(test)]
        trace_overlay_repository("output.publish-retained");
        let record = self.publish_retained(session, prepared).await?.record;

        #[cfg(test)]
        trace_overlay_repository("output.complete");
        Ok(record)
    }
}
