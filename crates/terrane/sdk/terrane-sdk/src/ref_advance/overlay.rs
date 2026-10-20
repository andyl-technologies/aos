//! Publishes input-only signed layers without selecting them as serving namespaces.
//!
//! Stored layer metadata and protected Original associations are durable before
//! returning an identity; existing GC grace still applies without a ref.
//! Complete history, current destination Commit authority
//! and the original deadline are rechecked after the actual immutable writes.

use terrane_format::auth::Verb;
use terrane_format::identity::Digest;

use super::{AdvanceError, Coordinator, PreparedAdvance, WriterSession};
use crate::guard::{HistoryObservation, OriginalCommitContext, OverlayInput};
use crate::store::{Clock, LocalFs, Store};

/// Reports an opt-in test boundary without exposing publication identities.
///
/// # Panics
/// Panics if enabled diagnostics cannot write to standard error.
#[cfg(test)]
fn trace_overlay_layer(phase: &'static str) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!("overlay-layer-subphase phase={phase}");
    }
}

/// Selects explicit layer publication or ordered ordinary overlay preparation.
pub(crate) enum AlgebraPreparation<'a> {
    /// Authors one input-only signed layer without selecting a serving ref.
    Layer,
    /// Materializes ordered authenticated signed inputs into an ordinary namespace.
    Overlay(&'a [OverlayInput]),
}

impl<S: Store, C: Clock, F: LocalFs> Coordinator<S, C, F> {
    /// Publishes and freshly authenticates an unreferenced input-only layer.
    ///
    /// # Errors
    /// Preserves failed durable uploads, missing or changed protected Original
    /// evidence, current authority revocation, expired tokens and publication deadlines.
    pub(crate) async fn publish_unreferenced_layer(
        &self,
        session: &WriterSession,
        prepared: &PreparedAdvance,
        original: &OriginalCommitContext,
    ) -> Result<(Digest, Digest), AdvanceError> {
        let (admitted, started) = prepared.algebra_inputs();
        if original.commit() != &prepared.commit()
            || original.baseline() != prepared.baseline()
            || original.baseline().reference() != session.reference()
            || original.baseline().epoch() != session.epoch()
            || admitted.expected.as_ref() != session.record()
            || admitted.commit.commit().profile_pair.recipe.is_some()
        {
            return Err(crate::guard::invalid().into());
        }
        #[cfg(test)]
        trace_overlay_layer("capture-inputs");
        let candidate = self.guard().capture_candidate_inputs(admitted)?;
        let observation = HistoryObservation::default()
            .candidate(&candidate)
            .overlay_layer(admitted.commit.identity(), admitted.commit.commit().tree);
        #[cfg(test)]
        trace_overlay_layer("initial.original");
        self.guard()
            .revalidate_original_context(original, observation)
            .await?;
        #[cfg(test)]
        trace_overlay_layer("initial.current-authority");
        self.check_layer_current_authority(session, prepared, observation)
            .await?;

        #[cfg(test)]
        trace_overlay_layer("immutable-publication");
        self.publish_immutable_observed(admitted, started, observation)
            .await?;
        #[cfg(test)]
        trace_overlay_layer("durable-history");
        self.guard()
            .verified_overlay_layer_history_observed(admitted.commit.identity(), observation)
            .await?;

        #[cfg(test)]
        trace_overlay_layer("final.original");
        self.guard()
            .revalidate_original_context(original, observation)
            .await?;
        #[cfg(test)]
        trace_overlay_layer("final.current-authority");
        self.check_layer_current_authority(session, prepared, observation)
            .await?;
        self.check_time(started)?;

        #[cfg(test)]
        trace_overlay_layer("complete");
        Ok((admitted.commit.identity(), admitted.commit.commit().tree))
    }

    /// Rechecks whole current authority and every independently governed source root.
    async fn check_layer_current_authority(
        &self,
        session: &WriterSession,
        prepared: &PreparedAdvance,
        observation: HistoryObservation<'_>,
    ) -> Result<(), AdvanceError> {
        let (admitted, started) = prepared.algebra_inputs();
        #[cfg(test)]
        trace_overlay_layer("current-authority.candidate-loading");
        let evidence = crate::guard::TreeEvidence::load_tree_for(
            self.store(),
            admitted.commit.commit().tree,
            &admitted.uploads,
            self.guard().config().min_chunk_size,
            admitted.tree_usage,
        )
        .await?;
        #[cfg(test)]
        trace_overlay_layer("current-authority.path-enumeration");
        let paths = evidence
            .occurrences(self.guard().config().min_chunk_size)?
            .into_iter()
            .map(|occurrence| occurrence.path)
            .collect::<Vec<_>>();
        drop(evidence);

        #[cfg(test)]
        trace_overlay_layer("current-authority.authorizing");
        for path in paths {
            let authorized = self
                .guard()
                .authorize_observed(
                    session.reference(),
                    &admitted.token,
                    Verb::Commit,
                    std::slice::from_ref(&path),
                    &admitted.surface,
                    observation,
                )
                .await?;
            if authorized.record() != session.record() {
                return Err(crate::guard::denied(session.reference(), Verb::Commit).into());
            }
            self.check_time(started)?;
        }
        #[cfg(test)]
        trace_overlay_layer("current-authority.complete");
        Ok(())
    }
}
