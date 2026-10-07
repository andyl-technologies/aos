//! Completes supported local source history before same-head lineage publication.
//!
//! The history owner alone promotes actual pending Legacy inputs to completion.
//! This route then checks current Fork separately for every real occurrence. Its
//! ordinary profile comparisons grant neither native publication nor cold reuse.

use terrane_core::auth::Verb;
use terrane_core::gc::publication::evidence::{
    CheckedLineage, ConsumedViewInterpretation, ConsumedViewPolicy, ViewInterpretationMode,
};
use terrane_core::provenance::VerifiedCommit;
use terrane_core::refs::{Commit, RefRecord};

use super::history::completion::InterpretationSelection;
use super::{
    AuthorizedRef, ConsumedResolver, Guard, HistoryObservation, OriginalCommitContext, denied,
    invalid,
};
use crate::bucket::held::HeldIdentity;
use crate::store::{Clock, Store, StoreErrorKind, StoreFailure};

/// Retains one existing source whose complete owning history and live checks ran.
pub(crate) struct CompletedForkSource {
    record: RefRecord,
    commit: VerifiedCommit,
    original: OriginalCommitContext,
    requests: Vec<AuthorizedRef>,
}

impl CompletedForkSource {
    /// Borrows the exact current whole source checked by this invocation.
    pub(crate) fn record(&self) -> &RefRecord {
        &self.record
    }

    /// Borrows the actual signed source whose complete owning checks succeeded.
    pub(crate) fn commit(&self) -> &VerifiedCommit {
        &self.commit
    }

    /// Borrows the independently verified local Original association.
    pub(crate) fn original(&self) -> &OriginalCommitContext {
        &self.original
    }

    /// Borrows actual current Fork requests without supplying reusable permission.
    pub(crate) fn requests(&self) -> &[AuthorizedRef] {
        &self.requests
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Completes supported owning history and current occurrence authority.
    ///
    /// The closed native caller supplies its actual held identity and resolver.
    /// This method constructs its own tracked observation; no decoded context or
    /// caller observation chooses Legacy, registers a profile or promotes a view.
    ///
    /// # Errors
    /// Preserves signed history/profile/Original and storage failures, including
    /// unsupported indexed, Recorded or foreign completion. Denies current Fork,
    /// path/domain restrictions, or a changed whole source record.
    pub(crate) async fn complete_fork_source_requalification<'operation>(
        &self,
        source: &str,
        token: &[u8],
        surface: &str,
        identity: &'operation HeldIdentity<'operation>,
        consumed: &'operation ConsumedResolver,
    ) -> Result<CompletedForkSource, StoreFailure> {
        let observation = HistoryObservation::held(identity).tracked(consumed);
        let initial = self
            .authorize_observed(source, token, Verb::Fork, &[], surface, observation)
            .await?;
        let record = initial
            .record()
            .cloned()
            .ok_or_else(|| denied(source, Verb::Fork))?;
        consumed.operation(&initial)?;
        let mut requests = vec![initial];

        let (verified, history) = self
            .verified_tree_history_observed(record.commit, observation)
            .await?;
        let completed = history.commit(&record.commit).ok_or_else(invalid)?;
        if completed.commit() != verified.commit.commit()
            || verified.commit.identity() != record.commit
        {
            return Err(invalid());
        }
        self.check_requalification_source_profile(&verified.commit)?;
        let original = self.original_commit(&record.commit)?;
        self.revalidate_original_context(&original, observation)
            .await?;

        // Core Trees contain Rc sharing. Own the actual paths before awaiting
        // independent current policy checks; repeated roots retain their paths.
        let paths = verified
            .evidence
            .occurrences(self.config().min_chunk_size)?
            .into_iter()
            .map(|occurrence| occurrence.path)
            .collect::<Vec<_>>();
        for path in paths {
            let current = self
                .authorize_observed(
                    source,
                    token,
                    Verb::Fork,
                    std::slice::from_ref(&path),
                    surface,
                    observation,
                )
                .await?;
            if current.record() != Some(&record) {
                return Err(denied(source, Verb::Fork));
            }
            consumed.operation(&current)?;
            requests.push(current);
        }

        Ok(CompletedForkSource {
            record,
            commit: verified.commit,
            original,
            requests,
        })
    }
}

impl<S, C> Guard<S, C> {
    /// Copies actual immutable selection and configuration for final comparisons.
    ///
    /// This adapter has no Store, clock or Original verifier. It supplies ordinary
    /// data comparisons only; the actual held Guard verifies history and controls.
    ///
    /// # Errors
    /// Preserves invalid configured registry inputs before copying the selection.
    pub(crate) fn source_requalification_configuration_adapter(
        &self,
    ) -> Result<Guard<(), ()>, StoreFailure> {
        self.completion_inputs()?;
        let mut configured = Guard::new((), (), self.keys.clone(), self.config.clone());
        configured.interpretation = self.interpretation;
        Ok(configured)
    }

    /// Checks the actual signed source's independently configured physical profile.
    ///
    /// # Errors
    /// Refuses unsupported tree/chunk semantics or mismatched seeded geometry.
    pub(crate) fn check_requalification_source_profile(
        &self,
        commit: &VerifiedCommit,
    ) -> Result<(), StoreFailure> {
        if commit.commit().profile_pair.tree_format != 1
            || commit.commit().profile_pair.chunk_profile != self.config().chunk_profile_name
            || self.config().chunk_profile_name != "cdc-1m"
            || self.config().min_chunk_size != self.config().chunk_profile.minimum() as u64
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        Ok(())
    }

    /// Compares a completed view's tuple with this Guard's actual installed inputs.
    ///
    /// Prior full history supplies the exact signed view/root association. Current
    /// selection and every registry field come independently from Guard construction,
    /// never the decoded tuple or a missing optional field. This bounded factory is
    /// explicitly Legacy/attribute1; it cannot qualify active or Recorded inputs.
    ///
    /// # Errors
    /// Refuses absent context and rejects differing modes, roots or full profiles.
    pub(crate) fn compare_requalification_view_inputs(
        &self,
        lineage: &CheckedLineage,
        view: &ConsumedViewPolicy,
    ) -> Result<(), StoreFailure> {
        let root = view.roots.first().ok_or_else(invalid)?.root;
        let contexts = lineage
            .used
            .view_interpretations
            .as_ref()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
        let index = contexts
            .binary_search_by_key(&view.view, |context| context.view)
            .map_err(|_| invalid())?;
        let retained = contexts.get(index).ok_or_else(invalid)?;
        let mode = match self.interpretation {
            InterpretationSelection::Legacy => ViewInterpretationMode::Legacy,
            InterpretationSelection::Active => {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
        };
        let current = ConsumedViewInterpretation {
            view: view.view,
            original_root: root,
            mode,
            registries: self.completion_inputs()?.registries,
        };
        current
            .check_supported_interpretation()
            .map_err(|_| invalid())?;
        retained
            .check_selected_data(&current)
            .map_err(|_| invalid())
    }

    /// Checks completed occurrence structure and the actual signed source root.
    ///
    /// This comparison supplies no signature, Original or history authority.
    ///
    /// # Errors
    /// Rejects contradictory paths/layers, invalid domains or a source-root mismatch.
    pub(crate) fn check_requalification_views(
        &self,
        lineage: &CheckedLineage,
        commit: &Commit,
    ) -> Result<(), StoreFailure> {
        use std::collections::{BTreeMap, BTreeSet};
        use terrane_core::identity::{IdentityKind, TERRANE_V1};

        let mut occurrences = BTreeMap::new();
        for view in &lineage.used.views {
            for root in &view.roots {
                if occurrences
                    .insert((view.view, root.path.as_slice()), root)
                    .is_some_and(|prior| prior != root)
                {
                    return Err(invalid());
                }
            }
            if view
                .roots
                .first()
                .is_none_or(|root| root.path != b"/" || root.layers.len() != 1)
            {
                return Err(invalid());
            }
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Node, &view.roots[0].root)
                .map_err(|_| invalid())?;
            if view.default_domain != crate::domain::private_default(&identity) {
                return Err(invalid());
            }
            let mut paths = BTreeSet::new();
            if view
                .roots
                .iter()
                .any(|root| !paths.insert(root.path.as_slice()))
            {
                return Err(invalid());
            }
            for root in view.roots.iter().skip(1) {
                let parent = view
                    .roots
                    .iter()
                    .filter(|parent| {
                        parent.path == b"/"
                            || root.path.starts_with(&parent.path)
                                && root.path.get(parent.path.len()) == Some(&b'/')
                    })
                    .max_by_key(|parent| parent.path.len())
                    .ok_or_else(invalid)?;
                if root.layers.len() != parent.layers.len() + 1
                    || !root.layers.starts_with(&parent.layers)
                {
                    return Err(invalid());
                }
            }
        }
        let source = lineage
            .used
            .views
            .iter()
            .find(|view| view.view == lineage.commit_id)
            .ok_or_else(invalid)?;
        if source.roots.first().ok_or_else(invalid)?.root != commit.tree {
            return Err(invalid());
        }
        Ok(())
    }
}
