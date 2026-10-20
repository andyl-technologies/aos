//! Authenticates stored commits against their signed original canonical root scope.

#[cfg(all(feature = "std", feature = "tokio", unix))]
mod current_reads;

#[cfg(all(feature = "std", feature = "tokio", unix))]
use std::collections::BTreeMap;
use terrane_format::auth::RequestRoot;
use terrane_format::identity::Digest;
use terrane_format::provenance::{self, VerifiedCommit, VerifiedHistory};

/// Owns operation-local reuse of ordinary candidate preparation.
#[cfg(feature = "std")]
pub(in crate::guard) mod candidate_preparation;
#[cfg(all(test, feature = "std", feature = "tokio", unix))]
mod candidate_preparation_tests;
#[cfg(feature = "std")]
mod collection;
/// Prepares selected view inputs for the owning signed-history checks.
#[cfg(feature = "std")]
pub(in crate::guard) mod completion;
mod disclosure;
#[cfg(feature = "std")]
mod layers;
#[cfg(feature = "std")]
pub(crate) use collection::CollectionOccurrence;
#[cfg(feature = "std")]
pub(crate) use disclosure::CompletedCollectionHistory;
#[cfg(all(feature = "std", unix))]
pub(crate) use disclosure::DisclosureSourceSelection;

use super::{Guard, TreeEvidence, invalid};
#[cfg(not(feature = "std"))]
use crate::store::StoreErrorKind;
use crate::store::{Clock, Store, StoreFailure};

/// Borrows synchronization evidence without converting it into authorization.
#[derive(Clone, Copy, Default)]
pub(crate) struct HistoryObservation<'a> {
    #[cfg(feature = "std")]
    held: Option<&'a crate::bucket::held::HeldIdentity<'a>>,
    #[cfg(feature = "std")]
    consumed: Option<&'a super::consumed::ConsumedResolver>,
    /// Borrows ordinary inputs captured for the actual candidate operation.
    #[cfg(feature = "std")]
    pub(super) candidate: Option<&'a super::view_selection::CandidateInputs>,
    /// Borrows a private repair purpose without supplying current authority.
    #[cfg(feature = "std")]
    pub(super) maintenance: Option<&'a super::index_maintenance::Purpose>,
    requested_target: bool,
    /// Selects one input-only signed layer for an explicit owning operation.
    overlay_layer: Option<(Digest, Digest)>,
    lifetime: std::marker::PhantomData<&'a ()>,
    /// Borrows a privately checked paired Guard transition without granting authority.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    paired_transition:
        Option<&'a crate::selected_bridge::native_guard::disclosure::GuardTransition<'a>>,
}

impl<'a> HistoryObservation<'a> {
    /// Borrows the held backend identity without granting authorization.
    #[cfg(feature = "std")]
    pub(crate) fn identity(self) -> Option<&'a crate::bucket::held::HeldIdentity<'a>> {
        self.held
    }

    /// Borrows the actual operation resolver without granting completion.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(crate) fn resolver(self) -> Option<&'a super::consumed::ConsumedResolver> {
        self.consumed
    }

    /// Requires the same actual candidate observation and complete input purpose.
    ///
    /// This compares borrowed data only; the native producer independently
    /// closes its actual physical, Original and current evidence.
    ///
    /// # Errors
    /// Refuses absent, foreign or substituted holder, resolver, candidate or purpose.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(crate) fn same_candidate_scope(self, other: Self) -> Result<(), StoreFailure> {
        let held = self.held.ok_or_else(invalid)?;
        let other_held = other.held.ok_or_else(invalid)?;
        let consumed = self.consumed.ok_or_else(invalid)?;
        let other_consumed = other.consumed.ok_or_else(invalid)?;
        let candidate = self.candidate.ok_or_else(invalid)?;
        let other_candidate = other.candidate.ok_or_else(invalid)?;
        let same_purpose = match (self.maintenance, other.maintenance) {
            (None, None) => true,
            (Some(left), Some(right)) => std::ptr::eq(left, right),
            _ => false,
        };
        if !std::ptr::eq(held, other_held)
            || !std::ptr::eq(consumed, other_consumed)
            || !std::ptr::eq(candidate, other_candidate)
            || candidate != other_candidate
            || !self.same_paired_transition(other)
            || !same_purpose
            || self.requested_target != other.requested_target
            || self.overlay_layer != other.overlay_layer
        {
            return Err(invalid());
        }
        Ok(())
    }

    #[cfg(feature = "std")]
    /// Borrows a backend identity whose exclusion remains live for the observation.
    pub(crate) fn held(identity: &'a crate::bucket::held::HeldIdentity<'a>) -> Self {
        Self {
            held: Some(identity),
            consumed: None,
            candidate: None,
            maintenance: None,
            requested_target: false,
            overlay_layer: None,
            lifetime: std::marker::PhantomData,
            #[cfg(all(feature = "std", feature = "tokio", unix))]
            paired_transition: None,
        }
    }

    /// Borrows the operation-local resolver without accepting dependency claims.
    #[cfg(feature = "std")]
    pub(crate) fn tracked(mut self, consumed: &'a super::consumed::ConsumedResolver) -> Self {
        self.consumed = Some(consumed);
        self
    }

    /// Borrows ordinary inputs independently captured from the closed actual admission.
    #[cfg(feature = "std")]
    pub(crate) fn candidate(
        mut self,
        candidate: &'a super::view_selection::CandidateInputs,
    ) -> Self {
        self.candidate = Some(candidate);
        self
    }

    /// Selects namespace-only dependency qualification for a private repair operation.
    ///
    /// This ordinary purpose grants no permission or serving completion. The
    /// actual authored candidate, when present, still requires every relationship.
    #[cfg(feature = "std")]
    pub(crate) fn maintenance(mut self, purpose: &'a super::index_maintenance::Purpose) -> Self {
        self.maintenance = Some(purpose);
        self
    }

    /// Reports whether this dependency needs namespace-only qualification.
    ///
    /// Collection always requires complete qualification. Maintenance excludes
    /// the actual candidate, while requested-target mode excludes the requested
    /// view; neither choice supplies current rights or serving completion.
    #[cfg(feature = "std")]
    pub(super) fn namespace_only(self, view: Digest, requested: Digest, collection: bool) -> bool {
        if collection {
            return false;
        }
        if self.maintenance.is_some() {
            return self
                .candidate
                .is_none_or(|candidate| candidate.view() != view);
        }
        self.requested_target && view != requested
    }

    /// Selects the exact immutable layer at an explicit authoring/use boundary.
    ///
    /// This supplies decoding context only; signatures, Original scopes and
    /// complete input histories remain mandatory before the layer may be used.
    #[cfg(feature = "std")]
    pub(crate) fn overlay_layer(mut self, view: Digest, root: Digest) -> Self {
        self.overlay_layer = Some((view, root));
        self
    }

    /// Reports whether the derived overlay context selects the given view.
    ///
    /// This decoding selection does not authenticate the layer or grant permission.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(in crate::guard) fn selects_overlay_layer(self, view: Digest) -> bool {
        self.overlay_layer
            .is_some_and(|(selected, _)| selected == view)
    }

    /// Checks the requested serving target while authenticating its source ancestry.
    ///
    /// Explicit maintenance qualification remains distinct and takes precedence.
    pub(crate) fn requested_target(mut self) -> Self {
        self.requested_target = true;
        self
    }

    /// Checks whether the actual resolver owns a freshly rechecked Original.
    ///
    /// This preserves the owning completion boundary for operation-local reuse;
    /// it neither rechecks the protected record nor records its consumption.
    ///
    /// # Errors
    /// Refuses an Original retained by a different concrete completion factory.
    #[cfg(feature = "std")]
    pub(in crate::guard) fn check_completion_original(
        self,
        checked: &super::OriginalCommitContext,
    ) -> Result<(), StoreFailure> {
        if let Some(consumed) = self.consumed {
            consumed.check_completion_original(checked)?;
        }
        Ok(())
    }

    /// Records freshly rechecked protected administrative dependencies.
    ///
    /// # Errors
    /// Rejects conflicting canonical rows or unavailable trace synchronization.
    #[cfg(feature = "std")]
    pub(crate) fn record_original(
        self,
        checked: &super::OriginalCommitContext,
    ) -> Result<(), StoreFailure> {
        if let Some(consumed) = self.consumed {
            consumed.original(checked)?;
        }
        Ok(())
    }

    /// Prepares the actual candidate without completing its signed history.
    ///
    /// # Errors
    /// Rejects invalid candidate witnesses, missing metadata, or trace contradictions.
    #[cfg(feature = "std")]
    pub(crate) async fn record_candidate<S: crate::store::ContentStore, C>(
        self,
        guard: &Guard<S, C>,
        admitted: &super::AdmittedCommit,
    ) -> Result<(), StoreFailure> {
        if let Some(consumed) = self.consumed {
            guard.capture_candidate_inputs(admitted)?;
            let evidence = TreeEvidence::load_tree_for(
                guard.store(),
                admitted.commit.commit().tree,
                &admitted.uploads,
                guard.config().min_chunk_size,
                admitted.tree_usage,
            )
            .await?;
            #[cfg(unix)]
            if guard.has_view_selection(admitted.commit.identity())? {
                let original = guard.original_commit(&admitted.commit.identity())?;
                consumed.historical_issuer(&admitted.commit, &original)?;
            } else {
                consumed.issuer(&admitted.commit)?;
            }
            #[cfg(not(unix))]
            consumed.issuer(&admitted.commit)?;
            // Only successful pure preparation is reusable. All independently
            // fresh physical, selected-input and issuer checks above still run.
            let key = candidate_preparation::Key::capture(
                guard,
                self.held,
                &admitted.completion_inputs,
                &admitted.commit,
                &evidence,
                admitted.tree_usage,
            );
            consumed.prepare_candidate(
                key,
                &admitted.completion_inputs,
                &admitted.commit,
                &evidence,
            )?;
        }
        Ok(())
    }
    /// Reports whether the observation borrows this exact operation trace.
    #[cfg(feature = "std")]
    pub(crate) fn tracks(self, consumed: &super::consumed::ConsumedResolver) -> bool {
        self.consumed
            .is_some_and(|actual| std::ptr::eq(actual, consumed))
    }

    /// Checks the actual operation trace before final publication effects.
    ///
    /// # Errors
    /// Rejects inconsistent canonical observations or unavailable synchronization.
    #[cfg(feature = "std")]
    pub(crate) fn finish(self) -> Result<(), StoreFailure> {
        if let Some(consumed) = self.consumed {
            consumed.finish()?;
        }
        Ok(())
    }
}

#[cfg(all(feature = "std", feature = "tokio", unix))]
impl<'a> HistoryObservation<'a> {
    /// Borrows the actual paired producer's checked transition input.
    ///
    /// This supplies no current permission or completed history. The native
    /// reader must independently close this input with its owning invocation.
    pub(crate) fn paired_transition(
        mut self,
        transition: &'a crate::selected_bridge::native_guard::disclosure::GuardTransition<'a>,
    ) -> Self {
        self.paired_transition = Some(transition);
        self
    }

    /// Borrows the transition attached by the actual paired producer.
    pub(crate) fn paired_transition_purpose(
        self,
    ) -> Option<&'a crate::selected_bridge::native_guard::disclosure::GuardTransition<'a>> {
        self.paired_transition
    }

    /// Compares actual transition input identity without completing its checks.
    pub(crate) fn same_paired_transition(self, other: Self) -> bool {
        match (self.paired_transition, other.paired_transition) {
            (None, None) => true,
            (Some(left), Some(right)) => std::ptr::eq(left, right),
            _ => false,
        }
    }
}

/// Owns view inputs promoted only after the complete signed history succeeds.
#[cfg(feature = "std")]
pub(super) struct CompletedViewUse {
    /// Retains all actual signed-view context and occurrence policies.
    prepared: completion::PendingViewUse,
}

#[cfg(feature = "std")]
impl CompletedViewUse {
    /// Borrows owning completion data without exposing its constructor.
    pub(super) fn prepared(&self) -> &completion::PendingViewUse {
        &self.prepared
    }
}

/// Authenticates namespace provenance without certifying auxiliary index coverage.
///
/// Only the complete owning history walk constructs this capability. It cannot
/// enter `complete_views` or certify its own auxiliary serving coverage.
#[cfg(feature = "std")]
pub(super) struct SourceResolvedViewUse {
    prepared: completion::PendingViewUse,
}

#[cfg(feature = "std")]
impl SourceResolvedViewUse {
    /// Borrows authenticated source data without exposing capability construction.
    pub(super) fn prepared(&self) -> &completion::PendingViewUse {
        &self.prepared
    }
}

/// Retains semantic candidate checks without promoting any view or history.
///
/// Only the owning verifier constructs this pending data. Promotion also needs
/// the producer's combined actual Original, selected and artifact closing check.
#[cfg(all(feature = "std", feature = "tokio", unix))]
pub(crate) struct PendingCandidateHistory<'scope, 'history> {
    history: Box<VerifiedHistory>,
    selection: super::view_selection::CandidateInputs,
    requested: Digest,
    observation: HistoryObservation<'history>,
    reads: &'scope dyn crate::bucket::held::NodeReads,
    pending_uses: BTreeMap<Digest, completion::PendingViewUse>,
}

/// Pairs a closed candidate selection with its freshly completed staged history.
///
/// Only the owning verifier constructs this after the tracked history walk
/// completes. This does not select a ref or cache an index coverage result.
#[cfg(feature = "std")]
pub(crate) struct CompletedCandidateHistory {
    history: VerifiedHistory,
    selection: super::view_selection::CandidateInputs,
}

#[cfg(feature = "std")]
impl CompletedCandidateHistory {
    /// Borrows the exact ordinary candidate inputs used by the completed walk.
    pub(super) fn selection(&self) -> &super::view_selection::CandidateInputs {
        &self.selection
    }

    /// Borrows the complete genuine history checked for this candidate.
    pub(super) fn history(&self) -> &VerifiedHistory {
        &self.history
    }
}

/// Retains a tree together with the dependency graph completed for that exact commit.
///
/// Only this Guard-owned verifier initializes the private paired fields. Neither
/// component is current collection permission; the producer checks current roots
/// and holds independently before constructing its private retirement carrier.
#[cfg(feature = "std")]
pub(crate) struct VerifiedCollectionTree {
    tree: VerifiedTree,
    completed: CompletedCollectionHistory,
    interpretation: super::recorded_properties::SelectedReadInterpretation,
}

#[cfg(feature = "std")]
impl VerifiedCollectionTree {
    /// Borrows the exact immutable canonical tree whose signed history completed.
    pub(crate) fn tree(&self) -> &VerifiedTree {
        &self.tree
    }

    /// Borrows the completed dependency observation paired with this signed tree.
    pub(crate) fn completed(&self) -> &CompletedCollectionHistory {
        &self.completed
    }
}

/// Pairs a signature-checked commit with its addressed canonical tree evidence.
///
/// The private loader constructs this before complete history verification.
/// Owning callers must finish Original and history checks before using it as
/// provenance evidence; this value supplies no current operation authority.
pub(crate) struct VerifiedTree {
    /// Retains the commit authenticated against its original signed claims.
    pub(crate) commit: VerifiedCommit,
    /// Retains addressed metadata for the exact signed tree and decoding usage.
    pub(crate) evidence: TreeEvidence,
    /// Retains the independently selected interpretation for this view and root.
    interpretation: super::recorded_properties::SelectedReadInterpretation,
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Completes staged candidate history using its actual tracked operation inputs.
    ///
    /// # Errors
    /// Rejects missing candidate or trace, a substituted view, and every owning
    /// signature, Original, history, disclosure, profile or index relationship failure.
    #[cfg(feature = "std")]
    pub(crate) async fn complete_candidate_history_observed(
        &self,
        view: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<CompletedCandidateHistory, StoreFailure> {
        let selected = observation.candidate.ok_or_else(invalid)?;
        if selected.view() != view || observation.consumed.is_none() {
            return Err(invalid());
        }
        let history = self.verified_history_observed(view, observation).await?;
        Ok(CompletedCandidateHistory {
            history,
            selection: selected.clone(),
        })
    }

    /// Prepares candidate relationships from one actual held Node read scope.
    ///
    /// The sealed reader supplies bytes only. Signatures, provenance and actual
    /// Original checks still use this Guard's owning verifier. The returned
    /// pending data promotes no view and constructs no completion receipt.
    ///
    /// # Errors
    /// Preserves every ordinary candidate/history failure and refuses changed or
    /// unavailable physical and selected evidence consumed by the Node reader.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(crate) async fn prepare_candidate_history_with_node_reads<'scope, 'history: 'scope>(
        &self,
        view: Digest,
        observation: HistoryObservation<'history>,
        reads: &'scope dyn crate::bucket::held::NodeReads,
    ) -> Result<PendingCandidateHistory<'scope, 'history>, StoreFailure> {
        let selected = observation.candidate.ok_or_else(invalid)?;
        if selected.view() != view || observation.consumed.is_none() {
            return Err(invalid());
        }
        reads.check_holder(observation.held.ok_or_else(invalid)?)?;
        self.prepare_history_with_node_reads(view, observation, reads)
            .await
    }

    /// Promotes pending candidate history after one genuine combined closure.
    ///
    /// This synchronous boundary performs no await after physical closing checks.
    ///
    /// # Errors
    /// Refuses a different closed scope, changed current inputs or contradictory
    /// view promotion without constructing a completed candidate receipt.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(crate) fn promote_candidate_history(
        &self,
        pending: PendingCandidateHistory<'_, '_>,
        checked: crate::store::native_publication_effects::CheckedHistoryInputs<'_, '_, '_>,
    ) -> Result<CompletedCandidateHistory, StoreFailure> {
        checked.check_candidate_scope(pending.observation, pending.reads)?;
        self.promote_prepared_view_inputs::<false, false>(
            pending.requested,
            pending.observation,
            pending.pending_uses,
            &pending.history,
        )?;
        Ok(CompletedCandidateHistory {
            history: *pending.history,
            selection: pending.selection,
        })
    }

    /// Loads an exact signed tree and completes its canonical dependency history.
    ///
    /// The result supplies immutable provenance evidence without current rights.
    ///
    /// # Errors
    /// Preserves metadata, signature, selected interpretation, complete history
    /// and protected Original failures under the default observation.
    pub(crate) async fn verified_tree(
        &self,
        identity: Digest,
    ) -> Result<VerifiedTree, StoreFailure> {
        self.verified_tree_observed(identity, HistoryObservation::default())
            .await
    }

    /// Checks a complete immutable tree using the supplied synchronization scope.
    ///
    /// # Errors
    /// Rejects malformed signatures, scopes, protected associations, or unavailable storage.
    pub(crate) async fn verified_tree_observed(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<VerifiedTree, StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::DirectTree);
        let result = self
            .verified_tree_history_observed(identity, observation)
            .await
            .map(|(verified, _)| verified);
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.finish_result(&result);
        result
    }

    /// Retains the complete history freshly checked for this exact target tree.
    ///
    /// Both witnesses belong to this invocation and its observation. Callers
    /// still perform their independent current-policy and content checks.
    ///
    /// # Errors
    /// Preserves tree/signature failures before complete canonical history and
    /// protected original-authority failures.
    pub(super) async fn verified_tree_history_observed(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<(VerifiedTree, VerifiedHistory), StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::DirectHistory);
        #[cfg(all(feature = "std", feature = "tokio", unix))]
        {
            let direct = self
                .direct_history_native(
                    identity,
                    super::direct_history::DirectMode::Tree,
                    observation,
                )
                .await;
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            if direct.is_err() {
                diagnostic.finish_result(&direct);
            }
            if let Some(completed) = direct? {
                let verified = completed.tree.ok_or_else(invalid)?;
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                diagnostic.complete();
                return Ok((verified, completed.history));
            }
        }
        let verified = self.signed_tree(identity, observation).await;
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if verified.is_err() {
            diagnostic.finish_result(&verified);
        }
        let verified = verified?;
        let history = self.verified_history_observed(identity, observation).await;
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.finish_result(&history);
        let history = history?;
        Ok((verified, history))
    }

    /// Retains the exact tree and fully completed collection dependency graph.
    ///
    /// This operation-local result provides no current collection or deletion
    /// authority. The collector separately checks current roots, lease, original
    /// controls, actual holder and every absolute proof occurrence.
    ///
    /// # Errors
    /// Preserves signature, scope, history, certificate and protected-control errors.
    #[cfg(feature = "std")]
    pub(crate) async fn verified_collection_tree_observed(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<VerifiedCollectionTree, StoreFailure> {
        let tree = if let Some((selected, root)) = observation.overlay_layer {
            if selected != identity {
                return Err(invalid());
            }
            let tree = self
                .signed_tree_for(
                    identity,
                    observation,
                    terrane_format::tree_format::TreeUse::OverlayLayer,
                )
                .await?;
            if tree.evidence.root != root {
                return Err(invalid());
            }
            tree
        } else {
            self.signed_tree(identity, observation).await?
        };
        let completed = self
            .complete_collection_history_observed(identity, observation)
            .await?;
        let interpretation = tree.interpretation.clone();
        Ok(VerifiedCollectionTree {
            tree,
            completed,
            interpretation,
        })
    }

    // This private value authenticates a signature only. Canonical original
    // scope and protected association must be checked before any caller uses
    // the record as policy or origin authority.
    async fn signed_tree(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<VerifiedTree, StoreFailure> {
        self.signed_tree_for(
            identity,
            observation,
            terrane_format::tree_format::TreeUse::Ordinary,
        )
        .await
    }

    /// Authenticates an explicitly selected layer without changing ordinary reads.
    async fn signed_tree_for(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
        usage: terrane_format::tree_format::TreeUse,
    ) -> Result<VerifiedTree, StoreFailure> {
        let evidence = TreeEvidence::load_commit_for(
            self.store(),
            identity,
            self.config().min_chunk_size,
            usage,
        )
        .await?;
        let commit = evidence.commit.as_ref().ok_or_else(invalid)?;
        if commit.profile_pair.chunk_profile != self.config().chunk_profile_name
            || self.config().min_chunk_size != self.config().chunk_profile.minimum() as u64
        {
            return Err(invalid());
        }
        let context = commit
            .profile_pair
            .commit_context
            .as_ref()
            .ok_or_else(invalid)?;
        let has_disclosures = commit
            .profile_pair
            .entry_receipts
            .iter()
            .flatten()
            .any(|receipt| receipt.disclosure_proof.is_some());
        // A certified candidate is authenticated against its signed claims only.
        // Complete candidate validation checks actual root scope before exposing
        // history; it alone determines whether any private parent is audit-only.
        let interpretation = self.select_view(identity, evidence.root, observation)?;
        let mut witnessed = interpretation.historical_roots(
            &evidence,
            self.config().min_chunk_size,
            self.defaults_for(&evidence),
        )?;
        let missing_candidate_claim = context.roots().iter().any(|claim| {
            !witnessed
                .iter()
                .any(|(path, domain)| path.as_slice() == claim.path() && domain == claim.domain())
        });
        if !has_disclosures && missing_candidate_claim {
            let parent = commit.parents.first().ok_or_else(invalid)?;
            let previous =
                TreeEvidence::load_commit(self.store(), *parent, self.config().min_chunk_size)
                    .await?;
            witnessed.extend(interpretation.historical_roots(
                &previous,
                self.config().min_chunk_size,
                self.defaults_for(&previous),
            )?);
        }
        if !has_disclosures
            && context.roots().iter().any(|claim| {
                !witnessed.iter().any(|(path, domain)| {
                    path.as_slice() == claim.path() && domain == claim.domain()
                })
            })
        {
            return Err(invalid());
        }
        let roots = context
            .roots()
            .iter()
            .map(|claim| RequestRoot {
                path: claim.path(),
                domain: claim.domain(),
            })
            .collect::<Vec<_>>();
        let epochs = [(context.reference(), commit.provenance.writer_epoch)];
        // Signature-only loading may encounter a genuinely local newly signed
        // view before owning Original verification. Only an already retained
        // imported context supplies alternate keys; a present import failure
        // never falls back to configured local keys. Complete history below
        // still requires the exact protected Original association.
        #[cfg(all(feature = "std", unix))]
        let historical_keys = {
            let retained = self
                .original_commits
                .read()
                .map_err(|_| {
                    StoreFailure::new(crate::store::StoreErrorKind::Unavailable {
                        retry_after: None,
                    })
                })?
                .get(&identity)
                .cloned();
            match retained {
                Some(original) => original.historical_keys()?,
                None => None,
            }
        };
        #[cfg(all(feature = "std", unix))]
        let keys = historical_keys.as_deref().unwrap_or(self.keys());
        #[cfg(not(all(feature = "std", unix)))]
        let keys = self.keys();
        let commit =
            provenance::verify_history(commit, keys, &roots, &epochs).map_err(|_| invalid())?;
        if commit.identity() != identity {
            return Err(invalid());
        }
        Ok(VerifiedTree {
            commit,
            evidence,
            interpretation,
        })
    }

    /// Loads parents and explicit source receipts before checking every entry
    /// introduction and independent attribute producer against complete trees.
    ///
    /// # Errors
    /// Rejects incomplete or unverifiable canonical history and protected associations.
    #[cfg(feature = "std")]
    pub(crate) async fn verified_history(
        &self,
        identity: Digest,
    ) -> Result<VerifiedHistory, StoreFailure> {
        self.verified_history_observed(identity, HistoryObservation::default())
            .await
    }

    /// Checks complete ordinary history within the supplied synchronization scope.
    ///
    /// # Errors
    /// Rejects incomplete or unverifiable canonical history and protected associations.
    pub(crate) async fn verified_history_observed(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<VerifiedHistory, StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::HistoryCompletion);
        #[cfg(all(feature = "std", feature = "tokio", unix))]
        if let Some(completed) = self
            .direct_history_native(
                identity,
                super::direct_history::DirectMode::History,
                observation,
            )
            .await?
        {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            diagnostic.complete();
            return Ok(completed.history);
        }
        let result = self.complete_history_observed(identity, observation).await;
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.finish_result(&result);
        result
    }

    #[cfg(feature = "std")]
    async fn check_original_scope(
        &self,
        history: &mut VerifiedHistory,
        identity: Digest,
        private_domain: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        let context = self.original_commit(&identity)?;
        let baseline = context.baseline();
        let association = super::AssociationView {
            commit: &identity,
            id: baseline.authority().id(),
            reference: baseline.reference(),
            epoch: baseline.epoch(),
        };
        let checked = match observation.held {
            Some(held) if held.writable() => {
                self.recheck_original_commit_observed(baseline, association, held)
                    .await?
            }
            Some(held) => {
                self.recheck_original_commit_read_observed(baseline, association, held)
                    .await?
            }
            None => self.check_original_commit(baseline, association).await?,
        };
        if checked != context {
            return Err(invalid());
        }
        if let Some(consumed) = observation.consumed {
            consumed.check_completion_original(&checked)?;
            consumed.original(&checked)?;
        }
        let authority = baseline
            .authority()
            .id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let acl = baseline
            .acl()
            .iter()
            .map(|(subject, verbs)| (subject.as_str(), *verbs))
            .collect::<Vec<_>>();
        let defaults = terrane_format::properties::Defaults {
            store: &self.config().store_name,
            private_domain,
            home: self.config().home.region.as_deref().unwrap_or("local"),
        };
        let root = history.commit(&identity).ok_or_else(invalid)?.commit().tree;
        let interpretation = self.select_view(identity, root, observation)?;
        interpretation.verify_original_scope(
            history,
            identity,
            defaults,
            &authority,
            provenance::OriginalBootstrapPolicy {
                authority: &authority,
                reference: baseline.reference(),
                writer_epoch: baseline.epoch(),
                acl: &acl,
            },
        )?;
        Ok(())
    }

    #[cfg(not(feature = "std"))]
    async fn check_original_scope(
        &self,
        _history: &mut VerifiedHistory,
        _identity: Digest,
        _private_domain: &str,
        _observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

#[cfg(not(feature = "std"))]
impl<S, C> Guard<S, C> {
    /// Projects the native-free deliberately configured selection as ordinary data.
    ///
    /// # Errors
    /// Preserves unsupported or unnormalized selection errors.
    pub(super) fn select_view(
        &self,
        view: Digest,
        root: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<super::recorded_properties::SelectedReadInterpretation, StoreFailure> {
        super::recorded_properties::SelectedReadInterpretation::from_selection(
            view,
            root,
            self.view_semantics(view, root, observation)?,
        )
    }
}

#[cfg(all(feature = "std", feature = "tokio", unix))]
impl<S: Store, C: Clock> Guard<S, C> {
    /// Prepares the original target request through the genuine direct DATA ledger.
    ///
    /// # Errors
    /// Preserves signature, full-history, Original and relationship failures.
    pub(in crate::guard) async fn prepare_direct_history<'scope, 'history, 'held>(
        &self,
        target: Digest,
        mode: super::direct_history::DirectMode,
        observation: HistoryObservation<'history>,
        purpose: &'scope super::direct_history::DirectPurpose<'history, 'held>,
        reads: &'scope dyn crate::bucket::held::DirectNodeReads,
    ) -> Result<
        (
            Option<VerifiedTree>,
            super::direct_history::PendingDirectHistory<'scope, 'history, 'held>,
        ),
        StoreFailure,
    > {
        purpose.check(target, observation)?;
        reads.check_holder(observation.identity().ok_or_else(invalid)?)?;
        reads.check_direct(purpose.read_check())?;
        let tree = match mode {
            super::direct_history::DirectMode::History => None,
            super::direct_history::DirectMode::Tree => {
                Some(self.signed_tree(target, observation).await?)
            }
        };
        let pending = self
            .prepare_direct_history_with_reads(target, observation, purpose, reads)
            .await?;
        Ok((tree, pending))
    }
}
