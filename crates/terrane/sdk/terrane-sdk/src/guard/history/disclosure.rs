//! Completes ordinary and certified history without loading attested private ancestry.
//!
//! Certificate authentication supplies only a private dependency plan. An
//! ancestor-first work stack completes every ordinary dependency and the entire
//! candidate before exposing any boundary, origin or attribute producer.

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::identity::Digest;
use terrane_format::provenance::{self, EntryLocation, VerifiedHistory};

#[cfg(feature = "std")]
use super::TreeEvidence;
use super::{Guard, HistoryObservation, invalid};
use crate::store::{Clock, Store, StoreFailure};

#[cfg(all(feature = "std", unix))]
mod recorded;
mod retained_reads;

use retained_reads::HistoryCompletion;
#[cfg(all(feature = "std", feature = "tokio", unix))]
use retained_reads::RetainedReadPurpose;

/// Retains dependency sets only after all actual history and control checks finish.
///
/// This is operation-local immutable evidence, not collection authority. Only
/// this Guard-owned completion routine initializes its private fields.
pub(crate) struct CompletedCollectionHistory {
    history: VerifiedHistory,
    #[cfg(feature = "std")]
    dependencies: BTreeMap<Digest, CollectionHistoryDependencies>,
    #[cfg(feature = "std")]
    contextual_layers: BTreeMap<Digest, Digest>,
}

/// Separates ordinary retention edges from independently retained proof metadata.
#[cfg(feature = "std")]
pub(crate) struct CollectionHistoryDependencies {
    parents: Vec<Digest>,
    witnesses: Vec<Digest>,
    disclosure: Option<provenance::VerifiedDisclosureBatch>,
}

#[cfg(feature = "std")]
impl CompletedCollectionHistory {
    /// Borrows the history whose canonical scopes and original controls completed.
    pub(crate) fn history(&self) -> &VerifiedHistory {
        &self.history
    }

    /// Returns an exact layer root established by fully completed signed input history.
    pub(crate) fn contextual_layer(&self, commit: &Digest) -> Option<Digest> {
        self.contextual_layers.get(commit).copied()
    }

    /// Borrows only dependencies whose actual ancestor-first completion succeeded.
    pub(crate) fn dependencies(&self, view: Digest) -> Option<&CollectionHistoryDependencies> {
        self.dependencies.get(&view)
    }
}

#[cfg(feature = "std")]
impl CollectionHistoryDependencies {
    /// Borrows ordinary parent edges after exact verified certified cuts.
    pub(crate) fn parents(&self) -> &[Digest] {
        &self.parents
    }

    /// Borrows the entire completed dependency set for metadata-only visitation.
    ///
    /// A parent also serving as an attribute/source proof keeps this independent
    /// lane regardless of its ordinary retention cutoff.
    pub(crate) fn witnesses(&self) -> &[Digest] {
        &self.witnesses
    }

    /// Borrows the final authenticated batch, including exact root occurrences.
    pub(crate) fn disclosure(&self) -> Option<&provenance::VerifiedDisclosureBatch> {
        self.disclosure.as_ref()
    }
}

enum Stage {
    Enter(Digest),
    Finish(Digest),
}

type EntryChecks = Vec<(EntryLocation, Vec<String>)>;

/// Borrows untrusted source selection fields for independent held Read checks.
#[cfg(all(feature = "std", unix))]
pub(crate) struct DisclosureSourceSelection<'a> {
    /// Separate current source policy reference.
    pub(crate) reference: &'a str,
    /// Exact immutable source commit selected by the request.
    pub(crate) commit: Digest,
    /// Capability checked against current configured source keys.
    pub(crate) token: &'a [u8],
    /// Full canonical source entry path.
    pub(crate) path: &'a [u8],
    /// Registered operation surface.
    pub(crate) surface: &'a str,
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Loads a completed history for union before disclosure candidate staging.
    ///
    /// # Errors
    /// Rejects invalid signed roots, incomplete provenance, changed original
    /// authority or public trust, and unavailable held canonical evidence.
    #[cfg(all(feature = "std", unix))]
    pub(crate) async fn completed_history_for_disclosure(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<VerifiedHistory, StoreFailure> {
        self.verified_tree_history_observed(identity, observation)
            .await
            .map(|(_, history)| history)
    }

    /// Captures independently checked live and historical source Read requests.
    ///
    /// This preserves the private read implementation's complete root, token,
    /// epoch, ACL and content-origin checks within the actual held observation.
    ///
    /// # Errors
    /// Rejects another policy reference, differing complete live ref values,
    /// invalid history, unauthorized paths and unavailable source evidence.
    #[cfg(all(feature = "std", unix))]
    pub(crate) async fn capture_disclosure_source_observed(
        &self,
        selection: DisclosureSourceSelection<'_>,
        observation: HistoryObservation<'_>,
    ) -> Result<
        (
            crate::guard::AuthorizedSnapshot,
            Vec<crate::guard::AuthorizedRef>,
        ),
        StoreFailure,
    > {
        let (snapshot, mut requests) = self
            .read_commit_snapshot_authorizations_observed(
                selection.commit,
                selection.token,
                selection.path,
                selection.surface,
                observation,
            )
            .await?;
        requests.extend(
            self.snapshot_authorizations_observed(&snapshot, selection.path, observation)
                .await?,
        );
        let current = requests.first().ok_or_else(invalid)?;
        if current.reference() != selection.reference
            || current.record().is_none()
            || requests.iter().any(|request| {
                request.reference() != selection.reference
                    || request.record() != current.record()
                    || request.subject() != current.subject()
                    || request.verb() != terrane_format::auth::Verb::Read
            })
        {
            return Err(crate::guard::denied(
                selection.reference,
                terrane_format::auth::Verb::Read,
            ));
        }
        Ok((snapshot, requests))
    }

    /// Checks every ordinary dependency and completes each certified candidate.
    ///
    /// # Errors
    /// Rejects cyclic or incomplete history, malformed certificates, invalid
    /// original contexts, missing producers and changed retained public trust.
    pub(super) async fn complete_history_observed(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<VerifiedHistory, StoreFailure> {
        self.complete_history::<false>(
            identity,
            observation,
            #[cfg(all(feature = "std", feature = "tokio", unix))]
            None,
        )
        .await
        .and_then(HistoryCompletion::completed)
        .map(|completed| completed.history)
    }

    /// Uses sealed held data only for the final owning relationship checks.
    ///
    /// # Errors
    /// Preserves ordinary history failures; this returns no promoted completion.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(super) async fn prepare_history_with_node_reads<'scope, 'history: 'scope>(
        &self,
        identity: Digest,
        observation: HistoryObservation<'history>,
        reads: &'scope dyn crate::bucket::held::NodeReads,
    ) -> Result<super::PendingCandidateHistory<'scope, 'history>, StoreFailure> {
        match self
            .complete_history::<false>(
                identity,
                observation,
                Some(RetainedReadPurpose::Candidate(reads)),
            )
            .await?
        {
            HistoryCompletion::Pending(pending) => Ok(pending),
            HistoryCompletion::Complete(_, _)
            | HistoryCompletion::PendingCurrent(_)
            | HistoryCompletion::PendingHeld(_)
            | HistoryCompletion::PendingDirect(_)
            | HistoryCompletion::PendingOverlay(_) => Err(invalid()),
        }
    }

    /// Prepares the full owning walk for one independently captured current ref.
    ///
    /// Every semantic history and relationship check precedes this pending
    /// result. Actual native physical closure remains mandatory before promotion.
    ///
    /// # Errors
    /// Refuses a foreign purpose or reader and preserves complete history,
    /// Original, producer, disclosure and relationship failures.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(super) async fn prepare_current_history_with_node_reads<'scope, 'history, 'held>(
        &self,
        identity: Digest,
        observation: HistoryObservation<'history>,
        purpose: &'scope crate::guard::current_history::CurrentPurpose<'history, 'held>,
        reads: &'scope dyn crate::bucket::held::CurrentNodeReads,
    ) -> Result<
        crate::guard::current_history::PendingCurrentHistory<'scope, 'history, 'held>,
        StoreFailure,
    > {
        purpose.check(identity, observation)?;
        reads.check_holder(observation.identity().ok_or_else(invalid)?)?;
        reads.check_current(purpose.current())?;
        match self
            .complete_history::<false>(
                identity,
                observation,
                Some(RetainedReadPurpose::Current { purpose, reads }),
            )
            .await?
        {
            HistoryCompletion::PendingCurrent(pending) => Ok(pending),
            HistoryCompletion::Complete(_, _)
            | HistoryCompletion::Pending(_)
            | HistoryCompletion::PendingHeld(_)
            | HistoryCompletion::PendingDirect(_)
            | HistoryCompletion::PendingOverlay(_) => Err(invalid()),
        }
    }

    /// Prepares the full owning walk for one independently captured current ref.
    ///
    /// Every semantic history and relationship check precedes this pending
    /// result. Actual native physical closure remains mandatory before promotion.
    ///
    /// # Errors
    /// Refuses a foreign purpose or reader and preserves complete history,
    /// Original, producer, disclosure and relationship failures.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(super) async fn prepare_held_history_with_node_reads<'scope, 'history, 'held>(
        &self,
        identity: Digest,
        observation: HistoryObservation<'history>,
        purpose: &'scope crate::guard::held_history::HeldPurpose<'history, 'held>,
        reads: &'scope dyn crate::bucket::held::CurrentNodeReads,
    ) -> Result<crate::guard::held_history::PendingHeldHistory<'scope, 'history, 'held>, StoreFailure>
    {
        purpose.check(identity, observation)?;
        reads.check_holder(observation.identity().ok_or_else(invalid)?)?;
        reads.check_current(purpose.current())?;
        match self
            .complete_history::<false>(
                identity,
                observation,
                Some(RetainedReadPurpose::Held { purpose, reads }),
            )
            .await?
        {
            HistoryCompletion::PendingHeld(pending) => Ok(pending),
            HistoryCompletion::Complete(_, _)
            | HistoryCompletion::Pending(_)
            | HistoryCompletion::PendingCurrent(_)
            | HistoryCompletion::PendingDirect(_)
            | HistoryCompletion::PendingOverlay(_) => Err(invalid()),
        }
    }

    /// Prepares the complete owning history for a distinct immutable native read.
    ///
    /// # Errors
    /// Preserves all history checks and refuses unrelated purpose or reader inputs.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(super) async fn prepare_direct_history_with_reads<'scope, 'history, 'held>(
        &self,
        identity: Digest,
        observation: HistoryObservation<'history>,
        purpose: &'scope crate::guard::direct_history::DirectPurpose<'history, 'held>,
        reads: &'scope dyn crate::bucket::held::DirectNodeReads,
    ) -> Result<
        crate::guard::direct_history::PendingDirectHistory<'scope, 'history, 'held>,
        StoreFailure,
    > {
        purpose.check(identity, observation)?;
        reads.check_holder(observation.identity().ok_or_else(invalid)?)?;
        reads.check_direct(purpose.read_check())?;
        match self
            .complete_history::<false>(
                identity,
                observation,
                Some(RetainedReadPurpose::Direct { purpose, reads }),
            )
            .await?
        {
            HistoryCompletion::PendingDirect(pending) => Ok(pending),
            HistoryCompletion::Complete(_, _)
            | HistoryCompletion::Pending(_)
            | HistoryCompletion::PendingCurrent(_)
            | HistoryCompletion::PendingHeld(_)
            | HistoryCompletion::PendingOverlay(_) => Err(invalid()),
        }
    }

    /// Prepares the complete owning history for a distinct immutable native read.
    ///
    /// # Errors
    /// Preserves all history checks and refuses unrelated purpose or reader inputs.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(in crate::guard) async fn prepare_overlay_history_with_reads<'scope, 'history, 'held>(
        &self,
        identity: Digest,
        observation: HistoryObservation<'history>,
        purpose: &'scope crate::guard::overlay_history::OverlayPurpose<'history, 'held>,
        reads: &'scope dyn crate::bucket::held::OverlayNodeReads,
    ) -> Result<
        crate::guard::overlay_history::PendingOverlayHistory<'scope, 'history, 'held>,
        StoreFailure,
    > {
        purpose.check(identity, observation)?;
        reads.check_holder(observation.identity().ok_or_else(invalid)?)?;
        reads.check_overlay(purpose.read_check())?;
        match self
            .complete_history::<false>(
                identity,
                observation,
                Some(RetainedReadPurpose::Overlay { purpose, reads }),
            )
            .await?
        {
            HistoryCompletion::PendingOverlay(pending) => Ok(pending),
            HistoryCompletion::Complete(_, _)
            | HistoryCompletion::Pending(_)
            | HistoryCompletion::PendingCurrent(_)
            | HistoryCompletion::PendingHeld(_)
            | HistoryCompletion::PendingDirect(_) => Err(invalid()),
        }
    }

    /// Retains actual scheduled dependencies only after every history check finishes.
    ///
    /// # Errors
    /// Preserves malformed scope/certificate, original association, attribute
    /// producer, consumed-control and incomplete dependency failures.
    #[cfg(feature = "std")]
    pub(crate) async fn complete_collection_history_observed(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<CompletedCollectionHistory, StoreFailure> {
        self.complete_history::<true>(
            identity,
            observation,
            #[cfg(all(feature = "std", feature = "tokio", unix))]
            None,
        )
        .await
        .and_then(HistoryCompletion::completed)
    }

    // Both lanes run the same ancestor-first verifier. Ordinary callers discard
    // the collection observations without allocating additional dependency rows.
    async fn complete_history<'scope, 'history, 'held, const RETAIN_COLLECTION: bool>(
        &self,
        identity: Digest,
        observation: HistoryObservation<'history>,
        #[cfg(all(feature = "std", feature = "tokio", unix))] node_reads: Option<
            RetainedReadPurpose<'scope, 'history, 'held>,
        >,
    ) -> Result<HistoryCompletion<'scope, 'history, 'held>, StoreFailure> {
        #[cfg(all(test, feature = "tokio", unix))]
        let trace = super::completion::active::HistoryTrace::new(format!(
            "complete-history view={identity:?}"
        ));
        let mut history =
            VerifiedHistory::new_selected(self.config().min_chunk_size, self.semantic_selection());
        let mut pending = vec![Stage::Enter(identity)];
        let mut active = BTreeSet::new();
        let mut completed = BTreeSet::new();
        let mut domains = BTreeMap::new();
        let layer_roots = observation
            .overlay_layer
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        #[cfg(feature = "std")]
        let mut layer_roots = layer_roots;
        #[cfg(feature = "std")]
        let mut overlay_plans = BTreeMap::new();
        #[cfg(feature = "std")]
        let mut tree_evidence = BTreeMap::new();
        let mut locations: BTreeMap<Digest, EntryChecks> = BTreeMap::new();
        let mut certified = BTreeSet::new();
        #[cfg(feature = "std")]
        let mut entered = BTreeMap::new();
        #[cfg(feature = "std")]
        let mut dependency_rows = BTreeMap::new();
        #[cfg(feature = "std")]
        let mut pending_uses = BTreeMap::new();
        #[cfg(feature = "std")]
        let mut relationship_plans = Vec::new();

        while let Some(stage) = pending.pop() {
            match stage {
                Stage::Enter(identity) => {
                    if completed.contains(&identity) {
                        continue;
                    }
                    if !active.insert(identity) {
                        return Err(invalid());
                    }
                    #[cfg(all(test, feature = "tokio", unix))]
                    let view_trace = super::completion::active::HistoryTrace::new(format!(
                        "enter view={identity:?}"
                    ));
                    let usage = if layer_roots.contains_key(&identity) {
                        terrane_format::tree_format::TreeUse::OverlayLayer
                    } else {
                        terrane_format::tree_format::TreeUse::Ordinary
                    };
                    let verified = self.signed_tree_for(identity, observation, usage).await?;
                    if layer_roots
                        .get(&identity)
                        .is_some_and(|root| *root != verified.evidence.root)
                    {
                        return Err(invalid());
                    }
                    #[cfg(feature = "std")]
                    if let Some(plan) =
                        super::layers::OverlayHistoryPlan::from_commit(verified.commit.commit())?
                    {
                        if verified.evidence.usage != terrane_format::tree_format::TreeUse::Ordinary
                        {
                            return Err(invalid());
                        }
                        for (input, root) in &plan.inputs {
                            if layer_roots
                                .insert(*input, *root)
                                .is_some_and(|previous| previous != *root)
                                || tree_evidence
                                    .get(input)
                                    .is_some_and(|evidence: &TreeEvidence| evidence.root != *root)
                            {
                                return Err(invalid());
                            }
                        }
                        overlay_plans.insert(identity, plan);
                    }
                    #[cfg(all(test, feature = "tokio", unix))]
                    view_trace.mark("signed-tree-returned");
                    #[cfg(feature = "std")]
                    {
                        let inputs = self.selected_view_inputs(
                            identity,
                            verified.evidence.root,
                            observation,
                        )?;
                        let requires_pending =
                            observation.consumed.is_some() || observation.candidate.is_some();
                        let plan = if requires_pending {
                            let (prepared, plan) =
                                super::completion::PendingViewUse::prepare_with_plan(
                                    &inputs,
                                    &verified.commit,
                                    &verified.evidence,
                                )?;
                            if let Some(consumed) = observation.consumed {
                                #[cfg(unix)]
                                if self
                                    .original_commit(&identity)?
                                    .historical_keys()?
                                    .is_none()
                                {
                                    consumed.issuer(&verified.commit)?;
                                }
                                #[cfg(not(unix))]
                                consumed.issuer(&verified.commit)?;
                                consumed.pending_view(&prepared)?;
                            }
                            pending_uses.insert(identity, prepared);
                            plan
                        } else if inputs.selection
                            != terrane_format::properties::selected::Selection::Legacy
                        {
                            // Plan-only callers retain their original acceptance and
                            // diagnostics; Pending has additional signed-policy checks.
                            Some(super::completion::active::plan(
                                &verified.evidence,
                                &inputs,
                            )?)
                        } else {
                            None
                        };
                        if let Some(plan) = plan {
                            relationship_plans.push((identity, plan));
                        }
                    }
                    #[cfg(all(test, feature = "tokio", unix))]
                    view_trace.mark("preparation-plan-returned");
                    let has_certificates = verified
                        .commit
                        .commit()
                        .profile_pair
                        .entry_receipts
                        .iter()
                        .flatten()
                        .any(|receipt| receipt.disclosure_proof.is_some());
                    let ordinary_dependencies = if has_certificates {
                        Vec::new()
                    } else {
                        verified
                            .commit
                            .commit()
                            .parents
                            .iter()
                            .copied()
                            .chain(provenance::source_commit_references(&verified.commit))
                            .collect()
                    };
                    history
                        .insert_commit_selected(
                            verified.commit,
                            verified.interpretation.selection(),
                        )
                        .map_err(|_| invalid())?;

                    // Trees carry local Rc sharing. Decode and collect their
                    // owned canonical witnesses before any subsequent await.
                    let mut entries = Vec::new();
                    for root in &verified.evidence.roots {
                        let tree = verified
                            .evidence
                            .tree(*root, self.config().min_chunk_size)?;
                        let nodes = tree
                            .nodes()
                            .map(|node| (node.identity(), node.encoded().to_vec()))
                            .collect::<Vec<_>>();
                        if verified.evidence.root_usage(*root)
                            == terrane_format::tree_format::TreeUse::OverlayLayer
                        {
                            history.insert_overlay_tree(*root, &nodes)
                        } else {
                            history.insert_tree(*root, &nodes)
                        }
                        .map_err(|_| invalid())?;
                        for entry in tree.iter() {
                            entries.push((
                                EntryLocation {
                                    commit: identity,
                                    root: *root,
                                    path: entry.key.clone(),
                                },
                                entry
                                    .entry
                                    .attrs
                                    .iter()
                                    .map(|attr| attr.name.to_owned())
                                    .collect(),
                            ));
                        }
                    }
                    #[cfg(all(test, feature = "tokio", unix))]
                    view_trace.mark("tree-insertion-entry-extraction-returned");
                    let dependencies = if has_certificates {
                        certified.insert(identity);
                        self.disclosure_dependencies(
                            &history,
                            identity,
                            &verified.evidence.default_domain,
                            observation,
                        )?
                    } else {
                        ordinary_dependencies
                    };
                    #[cfg(feature = "std")]
                    if RETAIN_COLLECTION {
                        entered.insert(identity, dependencies.clone());
                    }
                    domains.insert(identity, verified.evidence.default_domain.clone());
                    #[cfg(feature = "std")]
                    tree_evidence.insert(identity, verified.evidence);
                    locations.insert(identity, entries);
                    pending.push(Stage::Finish(identity));
                    for dependency in dependencies.into_iter().rev() {
                        pending.push(Stage::Enter(dependency));
                    }
                }
                Stage::Finish(identity) => {
                    #[cfg(all(test, feature = "tokio", unix))]
                    let finish_trace = super::completion::active::HistoryTrace::new(format!(
                        "finish view={identity:?}"
                    ));
                    let domain = domains.get(&identity).ok_or_else(invalid)?;
                    if certified.contains(&identity) {
                        let finished = self
                            .finish_disclosure_history(history, identity, domain, observation)
                            .await?;
                        #[cfg(feature = "std")]
                        if RETAIN_COLLECTION {
                            let batch = finished.1;
                            let mut scheduled = entered.get(&identity).ok_or_else(invalid)?.clone();
                            scheduled.sort();
                            scheduled.dedup();
                            if scheduled != batch.required_commits() {
                                return Err(invalid());
                            }
                            dependency_rows.insert(identity, Some(batch));
                        }
                        history = finished.0;
                    } else {
                        self.check_original_scope(&mut history, identity, domain, observation)
                            .await?;
                        #[cfg(all(test, feature = "tokio", unix))]
                        finish_trace.mark("original-scope-returned");
                        #[cfg(all(test, feature = "tokio", unix))]
                        let mut introduction_time = std::time::Duration::ZERO;
                        #[cfg(all(test, feature = "tokio", unix))]
                        let mut producer_time = std::time::Duration::ZERO;
                        #[cfg(all(test, feature = "tokio", unix))]
                        let mut entry_count = 0usize;
                        #[cfg(all(test, feature = "tokio", unix))]
                        let mut attribute_count = 0usize;
                        for (location, attributes) in
                            locations.get(&identity).ok_or_else(invalid)?
                        {
                            #[cfg(all(test, feature = "tokio", unix))]
                            let introduction_started = finish_trace.elapsed();
                            history
                                .introducing_commit(location)
                                .map_err(|_| invalid())?;
                            #[cfg(all(test, feature = "tokio", unix))]
                            {
                                introduction_time +=
                                    finish_trace.elapsed().saturating_sub(introduction_started);
                                entry_count += 1;
                            }
                            #[cfg(all(test, feature = "tokio", unix))]
                            let producers_started = finish_trace.elapsed();
                            for name in attributes {
                                history
                                    .attribute_producer(location, name)
                                    .map_err(|_| invalid())?;
                            }
                            #[cfg(all(test, feature = "tokio", unix))]
                            {
                                producer_time +=
                                    finish_trace.elapsed().saturating_sub(producers_started);
                                attribute_count += attributes.len();
                            }
                        }
                        #[cfg(all(test, feature = "tokio", unix))]
                        finish_trace.mark(&format!(
                            "provenance introduction_time={introduction_time:?} producer_time={producer_time:?} entries={entry_count} attributes={attribute_count}"
                        ));
                    }
                    #[cfg(all(test, feature = "tokio", unix))]
                    finish_trace.mark("entry-introduction-producers-returned");
                    #[cfg(feature = "std")]
                    if RETAIN_COLLECTION {
                        dependency_rows.entry(identity).or_insert(None);
                    }
                    #[cfg(feature = "std")]
                    if let Some(plan) = overlay_plans.get(&identity) {
                        self.verify_overlay_history_plan(
                            tree_evidence.get(&identity).ok_or_else(invalid)?,
                            plan,
                            &tree_evidence,
                            observation,
                        )
                        .await?;
                    }
                    active.remove(&identity);
                    completed.insert(identity);
                }
            }
        }
        #[cfg(all(test, feature = "tokio", unix))]
        trace.mark("dag-original-provenance-returned");
        // Awaited relationship work cannot preserve earlier protected-control
        // checks. Revalidate every reached Original before promoting any view.
        #[cfg(feature = "std")]
        for (view, plan) in &relationship_plans {
            if observation.namespace_only(*view, identity, RETAIN_COLLECTION) {
                continue;
            }
            #[cfg(all(feature = "tokio", unix))]
            if let Some(reads) = node_reads {
                match reads {
                    RetainedReadPurpose::Candidate(reads) => {
                        super::completion::active::check_relationships(
                            reads,
                            plan,
                            self.config().min_chunk_size,
                        )
                        .await?;
                    }
                    RetainedReadPurpose::Direct { reads, .. } => {
                        super::completion::active::check_relationships(
                            reads,
                            plan,
                            self.config().min_chunk_size,
                        )
                        .await?;
                    }
                    RetainedReadPurpose::Overlay { reads, .. } => {
                        super::completion::active::check_relationships(
                            reads,
                            plan,
                            self.config().min_chunk_size,
                        )
                        .await?;
                    }
                    RetainedReadPurpose::Current { reads, .. }
                    | RetainedReadPurpose::Held { reads, .. } => {
                        super::completion::active::check_relationships(
                            reads,
                            plan,
                            self.config().min_chunk_size,
                        )
                        .await?;
                    }
                }
                continue;
            }

            super::completion::active::check_relationships(
                self.store(),
                plan,
                self.config().min_chunk_size,
            )
            .await?;
        }
        #[cfg(all(test, feature = "tokio", unix))]
        trace.mark("relationships-returned");
        #[cfg(feature = "std")]
        if !relationship_plans.is_empty() {
            for view in domains.keys() {
                let original = self.original_commit(view)?;
                self.revalidate_original_context(&original, observation)
                    .await?;
            }
        }
        #[cfg(all(test, feature = "tokio", unix))]
        trace.mark("postawait-original-returned");

        #[cfg(all(feature = "std", feature = "tokio", unix))]
        if let Some(reads) = node_reads {
            if RETAIN_COLLECTION {
                return Err(invalid());
            }
            match reads {
                RetainedReadPurpose::Candidate(reads) => {
                    let selection = observation.candidate.ok_or_else(invalid)?;
                    if selection.view() != identity {
                        return Err(invalid());
                    }
                    // Select actual historical pins before native closing;
                    // preparation supplies no owning completion or permission.
                    self.record_historical_view_inputs(&history, observation, &pending_uses)?;
                    #[cfg(all(test, feature = "tokio", unix))]
                    trace.mark("candidate-history-pending-returned");
                    return Ok(HistoryCompletion::Pending(super::PendingCandidateHistory {
                        history: Box::new(history),
                        selection: selection.clone(),
                        requested: identity,
                        observation,
                        reads,
                        pending_uses,
                    }));
                }
                RetainedReadPurpose::Current { purpose, reads } => {
                    purpose.check(identity, observation)?;
                    self.record_historical_view_inputs(&history, observation, &pending_uses)?;
                    #[cfg(all(test, feature = "tokio", unix))]
                    trace.mark("current-history-pending-returned");
                    return Ok(HistoryCompletion::PendingCurrent(
                        crate::guard::current_history::PendingCurrentHistory {
                            history: Box::new(history),
                            requested: identity,
                            observation,
                            purpose,
                            reads,
                            pending_uses,
                        },
                    ));
                }
                RetainedReadPurpose::Direct { purpose, reads } => {
                    purpose.check(identity, observation)?;
                    self.record_historical_view_inputs(&history, observation, &pending_uses)?;
                    return Ok(HistoryCompletion::PendingDirect(
                        crate::guard::direct_history::PendingDirectHistory {
                            history: Box::new(history),
                            requested: identity,
                            observation,
                            purpose,
                            reads,
                            pending_uses,
                        },
                    ));
                }
                RetainedReadPurpose::Overlay { purpose, reads } => {
                    purpose.check(identity, observation)?;
                    self.record_historical_view_inputs(&history, observation, &pending_uses)?;
                    return Ok(HistoryCompletion::PendingOverlay(
                        crate::guard::overlay_history::PendingOverlayHistory {
                            history: Box::new(history),
                            requested: identity,
                            observation,
                            purpose,
                            reads,
                            pending_uses,
                        },
                    ));
                }
                RetainedReadPurpose::Held { purpose, reads } => {
                    purpose.check(identity, observation)?;
                    self.record_historical_view_inputs(&history, observation, &pending_uses)?;
                    #[cfg(all(test, feature = "tokio", unix))]
                    trace.mark("held-history-pending-returned");
                    return Ok(HistoryCompletion::PendingHeld(
                        crate::guard::held_history::PendingHeldHistory {
                            history: Box::new(history),
                            requested: identity,
                            observation,
                            purpose,
                            reads,
                            pending_uses,
                        },
                    ));
                }
            }
        }

        #[cfg(feature = "std")]
        self.promote_prepared_view_inputs::<RETAIN_COLLECTION, true>(
            identity,
            observation,
            pending_uses,
            &history,
        )?;
        #[cfg(all(test, feature = "tokio", unix))]
        trace.mark("selected-input-consumed-promotion-returned");
        #[cfg(feature = "std")]
        let mut dependencies = BTreeMap::new();
        #[cfg(feature = "std")]
        for (view, witnesses) in entered {
            let disclosure = dependency_rows.remove(&view).ok_or_else(invalid)?;
            let commit = history.commit(&view).ok_or_else(invalid)?;
            let parents = commit
                .commit()
                .parents
                .iter()
                .copied()
                .filter(|parent| {
                    disclosure
                        .as_ref()
                        .is_none_or(|batch| !batch.certified_parent(view, *parent))
                })
                .collect();
            dependencies.insert(
                view,
                CollectionHistoryDependencies {
                    parents,
                    witnesses,
                    disclosure,
                },
            );
        }
        Ok(HistoryCompletion::Complete(
            CompletedCollectionHistory {
                history,
                #[cfg(feature = "std")]
                dependencies,
                #[cfg(feature = "std")]
                contextual_layers: layer_roots
                    .into_iter()
                    .filter(|(commit, root)| {
                        tree_evidence.get(commit).is_some_and(|evidence| {
                            evidence.root == *root
                                && evidence.root_usage(*root)
                                    == terrane_format::tree_format::TreeUse::OverlayLayer
                        })
                    })
                    .collect(),
            },
            std::marker::PhantomData,
        ))
    }

    /// Records actual historical pins without promoting prepared view inputs.
    #[cfg(all(feature = "std", unix))]
    fn record_historical_view_inputs(
        &self,
        history: &VerifiedHistory,
        observation: HistoryObservation<'_>,
        pending_uses: &BTreeMap<Digest, super::completion::PendingViewUse>,
    ) -> Result<(), StoreFailure> {
        if let Some(consumed) = observation.consumed {
            for prepared in pending_uses.values() {
                let view = prepared.context.view;
                let verified = history.commit(&view).ok_or_else(invalid)?;
                consumed.historical_issuer(verified, &self.original_commit(&view)?)?;
            }
        }
        Ok(())
    }

    /// Promotes only prepared inputs whose complete owning checks succeeded.
    ///
    /// # Errors
    /// Refuses changed selected inputs, contradictory consumption or unavailable
    /// synchronized view preparation without constructing completed view uses.
    #[cfg(feature = "std")]
    pub(in crate::guard) fn promote_prepared_view_inputs<
        const RETAIN_COLLECTION: bool,
        const RECORD_HISTORICAL: bool,
    >(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
        pending_uses: BTreeMap<Digest, super::completion::PendingViewUse>,
        history: &VerifiedHistory,
    ) -> Result<(), StoreFailure> {
        for prepared in pending_uses.values() {
            let actual = self.selected_view_inputs(
                prepared.context.view,
                prepared.context.original_root,
                observation,
            )?;
            if actual != prepared.inputs {
                return Err(invalid());
            }
            self.retain_executed_view_inputs(
                prepared.context.view,
                prepared.context.original_root,
                &prepared.inputs,
            )?;
        }
        if let Some(consumed) = observation.consumed {
            #[cfg(unix)]
            if RECORD_HISTORICAL {
                self.record_historical_view_inputs(history, observation, &pending_uses)?;
            }
            #[cfg(not(unix))]
            let _ = history;

            let (namespace, complete): (Vec<_>, Vec<_>) =
                pending_uses.into_values().partition(|prepared| {
                    observation.namespace_only(prepared.context().view, identity, RETAIN_COLLECTION)
                });
            let namespace = namespace
                .into_iter()
                .map(|prepared| super::SourceResolvedViewUse { prepared })
                .collect::<Vec<_>>();
            let complete = complete
                .into_iter()
                .map(|prepared| super::CompletedViewUse { prepared })
                .collect::<Vec<_>>();
            consumed.namespace_views(&namespace)?;
            consumed.complete_views(&complete)?;
        }
        Ok(())
    }

    #[cfg(all(feature = "std", unix))]
    fn disclosure_dependencies(
        &self,
        history: &VerifiedHistory,
        identity: Digest,
        private_domain: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<Digest>, StoreFailure> {
        let roles = self.history_disclosure_roles()?;
        let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
        let defaults = terrane_format::properties::Defaults {
            store: &self.config().store_name,
            private_domain,
            home: self.config().home.region.as_deref().unwrap_or("local"),
        };
        recorded::mixed_dependencies(
            history,
            identity,
            &authorities,
            defaults,
            &self.property_selections(observation)?,
        )
    }

    #[cfg(all(feature = "std", unix))]
    async fn finish_disclosure_history(
        &self,
        history: VerifiedHistory,
        identity: Digest,
        private_domain: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<(VerifiedHistory, provenance::VerifiedDisclosureBatch), StoreFailure> {
        let original = self.recheck_history_original(identity, observation).await?;
        let baseline = original.baseline();
        let authority = identity_name(baseline.authority().id());
        let acl = baseline
            .acl()
            .iter()
            .map(|(subject, verbs)| (subject.as_str(), *verbs))
            .collect::<Vec<_>>();
        let roles = self.history_disclosure_roles()?;
        let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
        let defaults = terrane_format::properties::Defaults {
            store: &self.config().store_name,
            private_domain,
            home: self.config().home.region.as_deref().unwrap_or("local"),
        };
        let (finished, batch) = recorded::mixed_finish(
            &history,
            identity,
            &authorities,
            defaults,
            &self.property_selections(observation)?,
            &authority,
            provenance::OriginalBootstrapPolicy {
                authority: &authority,
                reference: baseline.reference(),
                writer_epoch: baseline.epoch(),
                acl: &acl,
            },
        )?;

        // A boundary's public mapping comes from a genuinely retained source
        // association, not the private source record or its certificate fields.
        for boundary in batch.boundaries() {
            let source = self
                .recheck_history_original(boundary.source().commit, observation)
                .await?;
            let retained_roles = source.historical_disclosure_roles()?.ok_or_else(invalid)?;
            // Original authoring authority is independent of the current
            // physical discloser. Its exact protected public role coordinates
            // were retained by the paired native import producer separately.
            if !retained_roles.iter().any(|role| {
                role.repository == boundary.authority_repository()
                    && role.domain == boundary.authority_domain()
                    && role.public_key == *boundary.authority_key()
                    && boundary.observed_at() >= role.not_before
                    && role
                        .not_after
                        .is_none_or(|end| boundary.observed_at() < end)
            }) {
                return Err(invalid());
            }
            if let Some(consumed) = observation.consumed {
                consumed.disclosure(boundary)?;
            }
        }
        Ok((finished, batch))
    }

    #[cfg(all(feature = "std", unix))]
    /// Returns checked local and retained imported disclosure-role mappings.
    ///
    /// # Errors
    /// Rejects unavailable or inconsistent protected role and import controls.
    pub(crate) fn history_disclosure_roles(
        &self,
    ) -> Result<
        Vec<crate::repository::local_authority::public_trust::DisclosureRoleRecord>,
        StoreFailure,
    > {
        let mut roles = self.configured_disclosure_roles()?;
        for trust in self.retained_public_trust()? {
            for role in trust.disclosure_roles {
                if !roles.contains(&role) {
                    roles.push(role);
                }
            }
        }
        Ok(roles)
    }

    #[cfg(all(feature = "std", unix))]
    async fn recheck_history_original(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<crate::guard::OriginalCommitContext, StoreFailure> {
        let context = self.original_commit(&identity)?;
        let baseline = context.baseline();
        let association = crate::guard::AssociationView {
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
        }
        observation.record_original(&checked)?;
        Ok(checked)
    }

    #[cfg(not(all(feature = "std", unix)))]
    fn disclosure_dependencies(
        &self,
        _history: &VerifiedHistory,
        _identity: Digest,
        _private_domain: &str,
        _observation: HistoryObservation<'_>,
    ) -> Result<Vec<Digest>, StoreFailure> {
        Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported))
    }

    #[cfg(not(all(feature = "std", unix)))]
    async fn finish_disclosure_history(
        &self,
        _history: VerifiedHistory,
        _identity: Digest,
        _private_domain: &str,
        _observation: HistoryObservation<'_>,
    ) -> Result<(VerifiedHistory, provenance::VerifiedDisclosureBatch), StoreFailure> {
        Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported))
    }
}

#[cfg(all(feature = "std", unix))]
fn identity_name(identity: &Digest) -> String {
    identity.iter().map(|byte| format!("{byte:02x}")).collect()
}
