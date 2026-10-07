//! Authenticates stored commits against their signed original canonical root scope.

#[cfg(feature = "std")]
pub(super) mod completion;

use std::collections::{BTreeMap, BTreeSet};

use terrane_core::auth::RequestRoot;
use terrane_core::identity::Digest;
use terrane_core::provenance::{self, EntryLocation, VerifiedCommit, VerifiedHistory};

use super::{Guard, TreeEvidence, invalid};
use crate::store::{Clock, Store, StoreErrorKind, StoreFailure};

/// Borrows synchronization evidence without converting it into authorization.
#[derive(Clone, Copy, Default)]
pub(crate) struct HistoryObservation<'a> {
    #[cfg(feature = "std")]
    held: Option<&'a crate::bucket::held::HeldIdentity<'a>>,
    #[cfg(feature = "std")]
    consumed: Option<&'a super::consumed::ConsumedResolver>,
    lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> HistoryObservation<'a> {
    #[cfg(feature = "std")]
    pub(crate) fn identity(self) -> Option<&'a crate::bucket::held::HeldIdentity<'a>> {
        self.held
    }

    #[cfg(feature = "std")]
    /// Borrows a backend identity whose exclusion remains live for the observation.
    pub(crate) fn held(identity: &'a crate::bucket::held::HeldIdentity<'a>) -> Self {
        Self {
            held: Some(identity),
            consumed: None,
            lifetime: std::marker::PhantomData,
        }
    }

    /// Borrows the operation-local resolver without accepting dependency claims.
    #[cfg(feature = "std")]
    pub(crate) fn tracked(mut self, consumed: &'a super::consumed::ConsumedResolver) -> Self {
        self.consumed = Some(consumed);
        self
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
    pub(crate) async fn record_candidate<S: crate::store::ContentStore>(
        self,
        store: &S,
        admitted: &super::AdmittedCommit,
        minimum: u64,
    ) -> Result<(), StoreFailure> {
        if let Some(consumed) = self.consumed {
            let evidence = TreeEvidence::load_tree(
                store,
                admitted.commit.commit().tree,
                &admitted.uploads,
                minimum,
            )
            .await?;
            consumed.issuer(&admitted.commit)?;
            let pending = completion::PendingViewUse::prepare(
                &admitted.completion_inputs,
                &admitted.commit,
                &evidence,
            )?;
            consumed.pending_view(&pending)?;
        }
        Ok(())
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

pub(crate) struct VerifiedTree {
    pub(crate) commit: VerifiedCommit,
    pub(crate) evidence: TreeEvidence,
}

impl<S: Store, C: Clock> Guard<S, C> {
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
        self.verified_tree_history_observed(identity, observation)
            .await
            .map(|(verified, _)| verified)
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
        let verified = self.signed_tree(identity).await?;
        let history = self
            .verified_history_observed(identity, observation)
            .await?;
        Ok((verified, history))
    }

    // This private value authenticates a signature only. Canonical original
    // scope and protected association must be checked before any caller uses
    // the record as policy or origin authority.
    async fn signed_tree(&self, identity: Digest) -> Result<VerifiedTree, StoreFailure> {
        let evidence =
            TreeEvidence::load_commit(self.store(), identity, self.config().min_chunk_size).await?;
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
        // Complete disclosure validation owns audit-edge cuts. Refuse this
        // ordinary loader before it can follow a private certified parent.
        if commit
            .profile_pair
            .entry_receipts
            .iter()
            .flatten()
            .any(|receipt| receipt.disclosure_proof.is_some())
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let mut witnessed = self.authoring_roots(&evidence)?;
        let missing_candidate_claim = context.roots().iter().any(|claim| {
            !witnessed
                .iter()
                .any(|(path, domain)| path.as_slice() == claim.path() && domain == claim.domain())
        });
        if missing_candidate_claim {
            let parent = commit.parents.first().ok_or_else(invalid)?;
            let previous =
                TreeEvidence::load_commit(self.store(), *parent, self.config().min_chunk_size)
                    .await?;
            witnessed.extend(self.authoring_roots(&previous)?);
        }
        if context.roots().iter().any(|claim| {
            !witnessed
                .iter()
                .any(|(path, domain)| path.as_slice() == claim.path() && domain == claim.domain())
        }) {
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
        let commit = provenance::verify_history(commit, self.keys(), &roots, &epochs)
            .map_err(|_| invalid())?;
        if commit.identity() != identity {
            return Err(invalid());
        }
        Ok(VerifiedTree { commit, evidence })
    }

    /// Loads parents and explicit source receipts before checking every entry
    /// introduction and independent attribute producer against complete trees.
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
        let mut history = VerifiedHistory::new(self.config().min_chunk_size);
        let mut pending = vec![identity];
        let mut visited = BTreeSet::new();
        let mut locations = Vec::new();
        let mut domains = BTreeMap::new();
        #[cfg(feature = "std")]
        let mut prepared_views = BTreeMap::new();
        while let Some(identity) = pending.pop() {
            if !visited.insert(identity) {
                continue;
            }
            let verified = self.signed_tree(identity).await?;
            #[cfg(feature = "std")]
            if let Some(consumed) = observation.consumed {
                consumed.issuer(&verified.commit)?;
                let prepared = completion::PendingViewUse::prepare(
                    &self.completion_inputs()?,
                    &verified.commit,
                    &verified.evidence,
                )?;
                consumed.pending_view(&prepared)?;
                prepared_views.insert(identity, prepared);
            }
            domains.insert(identity, verified.evidence.default_domain.clone());
            pending.extend(verified.commit.commit().parents.iter().copied());
            pending.extend(provenance::source_commit_references(&verified.commit));
            history
                .insert_commit(verified.commit)
                .map_err(|_| invalid())?;

            // Core Trees contain local Rc sharing. Keep this CPU-only witness
            // phase inside the iteration, before the next asynchronous fetch.
            for root in &verified.evidence.roots {
                let tree = verified
                    .evidence
                    .tree(*root, self.config().min_chunk_size)?;
                let nodes = tree
                    .nodes()
                    .map(|node| (node.identity(), node.encoded().to_vec()))
                    .collect::<Vec<_>>();
                history.insert_tree(*root, &nodes).map_err(|_| invalid())?;
                for entry in tree.iter() {
                    locations.push((
                        EntryLocation {
                            commit: identity,
                            root: *root,
                            path: entry.key.clone(),
                        },
                        entry
                            .entry
                            .attrs
                            .iter()
                            .map(|attribute| attribute.name.to_owned())
                            .collect::<Vec<_>>(),
                    ));
                }
            }
        }
        // Canonical context verification requires the actual first parent to
        // have checked scope first. No caller-supplied ordering or root label
        // can mint that history authority.
        let mut remaining = visited;
        while !remaining.is_empty() {
            let ready = remaining
                .iter()
                .filter(|identity| {
                    history.commit(identity).is_some_and(|commit| {
                        commit
                            .commit()
                            .parents
                            .iter()
                            .all(|parent| !remaining.contains(parent))
                    })
                })
                .copied()
                .collect::<Vec<_>>();
            if ready.is_empty() {
                return Err(invalid());
            }
            for identity in ready {
                self.check_original_scope(
                    &mut history,
                    identity,
                    domains.get(&identity).ok_or_else(invalid)?,
                    observation,
                )
                .await?;
                remaining.remove(&identity);
            }
        }

        for (location, attributes) in locations {
            history
                .introducing_commit(&location)
                .map_err(|_| invalid())?;
            for name in attributes {
                history
                    .attribute_producer(&location, &name)
                    .map_err(|_| invalid())?;
            }
        }
        // No prepared view becomes completed until the entire invocation has
        // passed Original scope, entry-origin and attribute-producer verification.
        #[cfg(feature = "std")]
        if let Some(consumed) = observation.consumed {
            let completed = prepared_views
                .into_values()
                .map(|prepared| CompletedViewUse { prepared })
                .collect::<Vec<_>>();
            consumed.complete_views(&completed)?;
        }
        Ok(history)
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
            Some(held) => {
                self.check_original_commit_held(baseline, association, held)
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
        let defaults = terrane_core::properties::Defaults {
            store: &self.config().store_name,
            private_domain,
            home: self.config().home.region.as_deref().unwrap_or("local"),
        };
        provenance::verify_root_context_with_bootstrap(
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
        )
        .map_err(|_| invalid())?;
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
