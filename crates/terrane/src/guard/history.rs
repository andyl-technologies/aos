//! Authenticates stored commits against their signed original canonical root scope.

use terrane_core::auth::RequestRoot;
use terrane_core::identity::Digest;
use terrane_core::provenance::{self, VerifiedCommit, VerifiedHistory};

mod disclosure;

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

    /// Loads and records the actual candidate only when a held trace is active.
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
            consumed.view(admitted.commit.identity(), &evidence, minimum)?;
        }
        Ok(())
    }

    /// Validates recorded ordinary inputs before the final publication effect.
    ///
    /// # Errors
    /// Rejects inconsistent canonical evidence or poisoned trace synchronization.
    #[cfg(feature = "std")]
    pub(crate) fn finish(self) -> Result<(), StoreFailure> {
        if let Some(consumed) = self.consumed {
            consumed.finish()?;
        }
        Ok(())
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
        let has_disclosures = commit
            .profile_pair
            .entry_receipts
            .iter()
            .flatten()
            .any(|receipt| receipt.disclosure_proof.is_some());
        // A certified candidate is authenticated against its signed claims only.
        // Complete candidate validation checks actual root scope before exposing
        // history; it alone determines whether any private parent is audit-only.
        let mut witnessed = self.authoring_roots(&evidence)?;
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
            witnessed.extend(self.authoring_roots(&previous)?);
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
        #[cfg(all(feature = "std", unix))]
        let historical_keys = self.original_commit(&identity)?.historical_keys()?;
        #[cfg(all(feature = "std", unix))]
        let keys = historical_keys.as_deref().unwrap_or(self.keys());
        #[cfg(not(all(feature = "std", unix)))]
        let keys = self.keys();
        let commit =
            provenance::verify_history(commit, keys, &roots, &epochs).map_err(|_| invalid())?;
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
        self.complete_history_observed(identity, observation).await
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
