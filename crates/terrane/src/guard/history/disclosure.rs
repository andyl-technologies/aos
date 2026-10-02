//! Completes ordinary and certified history without loading attested private ancestry.
//!
//! Certificate authentication supplies only a private dependency plan. An
//! ancestor-first work stack completes every ordinary dependency and the entire
//! candidate before exposing any boundary, origin or attribute producer.

use std::collections::{BTreeMap, BTreeSet};

use terrane_core::identity::Digest;
use terrane_core::provenance::{self, EntryLocation, VerifiedHistory};

use super::{Guard, HistoryObservation, invalid};
use crate::store::{Clock, Store, StoreFailure};

enum Stage {
    Enter(Digest),
    Finish(Digest),
}

type EntryChecks = Vec<(EntryLocation, Vec<String>)>;

impl<S: Store, C: Clock> Guard<S, C> {
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
        let mut history = VerifiedHistory::new(self.config().min_chunk_size);
        let mut pending = vec![Stage::Enter(identity)];
        let mut active = BTreeSet::new();
        let mut completed = BTreeSet::new();
        let mut domains = BTreeMap::new();
        let mut locations: BTreeMap<Digest, EntryChecks> = BTreeMap::new();
        let mut certified = BTreeSet::new();

        while let Some(stage) = pending.pop() {
            match stage {
                Stage::Enter(identity) => {
                    if completed.contains(&identity) {
                        continue;
                    }
                    if !active.insert(identity) {
                        return Err(invalid());
                    }
                    let verified = self.signed_tree(identity).await?;
                    #[cfg(feature = "std")]
                    if let Some(consumed) = observation.consumed {
                        consumed.issuer(&verified.commit)?;
                        consumed.view(
                            identity,
                            &verified.evidence,
                            self.config().min_chunk_size,
                        )?;
                    }
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
                        .insert_commit(verified.commit)
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
                        history.insert_tree(*root, &nodes).map_err(|_| invalid())?;
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
                    let dependencies = if has_certificates {
                        certified.insert(identity);
                        self.disclosure_dependencies(
                            &history,
                            identity,
                            &verified.evidence.default_domain,
                        )?
                    } else {
                        ordinary_dependencies
                    };
                    domains.insert(identity, verified.evidence.default_domain);
                    locations.insert(identity, entries);
                    pending.push(Stage::Finish(identity));
                    for dependency in dependencies.into_iter().rev() {
                        pending.push(Stage::Enter(dependency));
                    }
                }
                Stage::Finish(identity) => {
                    let domain = domains.get(&identity).ok_or_else(invalid)?;
                    if certified.contains(&identity) {
                        history = self
                            .finish_disclosure_history(history, identity, domain, observation)
                            .await?;
                    } else {
                        self.check_original_scope(&mut history, identity, domain, observation)
                            .await?;
                        for (location, attributes) in
                            locations.get(&identity).ok_or_else(invalid)?
                        {
                            history
                                .introducing_commit(location)
                                .map_err(|_| invalid())?;
                            for name in attributes {
                                history
                                    .attribute_producer(location, name)
                                    .map_err(|_| invalid())?;
                            }
                        }
                    }
                    active.remove(&identity);
                    completed.insert(identity);
                }
            }
        }
        Ok(history)
    }

    #[cfg(all(feature = "std", unix))]
    fn disclosure_dependencies(
        &self,
        history: &VerifiedHistory,
        identity: Digest,
        private_domain: &str,
    ) -> Result<Vec<Digest>, StoreFailure> {
        let roles = self.history_disclosure_roles()?;
        let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
        let defaults = terrane_core::properties::Defaults {
            store: &self.config().store_name,
            private_domain,
            home: self.config().home.region.as_deref().unwrap_or("local"),
        };
        let candidate =
            provenance::DisclosureCandidate::new(history, identity, &authorities, defaults)
                .map_err(|_| invalid())?;
        Ok(candidate.required_commits().to_vec())
    }

    #[cfg(all(feature = "std", unix))]
    async fn finish_disclosure_history(
        &self,
        history: VerifiedHistory,
        identity: Digest,
        private_domain: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<VerifiedHistory, StoreFailure> {
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
        let defaults = terrane_core::properties::Defaults {
            store: &self.config().store_name,
            private_domain,
            home: self.config().home.region.as_deref().unwrap_or("local"),
        };
        let (finished, batch) = provenance::DisclosureCandidate::new_with_bootstrap(
            &history,
            identity,
            &authorities,
            defaults,
            &authority,
            provenance::OriginalBootstrapPolicy {
                authority: &authority,
                reference: baseline.reference(),
                writer_epoch: baseline.epoch(),
                acl: &acl,
            },
        )
        .and_then(|candidate| candidate.finish())
        .map_err(|_| invalid())?;

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
        Ok(finished)
    }

    #[cfg(all(feature = "std", unix))]
    fn history_disclosure_roles(
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
            Some(held) => {
                self.check_original_commit_held(baseline, association, held)
                    .await?
            }
            None => self.check_original_commit(baseline, association).await?,
        };
        if checked != context {
            return Err(invalid());
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
    ) -> Result<VerifiedHistory, StoreFailure> {
        Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported))
    }
}

#[cfg(all(feature = "std", unix))]
fn identity_name(identity: &Digest) -> String {
    identity.iter().map(|byte| format!("{byte:02x}")).collect()
}
