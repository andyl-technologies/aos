//! Admits existing immutable commits under current publication policy.

use std::collections::BTreeSet;

use terrane_format::auth::Verb;
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::tree_format::{ContentRef, EntryKind};

use super::admission::{
    CandidateInterpretation, CandidatePrevious, CandidateRequest, CandidateValidation,
};
use super::{AdmittedCommit, Guard, TreeEvidence, denied, invalid};
use crate::domain::DomainRecord;
use crate::store::{Clock, Store, StoreFailure};

impl<S: Store, C: Clock> Guard<S, C> {
    /// Admits a verified ancestor as the destination under current root policy.
    ///
    /// # Errors
    /// Rejects non-ancestors, current authority or policy failures and preserves
    /// complete history, Original, attribute-producer and storage failures.
    pub(crate) async fn admit_rollback(
        &self,
        reference: &str,
        target: Digest,
        token: &[u8],
        surface: &str,
    ) -> Result<AdmittedCommit, StoreFailure> {
        terrane_format::refs::RefName::parse(reference)
            .map_err(|_| denied(reference, Verb::Commit))?;
        let now = self.now(reference, Verb::Commit)?;
        let authenticated = terrane_format::auth::verify(token, self.keys(), now)
            .map_err(|_| denied(reference, Verb::Commit))?;
        let expected = self
            .store()
            .ref_get(reference)
            .await?
            .ok_or_else(|| denied(reference, Verb::Commit))?;
        if expected.home != self.config().home {
            return Err(denied(reference, Verb::Commit));
        }
        let history = self.verified_history(expected.commit).await?;
        let mut pending = history
            .commit(&expected.commit)
            .ok_or_else(invalid)?
            .commit()
            .parents
            .clone();
        let mut visited = BTreeSet::new();
        let mut ancestor = false;
        while let Some(identity) = pending.pop() {
            if !visited.insert(identity) {
                continue;
            }
            if identity == target {
                ancestor = true;
                break;
            }
            let commit = history.commit(&identity).ok_or_else(invalid)?;
            pending.extend(commit.commit().parents.iter().copied());
        }
        if !ancestor {
            return Err(denied(reference, Verb::Commit));
        }

        let previous = self.verified_tree(expected.commit).await?;
        let selected = self.verified_tree(target).await?;
        let records = self.existing_records(&selected.evidence).await?;
        let request = CandidateRequest {
            commit: selected.commit.commit(),
            uploads: &[],
            token,
            surface,
            reference_records: &records,
        };
        let previous_interpretation = self.select_view(
            expected.commit,
            previous.evidence.root,
            super::HistoryObservation::default(),
        )?;
        let admission_interpretation = self.select_view(
            selected.commit.identity(),
            selected.evidence.root,
            super::HistoryObservation::default(),
        )?;
        let admission_profile = super::history::completion::profile_inputs(
            self,
            &selected.commit,
            &admission_interpretation,
        )?;
        let CandidateValidation {
            requirements,
            admin_checks,
            root_claims,
        } = self
            .validate_candidate(
                reference,
                request,
                &selected.evidence,
                CandidateInterpretation::Existing {
                    selected: &admission_interpretation,
                    profile: &admission_profile,
                },
                Some(CandidatePrevious {
                    evidence: &previous.evidence,
                    interpretation: &previous_interpretation,
                    commit: Some(&previous.commit),
                }),
            )
            .await?;
        let timestamp = self.now(reference, Verb::Commit)?;
        Ok(AdmittedCommit {
            tree_usage: terrane_format::tree_format::TreeUse::Ordinary,
            overlay_sources: Vec::new(),
            #[cfg(unix)]
            cold_fork: None,
            completion_inputs: self.completion_inputs_for(
                admission_interpretation.selection(),
                admission_profile.attribute_revision,
            )?,
            existing_owner_references: None,
            index_work: super::admission::IndexPublicationWork::default(),
            commit: selected.commit,
            #[cfg(feature = "std")]
            admission_interpretation,
            #[cfg(feature = "std")]
            admission_profile,
            requirements,
            admin_checks,
            publication_reference: reference.to_owned(),
            publication_paths: root_claims
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            uploads: Vec::new(),
            observed_current: Some(expected.clone()),
            expected: Some(expected),
            surface: surface.to_owned(),
            source_authorization: None,
            token: token.to_vec(),
            principal: authenticated.authority().subject.clone(),
            timestamp,
            publication_verb: Verb::Commit,
            policy_override: None,
        })
    }

    /// Admits a ref-policy replacement after current Admin checks on every root.
    ///
    /// # Errors
    /// Rejects denied Admin, missing current heads or invalid policy combinations
    /// and preserves complete history, selected-profile and storage failures.
    pub(crate) async fn admit_policy(
        &self,
        reference: &str,
        mut policy: Option<terrane_format::refs::RefPolicy>,
        token: &[u8],
        surface: &str,
    ) -> Result<AdmittedCommit, StoreFailure> {
        let authorization = self
            .authorize(reference, token, Verb::Admin, &[], surface)
            .await?;
        let expected = authorization
            .record()
            .cloned()
            .ok_or_else(|| denied(reference, Verb::Admin))?;
        self.verified_history(expected.commit).await?;
        let selected = self.verified_tree(expected.commit).await?;
        for occurrence in selected
            .evidence
            .occurrences(self.config().min_chunk_size)?
        {
            self.authorize(reference, token, Verb::Admin, &[occurrence.path], surface)
                .await?;
        }
        if let Some(policy) = &mut policy {
            if policy.snapshot.is_some()
                || (policy.multi_writer == Some(true)
                    && policy.merge_policies.as_ref().is_none_or(Vec::is_empty))
            {
                return Err(invalid());
            }
            policy.conflicted = selected.commit.commit().profile_pair.conflicted;
        }
        let admission_interpretation = self.select_view(
            selected.commit.identity(),
            selected.evidence.root,
            super::HistoryObservation::default(),
        )?;
        let admission_profile = super::history::completion::profile_inputs(
            self,
            &selected.commit,
            &admission_interpretation,
        )?;
        let publication_paths = selected
            .evidence
            .occurrences(self.config().min_chunk_size)?
            .into_iter()
            .map(|root| root.path)
            .collect();
        Ok(AdmittedCommit {
            tree_usage: terrane_format::tree_format::TreeUse::Ordinary,
            overlay_sources: Vec::new(),
            #[cfg(unix)]
            cold_fork: None,
            completion_inputs: self.completion_inputs_for(
                admission_interpretation.selection(),
                admission_profile.attribute_revision,
            )?,
            existing_owner_references: None,
            index_work: super::admission::IndexPublicationWork::default(),
            commit: selected.commit,
            #[cfg(feature = "std")]
            admission_interpretation,
            #[cfg(feature = "std")]
            admission_profile,
            requirements: Vec::new(),
            admin_checks: Vec::new(),
            publication_reference: reference.to_owned(),
            publication_paths,
            uploads: Vec::new(),
            observed_current: Some(expected.clone()),
            expected: Some(expected),
            surface: surface.to_owned(),
            source_authorization: None,
            token: token.to_vec(),
            principal: authorization.subject().to_owned(),
            timestamp: self.now(reference, Verb::Admin)?,
            publication_verb: Verb::Admin,
            policy_override: Some(policy),
        })
    }

    /// Confirms namespace membership through actual pinned backend reads.
    ///
    /// # Errors
    /// Preserves canonical tree, identity and pinned backend read failures.
    pub(super) async fn existing_records(
        &self,
        evidence: &TreeEvidence,
    ) -> Result<Vec<DomainRecord>, StoreFailure> {
        let mut identities = Vec::new();
        for root in &evidence.roots {
            let tree = evidence.tree(*root, self.config().min_chunk_size)?;
            identities.push(
                TERRANE_V1
                    .from_digest(IdentityKind::Node, root)
                    .map_err(|_| invalid())?,
            );
            let mut pending = tree.iter().map(|item| &item.entry).collect::<Vec<_>>();
            while let Some(entry) = pending.pop() {
                match &entry.kind {
                    EntryKind::File {
                        content: ContentRef::Inline(digest),
                        ..
                    } => identities.push(
                        TERRANE_V1
                            .from_digest(IdentityKind::Chunk, digest)
                            .map_err(|_| invalid())?,
                    ),
                    EntryKind::File {
                        content: ContentRef::Manifest(digest),
                        ..
                    } => identities.push(
                        TERRANE_V1
                            .from_digest(IdentityKind::Manifest, digest)
                            .map_err(|_| invalid())?,
                    ),
                    EntryKind::Conflict { candidates, base } => {
                        pending.extend(candidates.iter());
                        if let Some(Some(base)) = base {
                            pending.push(base.as_ref());
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut records = Vec::new();
        let mut verified = Vec::new();
        while let Some(identity) = identities.pop() {
            if verified.contains(&identity) {
                continue;
            }
            let bytes = self.store().get(&identity, None).await?;
            if identity.kind() == IdentityKind::Manifest {
                let manifest = terrane_format::manifest::Manifest::decode_verified(
                    &bytes,
                    &self.config().chunk_profile,
                    &identity,
                )
                .map_err(|_| invalid())?;
                for chunk in manifest.chunks {
                    identities.push(
                        TERRANE_V1
                            .from_digest(IdentityKind::Chunk, &chunk.digest)
                            .map_err(|_| invalid())?,
                    );
                }
            } else if identity.kind() == IdentityKind::Chunk {
                let envelope =
                    terrane_format::codec::parse_envelope(&bytes).map_err(|_| invalid())?;
                if let terrane_format::codec::Codec::ZstdDictionary(dictionary) = envelope.codec {
                    identities.push(
                        TERRANE_V1
                            .from_digest(IdentityKind::Chunk, &dictionary)
                            .map_err(|_| invalid())?,
                    );
                }
            }
            verified.push(identity.clone());
            records.push(DomainRecord::admitted(
                identity,
                self.config().storage_domain.clone(),
            )?);
        }
        Ok(records)
    }
}
