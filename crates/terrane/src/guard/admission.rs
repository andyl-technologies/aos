//! Checks canonical candidate trees and builds signed entry-origin receipts.

use std::collections::{BTreeMap, BTreeSet};

use terrane_core::auth::{self, Request, RequestRoot, Verb};
use terrane_core::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_core::properties::{self, PropertyName, RootLayer, Value};
use terrane_core::provenance::{self, VerifiedCommit};
use terrane_core::refs::{
    CommitContext, EntryOrigin, EntryReceipt, EntrySource, Provenance, RefRecord,
};

use super::policy::AdmissionContext;
use super::{CommitRequest, StagedUpload};
use super::{Guard, TreeEvidence, denied, domain_label};
use crate::store::{Clock, Store, StoreErrorKind, StoreFailure};

/// Retains the exact live source authority selected by canonical fork or join admission.
#[derive(Clone)]
pub(crate) struct SourceAuthorization {
    pub(crate) reference: String,
    pub(crate) verb: Verb,
    pub(crate) paths: Vec<Vec<u8>>,
    pub(crate) record: RefRecord,
}

/// Retains canonical root alternatives for one necessary current Admin decision.
pub(super) struct AdminCheck {
    pub(super) alternatives: Vec<Vec<u8>>,
}

pub(super) struct CandidateValidation {
    pub(super) requirements: Vec<super::attributes::RequirementEvidence>,
    pub(super) admin_checks: Vec<AdminCheck>,
}

/// A signed commit bound to the exact current-policy record it may replace.
pub(crate) struct AdmittedCommit {
    pub(crate) commit: VerifiedCommit,
    pub(super) requirements: Vec<super::attributes::RequirementEvidence>,
    pub(super) admin_checks: Vec<AdminCheck>,
    pub(super) publication_reference: String,
    pub(crate) uploads: Vec<StagedUpload>,
    pub(crate) expected: Option<RefRecord>,
    /// Captures live authority separately from the signed historical first parent.
    pub(crate) observed_current: Option<RefRecord>,
    pub(crate) surface: String,
    pub(crate) source_authorization: Option<SourceAuthorization>,
    pub(crate) token: Vec<u8>,
    pub(crate) principal: String,
    pub(crate) timestamp: u64,
    pub(crate) publication_verb: Verb,
    pub(crate) policy_override: Option<Option<terrane_core::refs::RefPolicy>>,
}

pub(super) struct CandidateRequest<'a> {
    pub(super) uploads: &'a [StagedUpload],
    pub(super) token: &'a [u8],
    pub(super) surface: &'a str,
    pub(super) reference_records: &'a [crate::domain::DomainRecord],
}

impl<'a> From<&'a CommitRequest> for CandidateRequest<'a> {
    fn from(request: &'a CommitRequest) -> Self {
        Self {
            uploads: &request.uploads,
            token: &request.token,
            surface: &request.surface,
            reference_records: &request.reference_records,
        }
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    async fn current_admin(
        &self,
        reference: &str,
        token: &[u8],
        paths: &[Vec<u8>],
        surface: &str,
    ) -> Result<bool, StoreFailure> {
        match self
            .authorize(reference, token, Verb::Admin, paths, surface)
            .await
        {
            Ok(_) => Ok(true),
            Err(failure) if matches!(failure.kind(), StoreErrorKind::Denied { .. }) => Ok(false),
            Err(failure) => Err(failure),
        }
    }

    pub(crate) async fn admit(
        &self,
        reference: &str,
        epoch: u64,
        request: CommitRequest,
    ) -> Result<AdmittedCommit, StoreFailure> {
        self.admit_inner(reference, epoch, request, None, None, None)
            .await
    }

    pub(crate) async fn admit_losing(
        &self,
        reference: &str,
        epoch: u64,
        request: CommitRequest,
        base: RefRecord,
    ) -> Result<AdmittedCommit, StoreFailure> {
        self.admit_inner(reference, epoch, request, None, Some(base), None)
            .await
    }

    pub(crate) async fn admit_fork(
        &self,
        source: &str,
        reference: &str,
        epoch: u64,
        mut request: CommitRequest,
    ) -> Result<AdmittedCommit, StoreFailure> {
        let authorized = self
            .authorize(source, &request.token, Verb::Fork, &[], &request.surface)
            .await?;
        let record = authorized
            .record()
            .ok_or_else(|| denied(source, Verb::Fork))?;
        self.verified_history(record.commit).await?;
        let verified = self.verified_tree(record.commit).await?;
        let paths = verified
            .evidence
            .occurrences(self.config().min_chunk_size)?
            .into_iter()
            .map(|root| root.path)
            .collect::<Vec<_>>();
        for path in &paths {
            self.authorize(
                source,
                &request.token,
                Verb::Fork,
                std::slice::from_ref(path),
                &request.surface,
            )
            .await?;
        }
        if !request.uploads.is_empty() {
            return Err(denied(reference, Verb::Commit));
        }
        request.commit.tree = verified.evidence.root;
        request.commit.parents = vec![verified.commit.identity()];
        let mut admitted = self
            .admit_inner(
                reference,
                epoch,
                request,
                Some((verified.commit.identity(), verified.evidence)),
                None,
                None,
            )
            .await?;
        if admitted.expected.is_some() {
            return Err(denied(reference, Verb::Commit));
        }
        admitted.source_authorization = Some(SourceAuthorization {
            reference: source.to_owned(),
            verb: Verb::Fork,
            paths,
            record: record.clone(),
        });
        Ok(admitted)
    }

    pub(super) async fn admit_inner(
        &self,
        reference: &str,
        epoch: u64,
        mut request: CommitRequest,
        copied: Option<(Digest, TreeEvidence)>,
        base: Option<RefRecord>,
        merged_source: Option<(Digest, TreeEvidence)>,
    ) -> Result<AdmittedCommit, StoreFailure> {
        // A scoped upload receipt does not establish a durable source-origin proof.
        // Publication must consume an authenticated certificate rather than drop it.
        if !request.disclosures.is_empty() {
            return Err(denied(reference, Verb::Commit));
        }

        if request.commit.profile_pair.chunk_profile != self.config().chunk_profile_name
            || self.config().min_chunk_size != self.config().chunk_profile.minimum() as u64
            || request.uploads.iter().any(|upload| matches!(upload,
                StagedUpload::Chunk { profile, .. } if profile.as_ref() != self.config().chunk_profile.as_ref())) {
            return Err(denied(reference, Verb::Commit));
        }
        let authorization = self
            .authorize(
                reference,
                &request.token,
                Verb::Commit,
                &[],
                &request.surface,
            )
            .await?;
        let live_record = authorization.record().cloned();
        let expected = base.or_else(|| live_record.clone());
        if expected
            .as_ref()
            .is_some_and(|record| record.home != self.config().home)
        {
            return Err(denied(reference, Verb::Commit));
        }
        if live_record
            .as_ref()
            .is_some_and(|record| epoch < record.writer_epoch)
        {
            return Err(denied(reference, Verb::Commit));
        }
        let now = self.now(reference, Verb::Commit)?;
        let token = auth::verify(&request.token, self.keys(), now)
            .map_err(|_| denied(reference, Verb::Commit))?;
        let candidate = TreeEvidence::load_tree(
            self.store(),
            request.commit.tree,
            &request.uploads,
            self.config().min_chunk_size,
        )
        .await?;
        let previous_identity = copied
            .as_ref()
            .map(|(identity, _)| *identity)
            .or_else(|| expected.as_ref().map(|record| record.commit));
        let previous = match copied {
            Some((_, evidence)) if expected.is_none() => Some(evidence),
            Some(_) => return Err(denied(reference, Verb::Commit)),
            None => match &expected {
                Some(record) => {
                    self.verified_history(record.commit).await?;
                    Some(self.verified_tree(record.commit).await?.evidence)
                }
                None => None,
            },
        };
        let CandidateValidation {
            requirements,
            admin_checks,
        } = self
            .validate_candidate(
                reference,
                CandidateRequest::from(&request),
                &candidate,
                previous.as_ref(),
            )
            .await?;
        let mut parents = previous_identity.into_iter().collect::<Vec<_>>();
        if let Some((identity, _)) = &merged_source {
            parents.push(*identity);
        }
        if request.commit.parents != parents
            || request.commit.profile_pair.recipe.is_some() != merged_source.is_some()
        {
            return Err(denied(reference, Verb::Commit));
        }
        let tree = candidate.tree(candidate.root, self.config().min_chunk_size)?;
        let root_properties = tree.props().unwrap_or(&[]);
        let effective = properties::resolve(
            &[RootLayer {
                properties: root_properties,
                overrides: &[],
            }],
            self.defaults_for(&candidate),
        )
        .map_err(|_| denied(reference, Verb::Commit))?;
        let root_bindings = self.authoring_roots(&candidate)?;
        let roots = root_bindings
            .iter()
            .map(|(path, domain)| RequestRoot { path, domain })
            .collect::<Vec<_>>();
        let epochs = [(reference, epoch)];
        let context = Request {
            reference: reference.as_bytes(),
            verb: Verb::Commit,
            roots: &roots,
            now,
            surface: &request.surface,
            locality: &self.config().home,
            epochs: &epochs,
        };
        token
            .authorize(&context)
            .map_err(|_| denied(reference, Verb::Commit))?;

        let previous_tree = previous
            .as_ref()
            .map(|previous| previous.tree(previous.root, self.config().min_chunk_size))
            .transpose()?;
        if let (Some(previous_tree), Some(previous)) = (&previous_tree, &previous) {
            let old_effective = properties::resolve(
                &[RootLayer {
                    properties: previous_tree.props().unwrap_or(&[]),
                    overrides: &[],
                }],
                self.defaults_for(previous),
            )
            .map_err(|_| denied(reference, Verb::Commit))?;
            if !effective
                .domain()
                .map_err(|_| denied(reference, Verb::Commit))?
                .permits_reference(
                    old_effective
                        .domain()
                        .map_err(|_| denied(reference, Verb::Commit))?,
                )
            {
                return Err(denied(reference, Verb::Commit));
            }
        }

        let candidate_occurrences = candidate.occurrences(self.config().min_chunk_size)?;
        let previous_occurrences = previous
            .as_ref()
            .map(|previous| previous.occurrences(self.config().min_chunk_size))
            .transpose()?
            .unwrap_or_default();
        let merged_occurrences = merged_source
            .as_ref()
            .map(|(_, evidence)| evidence.occurrences(self.config().min_chunk_size))
            .transpose()?
            .unwrap_or_default();
        let mut receipt_map = BTreeMap::new();
        for occurrence in &candidate_occurrences {
            let tree = candidate.tree(occurrence.root, self.config().min_chunk_size)?;
            let old_occurrence = previous_occurrences
                .iter()
                .find(|old| old.path == occurrence.path);
            let old_tree = match (previous.as_ref(), old_occurrence) {
                (Some(previous), Some(old)) => {
                    Some(previous.tree(old.root, self.config().min_chunk_size)?)
                }
                _ => None,
            };
            let merged_occurrence = merged_occurrences
                .iter()
                .find(|old| old.path == occurrence.path);
            let merged_tree = match (&merged_source, merged_occurrence) {
                (Some((_, evidence)), Some(old)) => {
                    Some(evidence.tree(old.root, self.config().min_chunk_size)?)
                }
                _ => None,
            };
            for item in tree.iter() {
                let prior = old_tree.as_ref().and_then(|tree| tree.get(&item.key));
                let merged_prior = merged_tree.as_ref().and_then(|tree| tree.get(&item.key));
                let mut source = prior
                    .filter(|entry| provenance::same_content(entry, &item.entry))
                    .and(previous_identity)
                    .map(|commit| EntrySource {
                        commit,
                        root: old_occurrence.map_or(occurrence.root, |old| old.root),
                        path: item.key.clone(),
                    });
                if source.is_none()
                    && merged_prior
                        .is_some_and(|entry| provenance::same_content(entry, &item.entry))
                {
                    let (commit, _) = merged_source.as_ref().ok_or_else(super::invalid)?;
                    source = Some(EntrySource {
                        commit: *commit,
                        root: merged_occurrence.ok_or_else(super::invalid)?.root,
                        path: item.key.clone(),
                    });
                }
                if source.is_none() && item.entry.provenance.is_some() {
                    return Err(denied(reference, Verb::Commit));
                }
                let attributes = item
                    .entry
                    .attrs
                    .iter()
                    .map(|attribute| {
                        let preserved = prior.is_some_and(|entry| {
                            entry.attrs.iter().any(|prior| prior == attribute)
                        });
                        let origin = if preserved
                            && prior
                                .is_some_and(|entry| provenance::same_content(entry, &item.entry))
                        {
                            previous_identity
                                .map(|commit| {
                                    EntryOrigin::Source(EntrySource {
                                        commit,
                                        root: old_occurrence
                                            .map_or(occurrence.root, |old| old.root),
                                        path: item.key.clone(),
                                    })
                                })
                                .unwrap_or(EntryOrigin::Current)
                        } else if merged_prior.is_some_and(|entry| {
                            provenance::same_content(entry, &item.entry)
                                && entry.attrs.iter().any(|prior| prior == attribute)
                        }) {
                            match (&merged_source, merged_occurrence) {
                                (Some((commit, _)), Some(old)) => {
                                    EntryOrigin::Source(EntrySource {
                                        commit: *commit,
                                        root: old.root,
                                        path: item.key.clone(),
                                    })
                                }
                                _ => EntryOrigin::Current,
                            }
                        } else {
                            EntryOrigin::Current
                        };
                        (attribute.name.to_owned(), origin)
                    })
                    .collect();
                let receipt = EntryReceipt {
                    root: occurrence.root,
                    path: item.key.clone(),
                    origin: source.map_or(EntryOrigin::Current, EntryOrigin::Source),
                    attributes: Some(attributes),
                    reintroduced_from: None,
                    disclosure_proof: None,
                };
                let key = (occurrence.root, item.key.clone());
                if receipt_map.get(&key).is_some_and(|prior| prior != &receipt) {
                    return Err(denied(reference, Verb::Commit));
                }
                receipt_map.insert(key, receipt);
            }
        }
        let receipts = receipt_map.into_values().collect();

        // Snapshot requirements using canonical values, so later changes do not
        // rewrite the admission rules under which this immutable commit passed.
        let mut required = Vec::new();
        let names = [
            PropertyName::Index,
            PropertyName::Hashes,
            PropertyName::Classify,
            PropertyName::StrictAttrs,
        ];
        terrane_core::cbor::write_map(&mut required, names.len());
        for name in names {
            terrane_core::cbor::write_text(&mut required, name.as_str());
            match effective.get(name) {
                Some(Value::Names(values)) => {
                    terrane_core::cbor::write_array(&mut required, values.len());
                    for value in values {
                        terrane_core::cbor::write_text(&mut required, value);
                    }
                }
                Some(Value::Boolean(value)) => required.push(if *value { 0xf5 } else { 0xf4 }),
                _ => return Err(denied(reference, Verb::Commit)),
            }
        }
        request.commit.profile_pair.required_properties = Some(required);
        request.commit.profile_pair.entry_receipts = Some(receipts);
        request.commit.profile_pair.conflicted =
            Some(candidate.roots.iter().try_fold(false, |conflicted, root| {
                Ok::<_, StoreFailure>(
                    conflicted
                        || candidate
                            .tree(*root, self.config().min_chunk_size)?
                            .has_conflicts(),
                )
            })?);
        request.commit.timestamp = now;
        let authority = token.authority();
        request.commit.provenance = Provenance {
            issuer: authority.issuer.clone(),
            token_id: authority.token_id,
            subject: authority.subject.clone(),
            kind: authority.kind,
            workload_identity: authority.workload.clone(),
            process: request.commit.provenance.process,
            observed_at: now,
            writer_epoch: epoch,
            source: request.commit.provenance.source,
            embedded_token: Some(request.token.clone()),
        };
        request.commit.profile_pair.commit_context = Some(
            CommitContext::from_request(&context).map_err(|_| denied(reference, Verb::Commit))?,
        );
        let commit = provenance::sign_authored(
            request.commit,
            &request.terminal_secret,
            self.keys(),
            &context,
            epoch,
        )
        .map_err(|_| denied(reference, Verb::Commit))?;
        Ok(AdmittedCommit {
            commit,
            requirements,
            admin_checks,
            publication_reference: reference.to_owned(),
            uploads: request.uploads,
            expected,
            observed_current: live_record,
            surface: request.surface,
            source_authorization: None,
            token: request.token,
            principal: token.authority().subject.clone(),
            timestamp: now,
            publication_verb: Verb::Commit,
            policy_override: None,
        })
    }

    pub(super) async fn validate_candidate(
        &self,
        reference: &str,
        request: CandidateRequest<'_>,
        candidate: &TreeEvidence,
        previous: Option<&TreeEvidence>,
    ) -> Result<CandidateValidation, StoreFailure> {
        let requirements = self.requirement_evidence(&request).await?;
        let mut admin_checks = Vec::new();
        let derived = requirements
            .iter()
            .map(|evidence| properties::DerivedAttribute {
                object: *evidence.attribute.object(),
                attribute: terrane_core::tree_format::Attribute {
                    name: evidence.attribute.name().as_str(),
                    value: evidence.attribute.value(),
                },
            })
            .collect::<Vec<_>>();
        let minimum = self.config().min_chunk_size;
        let occurrences = candidate.occurrences(minimum)?;
        let old_occurrences = previous
            .map(|evidence| evidence.occurrences(minimum))
            .transpose()?
            .unwrap_or_default();
        let mut staged = BTreeSet::<Digest>::new();
        let mut offered_bytes = 0u64;
        for upload in request.uploads {
            let (identity, bytes) = match upload {
                StagedUpload::Meta { kind, bytes } => {
                    if *kind == IdentityKind::Commit {
                        return Err(denied(reference, Verb::Commit));
                    }
                    (
                        TERRANE_V1
                            .calculate(*kind, bytes)
                            .map_err(|_| denied(reference, Verb::Commit))?,
                        bytes.len(),
                    )
                }
                StagedUpload::Chunk {
                    identity, encoded, ..
                } => (identity.clone(), encoded.len()),
            };
            staged.insert(
                identity
                    .terrane_v1_digest()
                    .map_err(|_| denied(reference, Verb::Commit))?,
            );
            offered_bytes = offered_bytes
                .checked_add(u64::try_from(bytes).map_err(|_| denied(reference, Verb::Commit))?)
                .ok_or_else(|| denied(reference, Verb::Commit))?;
        }

        for occurrence in &occurrences {
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let effective = properties::resolve(&layers, self.defaults_for(candidate))
                .map_err(|_| denied(reference, Verb::Commit))?;
            if domain_label(&effective).map_err(|_| denied(reference, Verb::Commit))?
                != self.config().storage_domain
                || effective.get(PropertyName::Store)
                    != Some(&Value::Text(&self.config().store_name))
            {
                return Err(denied(reference, Verb::Commit));
            }
            let old_occurrence = old_occurrences
                .iter()
                .find(|old| old.path == occurrence.path);
            let old_layers = old_occurrence.map(|old| {
                old.layers
                    .iter()
                    .map(|(properties, overrides)| RootLayer {
                        properties,
                        overrides,
                    })
                    .collect::<Vec<_>>()
            });
            let old_effective = old_layers
                .as_ref()
                .zip(previous)
                .map(|(layers, previous)| properties::resolve(layers, self.defaults_for(previous)))
                .transpose()
                .map_err(|_| denied(reference, Verb::Commit))?;
            let changed_domain = old_effective.as_ref().is_some_and(|old| {
                old.get(PropertyName::Domain) != effective.get(PropertyName::Domain)
            });
            if old_occurrence.is_some_and(|old| old.root == occurrence.root)
                && old_effective.as_ref() == Some(&effective)
            {
                // An unchanged independently governed graft is not a mutation
                // of that root. Fold exclusion can preserve it without granting
                // the folding principal authority to modify its descendants.
                continue;
            }
            if let Some(old) = &old_effective
                && !effective
                    .domain()
                    .map_err(|_| denied(reference, Verb::Commit))?
                    .permits_reference(old.domain().map_err(|_| denied(reference, Verb::Commit))?)
            {
                return Err(denied(reference, Verb::Commit));
            }
            let authorized = self
                .authorize(
                    reference,
                    request.token,
                    Verb::Commit,
                    std::slice::from_ref(&occurrence.path),
                    request.surface,
                )
                .await?;
            let mut administrator = self
                .current_admin(
                    reference,
                    request.token,
                    std::slice::from_ref(&occurrence.path),
                    request.surface,
                )
                .await?;
            let mut admin_paths = vec![occurrence.path.clone()];
            for ancestor in &old_occurrences {
                if ancestor.path != occurrence.path
                    && super::scope::contains_root(&ancestor.path, &occurrence.path)
                {
                    admin_paths.push(ancestor.path.clone());
                }
            }
            if !administrator {
                // ACL changes may be authorized by an actual ancestor root
                // (AUTH-28). Syntactic entry prefixes do not create authority.
                for ancestor in &old_occurrences {
                    if ancestor.path == occurrence.path
                        || !super::scope::contains_root(&ancestor.path, &occurrence.path)
                    {
                        continue;
                    }
                    if self
                        .current_admin(
                            reference,
                            request.token,
                            std::slice::from_ref(&ancestor.path),
                            request.surface,
                        )
                        .await?
                    {
                        administrator = true;
                        break;
                    }
                }
            }
            let tree = candidate.tree(occurrence.root, minimum)?;
            let old_tree = match (previous, old_occurrence) {
                (Some(previous), Some(old)) => Some(previous.tree(old.root, minimum)?),
                _ => None,
            };
            let changed = tree
                .iter()
                .filter(|item| {
                    changed_domain
                        || old_tree.as_ref().and_then(|old| old.get(&item.key)) != Some(&item.entry)
                })
                .map(|item| (&item.entry, &effective))
                .collect::<Vec<_>>();
            // Bootstrap policy governs the fresh view root. Descendant grafts
            // use their independently resolved ancestor policy below.
            let mut admin_required = false;
            if old_effective.is_none() && occurrence.path == b"/" {
                let Some(Value::Grants(grants)) = effective.get(PropertyName::Acl) else {
                    return Err(denied(reference, Verb::Commit));
                };
                let widened = grants.iter().any(|(principal, mask)| {
                    let initial = self
                        .config()
                        .initial_acl
                        .iter()
                        .filter(|(name, _)| name == principal)
                        .fold(0u8, |mask, (_, grant)| mask | grant);
                    let authority_bits = |mask| if mask & 16 != 0 { 20 } else { mask & 4 };
                    authority_bits(*mask) & !authority_bits(initial) != 0
                });
                if widened && !administrator {
                    return Err(denied(reference, Verb::Admin));
                }
                admin_required |= widened;
            }
            let acl_changed = old_effective
                .as_ref()
                .is_some_and(|old| old.get(PropertyName::Acl) != effective.get(PropertyName::Acl));
            if acl_changed && !administrator {
                return Err(denied(reference, Verb::Admin));
            }
            admin_required |= acl_changed;
            if let Some(Value::Quota { principal, root }) = old_effective
                .as_ref()
                .unwrap_or(&effective)
                .get(PropertyName::Quota)
            {
                let root_bytes = tree
                    .iter()
                    .try_fold(0u64, |bytes, item| match &item.entry.kind {
                        terrane_core::tree_format::EntryKind::File { size, .. } => {
                            bytes.checked_add(*size)
                        }
                        _ => Some(bytes),
                    })
                    .ok_or_else(|| denied(reference, Verb::Commit))?;
                if offered_bytes > *principal || root_bytes > *root {
                    return Err(crate::store::StoreFailure::new(
                        crate::store::StoreErrorKind::Capacity,
                    ));
                }
            }
            let mut grafts = Vec::new();
            for target in &occurrences {
                let target_layers = target
                    .layers
                    .iter()
                    .map(|(properties, overrides)| RootLayer {
                        properties,
                        overrides,
                    })
                    .collect::<Vec<_>>();
                let policy = properties::resolve(&target_layers, self.defaults_for(candidate))
                    .map_err(|_| denied(reference, Verb::Commit))?;
                grafts.push((
                    target.root,
                    target.layers.last().map(|(_, overrides)| overrides.clone()),
                    policy,
                ));
            }
            let mut context = AdmissionContext {
                records: request.reference_records,
                staged: &staged,
                storage_domain: &self.config().storage_domain,
                grafts,
                administrator,
            };
            properties::validate_commit_with_context(&changed, &derived, &mut context)
                .map_err(|_| denied(reference, Verb::Commit))?;
            if administrator {
                // Retain Admin only when this admission actually depended on
                // it. Ordinary content edits must remain Commit-only.
                context.administrator = false;
                admin_required |=
                    properties::validate_commit_with_context(&changed, &derived, &mut context)
                        .is_err();
            }
            if admin_required {
                admin_checks.push(AdminCheck {
                    alternatives: admin_paths,
                });
            }
            if changed_domain
                && request
                    .reference_records
                    .iter()
                    .any(|record| record.domain() != self.config().storage_domain)
            {
                return Err(denied(reference, Verb::Commit));
            }
            let _ = authorized;
        }
        Ok(CandidateValidation {
            requirements,
            admin_checks,
        })
    }
}
