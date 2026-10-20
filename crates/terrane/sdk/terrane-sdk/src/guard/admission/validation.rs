//! Validates canonical candidate changes against current authority and root policy.
//!
//! RootChangePlan selects affected units from exact candidate and prior witnesses.
//! Validation preserves independent property interpretation, retained graft checks
//! and current Commit/Admin decisions before admission effects or signing.

use std::collections::BTreeSet;

use terrane_format::auth::Verb;
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::properties::{self, PropertyName, RootLayer, Value};

use super::{
    AdminCheck, CandidateInterpretation, CandidatePrevious, CandidateRequest, CandidateValidation,
    index_inline,
};
use crate::guard::policy::AdmissionContext;
use crate::guard::{Guard, StagedUpload, TreeEvidence, denied, domain_label};
use crate::store::{Clock, Store, StoreFailure};

impl<S: Store, C: Clock> Guard<S, C> {
    /// Checks candidate roots against current authority and admission policy.
    ///
    /// # Errors
    /// Returns current-policy, bootstrap Admin, tree, attribute, domain, quota
    /// or storage failures before immutable publication may begin.
    pub(in crate::guard) async fn validate_candidate(
        &self,
        reference: &str,
        request: CandidateRequest<'_>,
        candidate: &TreeEvidence,
        interpretation: CandidateInterpretation<'_>,
        previous: Option<CandidatePrevious<'_>>,
    ) -> Result<CandidateValidation, StoreFailure> {
        self.validate_candidate_observed(
            reference,
            request,
            candidate,
            interpretation,
            previous,
            crate::guard::HistoryObservation::default().requested_target(),
        )
        .await
    }

    /// Validates candidate policy and producer evidence under the borrowed observation.
    ///
    /// # Errors
    /// Rejects unavailable required values, invalid provenance or policy changes
    /// and current administrative denial; preserves actual producer/store failures.
    pub(in crate::guard) async fn validate_candidate_observed(
        &self,
        reference: &str,
        request: CandidateRequest<'_>,
        candidate: &TreeEvidence,
        interpretation: CandidateInterpretation<'_>,
        previous: Option<CandidatePrevious<'_>>,
        observation: crate::guard::HistoryObservation<'_>,
    ) -> Result<CandidateValidation, StoreFailure> {
        // A copied source is a content baseline, not the prior authority of
        // a new destination view. Bootstrap checks follow its actual head.
        let initial_view = self.store().ref_get(reference).await?.is_none();

        // Keep one exact candidate interpretation through resolution and raw
        // graft validation without copying preservation names per occurrence.
        let property_selection = interpretation.property_selection(self)?;
        let plan = self.candidate_root_changes(
            request.commit,
            candidate,
            &property_selection,
            previous,
            initial_view,
        )?;

        self.validate_candidate_namespace_attributes(
            candidate,
            interpretation.attribute_revision(self)?,
        )
        .map_err(|_| denied(reference, Verb::Commit))?;
        let requirements = self
            .requirement_evidence_observed(&request, observation)
            .await?;
        let mut admin_checks = Vec::new();
        let derived = requirements
            .iter()
            .map(|evidence| properties::DerivedAttribute {
                object: *evidence.attribute.object(),
                attribute: terrane_format::tree_format::Attribute {
                    name: evidence.attribute.name().as_str(),
                    value: evidence.attribute.value(),
                },
            })
            .collect::<Vec<_>>();
        let minimum = self.config().min_chunk_size;
        let occurrences = candidate.occurrences(minimum)?;
        let old_occurrences = previous
            .map(|previous| previous.evidence.occurrences(minimum))
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
            let effective = property_selection
                .resolve(&layers, self.defaults_for(candidate))
                .map_err(|_| denied(reference, Verb::Commit))?;
            if domain_label(&effective).map_err(|_| denied(reference, Verb::Commit))?
                != self.config().storage_domain
                || effective.get(PropertyName::Store)
                    != Some(&Value::Text(&self.config().store_name))
            {
                return Err(denied(reference, Verb::Commit));
            }
            if initial_view && occurrence.path == b"/" {
                let Some(Value::Grants(grants)) = effective.get(PropertyName::Acl) else {
                    return Err(denied(reference, Verb::Commit));
                };
                if self.bootstrap_acl_widens(grants) {
                    self.authorize_observed(
                        reference,
                        request.token,
                        Verb::Admin,
                        std::slice::from_ref(&occurrence.path),
                        request.surface,
                        observation,
                    )
                    .await?;
                    admin_checks.push(AdminCheck {
                        alternatives: vec![occurrence.path.clone()],
                    });
                }
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
                .map(|(layers, previous)| {
                    previous
                        .interpretation
                        .resolve(layers, self.defaults_for(previous.evidence))
                })
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
            let mut administrator = self
                .current_admin_observed(
                    reference,
                    request.token,
                    std::slice::from_ref(&occurrence.path),
                    request.surface,
                    observation,
                )
                .await?;
            let mut admin_paths = vec![occurrence.path.clone()];
            for ancestor in &old_occurrences {
                if ancestor.path != occurrence.path
                    && crate::guard::scope::contains_root(&ancestor.path, &occurrence.path)
                {
                    admin_paths.push(ancestor.path.clone());
                }
            }
            if !administrator {
                // ACL changes may be authorized by an actual ancestor root
                // (AUTH-28). Syntactic entry prefixes do not create authority.
                for ancestor in &old_occurrences {
                    if ancestor.path == occurrence.path
                        || !crate::guard::scope::contains_root(&ancestor.path, &occurrence.path)
                    {
                        continue;
                    }
                    if self
                        .current_admin_observed(
                            reference,
                            request.token,
                            std::slice::from_ref(&ancestor.path),
                            request.surface,
                            observation,
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
                (Some(previous), Some(old)) => Some(previous.evidence.tree(old.root, minimum)?),
                _ => None,
            };
            let changed_items = tree
                .iter()
                .filter(|item| {
                    changed_domain
                        || old_tree.as_ref().and_then(|old| old.get(&item.key)) != Some(&item.entry)
                })
                .collect::<Vec<_>>();
            let changed = changed_items
                .iter()
                .map(|item| (&item.entry, &effective))
                .collect::<Vec<_>>();
            if matches!(interpretation, CandidateInterpretation::Authoring)
                && interpretation.attribute_revision(self)? == 2
            {
                index_inline::validate(&changed, &requirements)?;
            }
            let mut admin_required = false;
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
                        terrane_format::tree_format::EntryKind::File { size, .. } => {
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
                let policy = property_selection
                    .resolve(&target_layers, self.defaults_for(candidate))
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
                property_selection: &property_selection,
            };
            let mut introduced = Vec::new();
            for item in &changed_items {
                let retained = if !initial_view
                    && previous.is_some_and(|prior| prior.commit.is_some())
                    && old_effective
                        .as_ref()
                        .is_some_and(|old| same_boundary_policy(old, &effective))
                {
                    let boundary = retained_graft_descriptor(
                        &occurrence.path,
                        &item.key,
                        &item.entry,
                        old_tree.as_ref().and_then(|tree| tree.get(&item.key)),
                    )
                    .and_then(|(path, new_root, old_root)| {
                        let current = occurrences
                            .iter()
                            .find(|root| root.path == path && root.root == new_root)?;
                        let prior = old_occurrences
                            .iter()
                            .find(|root| root.path == path && root.root == old_root)?;
                        Some((current, prior))
                    });
                    match boundary {
                        Some((current, old)) => {
                            let current_layers = current
                                .layers
                                .iter()
                                .map(|(properties, overrides)| RootLayer {
                                    properties,
                                    overrides,
                                })
                                .collect::<Vec<_>>();
                            let old_layers = old
                                .layers
                                .iter()
                                .map(|(properties, overrides)| RootLayer {
                                    properties,
                                    overrides,
                                })
                                .collect::<Vec<_>>();
                            let prior = previous.ok_or_else(crate::guard::invalid)?;
                            let current_policy = property_selection
                                .resolve(&current_layers, self.defaults_for(candidate))
                                .map_err(|_| denied(reference, Verb::Commit))?;
                            let old_policy = prior
                                .interpretation
                                .resolve(&old_layers, self.defaults_for(prior.evidence))
                                .map_err(|_| denied(reference, Verb::Commit))?;
                            if same_boundary_policy(&old_policy, &current_policy) {
                                Some(current_policy)
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                } else {
                    None
                };
                if let Some(target) = retained {
                    // The genuine prior history authenticated this unchanged
                    // delegation. Recheck raw metadata and actual references
                    // without treating a propagated child hash as a new grant.
                    context
                        .validate_retained_graft(&item.entry, &effective, &target)
                        .map_err(|_| denied(reference, Verb::Commit))?;
                } else {
                    introduced.push((&item.entry, &effective));
                }
            }
            properties::validate_commit_with_context(&introduced, &derived, &mut context)
                .map_err(|_| denied(reference, Verb::Commit))?;
            if administrator {
                // Retain Admin only when this admission actually depended on
                // it. Ordinary content edits must remain Commit-only.
                context.administrator = false;
                admin_required |=
                    properties::validate_commit_with_context(&introduced, &derived, &mut context)
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
        }
        for required in plan.required_admin() {
            let alternatives = old_occurrences
                .iter()
                .filter(|root| crate::guard::scope::contains_root(&root.path, required.path()))
                .map(|root| root.path.clone())
                .collect::<Vec<_>>();
            let mut permitted = false;
            for path in &alternatives {
                if self
                    .current_admin_observed(
                        reference,
                        request.token,
                        std::slice::from_ref(path),
                        request.surface,
                        observation,
                    )
                    .await?
                {
                    permitted = true;
                    break;
                }
            }
            if !permitted {
                return Err(denied(reference, Verb::Admin));
            }
            admin_checks.push(AdminCheck { alternatives });
        }
        // Canonical change units include removed roots under their prior policy.
        // Propagated child target hashes alone never add an ancestor decision.
        let mut root_claims = BTreeSet::new();
        for affected in plan.affected() {
            self.authorize_observed(
                reference,
                request.token,
                Verb::Commit,
                &[affected.path().to_vec()],
                request.surface,
                observation,
            )
            .await?;
            root_claims.insert((affected.path().to_vec(), affected.domain().to_owned()));
        }
        if root_claims.is_empty() {
            let root = occurrences
                .iter()
                .find(|root| root.path == b"/")
                .ok_or_else(crate::guard::invalid)?;
            let layers = root
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let policy = property_selection
                .resolve(&layers, self.defaults_for(candidate))
                .map_err(|_| denied(reference, Verb::Commit))?;
            self.authorize_observed(
                reference,
                request.token,
                Verb::Commit,
                std::slice::from_ref(&root.path),
                request.surface,
                observation,
            )
            .await?;
            root_claims.insert((
                root.path.clone(),
                domain_label(&policy)
                    .map_err(|_| denied(reference, Verb::Commit))?
                    .to_owned(),
            ));
        }
        Ok(CandidateValidation {
            requirements,
            admin_checks,
            root_claims: root_claims.into_iter().collect(),
        })
    }
}

/// Recognizes an unchanged descriptor independently of its child target digest.
fn retained_graft_descriptor(
    parent: &[u8],
    key: &[u8],
    candidate: &terrane_format::tree_format::Entry<'_>,
    previous: Option<&terrane_format::tree_format::Entry<'_>>,
) -> Option<(Vec<u8>, Digest, Digest)> {
    use terrane_format::tree_format::EntryKind;

    let previous = previous?;
    let (EntryKind::Tree { root: new_root, .. }, EntryKind::Tree { root: old_root, .. }) =
        (&candidate.kind, &previous.kind)
    else {
        return None;
    };
    let mut normalized = candidate.clone();
    if let EntryKind::Tree { root, .. } = &mut normalized.kind {
        *root = *old_root;
    }
    if normalized != *previous {
        return None;
    }
    let mut path = parent.to_vec();
    if path != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(key);
    Some((path, *new_root, *old_root))
}

/// Separates unchanged delegation from separately governed child content policy.
fn same_boundary_policy(
    left: &properties::EffectiveProperties<'_>,
    right: &properties::EffectiveProperties<'_>,
) -> bool {
    [PropertyName::Acl, PropertyName::Domain]
        .into_iter()
        .all(|name| left.get(name) == right.get(name))
}
