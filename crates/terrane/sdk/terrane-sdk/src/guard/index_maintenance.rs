//! Verifies auxiliary indexes without granting namespace or publication authority.
//!
//! Explicit rebuilding authenticates namespace and provenance independently of
//! lost derived data, then publishes a corrected immutable owner through native
//! admission. Source-only history cannot qualify ordinary serving or cold reuse.

mod execution;
mod producers;

#[cfg(all(test, feature = "tokio", feature = "surface-sdk", unix))]
mod tests;

use terrane_format::identity::Digest;
#[cfg(all(feature = "tokio", unix))]
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::indexing::maintenance;
use terrane_format::refs::RefRecord;

use super::read::indexes::{IndexLookupCurrentWork, IndexLookupError};
use crate::indexing;
#[cfg(all(feature = "tokio", unix))]
use crate::store::{CorruptSubject, StoreErrorKind};

/// Selects one private metadata-only corrective operation, never serving authority.
///
/// Construction remains in this module. Its exact source is also checked by the
/// independent native unchanged-owner receipt before admission and final effects.
#[derive(Clone, Copy)]
pub(crate) struct Purpose {
    source: Digest,
}

impl Purpose {
    /// Binds private recovery to the exact already selected signed source.
    pub(crate) fn for_source(source: Digest) -> Self {
        Self { source }
    }

    /// Returns the exact signed source required by the native corrective receipt.
    pub(crate) fn source(&self) -> Digest {
        self.source
    }
}

/// Holds an independently reconstructed auxiliary body for one native offer.
#[cfg(feature = "tokio")]
pub(crate) struct Replacement {
    digest: Digest,
    identity: terrane_format::identity::Identity,
    bytes: Vec<u8>,
}

#[cfg(feature = "tokio")]
impl Replacement {
    /// Returns the canonical auxiliary digest reconstructed by maintenance.
    pub(crate) fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Borrows the independently reconstructed Node identity.
    pub(crate) fn identity(&self) -> &terrane_format::identity::Identity {
        &self.identity
    }

    /// Borrows canonical auxiliary bytes, never caller-supplied uploads.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Retains the actual operation clock without widening the shared time module.
///
/// # Errors
/// Preserves unsupported or unavailable native clock retention failures.
#[cfg(feature = "tokio")]
pub(crate) fn retain_recovery_clock(
    clock: &impl crate::store::Clock,
) -> Result<crate::store::NativeEffectClock, crate::store::StoreFailure> {
    clock
        .retain_native_clock()
        .map_err(super::time::retention_failure)
}

#[cfg(feature = "tokio")]
impl<S: crate::store::Store, C: crate::store::Clock> super::Guard<S, C> {
    /// Qualifies one auxiliary offer independently under its actual held history.
    ///
    /// # Errors
    /// Preserves source, producer and current Commit authorization failures and
    /// rejects a source ref mismatch or authoritative namespace Node overlap.
    pub(crate) async fn qualify_index_recovery_source(
        &self,
        source: Digest,
        reference: &str,
        token: &[u8],
        surface: &str,
        replacement: &Digest,
        history: super::HistoryObservation<'_>,
    ) -> Result<Vec<super::AuthorizedRef>, crate::store::StoreFailure> {
        let (snapshot, mut requests) = self
            .read_commit_snapshot_authorizations_observed(source, token, b"/", surface, history)
            .await?;
        if snapshot.maintenance_credentials().0 != reference
            || snapshot.evidence.nodes.contains_key(replacement)
        {
            return Err(super::invalid());
        }
        let mut paths = std::collections::BTreeSet::new();
        for occurrence in snapshot
            .evidence
            .occurrences(self.config().min_chunk_size)?
        {
            let tree = snapshot
                .evidence
                .tree(occurrence.root, self.config().min_chunk_size)?;
            for item in tree.iter() {
                if matches!(
                    item.entry.kind,
                    terrane_format::tree_format::EntryKind::File { .. }
                ) {
                    let mut path = occurrence.path.clone();
                    if path != b"/" {
                        path.push(b'/');
                    }
                    path.extend_from_slice(&item.key);
                    paths.insert(path);
                }
            }
        }
        for path in paths {
            requests.extend(
                self.snapshot_authorizations_observed(&snapshot, &path, history)
                    .await?,
            );
        }
        requests.extend(
            self.check_index_source_producers(&snapshot, history, &mut Default::default())
                .await?,
        );
        requests.push(
            self.authorize_observed(
                reference,
                token,
                terrane_format::auth::Verb::Commit,
                &[],
                surface,
                history,
            )
            .await?,
        );
        Ok(requests)
    }
}

/// Distinguishes checked relationships from divergent or unavailable derived data.
#[derive(Debug)]
pub enum IndexVerificationStatus {
    /// The entire owner-to-primary, route and gap relationship verified.
    Verified,
    /// Independent canonical reconstruction disagrees with the immutable binding.
    Divergent {
        /// Actual owner-local binding, without substituting a memo association.
        bound: Digest,
        /// Independently reconstructed canonical primary identity.
        expected: Digest,
    },
    /// A required binding or auxiliary closure is unavailable or unsupported.
    Incomplete(indexing::Error),
}

/// Reports one independently reconstructed immutable owner and named attribute.
#[derive(Debug)]
pub struct IndexVerification {
    /// Exact signed source namespace owner.
    pub owner: Digest,
    /// Registered value attribute whose relationship was examined.
    pub attribute: String,
    /// Full independent verification result, without mutating stored evidence.
    pub status: IndexVerificationStatus,
    /// Actual exhaustive immutable source preparation.
    pub preparation: terrane_format::indexing::incremental::PreparationWork,
    /// Actual full canonical reconstruction, separately from incremental work.
    pub reconstruction: maintenance::ConstructionWork,
    /// Actual complete canonical closure export.
    pub export: maintenance::ExportWork,
    /// Actual bound-closure acquisition, absent when binding divergence was decisive.
    pub verification_loading: Option<indexing::Loading>,
    /// Actual bound-closure namespace reconstruction.
    pub verification_reconstruction: Option<indexing::Reconstruction>,
    /// Actual exhaustive I/P/G relationship verification.
    pub relationship_verification: Option<terrane_format::indexing::lookup::Preparation>,
    /// Missing canonical inline inputs remain explicit coverage gaps.
    pub missing_values: Vec<Vec<u8>>,
}

/// Reports read-only verification and independently repeated current checks.
#[derive(Debug)]
pub struct IndexVerificationReport {
    /// Actual signed view authenticated independently of auxiliary availability.
    pub source_view: Digest,
    /// Actual complete namespace acquisition, excluding auxiliary acquisition.
    pub namespace_loading: indexing::Loading,
    /// Actual canonical namespace reconstruction before owner rebuilding.
    pub namespace_reconstruction: indexing::Reconstruction,
    /// Every selected owner, including distinct physical graft owners.
    pub indexes: Vec<IndexVerification>,
    /// Actual final native control, source and request revalidation work.
    pub current: IndexLookupCurrentWork,
}

/// Reports explicit full rebuilding and its actual acknowledged publication.
#[derive(Debug)]
pub struct IndexRebuildReport {
    /// Actual source diagnosis before correction, never incremental work.
    pub verification: IndexVerificationReport,
    /// Newly identified corrected immutable namespace root.
    pub owner: Digest,
    /// Actual acknowledged signed commit record, including closure-only recovery.
    pub record: Option<RefRecord>,
    /// Total rebuilding namespace acquisition across all recovery rounds.
    pub namespace_loading: indexing::Loading,
    /// Total canonical namespace reconstruction across all recovery rounds.
    pub namespace_reconstruction: indexing::Reconstruction,
    /// Total namespace reconstruction for canonical owner completion across all rounds.
    pub owner_reconstruction: indexing::Reconstruction,
    /// Each full source preparation, including repeated owners in later rounds.
    pub preparation: Vec<terrane_format::indexing::incremental::PreparationWork>,
    /// Each explicit full operation, including repeated recovery rounds.
    pub rebuilding: Vec<maintenance::ConstructionWork>,
}

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> crate::store::StoreFailure {
    crate::store::StoreFailure::with_source(super::invalid().kind().clone(), error)
}

fn index_failure(error: indexing::Error) -> crate::store::StoreFailure {
    match error {
        indexing::Error::Store { failure, .. } => failure,
        indexing::Error::Unsupported => {
            crate::store::StoreFailure::new(crate::store::StoreErrorKind::Unsupported)
        }
        other => failure(other),
    }
}

fn lookup_failure(error: IndexLookupError) -> crate::store::StoreFailure {
    match error {
        IndexLookupError::Store(error) => error,
        IndexLookupError::Index(error) => index_failure(error),
        other => failure(other),
    }
}

/// Charges every repeated full loading event, refusing unrepresentable totals.
fn accumulate_loading(
    total: &mut indexing::Loading,
    round: indexing::Loading,
) -> Result<(), crate::store::StoreFailure> {
    for (counter, amount) in [
        (&mut total.gets, round.gets),
        (&mut total.fetched_bytes, round.fetched_bytes),
        (&mut total.identity_checks, round.identity_checks),
        (&mut total.node_decodes, round.node_decodes),
        (&mut total.namespace_roots, round.namespace_roots),
        (&mut total.carrier_checks, round.carrier_checks),
    ] {
        *counter = counter.checked_add(amount).ok_or_else(super::invalid)?;
    }
    Ok(())
}

/// Charges repeated canonical reconstruction without deduplicating its work.
fn accumulate_reconstruction(
    total: &mut indexing::Reconstruction,
    round: indexing::Reconstruction,
) -> Result<(), crate::store::StoreFailure> {
    for (counter, amount) in [
        (&mut total.node_decodes, round.node_decodes),
        (&mut total.identity_checks, round.identity_checks),
        (&mut total.trees, round.trees),
        (&mut total.entries, round.entries),
        (&mut total.compared_nodes, round.compared_nodes),
    ] {
        *counter = counter.checked_add(amount).ok_or_else(super::invalid)?;
    }
    Ok(())
}

/// Selects diagnostics requiring an independent physical auxiliary-loss probe.
#[cfg(all(feature = "tokio", unix))]
fn container_corruption(failure: &crate::store::StoreFailure) -> bool {
    matches!(failure.kind(), StoreErrorKind::Corrupt(CorruptSubject::Identity(subject))
        if matches!(subject.kind(), IdentityKind::Pack | IdentityKind::Index))
}

#[cfg(unix)]
impl<F, B, V, C> super::Guard<crate::bucket::FileBucket<F, B, V>, C>
where
    F: crate::store::LocalFs + crate::bucket::BucketBinding + Sync,
    B: crate::store::Clock + crate::bucket::BucketBinding + Sync,
    V: crate::store::ContentValidator + crate::bucket::BucketBinding + Sync,
    C: crate::store::Clock + Sync,
{
    /// Reconstructs every selected index and reports divergence without mutation.
    ///
    /// Source namespace, provenance and current requests are qualified under real
    /// read-only native and Original exclusion. This result grants no future Read
    /// right, index serving qualification or checked source lineage.
    ///
    /// # Errors
    /// Preserves source signature, Original, current authorization, producer,
    /// namespace, selected-profile and physical-read failures. Auxiliary absence
    /// is reported independently rather than selecting fabricated source facts.
    pub async fn verify_index(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
        attribute: &str,
    ) -> Result<IndexVerificationReport, IndexLookupError> {
        use crate::store::RefStore;
        let holder = crate::bucket::held::SingleHeld::acquire_read_only(self.store()).await?;
        let held = holder.source();
        // Capture original selected physical recipes before history or auxiliary
        // reads consume them; closing must use this same observation.
        #[cfg(feature = "tokio")]
        let observed = held.observe_publication_ordinary_retained().await?;
        #[cfg(not(feature = "tokio"))]
        let observed = held.observe_publication_unrepaired().await?;
        let authority = self.configured_original_authority()?;
        let mut controls = self
            .hold_original_registration(&authority, observed.identity())
            .await?;
        let retained = super::read::indexes::retention::capture(
            self,
            &authority,
            &mut controls,
            &held,
            &observed,
        )
        .await?;
        let clock = self
            .clock()
            .retain_native_clock()
            .map_err(super::time::retention_failure)?;
        let guard = self.held_guard(holder.source(), clock)?;
        guard.retain_original_controls(retained.controls())?;
        let record = guard
            .store()
            .ref_get(reference)
            .await?
            .ok_or_else(super::invalid)?;
        let purpose = Purpose {
            source: record.commit,
        };
        let consumed = super::ConsumedResolver::new(&guard, &authority)?;
        consumed.registration(&authority)?;
        let observation = super::HistoryObservation::held(observed.identity())
            .tracked(&consumed)
            .maintenance(&purpose);
        let (snapshot, mut requests) = guard
            .read_commit_snapshot_authorizations_observed(
                record.commit,
                token,
                b"/",
                surface,
                observation,
            )
            .await?;
        if snapshot.maintenance_credentials().0 != reference {
            return Err(super::invalid().into());
        }
        let (_, profile) = guard.selected_view_profile(&snapshot.commit, observation)?;
        let revisions = indexing::SemanticRevisions {
            property: profile.property_revision,
            attribute: profile.attribute_revision,
            tree: profile.tree_revision,
        };
        let inputs = super::history::completion::indexes::Inputs::new(
            guard.store(),
            &snapshot.evidence,
            &[],
        )?;
        let source = indexing::load_source(
            &inputs,
            snapshot.evidence.root,
            revisions,
            guard.config().min_chunk_size,
        )
        .await?;
        let (candidates, namespace_reconstruction) =
            execution::evaluate(&guard, &snapshot, &source, attribute)?;
        let mut indexes = Vec::new();
        for candidate in candidates {
            let mut verification_loading = None;
            let mut verification_reconstruction = None;
            let mut relationship_verification = None;
            let status = match candidate.bound {
                Some(bound) if bound != candidate.data.root => IndexVerificationStatus::Divergent {
                    bound,
                    expected: candidate.data.root,
                },
                _ => match indexing::load(
                    &inputs,
                    candidate.owner,
                    attribute,
                    revisions,
                    guard.config().min_chunk_size,
                )
                .await
                {
                    Ok(loaded) => {
                        verification_loading = Some(loaded.loading());
                        let sources = loaded.sources()?;
                        verification_reconstruction = Some(sources.work);
                        let prepared = loaded.prepare(&sources.trees)?;
                        relationship_verification = Some(prepared.preparation().clone());
                        IndexVerificationStatus::Verified
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            indexing::ErrorKind::Incomplete | indexing::ErrorKind::Unsupported
                        ) =>
                    {
                        IndexVerificationStatus::Incomplete(error)
                    }
                    #[cfg(feature = "tokio")]
                    Err(indexing::Error::Store { node, failure })
                        if candidate.data.nodes.contains_key(&node)
                            && !snapshot.evidence.nodes.contains_key(&node)
                            && container_corruption(&failure) =>
                    {
                        // Only independently reconstructed auxiliary identities
                        // may use physical absence as a recovery diagnosis. The
                        // held history's final closure still protects every
                        // authoritative source and producer input.
                        let identity = TERRANE_V1
                            .from_digest(IdentityKind::Node, &node)
                            .map_err(|_| super::invalid())?;
                        if held.index_auxiliary_absent(&observed, &identity).await? {
                            IndexVerificationStatus::Incomplete(indexing::Error::Store {
                                node,
                                failure: crate::store::StoreFailure::with_source(
                                    StoreErrorKind::Absent(identity),
                                    failure,
                                ),
                            })
                        } else {
                            return Err(indexing::Error::Store { node, failure }.into());
                        }
                    }
                    Err(error) => return Err(error.into()),
                },
            };
            indexes.push(IndexVerification {
                owner: candidate.owner,
                attribute: attribute.to_owned(),
                status,
                preparation: candidate.preparation,
                reconstruction: candidate.construction,
                export: candidate.export,
                verification_loading,
                verification_reconstruction,
                relationship_verification,
                missing_values: candidate.missing,
            });
        }
        let mut current = IndexLookupCurrentWork {
            history_boundary_calls: 1,
            ..Default::default()
        };
        requests.extend(
            guard
                .check_index_source_producers(&snapshot, observation, &mut current)
                .await?,
        );
        super::read::indexes::retention::finish(
            self,
            &authority,
            &mut controls,
            &retained,
            &observed,
            &consumed,
            &mut current,
        )
        .await?;
        if guard.store().ref_get(reference).await?.as_ref() != Some(&record) {
            return Err(super::invalid().into());
        }
        for request in &requests {
            super::time::refresh(self.keys(), &self.config().home, guard.clock(), request)?;
            current.token_refreshes = current
                .token_refreshes
                .checked_add(1)
                .ok_or_else(super::invalid)?;
        }
        Ok(IndexVerificationReport {
            source_view: record.commit,
            namespace_loading: source.loading(),
            namespace_reconstruction,
            indexes,
            current,
        })
    }
}

#[cfg(unix)]
impl<F, B, V, C> crate::repository::Repository<crate::bucket::FileBucket<F, B, V>, C, F>
where
    crate::bucket::FileBucket<F, B, V>: Sync,
    F: crate::store::LocalFs + crate::bucket::BucketBinding + Sync,
    B: crate::store::Clock + crate::bucket::BucketBinding + Sync,
    V: crate::store::ContentValidator + crate::bucket::BucketBinding + Sync,
    C: crate::store::Clock + Sync,
{
    /// Starts a current-authorized corrective session even when auxiliary data is lost.
    ///
    /// # Errors
    /// Preserves missing source, Original, namespace/provenance, current Commit
    /// denial and writer-epoch failures. This session grants no index serving right.
    pub async fn begin_index_rebuild(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<crate::ref_advance::WriterSession, crate::repository::Error> {
        use crate::store::RefStore;
        let record = self
            .coordinator()
            .store()
            .ref_get(reference)
            .await?
            .ok_or_else(super::invalid)?;
        let purpose = Purpose {
            source: record.commit,
        };
        self.coordinator()
            .begin_index_rebuild(reference, token, surface, &purpose)
            .await
            .map_err(crate::repository::Error::Advance)
    }

    /// Rebuilds lost or divergent auxiliaries and publishes a corrected signed owner.
    ///
    /// The unsigned request supplies metadata and credentials, never completed
    /// evidence. Rebuilding preserves all namespace content and origins. The
    /// independently qualified native owner receipt rechecks source, producer,
    /// current requests, Original and physical inputs through actual publication.
    ///
    /// # Errors
    /// Preserves invalid templates, unsupported selected semantics, missing signed
    /// namespace/provenance, current denial, source changes, final retention and
    /// acknowledgment failures. Auxiliary loss never authorizes namespace changes.
    pub async fn rebuild_index(
        &self,
        session: &mut crate::ref_advance::WriterSession,
        mut request: super::CommitRequest,
        attribute: &str,
    ) -> Result<IndexRebuildReport, crate::repository::Error> {
        use crate::store::RefStore;

        let started = self.coordinator().guard().clock().monotonic();
        let guard = self.coordinator().guard();
        let source_record = session.record().ok_or_else(super::invalid)?.clone();
        if request.commit.signature.is_some()
            || !request.uploads.is_empty()
            || !request.reference_records.is_empty()
            || !request.disclosures.is_empty()
            || request.commit.parents != [source_record.commit]
            || request.commit.profile_pair.recipe.is_some()
            || request.commit.profile_pair.entry_receipts.is_some()
            || request.commit.profile_pair.commit_context.is_some()
            || request.commit.profile_pair.required_properties.is_some()
            || request.commit.profile_pair.lease.is_some()
            || request.commit.packs.is_some()
        {
            return Err(super::invalid().into());
        }
        let verification = guard
            .verify_index(
                session.reference(),
                &request.token,
                &request.surface,
                attribute,
            )
            .await
            .map_err(lookup_failure)?;
        if verification.source_view != source_record.commit {
            return Err(super::invalid().into());
        }
        // The first replacement pack and final signed publication share one
        // deadline. Each loss transition ends its actual authority scope.
        #[cfg(feature = "tokio")]
        let mut offered = std::collections::BTreeSet::new();
        let mut namespace_loading = indexing::Loading::default();
        let mut namespace_reconstruction = indexing::Reconstruction::default();
        let mut owner_reconstruction = indexing::Reconstruction::default();
        let mut preparation = Vec::new();
        let mut rebuilding = Vec::new();
        let mut prepared = None;
        while prepared.is_none() {
            self.coordinator().check_time(started)?;
            if guard.store().ref_get(session.reference()).await?.as_ref() != Some(&source_record) {
                return Err(super::invalid().into());
            }
            let purpose = Purpose::for_source(source_record.commit);
            let observation = super::HistoryObservation::default().maintenance(&purpose);
            let snapshot = guard
                .read_commit_snapshot_observed(
                    source_record.commit,
                    &request.token,
                    b"/",
                    &request.surface,
                    observation,
                )
                .await?;
            if request.commit.tree != snapshot.evidence.root
                || snapshot.maintenance_credentials().0 != session.reference()
            {
                return Err(super::invalid().into());
            }
            let (_, profile) = guard.selected_view_profile(&snapshot.commit, observation)?;
            if profile != guard.configured_authoring_registries()? {
                return Err(super::invalid().into());
            }
            let revisions = indexing::SemanticRevisions {
                property: profile.property_revision,
                attribute: profile.attribute_revision,
                tree: profile.tree_revision,
            };
            let inputs = super::history::completion::indexes::Inputs::new(
                guard.store(),
                &snapshot.evidence,
                &[],
            )?;
            let source = indexing::load_source(
                &inputs,
                snapshot.evidence.root,
                revisions,
                guard.config().min_chunk_size,
            )
            .await
            .map_err(index_failure)?;
            let (candidates, source_work) =
                execution::evaluate(guard, &snapshot, &source, attribute)?;
            accumulate_loading(&mut namespace_loading, source.loading())?;
            accumulate_reconstruction(&mut namespace_reconstruction, source_work)?;
            preparation.extend(candidates.iter().map(|candidate| candidate.preparation));
            rebuilding.extend(
                candidates
                    .iter()
                    .map(|candidate| candidate.construction.clone()),
            );
            let (mut tree, owner_work) =
                execution::corrected(guard, &snapshot, &source, attribute, &candidates)?;
            accumulate_reconstruction(&mut owner_reconstruction, owner_work)?;
            #[cfg(feature = "tokio")]
            let replacements = candidates
                .iter()
                .flat_map(|candidate| &candidate.data.nodes)
                .filter(|(node, _)| !snapshot.evidence.nodes.contains_key(*node))
                .map(|(node, bytes)| {
                    let identity = TERRANE_V1
                        .from_digest(IdentityKind::Node, node)
                        .map_err(|_| super::invalid())?;
                    Ok((
                        *node,
                        Replacement {
                            digest: *node,
                            identity,
                            bytes: bytes.clone(),
                        },
                    ))
                })
                .collect::<Result<std::collections::BTreeMap<_, _>, crate::store::StoreFailure>>(
                )?;
            #[cfg(feature = "tokio")]
            let replacements = {
                let holder =
                    crate::bucket::held::SingleHeld::acquire_read_only(guard.store()).await?;
                let held = holder.source();
                let observed = held.observe_publication_ordinary_retained().await?;
                let mut missing = std::collections::BTreeMap::new();
                for (node, replacement) in replacements {
                    if !offered.contains(&node)
                        && held
                            .index_auxiliary_placement(&observed, replacement.identity())
                            .await?
                            == Some(true)
                    {
                        missing.insert(node, replacement);
                    }
                }
                missing
            };
            let references = guard
                .existing_owner_references_for_index_rebuild(snapshot, &mut tree, &[], purpose)
                .await?;
            #[cfg(feature = "tokio")]
            if let Some((node, replacement)) = replacements
                .iter()
                .find(|(node, _)| !offered.contains(*node))
            {
                crate::selected_bridge::native_guard::index_recovery::prestage_one(
                    self.coordinator(),
                    session,
                    &request.token,
                    &request.surface,
                    replacement,
                    &references,
                    started,
                )
                .await?;
                offered.insert(*node);
                // Even if another repair won before this offer, no old selected
                // snapshot, controls, placement or source receipt crosses the
                // boundary. Final admission always uses full fresh qualification.
                continue;
            }
            self.coordinator().check_time(started)?;
            prepared = Some((tree, references));
        }

        let (tree, references) = prepared.ok_or_else(super::invalid)?;
        request.commit.tree = tree.root();
        let owner = tree.root();
        // Re-emitting an unchanged canonical owner is necessary when its derived
        // closure was lost. The new signed commit durably republishes that closure.
        let committed = self
            .commit_with_existing_owner_report_started(session, tree, request, references, started)
            .await?;
        Ok(IndexRebuildReport {
            verification,
            owner,
            record: Some(committed.record),
            namespace_loading,
            namespace_reconstruction,
            owner_reconstruction,
            preparation,
            rebuilding,
        })
    }
}
