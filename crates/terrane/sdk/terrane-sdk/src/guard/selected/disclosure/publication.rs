//! Publishes authenticated native disclosures under genuine paired exclusions.
//!
//! Preliminary destination admission and early source bytes remain unpublished.
//! Only the actual held pair supplies original controls, dedicated source signing
//! rights and the final source/destination selected-publication handoff.

use std::collections::{BTreeMap, BTreeSet};

use super::{DisclosureSource, capture_source, destination, invalid, projection};
use crate::bucket::held::HeldBuckets;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{
    ConsumedResolver, DisclosureSourceSelection, Guard, HistoryObservation, TreeEvidence,
};
use crate::ref_advance::{
    AdvanceError, CommitRequest, CommitTiming, Coordinator, FsRef, PreloadedSelection,
    RetainedPublication, StagedUpload, WriterSession,
};
use crate::store::{Clock, ContentStore, ContentValidator, LocalFs, StoreFailure};
use terrane_format::auth::{Request, RequestRoot, Verb};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::provenance::{self, EntryLocation, VerifiedCommit, VerifiedHistory};
use terrane_format::refs::{DisclosureProof, EntryOrigin, EntrySource, RefLogReason};
use terrane_format::tree_format::EntryKind;

/// Publishes only after both native factories freshly verify the exact proposal.
///
/// # Errors
/// Preserves current authority, complete candidate/original verification, timing,
/// physical exclusion, storage and indeterminate selected-publication failures.
pub(crate) async fn publish<F, B, V, C, D>(
    concrete: &Coordinator<FileBucket<F, B, V>, C, F>,
    source: &Guard<FileBucket<F, B, V>, D>,
    session: &mut WriterSession,
    mut request: CommitRequest,
    preloaded: Vec<PreloadedSelection>,
    started: std::time::Duration,
    timing: CommitTiming,
) -> Result<terrane_format::refs::RefRecord, AdvanceError>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    let secret = request.terminal_secret;
    let paths = preloaded
        .iter()
        .map(|selection| selection.selector.destination_path.clone())
        .collect::<Vec<_>>();
    let mut evidence = TreeEvidence::load_tree(
        concrete.store(),
        request.commit.tree,
        &request.uploads,
        concrete.guard().config().min_chunk_size,
    )
    .await?;
    let mut markers = Vec::new();
    let authoring = concrete.guard().authoring_property_selection()?;
    for selection in &preloaded {
        let (root, path, domain) = locate(
            concrete.guard(),
            &evidence,
            &selection.selector.destination_path,
            &authoring,
        )?;
        markers.push(projection::MarkerOccurrence {
            root,
            path,
            introducer: selection.introducer,
            destination_domain: domain,
        });
        request.uploads.extend(selection.uploads.clone());
    }
    let normalized = projection::normalize_markers(
        &evidence,
        &markers,
        concrete.guard().config().min_chunk_size,
    )?;
    if normalized.roots.get(&request.commit.tree) != Some(&normalized.root) {
        return Err(invalid().into());
    }
    request.commit.tree = normalized.root;
    request.uploads.extend(normalized.uploads);
    request.uploads = coalesce_metadata(request.uploads)?;
    evidence = TreeEvidence::load_tree(
        concrete.store(),
        request.commit.tree,
        &request.uploads,
        concrete.guard().config().min_chunk_size,
    )
    .await?;

    // Preliminary admission proves destination obligations without any source
    // certificate or publication context. The held pair repeats these checks.
    let mut admitted = {
        let holder = HeldBuckets::acquire(source.store(), concrete.store()).await?;
        let guard = concrete.guard().held_guard(
            holder.destination(),
            retained_clock(concrete.guard().clock())?,
        )?;
        let observed = guard.store().observe_publication().await?;
        guard
            .admit_held(
                session.reference(),
                session.epoch(),
                request,
                observed.identity(),
            )
            .await?
    };
    if admitted.observed_current.as_ref() != session.record() {
        return Err(invalid().into());
    }
    let authority = concrete.guard().configured_original_authority()?;
    let retention = crate::repository::local_authority::NativeRetention {
        authority: authority.clone(),
        owner_uid: concrete
            .store()
            .publication_operator_uid()
            .ok_or_else(invalid)?,
        authoring_acl: concrete.guard().config().initial_acl.clone(),
    };
    // Baseline retention takes its own namespace exclusion. Preliminary
    // admission releases the pair first; final publication recaptures both
    // repositories and compares the whole observed destination head below.
    retention
        .retain_baseline(concrete.guard(), concrete.store().fs(), session)
        .await
        .map_err(crate::guard::retention_failure)?;
    concrete.check_time(started)?;

    #[cfg(all(test, feature = "tokio"))]
    test_pause::after_baseline(concrete.store().root()).await?;

    let holder = HeldBuckets::acquire(source.store(), concrete.store()).await?;
    let source_clock = retained_clock(source.clock())?;
    let destination_clock = retained_clock(concrete.guard().clock())?;
    let source_guard = source.held_guard(holder.source(), source_clock)?;
    let destination_guard = concrete
        .guard()
        .held_guard(holder.destination(), destination_clock)?;
    let destination = Coordinator::new(destination_guard, timing, FsRef(concrete.store().fs()));
    #[cfg(all(feature = "tokio", unix))]
    // The read-only source holder performs no repair; its original selected
    // recipes must also remain compatible with the later Guard carry effect.
    let source_observed = source_guard.store().observe_publication_retained().await?;
    #[cfg(not(all(feature = "tokio", unix)))]
    let source_observed = source_guard.store().observe_publication().await?;
    let observed = destination.store().observe_publication().await?;
    let selections = preloaded
        .iter()
        .map(|selection| DisclosureSourceSelection {
            reference: &selection.selector.source_reference,
            commit: selection.selector.source_commit,
            token: &selection.selector.source_token,
            path: &selection.selector.source_path,
            surface: &admitted.surface,
        })
        .collect::<Vec<_>>();
    let mut checked =
        capture_source(source, &source_guard, &source_observed, &selections, timing).await?;
    if checked.retained.owner() != source_observed.configured_operator_uid()
        || checked.retained.exclusions().is_empty()
    {
        return Err(invalid().into());
    }
    for (selected, snapshot) in preloaded.iter().zip(&checked.snapshots) {
        if selected.physical_source != checked.authority {
            return Err(invalid().into());
        }
        let (location, _) = snapshot
            .history
            .locate(
                selected.selector.source_commit,
                relative(&selected.selector.source_path)?,
            )
            .map_err(|_| invalid())?;
        let entry = snapshot.history.entry(&location).map_err(|_| invalid())?;
        let content = match entry.kind {
            EntryKind::File { content, size, .. } => Some((content, size)),
            EntryKind::Directory { .. } | EntryKind::Symlink { .. } => None,
            _ => return Err(invalid().into()),
        };
        let (_, _, domain) = locate(
            &source_guard,
            &snapshot.evidence,
            &selected.selector.source_path,
            &snapshot.interpretation.selection(),
        )?;
        if location.root != selected.root
            || location.path != selected.path
            || content != selected.content
            || domain != selected.domain
            || snapshot
                .history
                .introducing_commit(&location)
                .map_err(|_| invalid())?
                != selected.introducer
        {
            return Err(invalid().into());
        }
    }
    destination::install(
        concrete.guard(),
        destination.guard(),
        &observed,
        &source_observed,
        &mut checked,
        destination::DestinationRequest {
            reference: session.reference(),
            token: &admitted.token,
            paths: &paths,
            surface: &admitted.surface,
            expected: session.record(),
            started,
            timing,
        },
    )
    .await?;
    let observed = destination.store().observe_publication().await?;
    let consumed = ConsumedResolver::new(destination.guard(), &authority)?;
    consumed.registration(&authority)?;
    let history_observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let mut requests = destination
        .guard()
        .capture_admission_authorizations_observed(&admitted, history_observation)
        .await?;
    let current = destination
        .guard()
        .authorize_observed(
            session.reference(),
            &admitted.token,
            Verb::Commit,
            &paths,
            &admitted.surface,
            history_observation,
        )
        .await?;
    if current.record() != session.record() || !current.same_principal(&checked.requests[0]) {
        return Err(invalid().into());
    }
    requests.push(current);
    for request in &requests {
        consumed.operation(request)?;
    }
    let destination_check =
        super::super::retain_final_check(destination.guard(), &requests, started, timing)?;

    let mut record = admitted.commit.commit().clone();
    for (selection, snapshot) in preloaded.iter().zip(&checked.snapshots) {
        // Public producers remain ordinary dependencies; only actual private
        // source parents are supplied as certified cuts.
        if selection.domain != "public" && !record.parents.contains(&snapshot.commit.identity()) {
            record.parents.push(snapshot.commit.identity());
        }
    }
    let mut receipt_sources = BTreeMap::new();
    for (index, selection) in preloaded.iter().enumerate() {
        let snapshot = &checked.snapshots[index];
        let (source_location, _) = snapshot
            .history
            .locate(
                selection.selector.source_commit,
                relative(&selection.selector.source_path)?,
            )
            .map_err(|_| invalid())?;
        let (root, path, _) = locate(
            destination.guard(),
            &evidence,
            &selection.selector.destination_path,
            &admitted.admitted_property_selection(),
        )?;
        let source_entry = EntrySource {
            commit: source_location.commit,
            root: source_location.root,
            path: source_location.path.clone(),
        };
        let selector = (root, path.clone());
        if receipt_sources
            .insert(selector.clone(), source_entry.clone())
            .is_some_and(|previous| previous != source_entry)
        {
            return Err(invalid().into());
        }
        let receipt = record
            .profile_pair
            .entry_receipts
            .as_mut()
            .ok_or_else(invalid)?
            .iter_mut()
            .find(|receipt| receipt.root == root && receipt.path == path)
            .ok_or_else(invalid)?;
        receipt.origin = EntryOrigin::Current;
        receipt.reintroduced_from = Some(source_entry);
        receipt.disclosure_proof = Some(DisclosureProof {
            authority_key: hex(&checked.signer.role().public_key),
            source_domain: selection.domain.clone(),
            observed_at: source_guard.now(&selection.selector.source_reference, Verb::Read)?,
            signature: [0; 64],
        });
        for (name, origin) in receipt.attributes.as_mut().ok_or_else(invalid)? {
            if name == "provenance.reintroduced-from" {
                *origin = EntryOrigin::Current;
                continue;
            }
            let producer = snapshot
                .history
                .attribute_producer(&source_location, name)
                .map_err(|_| invalid())?;
            let producer_location = attribute_location(
                &snapshot.history,
                &source_location,
                name,
                producer,
                relative(&selection.selector.source_path)?,
            )?;
            *origin = EntryOrigin::Source(EntrySource {
                commit: producer_location.commit,
                root: producer_location.root,
                path: producer_location.path,
            });
        }
    }
    #[cfg(all(test, feature = "tokio"))]
    super::mutations::apply_before_sign(concrete.store().root(), &mut record)?;
    let destination_interpretation = admitted.admitted_property_selection();
    let mut prototype_history = VerifiedHistory::new_selected(
        destination.guard().config().min_chunk_size,
        destination_interpretation.clone(),
    );
    for snapshot in &checked.snapshots {
        prototype_history
            .append_verified(&snapshot.history)
            .map_err(|_| invalid())?;
    }
    let retained_destination = if let Some(previous) = session.record() {
        let history = destination
            .guard()
            .completed_history_for_disclosure(previous.commit, history_observation)
            .await?;
        prototype_history
            .append_verified(&history)
            .map_err(|_| invalid())?;
        Some(history)
    } else {
        None
    };
    let prototype = resign(destination.guard(), record, &secret, session.epoch())?;
    prototype_history
        .insert_commit_selected(prototype.clone(), destination_interpretation.clone())
        .map_err(|_| invalid())?;
    let nodes = evidence
        .nodes
        .iter()
        .map(|(identity, bytes)| (*identity, bytes.clone()))
        .collect::<Vec<_>>();
    for root in &evidence.roots {
        prototype_history
            .insert_tree(*root, &nodes)
            .map_err(|_| invalid())?;
    }
    let mut finalized = prototype.commit().clone();
    for (index, selection) in preloaded.iter().enumerate() {
        checked.final_check.recheck()?;
        destination_check.recheck()?;
        let signature = checked.signer.sign(provenance::DisclosureSigning {
            source_history: &checked.snapshots[index].history,
            source_commit: selection.selector.source_commit,
            source_path: relative(&selection.selector.source_path)?,
            destination_history: &prototype_history,
            destination_commit: prototype.identity(),
            destination_path: relative(&selection.selector.destination_path)?,
            source_defaults: source_guard.defaults_for(&checked.snapshots[index].evidence),
            destination_defaults: destination.guard().defaults_for(&evidence),
        })?;
        let (root, path, _) = locate(
            destination.guard(),
            &evidence,
            &selection.selector.destination_path,
            &admitted.admitted_property_selection(),
        )?;
        finalized
            .profile_pair
            .entry_receipts
            .as_mut()
            .ok_or_else(invalid)?
            .iter_mut()
            .find(|receipt| receipt.root == root && receipt.path == path)
            .and_then(|receipt| receipt.disclosure_proof.as_mut())
            .ok_or_else(invalid)?
            .signature = signature;
    }
    #[cfg(all(test, feature = "tokio"))]
    super::mutations::apply(concrete.store().root(), &mut finalized)?;
    admitted.commit = resign(destination.guard(), finalized, &secret, session.epoch())?;
    prototype_history
        .insert_commit_selected(admitted.commit.clone(), destination_interpretation)
        .map_err(|_| invalid())?;
    let baseline = destination
        .guard()
        .original_bootstrap(session.reference(), session.epoch())?;
    let original_authority = hex(baseline.authority().id());
    let original_acl = baseline
        .acl()
        .iter()
        .map(|(subject, verbs)| (subject.as_str(), *verbs))
        .collect::<Vec<_>>();
    let roles = destination.guard().history_disclosure_roles()?;
    let role_views = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
    let candidate = provenance::DisclosureCandidate::new_with_bootstrap(
        &prototype_history,
        admitted.commit.identity(),
        &role_views,
        destination.guard().defaults_for(&evidence),
        &original_authority,
        provenance::OriginalBootstrapPolicy {
            authority: &original_authority,
            reference: baseline.reference(),
            writer_epoch: baseline.epoch(),
            acl: &original_acl,
        },
    )
    .map_err(|_| invalid())?;
    // Private introducers remain audit data. Complete candidate verification
    // precedes any immutable transfer and chooses every public dependency.
    let public = candidate.required_commits().iter().copied().collect();
    candidate.finish().map_err(|_| invalid())?;
    let mut transfers = public_transfers(
        &source_guard,
        &checked,
        retained_destination.as_ref(),
        public,
    )
    .await?;
    transfers.append(&mut admitted.uploads);
    let mut transfers = coalesce_metadata(transfers)?;
    // Chunk dictionaries precede their dependent chunks in the source staging
    // list. All chunks precede manifests and canonical metadata publication.
    transfers.sort_by_key(|upload| match upload {
        StagedUpload::Chunk { .. } => 0,
        StagedUpload::Meta {
            kind: IdentityKind::Manifest,
            ..
        } => 1,
        StagedUpload::Meta {
            kind: IdentityKind::Node,
            ..
        } => 2,
        StagedUpload::Meta { .. } => 3,
    });
    for upload in &transfers {
        checked.final_check.recheck()?;
        destination_check.recheck()?;
        destination.check_time(started)?;
        destination.store().put(upload.as_upload()?).await?;
    }
    let association = crate::repository::local_authority::retention::CommitAssociation {
        commit: admitted.commit.identity(),
        id: *authority.id(),
        reference: session.reference().to_owned(),
        epoch: session.epoch(),
    };
    let current_observed = destination.store().observe_publication().await?;
    let mut controls = concrete
        .guard()
        .hold_original_registration_write(&authority, current_observed.identity())
        .await?;
    crate::repository::local_authority::retention::retain(
        destination.store().fs(),
        authority.control(),
        concrete
            .store()
            .publication_operator_uid()
            .ok_or_else(invalid)?,
        &association.selector(),
        &association,
        false,
    )
    .await
    .map_err(crate::guard::retention_failure)?;
    controls.revalidate().await?;
    drop(controls);
    let original = destination
        .guard()
        .check_original_commit_held(&baseline, association.view(), current_observed.identity())
        .await?;
    let concrete_original = concrete
        .guard()
        .check_original_commit_held(&baseline, association.view(), current_observed.identity())
        .await?;
    if original != concrete_original {
        return Err(invalid().into());
    }
    let source_latest = source_guard.store().observe_publication().await?;
    same_heads(&source_observed, &source_latest)?;
    let mut source_records = Vec::new();
    for pin in &checked.controls.used.controls {
        let bytes = checked.controls.exclusion.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
        source_records.push((pin.key.clone(), bytes));
    }
    source_records.extend(
        checked
            .signer
            .retained_records()
            .map_err(crate::guard::retention_failure)?,
    );
    let retained = checked
        .controls
        .exclusion
        .retain_named(&source_records)
        .await?;
    let mut publication = RetainedPublication {
        admitted,
        original,
        started,
        reason: RefLogReason::Commit,
        timing,
    };
    super::super::publish_candidate_inner(
        concrete.guard(),
        &authority,
        &destination,
        &current_observed,
        super::super::CandidateInputs {
            consumed: &consumed,
            session,
            publication: &mut publication,
            paired: Some(super::super::PairedSource {
                observed: &source_latest,
                final_check: checked.final_check.clone(),
                controls: retained,
                selected_reads: checked
                    .selected_reads
                    .iter()
                    .map(|record| {
                        super::super::selected_control_read(&source_latest, record.clone())
                    })
                    .collect(),
            }),
        },
    )
    .await
}

/// Removes identical metadata witnesses while preserving every chunk validation.
fn coalesce_metadata(uploads: Vec<StagedUpload>) -> Result<Vec<StagedUpload>, StoreFailure> {
    let mut metadata = BTreeMap::new();
    let mut result = Vec::new();
    for upload in uploads {
        if let StagedUpload::Meta { kind, bytes } = &upload {
            let identity = TERRANE_V1.calculate(*kind, bytes).map_err(|_| invalid())?;
            let selector = (
                TERRANE_V1.domain(*kind).map_err(|_| invalid())?,
                identity.terrane_v1_digest().map_err(|_| invalid())?,
            );
            if let Some(previous) = metadata.get(&selector) {
                if previous != bytes {
                    return Err(invalid());
                }
                continue;
            }
            metadata.insert(selector, bytes.clone());
        }
        result.push(upload);
    }
    Ok(result)
}

fn retained_clock<C: Clock>(clock: &C) -> Result<crate::store::NativeEffectClock, StoreFailure> {
    clock.retain_native_clock().map_err(|error| {
        let kind = if error.kind() == std::io::ErrorKind::Unsupported {
            crate::store::StoreErrorKind::Unsupported
        } else {
            crate::store::StoreErrorKind::Unavailable { retry_after: None }
        };
        StoreFailure::with_source(kind, error)
    })
}

fn relative(path: &[u8]) -> Result<&[u8], StoreFailure> {
    let path = path.strip_prefix(b"/").ok_or_else(invalid)?;
    terrane_format::tree_format::validate_key(path).map_err(|_| invalid())?;
    Ok(path)
}

fn locate<S: crate::store::Store, C: Clock>(
    guard: &Guard<S, C>,
    evidence: &TreeEvidence,
    absolute: &[u8],
    interpretation: &terrane_format::properties::selected::Selection,
) -> Result<(Digest, Vec<u8>, String), StoreFailure> {
    relative(absolute)?;
    let mut result = None;
    for occurrence in evidence.occurrences(guard.config().min_chunk_size)? {
        let tree = evidence.tree(occurrence.root, guard.config().min_chunk_size)?;
        for item in tree.iter() {
            let mut path = occurrence.path.clone();
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(&item.key);
            if path != absolute {
                continue;
            }
            let layers = occurrence
                .layers
                .iter()
                .map(
                    |(properties, overrides)| terrane_format::properties::RootLayer {
                        properties,
                        overrides,
                    },
                )
                .collect::<Vec<_>>();
            let effective = interpretation
                .resolve(&layers, guard.defaults_for(evidence))
                .map_err(|_| invalid())?;
            if result.is_some() {
                return Err(invalid());
            }
            result = Some((
                occurrence.root,
                item.key.clone(),
                crate::guard::domain_label(&effective)
                    .map_err(|_| invalid())?
                    .to_owned(),
            ));
        }
    }
    result.ok_or_else(invalid)
}

fn resign<S, C>(
    guard: &Guard<S, C>,
    commit: terrane_format::refs::Commit,
    secret: &[u8; 32],
    epoch: u64,
) -> Result<VerifiedCommit, StoreFailure> {
    let context = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or_else(invalid)?;
    let roots = context
        .roots()
        .iter()
        .map(|root| RequestRoot {
            path: root.path(),
            domain: root.domain(),
        })
        .collect::<Vec<_>>();
    let reference = context.reference().to_owned();
    let surface = context.surface().to_owned();
    let locality = context.locality().clone();
    let request = Request {
        reference: reference.as_bytes(),
        verb: Verb::Commit,
        roots: &roots,
        now: commit.provenance.observed_at,
        surface: &surface,
        locality: &locality,
        epochs: &[(&reference, epoch)],
    };
    provenance::sign_authored(commit.clone(), secret, guard.keys(), &request, epoch)
        .map_err(|_| invalid())
}

fn attribute_location(
    history: &VerifiedHistory,
    initial: &EntryLocation,
    name: &str,
    producer: Digest,
    full_path: &[u8],
) -> Result<EntryLocation, StoreFailure> {
    let mut current = initial.clone();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.clone()) {
            return Err(invalid());
        }
        if current.commit == producer {
            history.entry(&current).map_err(|_| invalid())?;
            return Ok(current);
        }
        let commit = history.commit(&current.commit).ok_or_else(invalid)?;
        let origin = commit
            .commit()
            .profile_pair
            .entry_receipts
            .as_ref()
            .and_then(|receipts| {
                receipts
                    .iter()
                    .find(|receipt| receipt.root == current.root && receipt.path == current.path)
            })
            .and_then(|receipt| receipt.attributes.as_ref())
            .and_then(|attributes| attributes.iter().find(|(attribute, _)| attribute == name))
            .map(|(_, origin)| origin);
        match origin {
            Some(EntryOrigin::Source(source)) => {
                current = EntryLocation {
                    commit: source.commit,
                    root: source.root,
                    path: source.path.clone(),
                }
            }
            Some(EntryOrigin::Current) => return Err(invalid()),
            None => {
                let (location, _) = history.locate(producer, full_path).map_err(|_| invalid())?;
                history.entry(&location).map_err(|_| invalid())?;
                return Ok(location);
            }
        }
    }
}

async fn public_transfers<F, B, V, C>(
    source: &Guard<crate::bucket::held::HeldBucket<'_, F, B, V, false>, C>,
    checked: &DisclosureSource<'_, F>,
    retained_destination: Option<&VerifiedHistory>,
    roots: BTreeSet<Digest>,
) -> Result<Vec<StagedUpload>, StoreFailure>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let mut pending = roots.into_iter().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut uploads = Vec::new();
    while let Some(identity) = pending.pop() {
        if !seen.insert(identity) {
            continue;
        }
        // Candidate completion establishes public retainability. A dependency
        // freshly verified under the destination observation already has its
        // complete ancestry and immutable witnesses there; raw byte presence
        // alone never permits this transfer omission.
        if retained_destination.is_some_and(|history| history.commit(&identity).is_some()) {
            continue;
        }
        let history = checked
            .snapshots
            .iter()
            .map(|snapshot| &snapshot.history)
            .find(|history| history.commit(&identity).is_some())
            .ok_or_else(invalid)?;
        let commit = history.commit(&identity).ok_or_else(invalid)?;
        let evidence = TreeEvidence::load_tree(
            source.store(),
            commit.commit().tree,
            &[],
            source.config().min_chunk_size,
        )
        .await?;
        uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Commit,
            bytes: commit.commit().encode().map_err(|_| invalid())?,
        });
        for bytes in evidence.nodes.values() {
            uploads.push(StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: bytes.clone(),
            });
        }
        if commit
            .commit()
            .profile_pair
            .entry_receipts
            .iter()
            .flatten()
            .any(|receipt| receipt.disclosure_proof.is_some())
        {
            let roles = source.history_disclosure_roles()?;
            let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
            let candidate = provenance::DisclosureCandidate::new(
                history,
                identity,
                &authorities,
                source.defaults_for(&evidence),
            )
            .map_err(|_| invalid())?;
            pending.extend(candidate.required_commits());
        } else {
            pending.extend(commit.commit().parents.iter().copied());
            pending.extend(provenance::source_commit_references(commit));
        }
    }
    Ok(uploads)
}

fn same_heads(
    before: &SelectedObservation<'_>,
    after: &SelectedObservation<'_>,
) -> Result<(), StoreFailure> {
    if before.state().guard != after.state().guard
        || before.state().branches != after.state().branches
        || before.state().sources != after.state().sources
        || before.state().loss_generation != after.state().loss_generation
    {
        return Err(invalid());
    }
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Coordinates opt-in native test pauses after baseline retention and before pair acquisition.
#[cfg(all(test, feature = "tokio"))]
pub(super) mod test_pause {
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };
    use tokio::sync::oneshot;

    use super::{StoreFailure, invalid};

    struct Pause {
        entered: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }

    static PAUSES: OnceLock<Mutex<BTreeMap<PathBuf, Pause>>> = OnceLock::new();

    /// Arms one exact native destination after baseline retention and before pair acquisition.
    ///
    /// # Errors
    /// Rejects poisoned synchronization or an already armed physical destination.
    pub(crate) fn pause_next_after_baseline(
        root: &Path,
    ) -> Result<(oneshot::Receiver<()>, oneshot::Sender<()>), StoreFailure> {
        let (entered, observed) = oneshot::channel();
        let (resume, resumed) = oneshot::channel();
        let mut pauses = PAUSES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invalid())?;
        if pauses.contains_key(root) {
            return Err(invalid());
        }
        pauses.insert(
            root.to_owned(),
            Pause {
                entered,
                resume: resumed,
            },
        );
        Ok((observed, resume))
    }

    /// Signals an armed destination's baseline boundary and waits for its test to resume.
    ///
    /// Returns immediately when this destination has no armed pause. The pause
    /// supplies no publication authority or guarantee about elapsed time.
    ///
    /// # Errors
    /// Rejects poisoned synchronization, a dropped entered receiver or a dropped
    /// resume sender.
    pub(super) async fn after_baseline(root: &Path) -> Result<(), StoreFailure> {
        let pause = PAUSES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invalid())?
            .remove(root);
        if let Some(pause) = pause {
            pause.entered.send(()).map_err(|_| invalid())?;
            pause.resume.await.map_err(|_| invalid())?;
        }
        Ok(())
    }
}
