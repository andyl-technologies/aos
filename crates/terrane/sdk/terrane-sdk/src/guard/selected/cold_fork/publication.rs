//! Publishes fresh cold forks through the genuine selected mutation factory.
//!
//! The source is requalified after immutable staging. Its prior complete
//! evidence covers the identical physical tree only under independently equal
//! new authoring semantics; fresh signing, Original and current rights remain
//! separate checks. No normal tree/history walker is called by this route.

use super::super::{GuardEffectContext, capture_selected_reads, retain_final_check};
use super::*;
use crate::guard::AssociationView;
use crate::ref_advance::{Coordinator, RetainedPublication, WriterSession};
use crate::store::{ContentUpload, MetaUpload, RefLogAppendOutcome};
use terrane_format::gc::publication::{CommittedSelection, SourceLineage};
use terrane_format::refs::{RefClass, RefLogRecord, RefName};

/// Publishes a previously genuinely cold-prepared candidate under actual exclusion.
///
/// # Errors
/// Refuses changed sources, profiles or controls, missing Original associations,
/// denied original/current rights, stale heads, expiry and typed durable failures.
pub(crate) async fn publish<'operation, 'held: 'operation, F, B, V, C, R, D>(
    concrete: &Guard<FileBucket<F, B, V>, D>,
    authority: &OriginalAuthority,
    coordinator: &'operation Coordinator<HeldBucket<'held, F, B, V, true>, C, R>,
    observed: &SelectedObservation<'held>,
    session: &mut WriterSession,
    publication: &RetainedPublication,
) -> Result<RefRecord, AdvanceError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + BucketBinding,
    R: LocalFs + BucketBinding,
{
    #[cfg(test)]
    let mut trace = crate::ref_advance::PhaseTrace::new(
        coordinator.guard().clock(),
        session.reference(),
        Some(publication.admitted.commit.identity()),
        Some(publication.started),
        "cold-publication-entry",
    );
    let admitted = &publication.admitted;
    admitted
        .cold_fork
        .as_ref()
        .ok_or_else(invalid)?
        .check(admitted)?;
    let source = admitted.source_authorization.as_ref().ok_or_else(invalid)?;
    if session.record().is_some()
        || RefName::parse(session.reference())
            .map_err(|_| invalid())?
            .class()
            != RefClass::Heads
    {
        return Err(invalid().into());
    }
    let selected_reads =
        capture_selected_reads(coordinator.store(), observed, &[&source.reference]).await?;
    let mut qualified = qualify_source(
        concrete,
        authority,
        coordinator.guard(),
        observed,
        ColdForkRequest {
            source: &source.reference,
            token: &admitted.token,
            surface: &admitted.surface,
            started: publication.started,
            timing: publication.timing,
        },
    )
    .await?;
    #[cfg(test)]
    trace.mark("cold-source-qualified");
    let early_destination = coordinator
        .guard()
        .check_cold_fork_candidate(
            &mut qualified,
            admitted,
            session.reference(),
            session.epoch(),
            publication.original.baseline(),
        )
        .await?;
    #[cfg(test)]
    trace.mark("cold-early-candidate-checked");
    let original_pins = crate::guard::publication_original_pins(&publication.original)?;
    let mut controls = qualified.policies.lineage.controls.clone();
    merge_controls(&mut controls, &original_pins)?;
    let initial_controls = qualified.controls.retain_used(&controls).await?;
    check_original(
        coordinator.guard(),
        &publication.original,
        &initial_controls,
        observed,
    )
    .await?;
    qualified.revalidate(coordinator.guard()).await?;
    #[cfg(test)]
    trace.mark("cold-initial-original-revalidated");
    let initial_control_stamp = control_stamp(&initial_controls);
    let initial_guard = qualified.guard_read.clone();
    let initial_lineage = qualified.lineage_read.clone();
    let early_requests = [qualified.authorization().clone(), early_destination];
    let early_check = retain_final_check(
        coordinator.guard(),
        &early_requests,
        publication.started,
        publication.timing,
    )?;
    let immutable = super::super::meta_batch::from_cold(ColdImmutableInputs {
        effect: GuardEffectContext {
            existing_reads: Vec::new(),
            final_check: early_check,
            controls: vec![initial_controls.clone()],
            selected_reads: selected_reads.clone(),
            publication_original: Some(publication.original.clone()),
        },
        selected: observed.state().clone(),
    });
    immutable.check_selection(observed)?;

    // Keep the same actual Original exclusion through Commit staging and final
    // requalification. No early resolver finish or ordinary history walk runs.
    coordinator.check_time(publication.started)?;
    let encoded = admitted.commit.commit().encode().map_err(|_| invalid())?;
    let offered = [MetaUpload::new(IdentityKind::Commit, &encoded)?];
    let written = match coordinator
        .store()
        .put_meta_batch(&offered, &immutable)
        .await?
    {
        crate::bucket::held::BatchOutcome::Complete(mut identities) if identities.len() == 1 => {
            identities.remove(0)
        }
        crate::bucket::held::BatchOutcome::Complete(_) => return Err(invalid().into()),
        crate::bucket::held::BatchOutcome::Sequential => {
            coordinator
                .store()
                .put_contextual(ContentUpload::Meta(offered[0]), &immutable)
                .await?
        }
    };
    if written
        != TERRANE_V1
            .from_digest(IdentityKind::Commit, &admitted.commit.identity())
            .map_err(|_| invalid())?
    {
        return Err(invalid().into());
    }
    #[cfg(test)]
    trace.mark("cold-commit-staged");
    let retained = observed
        .state()
        .branches
        .iter()
        .find(|row| row.name == session.reference())
        .map(|row| &row.selection);
    let previous = match retained {
        Some(CommittedSelection::Unknown) => {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
        }
        Some(CommittedSelection::Selected(previous)) => {
            if session.epoch() <= previous.writer_epoch {
                return Err(invalid().into());
            }
            Some(previous.as_ref())
        }
        _ => None,
    };
    let mut next = match previous {
        Some(previous) => previous
            .advance(admitted.commit.identity(), session.epoch())
            .map_err(|_| AdvanceError::Exhausted)?,
        None => RefRecord::first(
            admitted.commit.identity(),
            session.epoch(),
            coordinator.guard().config().home.clone(),
        ),
    };
    if next.policy.is_none() && admitted.commit.commit().profile_pair.conflicted == Some(true) {
        next.policy = Some(terrane_format::refs::RefPolicy::default());
    }
    if let Some(policy) = &mut next.policy {
        policy.conflicted = admitted.commit.commit().profile_pair.conflicted;
    }
    loop {
        coordinator.check_time(publication.started)?;
        immutable.recheck()?;
        qualified.controls.revalidate().await?;
        next.candidate_id = Some(
            coordinator
                .fs()
                .random_bytes(32)
                .await
                .map_err(|error| {
                    StoreFailure::with_source(
                        StoreErrorKind::Unavailable { retry_after: None },
                        error,
                    )
                })?
                .try_into()
                .map_err(|_| invalid())?,
        );
        let log = RefLogRecord {
            record: next.clone(),
            previous_commit: previous.map(|record| record.commit),
            principal: admitted.principal.clone(),
            reason: publication.reason,
            timestamp: admitted.timestamp,
            expected_previous: Some(None),
            committed_previous: previous.cloned(),
        };
        match coordinator
            .store()
            .ref_log_append(session.reference(), next.seq, &log)
            .await?
        {
            RefLogAppendOutcome::Appended => break,
            RefLogAppendOutcome::Exists => {
                if coordinator
                    .store()
                    .ref_get(session.reference())
                    .await?
                    .is_some()
                {
                    return coordinator.fence(session).await;
                }
            }
        }
    }
    #[cfg(test)]
    trace.mark("cold-log-staged");
    let staged = coordinator.store().observe_publication().await?;
    if staged.state().guard != observed.state().guard
        || staged.state().loss_generation != observed.state().loss_generation
        || staged.state().branches != observed.state().branches
        || staged.state().sources != observed.state().sources
    {
        return Err(invalid().into());
    }
    #[cfg(test)]
    trace.mark("cold-staged-authority-compared");
    immutable.check_selection(&staged)?;
    #[cfg(test)]
    trace.mark("cold-staged-selection-checked");
    let same_controls = qualified.controls;
    let mut qualified = qualify_source_with_controls(
        concrete,
        authority,
        coordinator.guard(),
        &staged,
        ColdForkRequest {
            source: &source.reference,
            token: &admitted.token,
            surface: &admitted.surface,
            started: publication.started,
            timing: publication.timing,
        },
        Some(same_controls),
    )
    .await?;
    #[cfg(test)]
    trace.mark("cold-source-requalified");
    check_read(&initial_guard, &qualified.guard_read)?;
    check_read(&initial_lineage, &qualified.lineage_read)?;
    #[cfg(test)]
    trace.mark("cold-source-records-compared");
    let destination = coordinator
        .guard()
        .check_cold_fork_candidate(
            &mut qualified,
            admitted,
            session.reference(),
            session.epoch(),
            publication.original.baseline(),
        )
        .await?;
    #[cfg(test)]
    trace.mark("cold-final-candidate-checked");
    let retained_controls = qualified.controls.retain_used(&controls).await?;
    super::super::meta_batch::check_continuity(&initial_controls, &retained_controls)?;
    if initial_control_stamp != control_stamp(&retained_controls) {
        return Err(invalid().into());
    }
    check_original(
        coordinator.guard(),
        &publication.original,
        &retained_controls,
        &staged,
    )
    .await?;
    qualified.revalidate(coordinator.guard()).await?;
    coordinator
        .guard()
        .retain_cold_fork_selection(&qualified, admitted, &publication.original)?;

    #[cfg(test)]
    trace.mark("cold-final-original-retained");
    let requests = [qualified.authorization().clone(), destination];
    let consumed = ConsumedResolver::new(coordinator.guard(), authority)?;
    consumed.registration(authority)?;
    consumed.original(&publication.original)?;
    consumed.issuer(&admitted.commit)?;
    for request in &requests {
        consumed.operation(request)?;
    }
    let actual = consumed.finish()?;
    let snapshot = consumed.snapshot_bytes()?;
    let mut used = qualified.policies.lineage.used.clone();
    merge_controls(&mut used.controls, &actual.controls)?;
    merge_rows(&mut used.issuers, &actual.issuers, |row| {
        (row.issuer.clone(), row.key_id.clone())
    })?;
    merge_rows(&mut used.disclosures, &actual.disclosures, |row| {
        (
            row.repository.clone(),
            row.domain.clone(),
            row.public_key,
            row.not_before,
        )
    })?;
    used.configuration = actual.configuration;
    used.registries = actual.registries;
    #[cfg(test)]
    trace.mark("cold-actual-inputs-captured");
    derivation::extend_completed_fork(
        coordinator.guard(),
        &qualified,
        admitted,
        &publication.original,
        &mut used,
    )?;
    #[cfg(test)]
    trace.mark("cold-fork-lineage-extended");
    let digest = *blake3::hash(&snapshot).as_bytes();
    let lineage = CheckedLineage {
        source_name: session.reference().to_owned(),
        source: next.clone(),
        commit_id: admitted.commit.identity(),
        commit_bytes: encoded,
        guard_digest: digest,
        loss_generation: staged.state().loss_generation,
        controls: used.controls.clone(),
        original: consumed_registration(authority),
        used,
    }
    .encode()
    .map_err(|_| invalid())?;
    #[cfg(test)]
    trace.mark("cold-lineage-encoded");
    let (mut state, changes) = staged.ref_transition(session.reference(), &next)?;
    state.sources.push(SourceLineage {
        name: session.reference().to_owned(),
        digest: *blake3::hash(&lineage).as_bytes(),
    });
    state
        .sources
        .sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let requests = retain_final_check(
        coordinator.guard(),
        &requests,
        publication.started,
        publication.timing,
    )?;
    let configured = coordinator
        .guard()
        .source_requalification_configuration_adapter()?;
    let checked_lineage = qualified.policies.lineage.clone();
    let snapshot_disclosures = ConsumedResolver::snapshot_disclosure_inputs(coordinator.guard())?;
    let final_snapshot = snapshot.clone();
    let final_authority = authority.clone();
    #[cfg(test)]
    let callback_trace =
        crate::ref_advance::NativeTrace::new(authority.root(), "cold-final-callback");
    let final_check = super::super::super::OwnedFinalCheck {
        check: super::super::SharedCheck::new(move || {
            #[cfg(test)]
            callback_trace.mark("callback-entry");
            requests.recheck()?;
            #[cfg(test)]
            callback_trace.mark("callback-requests-rechecked");
            #[cfg(test)]
            if std::env::var_os("TERRANE_REF_PHASE_TRACE").is_some() {
                match ConsumedResolver::new_with_snapshot_disclosures(
                    &configured,
                    &final_authority,
                    &snapshot_disclosures,
                ) {
                    Err(error) => eprintln!("cold-snapshot-acquisition-error {:?}", error.kind()),
                    Ok(resolver) => match resolver.snapshot_bytes() {
                        Err(error) => eprintln!("cold-snapshot-encoding-error {:?}", error.kind()),
                        Ok(bytes) => {
                            let actual = GuardSnapshot::decode(&bytes);
                            let expected = GuardSnapshot::decode(&final_snapshot);
                            if let (Ok(actual), Ok(expected)) = (actual, expected) {
                                eprintln!(
                                    "cold-snapshot-equality bytes={} registration={} issuers={} disclosures={} configuration={} registries={}",
                                    bytes == final_snapshot,
                                    actual.registration == expected.registration,
                                    actual.issuers == expected.issuers,
                                    actual.disclosures == expected.disclosures,
                                    actual.configuration == expected.configuration,
                                    actual.registries == expected.registries,
                                );
                            } else {
                                eprintln!("cold-snapshot-diagnostic-decode-error");
                            }
                        }
                    },
                }
            }
            if ConsumedResolver::new_with_snapshot_disclosures(
                &configured,
                &final_authority,
                &snapshot_disclosures,
            )?
            .snapshot_bytes()?
                != final_snapshot
            {
                return Err(invalid());
            }
            #[cfg(test)]
            callback_trace.mark("callback-snapshot-compared");
            for view in &checked_lineage.used.views {
                #[cfg(test)]
                callback_trace.mark("callback-view-comparison-entry");
                configured.compare_requalification_view_inputs(&checked_lineage, view)?;
                #[cfg(test)]
                callback_trace.mark("callback-view-compared");
            }
            Ok(())
        }),
    };
    #[cfg(test)]
    trace.mark("cold-final-check-retained");
    let permit = super::super::super::CheckedMutation {
        observed: &staged,
        sources: Vec::new(),
        next: state,
        changes,
        evidence: super::super::super::CheckedEvidence::Candidate { snapshot, lineage },
        final_check: Box::new(|| final_check.recheck()),
        effect_context: Some(GuardEffectContext {
            existing_reads: Vec::new(),
            final_check: final_check.clone(),
            controls: vec![retained_controls],
            selected_reads,
            publication_original: Some(publication.original.clone()),
        }),
    };
    match coordinator.store().publish_checked(permit).await {
        Ok(_) => Ok(coordinator.acknowledge_selected(session, next)),
        Err(error) if matches!(error.kind(), StoreErrorKind::Unavailable { .. }) => {
            Err(coordinator.selected_indeterminate(session, error).await)
        }
        Err(error) => Err(error.into()),
    }
}

async fn check_original<F, B, V, C>(
    guard: &Guard<HeldBucket<'_, F, B, V, true>, C>,
    original: &crate::guard::OriginalCommitContext,
    controls: &RetainedControls,
    observed: &SelectedObservation<'_>,
) -> Result<(), StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    guard.retain_original_controls(controls)?;
    let baseline = original.baseline();
    let checked = guard
        .recheck_original_commit_observed(
            baseline,
            AssociationView {
                commit: original.commit(),
                id: baseline.authority().id(),
                reference: baseline.reference(),
                epoch: baseline.epoch(),
            },
            observed.identity(),
        )
        .await?;
    if checked != *original {
        return Err(invalid());
    }
    Ok(())
}

fn merge_controls(
    retained: &mut Vec<terrane_format::gc::publication::evidence::RequiredControlPin>,
    actual: &[terrane_format::gc::publication::evidence::RequiredControlPin],
) -> Result<(), StoreFailure> {
    let mut rows = BTreeMap::new();
    for pin in retained.iter().chain(actual) {
        let key = (
            pin.kind,
            pin.owner.encode().map_err(|_| invalid())?,
            pin.key.clone(),
        );
        if rows.insert(key, pin.clone()).is_some_and(|old| old != *pin) {
            return Err(invalid());
        }
    }
    *retained = rows.into_values().collect();
    Ok(())
}

fn merge_rows<T: Clone + Eq, K: Ord>(
    retained: &mut Vec<T>,
    actual: &[T],
    key: impl Fn(&T) -> K,
) -> Result<(), StoreFailure> {
    let mut rows = BTreeMap::new();
    for row in retained.iter().chain(actual) {
        if rows
            .insert(key(row), row.clone())
            .is_some_and(|old| old != *row)
        {
            return Err(invalid());
        }
    }
    *retained = rows.into_values().collect();
    Ok(())
}

/// Copies an ancestor's path, physical identity and ownership/protection stamp.
type ProtectedAncestorStamp = (std::path::PathBuf, (u64, u64), (u32, u32));

// Copies observations for continuity checks while the same actual control
// exclusion remains retained through catalog staging and final qualification.
#[derive(Eq, PartialEq)]
struct ControlStamp {
    directory: std::path::PathBuf,
    owner: u32,
    identities: ((u64, u64), (u64, u64)),
    ancestors: Vec<ProtectedAncestorStamp>,
    records: Vec<(std::path::PathBuf, (u64, u64), Vec<u8>)>,
}

fn control_stamp(controls: &RetainedControls) -> ControlStamp {
    ControlStamp {
        directory: controls.directory().to_path_buf(),
        owner: controls.owner(),
        identities: controls.identities(),
        ancestors: controls
            .ancestors()
            .iter()
            .map(|row| (row.path().to_path_buf(), row.identity(), row.protection()))
            .collect(),
        records: controls
            .records()
            .iter()
            .map(|row| {
                (
                    row.path().to_path_buf(),
                    row.identity(),
                    row.bytes().to_vec(),
                )
            })
            .collect(),
    }
}
