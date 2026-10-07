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
use terrane_core::gc::publication::{CommittedSelection, SourceLineage};
use terrane_core::refs::{RefClass, RefLogRecord, RefName};

/// Publishes a previously genuinely cold-prepared candidate under actual exclusion.
///
/// # Errors
/// Refuses changed sources, profiles or controls, missing Original associations,
/// denied original/current rights, stale heads, expiry and typed durable failures.
pub(crate) async fn publish<'held, F, B, V, C, R, D>(
    concrete: &Guard<FileBucket<F, B, V>, D>,
    authority: &OriginalAuthority,
    coordinator: &'held Coordinator<HeldBucket<'held, F, B, V, true>, C, R>,
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
        next.policy = Some(terrane_core::refs::RefPolicy::default());
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
    let staged = coordinator.store().observe_publication().await?;
    if staged.state().guard != observed.state().guard
        || staged.state().loss_generation != observed.state().loss_generation
        || staged.state().branches != observed.state().branches
        || staged.state().sources != observed.state().sources
    {
        return Err(invalid().into());
    }
    immutable.check_selection(&staged)?;
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
    check_read(&initial_guard, &qualified.guard_read)?;
    check_read(&initial_lineage, &qualified.lineage_read)?;
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
    derivation::extend_completed_fork(
        coordinator.guard(),
        &qualified,
        admitted,
        &publication.original,
        &mut used,
    )?;
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
    let final_snapshot = snapshot.clone();
    let final_authority = authority.clone();
    let final_check = super::super::super::OwnedFinalCheck {
        check: super::super::SharedCheck::new(move || {
            requests.recheck()?;
            if ConsumedResolver::new(&configured, &final_authority)?.snapshot_bytes()?
                != final_snapshot
            {
                return Err(invalid());
            }
            for view in &checked_lineage.used.views {
                configured.compare_requalification_view_inputs(&checked_lineage, view)?;
            }
            Ok(())
        }),
    };
    let permit = super::super::super::CheckedMutation {
        observed: &staged,
        sources: Vec::new(),
        next: state,
        changes,
        evidence: super::super::super::CheckedEvidence::Candidate { snapshot, lineage },
        final_check: Box::new(|| final_check.recheck()),
        effect_context: Some(GuardEffectContext {
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
    retained: &mut Vec<terrane_core::gc::publication::evidence::RequiredControlPin>,
    actual: &[terrane_core::gc::publication::evidence::RequiredControlPin],
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
