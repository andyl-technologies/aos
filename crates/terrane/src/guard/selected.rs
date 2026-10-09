//! Owns native checked-publication producers under actual held observations.
//!
//! This file is a descendant of `selected_bridge`, so its genuine verification
//! factories can construct the neutral capability's private fields. Storage
//! consumers receive only the opaque capability and its read-only accessors.

use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{ConsumedResolver, Guard, OriginalAuthority};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_core::gc::publication::{BackendBinding, RawDigest};

use super::{CheckedEvidence, CheckedMutation};

#[cfg(unix)]
#[path = "selected/source_requalification.rs"]
pub(crate) mod source_requalification;

#[path = "selected/meta_batch.rs"]
pub(crate) mod meta_batch;

#[cfg(all(feature = "tokio", unix))]
#[path = "selected/held_history.rs"]
mod held_history;

#[cfg(unix)]
#[path = "selected/cold_fork.rs"]
pub(crate) mod cold_fork;

#[cfg(not(feature = "send"))]
use std::rc::Rc as SharedCheck;
#[cfg(feature = "send")]
use std::sync::Arc as SharedCheck;

/// Retains checks from actual successful authenticated authorization snapshots.
///
/// This check remains separate from the held physical and control evidence.
///
/// # Errors
/// Refuses mismatched or invalid request snapshots and unsupported retained
/// clocks; later checks preserve the original token and operation deadlines.
pub(crate) fn retain_final_check<S: crate::store::Store, C: Clock>(
    guard: &Guard<S, C>,
    requests: &[crate::guard::AuthorizedRef],
    started: std::time::Duration,
    timing: crate::ref_advance::CommitTiming,
) -> Result<super::OwnedFinalCheck, StoreFailure> {
    let checks = guard.retain_request_checks(requests, started, timing.maximum())?;
    Ok(super::OwnedFinalCheck {
        check: SharedCheck::new(move || checks.recheck()),
    })
}

/// Retains local control exclusion with exact data consumed by a held operation.
pub(crate) struct LocalControlInputs<'guard, F: LocalFs> {
    exclusion: crate::guard::ControlExclusion<'guard, F>,
    snapshot: Vec<u8>,
    used: terrane_core::gc::publication::evidence::LineageUsedInputs,
}

/// Owns genuine final request checks and the actual consumed control receipts.
///
/// Only this producer initializes the private fields after canonical selected
/// state and control verification. The lower executor derives fixed effects
/// from a checked mutation carrying this context; decoded records cannot mint it.
pub(crate) struct GuardEffectContext {
    final_check: super::OwnedFinalCheck,
    controls: Vec<crate::guard::RetainedControls>,
    selected_reads: Vec<SelectedControlRead>,
    publication_original: Option<crate::guard::OriginalCommitContext>,
    existing_reads: Vec<crate::bucket::publication::receipts::RecordRead>,
}

/// Retains one actual separately protected selected read and its configured owner.
///
/// Only this producer binds records to actual backend observations. It grants
/// no mutation, actor or trust authority and accepts no caller UID.
#[derive(Clone)]
pub(crate) struct SelectedControlRead {
    record: crate::bucket::publication::receipts::RecordRead,
    owner: u32,
}

impl SelectedControlRead {
    /// Borrows the exact actual protected record and its initial physical preimage.
    pub(crate) fn record(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.record
    }

    /// Returns the independently configured owner of that actual observation.
    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }
}

// Binds ordinary physical read data only to the actual configured backend owner.
fn selected_control_read(
    observed: &SelectedObservation<'_>,
    record: crate::bucket::publication::receipts::RecordRead,
) -> SelectedControlRead {
    SelectedControlRead {
        record,
        owner: observed.configured_operator_uid(),
    }
}

// Captures the initial protected selected preimages before any staging work.
async fn capture_selected_reads<F, B, V, const WRITABLE: bool>(
    held: &HeldBucket<'_, F, B, V, WRITABLE>,
    observed: &SelectedObservation<'_>,
    names: &[&str],
) -> Result<Vec<SelectedControlRead>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let mut reads = Vec::new();
    if let Some(record) = held.selected_guard_snapshot_record(observed).await? {
        reads.push(selected_control_read(observed, record));
    }
    let mut unique = std::collections::BTreeSet::new();
    for name in names {
        if !unique.insert(*name) {
            continue;
        }
        if let Some(record) = held.selected_lineage_record(observed, name).await? {
            reads.push(selected_control_read(observed, record));
        }
    }
    Ok(reads)
}

impl GuardEffectContext {
    /// Borrows original payload observations retained by this actual operation.
    pub(crate) fn existing_reads(&self) -> &[crate::bucket::publication::receipts::RecordRead] {
        &self.existing_reads
    }

    /// Borrows the actual retained new candidate context chosen by this producer.
    ///
    /// Absence never establishes that consumed controls were previously durable;
    /// non-candidate producers conservatively synchronize all their actual rows.
    pub(crate) fn publication_original(&self) -> Option<&crate::guard::OriginalCommitContext> {
        self.publication_original.as_ref()
    }

    /// Retains the same genuine owned request check for submitted dispatch.
    pub(crate) fn final_check(&self) -> super::OwnedFinalCheck {
        self.final_check.clone()
    }

    /// Borrows protected selected preimages retained through native acknowledgment.
    pub(crate) fn selected_reads(&self) -> &[SelectedControlRead] {
        &self.selected_reads
    }

    /// Borrows each owner's exact controls and already duplicated kernel exclusions.
    pub(crate) fn controls(&self) -> &[crate::guard::RetainedControls] {
        &self.controls
    }
}

/// Publishes a create-once tag under actual source and selected Guard exclusion.
///
/// Tag-only source authority remains sufficient. The exact name, source whole
/// record, annotation signature and real current requests are independently
/// checked before constructing an advisory transition with no branch lineage.
///
/// # Errors
/// Rejects altered target bindings, current source denial, existing targets,
/// stale Guard configuration and controls, and expired operation authority.
pub(crate) async fn publish_tag<F, B, V, C, R, D>(
    concrete: &Guard<FileBucket<F, B, V>, D>,
    authority: &OriginalAuthority,
    coordinator: &crate::ref_advance::Coordinator<HeldBucket<'_, F, B, V, true>, C, R>,
    observed: &SelectedObservation<'_>,
    request: crate::ref_advance::NativeTagRequest,
) -> Result<terrane_core::refs::RefRecord, crate::ref_advance::AdvanceError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + BucketBinding,
    R: LocalFs + BucketBinding,
{
    use crate::store::RefStore;
    let crate::ref_advance::NativeTagRequest {
        source,
        target,
        token,
        surface,
        publication,
        started,
        timing,
    } = request;
    let selected_reads =
        capture_selected_reads(coordinator.store(), observed, &[source.as_str()]).await?;
    publication.validate_target(&target)?;
    coordinator.check_time(started)?;
    let consumed = ConsumedResolver::new(concrete, authority)?;
    consumed.registration(authority)?;
    let history = crate::guard::HistoryObservation::held(observed.identity()).tracked(&consumed);
    let requests = coordinator
        .guard()
        .capture_tag_authorizations_observed(&source, &token, &surface, &publication, history)
        .await?;
    for request in &requests {
        consumed.operation(request)?;
    }
    if let Some(current) = coordinator.store().ref_get(&target).await? {
        return Err(crate::ref_advance::AdvanceError::Fenced {
            current: Some(Box::new(current)),
        });
    }
    let held = coordinator.store();
    let LocalControlInputs {
        exclusion: mut controls,
        snapshot,
        used,
    } = hold_consumed_controls(concrete, authority, held, observed, &consumed).await?;
    coordinator.check_time(started)?;
    let (next, changes) = observed.ref_transition(&target, &publication.target)?;
    let retained_controls = controls.retain_used(&used.controls).await?;
    let final_check = retain_final_check(coordinator.guard(), &requests, started, timing)?;
    let permit = CheckedMutation {
        observed,
        sources: Vec::new(),
        next,
        changes,
        evidence: CheckedEvidence::Advisory { snapshot },
        final_check: Box::new(|| final_check.recheck()),
        effect_context: Some(GuardEffectContext {
            existing_reads: Vec::new(),
            final_check: final_check.clone(),
            controls: vec![retained_controls],
            selected_reads,
            publication_original: None,
        }),
    };
    match held.publish_checked(permit).await {
        Ok(_) => Ok(publication.target),
        Err(failure) if matches!(failure.kind(), StoreErrorKind::Unavailable { .. }) => {
            Err(crate::ref_advance::AdvanceError::Indeterminate {
                observed: held
                    .ref_get(&target)
                    .await
                    .map(|record| record.map(Box::new)),
                source: Box::new(failure),
            })
        }
        Err(failure) => {
            coordinator.check_time(started)?;
            Err(failure.into())
        }
    }
}

/// Publishes an authored record against its exact selected observation.
///
/// Immutable content and the candidate log become durable before the private
/// checked transition is constructed. Actual current requests and local consumed
/// controls remain captured through selected-slot acknowledgment. This local
/// route rejects foreign original controls instead of treating imports as local.
/// Notes retain the selected Guard without acquiring branch history or lineage.
///
/// # Errors
/// Preserves current-policy, original-context, storage and duration failures;
/// rejects unknown retained history, stale selected configuration and epochs.
pub(crate) async fn publish_candidate<'held, F, B, V, C, R, D>(
    concrete: &Guard<FileBucket<F, B, V>, D>,
    authority: &OriginalAuthority,
    coordinator: &crate::ref_advance::Coordinator<HeldBucket<'held, F, B, V, true>, C, R>,
    observed: &SelectedObservation<'held>,
    consumed: &ConsumedResolver,
    session: &mut crate::ref_advance::WriterSession,
    publication: &mut crate::ref_advance::RetainedPublication,
) -> Result<terrane_core::refs::RefRecord, crate::ref_advance::AdvanceError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + BucketBinding,
    R: LocalFs + BucketBinding,
{
    use terrane_core::gc::publication::evidence::CheckedLineage;
    use terrane_core::gc::publication::{CommittedSelection, SourceLineage};
    use terrane_core::refs::{RefClass, RefName};

    let source_names = publication
        .admitted
        .source_authorization
        .as_ref()
        .map(|source| source.reference.as_str())
        .into_iter()
        .collect::<Vec<_>>();
    let selected_reads =
        capture_selected_reads(coordinator.store(), observed, &source_names).await?;
    let crate::ref_advance::RetainedPublication {
        admitted,
        original,
        started,
        reason,
        timing,
    } = publication;
    let started = *started;
    let reason = *reason;
    let timing = *timing;

    #[cfg(test)]
    let mut trace = coordinator.phase_trace(
        session.reference(),
        Some(admitted.commit.identity()),
        started,
        "selected-entry",
    );

    let publication_reference = session.reference().to_owned();
    let class = RefName::parse(&publication_reference)
        .map_err(|_| invalid())?
        .class();
    if class == RefClass::Tags {
        return Err(crate::ref_advance::AdvanceError::InvalidRefClass);
    }

    let retained = observed
        .state()
        .branches
        .iter()
        .find(|row| row.name == session.reference())
        .map(|row| &row.selection);
    let retained_previous = match retained {
        Some(CommittedSelection::Selected(previous)) if session.record().is_none() => {
            if session.epoch() <= previous.writer_epoch {
                return Err(invalid().into());
            }
            Some(previous.as_ref())
        }
        Some(CommittedSelection::Unknown) => {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
        }
        _ => None,
    };
    let proof = observed.identity();
    let candidate_inputs = coordinator.guard().capture_candidate_inputs(admitted)?;
    let history = crate::guard::HistoryObservation::held(proof)
        .tracked(consumed)
        .candidate(&candidate_inputs)
        .requested_target();
    let direct_container = admitted.uploads.iter().any(|upload| {
        matches!(upload, crate::guard::StagedUpload::Meta { kind, .. }
            if matches!(kind, terrane_core::identity::IdentityKind::Pack
                | terrane_core::identity::IdentityKind::Index))
    });
    let publication_observation = crate::ref_advance::PublicationObservation {
        history,
        original: Some(original),
    };
    let (next, local_controls, early_controls, history_context) = if direct_container {
        // Direct import/Index lanes retain their ordinary existing semantics.
        // No early control lock or contextual batch is created for this attempt.
        let next = coordinator
            .stage_observed_ref(
                session,
                admitted,
                started,
                reason,
                publication_observation,
                retained_previous,
            )
            .await?;
        (next, None, None, None)
    } else {
        let (immutable_context, local_controls) = meta_batch::retain(
            meta_batch::ControlOwner {
                concrete,
                authority,
            },
            meta_batch::NativeSelection {
                coordinator,
                observed,
                consumed,
            },
            meta_batch::CandidateRetention {
                admitted,
                publication_reference: &publication_reference,
                original,
                history,
                started,
                timing,
                selected_reads: &selected_reads,
            },
        )
        .await?;
        let next = coordinator
            .stage_observed_ref_native(
                crate::ref_advance::NativeStage {
                    session,
                    admitted,
                    started,
                    reason,
                    observation: publication_observation,
                    retained_previous,
                },
                &immutable_context,
            )
            .await?;
        let early_controls = immutable_context
            .effect_context()
            .controls()
            .first()
            .ok_or_else(invalid)?
            .clone();
        (
            next,
            Some(local_controls),
            Some(early_controls),
            Some(immutable_context),
        )
    };
    #[cfg(all(feature = "tokio", unix))]
    let mut local_controls = local_controls;
    #[cfg(all(feature = "tokio", unix))]
    let mut history_context = history_context;

    // Durable content and log staging can publish lower logical revisions. The
    // candidate therefore binds the refreshed actual held selection, while its
    // root-policy reads remain under this same physical exclusion.
    #[cfg(test)]
    trace.mark("selected-stage-durable");
    let retain_history_inputs = cfg!(all(feature = "tokio", unix)) && history_context.is_some();
    let staged_observation = if retain_history_inputs {
        coordinator.store().observe_publication_retained().await?
    } else {
        coordinator.store().observe_publication().await?
    };
    if staged_observation.state().guard != observed.state().guard
        || staged_observation.state().loss_generation != observed.state().loss_generation
        || staged_observation.state().branches != observed.state().branches
        || staged_observation.state().sources != observed.state().sources
    {
        return Err(invalid().into());
    }
    let observed = &staged_observation;
    #[cfg(all(feature = "tokio", unix))]
    let (completed_history, existing_reads) = match history_context.as_mut() {
        Some(context) => {
            held_history::complete(
                held_history::HistoryScope {
                    coordinator,
                    observed,
                    history,
                    view: admitted.commit.identity(),
                },
                authority,
                context,
                local_controls.as_mut().ok_or_else(invalid)?,
            )
            .await?
        }
        None => (
            coordinator
                .guard()
                .complete_candidate_history_observed(admitted.commit.identity(), history)
                .await?,
            Vec::new(),
        ),
    };
    #[cfg(not(all(feature = "tokio", unix)))]
    let (completed_history, existing_reads) = (
        coordinator
            .guard()
            .complete_candidate_history_observed(admitted.commit.identity(), history)
            .await?,
        Vec::new(),
    );

    #[cfg(test)]
    trace.mark("selected-candidate-history-checked");
    let mut requests = coordinator
        .guard()
        .capture_admission_authorizations_observed(admitted, history)
        .await?;
    requests.extend(
        coordinator
            .capture_source_authorizations_observed(admitted, history)
            .await?,
    );
    #[cfg(test)]
    trace.mark("selected-admission-source-captured");
    let current = coordinator
        .guard()
        .authorize_observed(
            session.reference(),
            &admitted.token,
            admitted.publication_verb,
            &[],
            &admitted.surface,
            history,
        )
        .await?;
    if current.record() != session.record() {
        return Err(invalid().into());
    }
    requests.push(current);
    for request in &requests {
        consumed.operation(request)?;
    }

    #[cfg(test)]
    trace.mark("selected-current-captured");
    let held = coordinator.store();
    let LocalControlInputs {
        exclusion: mut controls,
        snapshot,
        used,
    } = match local_controls {
        Some(local) => {
            refresh_consumed_controls(authority, held, observed, consumed, local.exclusion).await?
        }
        None => hold_consumed_controls(concrete, authority, held, observed, consumed).await?,
    };
    coordinator.check_time(started)?;
    #[cfg(test)]
    trace.mark("selected-consumed-controls-held");
    let retained_controls = controls.retain_used(&used.controls).await?;
    if let Some(early) = &early_controls {
        meta_batch::check_continuity(early, &retained_controls)?;
    }
    // The same held operation now owns the checked control receipt. Rechecking
    // its Original must read those exact records without reacquiring its lock.
    coordinator
        .guard()
        .retain_original_controls(&retained_controls)?;
    coordinator
        .guard()
        .revalidate_original_context(original, history)
        .await?;
    observed.revalidate().await?;
    coordinator.check_time(started)?;
    #[cfg(test)]
    trace.mark("selected-consumed-controls-retained");
    let digest = *blake3::hash(&snapshot).as_bytes();
    let (mut state, changes) = observed.ref_transition(session.reference(), &next)?;
    let evidence = if class == RefClass::Notes {
        CheckedEvidence::Advisory { snapshot }
    } else {
        let lineage = CheckedLineage {
            source_name: session.reference().to_owned(),
            source: next.clone(),
            commit_id: admitted.commit.identity(),
            commit_bytes: admitted.commit.commit().encode().map_err(|_| invalid())?,
            guard_digest: digest,
            loss_generation: observed.state().loss_generation,
            controls: used.controls.clone(),
            original: crate::guard::consumed_registration(authority),
            used,
        }
        .encode()
        .map_err(|_| invalid())?;
        state.sources.push(SourceLineage {
            name: session.reference().to_owned(),
            digest: *blake3::hash(&lineage).as_bytes(),
        });
        state
            .sources
            .sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        CheckedEvidence::Candidate { snapshot, lineage }
    };
    coordinator.guard().retain_completed_selection(
        &candidate_inputs,
        &completed_history,
        history,
    )?;
    let final_check = retain_final_check(coordinator.guard(), &requests, started, timing)?;
    let permit = CheckedMutation {
        observed,
        sources: Vec::new(),
        next: state,
        changes,
        evidence,
        final_check: Box::new(|| final_check.recheck()),
        effect_context: Some(GuardEffectContext {
            existing_reads,
            final_check: final_check.clone(),
            controls: vec![retained_controls],
            selected_reads,
            publication_original: Some(original.clone()),
        }),
    };
    #[cfg(test)]
    trace.mark("selected-dispatch");
    match held.publish_checked(permit).await {
        Ok(_) => {}
        Err(source) if matches!(source.kind(), StoreErrorKind::Unavailable { .. }) => {
            return Err(coordinator.selected_indeterminate(session, source).await);
        }
        Err(source) => {
            coordinator.check_time(started)?;
            return Err(source.into());
        }
    }
    #[cfg(test)]
    trace.mark("selected-durable-ack");
    Ok(coordinator.acknowledge_selected(session, next))
}

fn invalid() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(
        crate::store::InvalidReason::MalformedRequest,
    ))
}

/// Checks the exact selected Guard and all actually consumed local controls.
///
/// This retains the protected configuration exclusion for the caller's entire
/// selected operation. The returned canonical data establishes no publication
/// authority and cannot replace final operation or submitted-effect checks.
///
/// # Errors
/// Rejects a stale selected Guard, a different physical original authority,
/// unsupported foreign control owners, or changed protected canonical records.
pub(crate) async fn hold_consumed_controls<'guard, F, B, V, C>(
    guard: &'guard Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &SelectedObservation<'_>,
    consumed: &ConsumedResolver,
) -> Result<LocalControlInputs<'guard, F>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    observed.revalidate().await?;
    let controls = guard
        .hold_original_registration(authority, observed.identity())
        .await?;
    refresh_consumed_controls(authority, held, observed, consumed, controls).await
}

/// Revalidates consumed controls using the same actual acquired exclusion.
///
/// # Errors
/// Preserves selected Guard/trust/pin checks without reacquiring the held lock.
async fn refresh_consumed_controls<'guard, F, B, V, const WRITABLE: bool>(
    authority: &OriginalAuthority,
    held: &HeldBucket<'_, F, B, V, WRITABLE>,
    observed: &SelectedObservation<'_>,
    consumed: &ConsumedResolver,
    controls: crate::guard::ControlExclusion<'guard, F>,
) -> Result<LocalControlInputs<'guard, F>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    observed.revalidate().await?;
    let mut controls = controls;
    let snapshot = consumed.snapshot_bytes()?;
    if held.selected_guard_snapshot(observed).await?.as_deref() != Some(snapshot.as_slice()) {
        return Err(StoreFailure::new(StoreErrorKind::Denied {
            verb: "guard-install",
            pattern: authority.root().display().to_string(),
        }));
    }
    let inputs = consumed.finish()?;
    let registration = crate::guard::consumed_registration(authority);
    for pin in &inputs.controls {
        // Ordinary local controls use this exact protected owner. Imported
        // controls require the separate paired-control factory, not these locks.
        if pin.owner != registration {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let bytes = controls.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
    }
    controls.revalidate().await?;
    observed.revalidate().await?;
    Ok(LocalControlInputs {
        exclusion: controls,
        snapshot,
        used: inputs,
    })
}

/// Installs an initial Guard from the actual protected native setup.
///
/// Existing selected configuration must match exactly. Ordinary reopen cannot
/// overwrite a newer selected Guard with an old in-memory configuration. This
/// operation retains original-control exclusion through the durable slot and
/// pointer acknowledgment; it returns no reusable publication capability.
///
/// # Errors
/// Refuses incompatible physical or seeded profiles, unsafe or changed original
/// controls, a different selected Guard, stale observations and failed durable I/O.
pub(crate) async fn install_initial_guard<F, B, V>(
    guard: SharedCheck<Guard<FileBucket<F, B, V>, crate::store::NativeEffectClock>>,
    authority: &OriginalAuthority,
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &SelectedObservation<'_>,
) -> Result<(u64, RawDigest), StoreFailure>
where
    F: LocalFs + BucketBinding + 'static,
    B: Clock + BucketBinding + 'static,
    V: ContentValidator + BucketBinding + 'static,
{
    let selected_reads = capture_selected_reads(held, observed, &[]).await?;
    observed.revalidate().await?;
    let operator = held.operator_uid(observed).await?;
    if guard.store().publication_operator_uid() != Some(operator)
        || observed.identity().root() != authority.root()
        || observed.identity().physical_identity() != authority.physical_identity()
    {
        return Err(invalid());
    }
    let ((root_device, root_inode), (coordination_device, coordination_inode)) =
        authority.physical_identity();
    let binding = BackendBinding::Local {
        root: authority.root().as_os_str().as_encoded_bytes().to_vec(),
        root_device,
        root_inode,
        coordination_device,
        coordination_inode,
    };
    if observed.state().binding != binding {
        return Err(invalid());
    }

    let consumed = ConsumedResolver::new(guard.as_ref(), authority)?;
    consumed.registration(authority)?;
    let snapshot = consumed.snapshot_bytes()?;
    if held.selected_guard_snapshot(observed).await?.is_some() {
        let _inputs =
            hold_consumed_controls(guard.as_ref(), authority, held, observed, &consumed).await?;
        return Ok(observed.stamp());
    }

    let mut controls = guard
        .hold_original_registration(authority, observed.identity())
        .await?;
    let inputs = consumed.finish()?;
    for pin in &inputs.controls {
        let bytes = controls.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
    }
    controls.revalidate().await?;
    observed.revalidate().await?;

    let mut next = observed.state().clone();
    next.revision = next.revision.checked_add(1).ok_or_else(invalid)?;
    next.guard = Some(*blake3::hash(&snapshot).as_bytes());
    next.sources.clear();
    let final_snapshot = snapshot.clone();
    let retained_controls = controls.retain_used(&inputs.controls).await?;
    let setup_guard = SharedCheck::clone(&guard);
    let setup_authority = authority.clone();
    // Explicit trusted setup has no Commit/session deadline. Its distinct check
    // retains the actual clock and complete immutable configured obligations;
    // the worker independently refreshes all physical controls and exclusions.
    let final_check = super::OwnedFinalCheck {
        check: SharedCheck::new(move || {
            if ConsumedResolver::new(setup_guard.as_ref(), &setup_authority)?.snapshot_bytes()?
                != final_snapshot
            {
                return Err(invalid());
            }
            Ok(())
        }),
    };
    let permit = CheckedMutation {
        observed,
        sources: Vec::new(),
        next,
        changes: Vec::new(),
        evidence: CheckedEvidence::Guard {
            snapshot,
            carried: Vec::new(),
        },
        final_check: Box::new(|| final_check.recheck()),
        effect_context: Some(GuardEffectContext {
            existing_reads: Vec::new(),
            final_check: final_check.clone(),
            controls: vec![retained_controls],
            selected_reads,
            publication_original: None,
        }),
    };
    let receipt = held.publish_checked(permit).await?;
    controls.revalidate().await?;
    Ok(receipt.stamp)
}
