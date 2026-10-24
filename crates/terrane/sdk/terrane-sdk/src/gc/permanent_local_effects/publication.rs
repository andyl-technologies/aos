//! Selects immutable recurring events before repairing mutable recovery caches.
//!
//! The current owner and DATA qualifier remain independent of the original
//! authorization lease. Fresh checkpoint proposals become usable only after
//! real native installation, selecting-slot durability and acknowledgment.

use super::super::{
    CheckedPublication, CompletedWrites, FencePolicy, LocalFs, Plan, StoreFailure, hex,
};
use super::{capture, corrupt, io_failure};
use crate::bucket::BucketBinding;
use crate::selected_bridge::native_copied_placement::{CheckedOwnedPlacement, PlacementArtifacts};
use crate::store::native_effect::artifact_seal::permanent_local::{
    NativePermanentObservation, publication,
};
use std::collections::BTreeMap;
use terrane_format::bucket::Mutability;
use terrane_format::gc::publication::{
    LogicalChange, PortableCurrent, PortableSnapshot, PredecessorSlot, PublicationCommit,
    PublicationProof, PublicationTransaction,
};
use terrane_format::gc::retirement::{
    OperationPhase, OwnershipSlot, PassCoverage, PassPhase, PermanentDeleteOperation,
    PermanentDeletePass, RecordPointer,
};

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Selects actual candidate traversal and complete accumulated pass progress.
///
/// A completed fixed discovery may finish a pass only after every accumulated
/// Planned duty is resolved. Candidate coverage never certifies universal absence
/// or terminates permanent ownership; later passes still inspect late residues.
///
/// # Errors
/// Refuses changed owner, DATA, lease, original controls, predecessor progress,
/// checkpoint proposals, physical observations, native effects or acknowledgment.
/// Failure after slot installation leaves recoverable selected progress.
///
/// # Panics
/// In test builds, panics if opt-in phase diagnostics cannot write to
/// standard error.
pub(crate) async fn publish_observed<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedOwnedPlacement<'_, '_>,
    artifacts: &PlacementArtifacts,
    observation: &std::sync::Arc<NativePermanentObservation>,
) -> Result<(CheckedPublication, PassPhase), StoreFailure> {
    #[cfg(test)]
    let trace = crate::ref_advance::NativeTrace::new(
        checked.owner().observed().identity().root(),
        "permanent-progress-publication",
    );
    checked.revalidate().await?;
    let owner = checked.owner();
    let observed = owner.observed();
    if observation.pack() != owner.pack() {
        return Err(corrupt());
    }
    let (mut frame, control) = capture(fs, checked).await?;
    #[cfg(test)]
    trace.mark("frame-captured");
    let current = frame.final_check.clone().ok_or_else(corrupt)?;
    // Fresh unselected proposals carry no traversal or deletion authority.
    // Keep every original directory recipe while staging their unrelated bytes.
    frame.final_check = Some(current.with_permanent_candidate_continuity(observation));
    // Parent recipes are fresh physical reads inside this progress request,
    // before any proposal staging. Whole current qualification brackets their
    // complete capture; every later effect retains its own current predicate.
    checked.revalidate().await?;
    super::capture_observation_parent(
        fs,
        &mut frame,
        observed.identity().root(),
        &observed.identity().root().join("trash"),
    )
    .await?;
    for path in observation.paths() {
        super::capture_observation_parent(
            fs,
            &mut frame,
            observed.identity().root(),
            path.parent().ok_or_else(corrupt)?,
        )
        .await?;
    }
    checked.revalidate().await?;
    #[cfg(test)]
    trace.mark("candidate-parent-recipes-captured");
    let uid = frame.owner;
    let history =
        crate::selected_bridge::native_permanent_local::history::selected(fs, owner).await?;
    for read in history.reads() {
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::ProtectedRecord { owner: uid },
            )
            .await?;
    }
    #[cfg(test)]
    trace.mark("selected-history-recipes-captured");
    frame.writes = Some(CompletedWrites {
        records: BTreeMap::new(),
    });
    let previous_bytes = observed
        .logical()
        .get(owner.key())
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)?;
    if !observation.matches_selected(
        observed.identity().root(),
        &control,
        owner.key(),
        previous_bytes,
    ) {
        return Err(corrupt());
    }
    let previous = PermanentDeleteOperation::decode(previous_bytes).map_err(|_| corrupt())?;
    let nonce: [u8; 32] = fs
        .random_bytes(32)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| corrupt())?;
    let mut retained_previous = None;
    let (pass_number, event_number) = match previous.pass.as_ref() {
        None if previous.phase == OperationPhase::Proposed => (0, 0),
        Some(pointer) if previous.phase == OperationPhase::Owned => {
            let read = crate::bucket::permanent_restore::read_pass(
                fs,
                &control,
                &pointer.key,
                uid,
                owner.authorization().exclusion().cycle,
            )
            .await?;
            let bytes = read.bytes().ok_or_else(corrupt)?;
            previous
                .check_pass(bytes, owner.key())
                .map_err(|_| corrupt())?;
            let pass = PermanentDeletePass::decode(bytes).map_err(|_| corrupt())?;
            frame
                .observed_read(
                    fs,
                    read.path(),
                    read.bytes(),
                    read.metadata(),
                    FencePolicy::ProtectedRecord { owner: uid },
                )
                .await?;
            let counters = match pass.phase {
                PassPhase::Open => (pass.pass, pass.event.checked_add(1).ok_or_else(corrupt)?),
                PassPhase::PassCompleted => (pass.pass.checked_add(1).ok_or_else(corrupt)?, 0),
            };
            retained_previous = Some(pass);
            counters
        }
        _ => return Err(corrupt()),
    };
    let operation_revision = previous.revision.checked_add(1).ok_or_else(corrupt)?;
    let (fence_pointer, fence_bytes) = artifacts.fence();
    let fence = terrane_format::gc::retirement::CopiedPlacementFence::decode(fence_bytes)
        .map_err(|_| corrupt())?;
    fence.check_pointer(fence_pointer).map_err(|_| corrupt())?;
    if fence.state != *observed.state()
        || fence.backend != observed.state().binding
        || fence.genesis != *owner.genesis()
        || fence.roots != *artifacts.roots().0
        || fence.marks != *artifacts.marks().0
        || fence.capabilities != checked.data().capabilities()
        || fence.manifest != checked.data().manifest()
        || fence.refs != checked.data().refs()
        || Some(fence.guard) != observed.state().guard
        || fence.projection.key != observed.snapshot().key
        || fence.projection.digest != observed.snapshot().digest
        || fence.controls
            != checked
                .data()
                .effects()
                .control_owners()
                .iter()
                .flat_map(|owner| owner.pins().iter().cloned())
                .collect::<Vec<_>>()
    {
        return Err(corrupt());
    }
    let observations = observation
        .progress()
        .map_err(crate::selected_bridge::native_restore_failure)?;
    let complete = observation.candidate_traversal_completed()
        && (pass_number != 0 || event_number != 0)
        && history.resolved_after(&observations);
    let pass = PermanentDeletePass {
        authorization_digest: digest(&owner.authorization().encode().map_err(|_| corrupt())?),
        owner: *owner.owner(),
        revision: operation_revision,
        pass: pass_number,
        event: event_number,
        predecessor: OwnershipSlot {
            revision: observed.stamp().0,
            digest: observed.stamp().1,
        },
        state: observed.state().clone(),
        lease: owner.session().lease().clone(),
        backend: observed.state().binding.clone(),
        phase: if complete {
            PassPhase::PassCompleted
        } else {
            PassPhase::Open
        },
        observations,
        coverage: [if complete {
            PassCoverage::CandidateTraversalCompleted
        } else {
            PassCoverage::Unknown
        }; 3],
        nonce,
        placement_fence: Some(fence_pointer.clone()),
    };
    pass.check_owner(owner.authorization(), owner.key(), owner.owner())
        .map_err(|_| corrupt())?;
    if let Some(previous_pass) = retained_previous {
        previous_pass
            .check_successor(&pass)
            .map_err(|_| corrupt())?;
    } else {
        pass.check_initial(&previous).map_err(|_| corrupt())?;
    }
    let mut events = if history
        .events()
        .last()
        .is_some_and(|event| event.pass == pass.pass)
    {
        history.events().to_vec()
    } else {
        Vec::new()
    };
    events.push(pass.clone());
    PermanentDeletePass::check_pass_history(&events).map_err(|_| corrupt())?;
    let pass_key = format!(
        "gc/{}/reconcile/{}/{}",
        owner.authorization().exclusion().cycle,
        hex(&nonce),
        pass.revision
    );
    pass.check_key(&pass_key, owner.authorization().exclusion().cycle)
        .map_err(|_| corrupt())?;
    let pass_bytes = pass.encode().map_err(|_| corrupt())?;
    let next_operation = PermanentDeleteOperation {
        revision: operation_revision,
        phase: OperationPhase::Owned,
        authorization: owner.authorization().clone(),
        owner: Some(*owner.owner()),
        pass: Some(RecordPointer {
            key: pass_key.clone(),
            digest: digest(&pass_bytes),
        }),
    };
    previous
        .check_successor(&next_operation)
        .map_err(|_| corrupt())?;
    next_operation
        .check_pass(&pass_bytes, owner.key())
        .map_err(|_| corrupt())?;
    let operation_bytes = next_operation.encode().map_err(|_| corrupt())?;

    let root = observed.identity().root();
    let roots = terrane_format::gc::GcRoots::decode(artifacts.roots().1).map_err(|_| corrupt())?;
    let marks = terrane_format::gc::GcState::decode(artifacts.marks().1).map_err(|_| corrupt())?;
    let reservation = format!("gc/cycle/{}", roots.cycle);
    if artifacts.roots().0.key != format!("gc/{}/roots", roots.cycle)
        || artifacts.marks().0.key != format!("gc/{}/state", roots.cycle)
        || digest(artifacts.roots().1) != artifacts.roots().0.digest
        || digest(artifacts.marks().1) != artifacts.marks().0.digest
        || roots.epoch != owner.session().lease().epoch
        || roots.roots != checked.data().roots()
        || marks.cycle != roots.cycle
        || marks.epoch != roots.epoch
        || marks.phase != terrane_format::gc::Phase::Sweep
        || marks.expanded != checked.data().expanded()
        || marks.objects != checked.data().objects()
    {
        return Err(corrupt());
    }
    let mut allowed = std::collections::BTreeSet::from([
        root.join(&reservation),
        root.join(&artifacts.roots().0.key),
        root.join(&artifacts.marks().0.key),
        control.join(&fence_pointer.key),
    ]);
    allowed.extend(
        artifacts
            .checkpoints()
            .iter()
            .map(|(pointer, _)| root.join(&pointer.key)),
    );
    if artifacts.absent().len() != allowed.len()
        || artifacts
            .absent()
            .iter()
            .map(|read| read.path().to_owned())
            .collect::<std::collections::BTreeSet<_>>()
            != allowed
    {
        return Err(corrupt());
    }

    // Every private proposal retains actual absence at its real namespace.
    // Root/state are payloads; fence is a protected control record.
    for read in artifacts.absent() {
        if read.bytes().is_some() || read.metadata().is_some() {
            return Err(corrupt());
        }
        let (boundary, policy, directory_policy) =
            if read.path() == control.join(&fence_pointer.key) {
                (
                    control.as_path(),
                    FencePolicy::ProtectedRecord { owner: uid },
                    FencePolicy::PrivateControlDirectory { owner: uid },
                )
            } else {
                (
                    observed.identity().root(),
                    FencePolicy::Payload { owner: uid },
                    FencePolicy::NamespaceDirectory { owner: uid },
                )
            };
        let parent = read.path().parent().ok_or_else(corrupt)?;
        let mut actual_parent = boundary.to_owned();
        for component in parent
            .strip_prefix(boundary)
            .map_err(|_| corrupt())?
            .components()
        {
            if !matches!(component, std::path::Component::Normal(_)) {
                return Err(corrupt());
            }
            actual_parent.push(component);
            frame
                .directory(fs, &actual_parent, directory_policy)
                .await?;
        }
        if frame.actual_read(fs, read.path(), policy).await?.is_some() {
            return Err(corrupt());
        }
        frame
            .observed_read(fs, read.path(), read.bytes(), read.metadata(), policy)
            .await?;
    }
    if !artifacts
        .absent()
        .iter()
        .any(|read| read.path() == root.join(&reservation))
        || !artifacts
            .absent()
            .iter()
            .any(|read| read.path() == control.join(&fence_pointer.key))
    {
        return Err(corrupt());
    }
    #[cfg(test)]
    trace.mark("fresh-proposal-preimages-captured");
    let mut changes = vec![LogicalChange {
        key: owner.key().to_owned(),
        expected: Some(previous_bytes.to_vec()),
        new: Some(operation_bytes.clone()),
    }];
    for (key, bytes, discipline) in [
        (reservation.as_str(), &[][..], Mutability::CreateOnce),
        (
            artifacts.roots().0.key.as_str(),
            artifacts.roots().1,
            Mutability::CreateOnce,
        ),
        (
            artifacts.marks().0.key.as_str(),
            artifacts.marks().1,
            Mutability::CompareAndSwap,
        ),
    ] {
        if !artifacts
            .absent()
            .iter()
            .any(|read| read.path() == root.join(key))
            || observed.logical().get(key).is_some_and(Option::is_some)
        {
            return Err(corrupt());
        }
        frame
            .install(
                fs,
                root,
                key,
                bytes,
                FencePolicy::Payload { owner: uid },
                discipline,
            )
            .await?;
        changes.push(LogicalChange {
            key: key.to_owned(),
            expected: None,
            new: Some(bytes.to_vec()),
        });
    }
    for (pointer, bytes) in artifacts.checkpoints() {
        let key = terrane_format::bucket::BucketKey::parse(&pointer.key).map_err(|_| corrupt())?;
        if key.mutability() != Mutability::CreateOnce
            || digest(bytes) != pointer.digest
            || !artifacts
                .absent()
                .iter()
                .any(|read| read.path() == root.join(&pointer.key))
            || observed
                .logical()
                .get(&pointer.key)
                .is_some_and(Option::is_some)
        {
            return Err(corrupt());
        }
        terrane_format::gc::GcMark::decode(bytes).map_err(|_| corrupt())?;
        frame
            .install(
                fs,
                root,
                &pointer.key,
                bytes,
                FencePolicy::Payload { owner: uid },
                Mutability::CreateOnce,
            )
            .await?;
        changes.push(LogicalChange {
            key: pointer.key.clone(),
            expected: None,
            new: Some(bytes.to_vec()),
        });
    }
    frame
        .install(
            fs,
            &control,
            &fence_pointer.key,
            fence_bytes,
            FencePolicy::ProtectedRecord { owner: uid },
            Mutability::CreateOnce,
        )
        .await?;
    frame
        .install(
            fs,
            &control,
            &pass_key,
            &pass_bytes,
            FencePolicy::ProtectedRecord { owner: uid },
            Mutability::CreateOnce,
        )
        .await?;
    changes.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    let mut next = observed.state().clone();
    next.revision = next.revision.checked_add(1).ok_or_else(corrupt)?;
    let snapshot = PortableSnapshot {
        revision: next.revision,
        origin: next.binding.clone(),
        predecessor: Some(observed.snapshot().clone()),
        // GC records remain transaction changes, outside the portable projection.
        projection: Vec::new(),
    };
    let snapshot_bytes = snapshot.encode().map_err(|_| corrupt())?;
    let pointer = PortableCurrent {
        key: format!("publication/snapshots/{}:{}", next.revision, hex(&nonce)),
        digest: digest(&snapshot_bytes),
    };
    let transaction = PublicationTransaction {
        nonce,
        old: Some(observed.state().clone()),
        new: next,
        changes: changes.clone(),
        proof: PublicationProof::Raw,
        predecessor: Some(PredecessorSlot {
            revision: observed.stamp().0,
            digest: observed.stamp().1,
        }),
        snapshot: pointer.clone(),
    };
    transaction
        .check_snapshot(&snapshot_bytes)
        .map_err(|_| corrupt())?;
    let transaction_key = format!("publication/transactions/{}", hex(&nonce));
    transaction
        .check_key(&transaction_key)
        .map_err(|_| corrupt())?;
    let transaction_bytes = transaction.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            root,
            &pointer.key,
            &snapshot_bytes,
            FencePolicy::Payload { owner: uid },
            Mutability::Immutable,
        )
        .await?;
    frame
        .install(
            fs,
            &control,
            &transaction_key,
            &transaction_bytes,
            FencePolicy::ProtectedRecord { owner: uid },
            Mutability::Immutable,
        )
        .await?;
    #[cfg(test)]
    trace.mark("unselected-proposals-installed");
    checked.revalidate().await?;
    // Full retained checks and genuine durability precede selecting the slot.
    // Restore the original current predicate with full traversal, without nesting
    // the staging predicate, and retain it through selection and acknowledgment.
    frame.final_check = Some(current.with_permanent_traversal(observation));
    for directory in [root, control.as_path()] {
        frame
            .execute(
                fs,
                Plan::SyncDirectory {
                    path: directory.to_owned(),
                },
            )
            .await?;
    }
    #[cfg(test)]
    trace.mark("full-preselection-synchronization-completed");
    let slot = PublicationCommit {
        revision: transaction.new.revision,
        predecessor: Some(observed.stamp().1),
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    };
    let slot_bytes = slot.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            &control,
            &format!("publication/commits/{}", slot.revision),
            &slot_bytes,
            FencePolicy::ProtectedRecord { owner: uid },
            Mutability::CreateOnce,
        )
        .await?;
    #[cfg(test)]
    trace.mark("selecting-slot-installed");

    // A crash here leaves an authoritative selected event and a stale cache.
    // The next current-owned producer resolves history and repairs that cache.
    frame
        .install(
            fs,
            &control,
            owner.key(),
            &operation_bytes,
            FencePolicy::ProtectedRecord { owner: uid },
            Mutability::CompareAndSwap,
        )
        .await?;
    #[cfg(test)]
    trace.mark("selected-operation-cache-installed");
    let mut logical = observed.logical().clone();
    for change in changes {
        logical.insert(change.key, change.new);
    }
    frame.project(fs, root, &pointer, &logical).await?;
    #[cfg(test)]
    trace.mark("portable-projection-installed");
    let (plan, receiver) = publication::plan(publication::ProgressInputs {
        checked,
        writes: frame.writes.as_ref().ok_or_else(corrupt)?,
        slot: &slot,
        transaction: &transaction,
        snapshot: &snapshot_bytes,
        pass: (&pass_key, &pass_bytes),
        observation,
    })
    .map_err(crate::selected_bridge::native_restore_failure)?;
    #[cfg(test)]
    trace.mark("native-progress-seal-start");
    let sealed = frame.execute(fs, plan).await;
    #[cfg(test)]
    trace.mark("native-progress-seal-returned");
    sealed?;
    receiver
        .take()
        .map_err(crate::selected_bridge::native_restore_failure)?;
    #[cfg(test)]
    trace.mark("native-progress-acknowledgment-consumed");
    Ok((
        CheckedPublication {
            revision: slot.revision,
            digest: digest(&slot_bytes),
        },
        pass.phase,
    ))
}
