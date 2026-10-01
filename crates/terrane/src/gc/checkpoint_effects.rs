//! Stages closed mark records and selects genuinely checked collector progress.
//!
//! This private descendant reuses the sealed retained executor. It validates the
//! closed collector paths and exact selected successor before staging any bytes; every
//! command retains actual namespace and consumed control descriptors through its
//! final preimage/clock checks, syscall, and directory synchronization.
//!
//! ```text
//! gc/<cycle>/roots + gc/<cycle>/state: one selected whole transaction
//! gc/<cycle>/mark/<shard>/<revision>: immutable canonical GcMark bytes
//! state key 5: exact raw BLAKE3 pointers to complete selected revisions
//! ```

use super::{
    BTreeMap, BucketBinding, CheckedPublication, FencePolicy, Frame, LocalFs, MetadataStamp,
    Mutability, Plan, PortableCurrent, PortableSnapshot, PredecessorSlot, PublicationCommit,
    PublicationTransaction, StoreFailure, corrupt, digest, duplicate, hex, io_failure, unsupported,
};
use crate::selected_bridge::{CheckedGcCheckpoint, GcCheckpointPublication, GcMarkRead};
use terrane_core::gc::GcLease;
use terrane_core::gc::publication::LogicalChange;
use terrane_core::gc::publication::PublicationProof;
use terrane_core::gc::publication::evidence::PhysicalRegistration;
use terrane_core::gc::{GcMark, GcRoots, GcState, Phase};

fn validate(checked: &CheckedGcCheckpoint<'_, '_>) -> Result<Vec<LogicalChange>, StoreFailure> {
    let observed = checked.observed();
    let roots = checked.roots();
    let state = checked.publication().state();
    let root_key = format!("gc/{}/roots", roots.cycle);
    let state_key = format!("gc/{}/state", roots.cycle);
    let root_bytes = roots.encode();
    if GcRoots::decode(&root_bytes).map_err(|_| corrupt())? != *roots
        || digest(&root_bytes) != checked.roots_digest()
        || checked.reads().roots().path() != observed.identity().root().join(&root_key)
        || checked.reads().state().path() != observed.identity().root().join(&state_key)
        || observed.logical().get(&root_key).and_then(Option::as_deref) != checked.previous_roots()
        || observed
            .logical()
            .get(&state_key)
            .and_then(Option::as_deref)
            != checked.previous_state()
        || observed
            .logical()
            .get("gc/lease")
            .and_then(Option::as_deref)
            .map(GcLease::decode)
            .transpose()
            .map_err(|_| corrupt())?
            .as_ref()
            != Some(checked.effect_context().lease())
        || observed.state().guard.is_none()
        || state.cycle != roots.cycle
        || state.snapshot_at != roots.timestamp
        || state.epoch != checked.effect_context().lease().epoch
        || roots.epoch > state.epoch
    {
        return Err(corrupt());
    }
    let mut expected = observed.state().clone();
    expected.revision = expected.revision.checked_add(1).ok_or_else(corrupt)?;
    if *checked.next() != expected {
        return Err(corrupt());
    }
    let previous = checked
        .previous_state()
        .map(GcState::decode)
        .transpose()
        .map_err(|_| corrupt())?;
    let mut changes = Vec::new();
    match checked.publication() {
        GcCheckpointPublication::Begin { state } => {
            if previous.is_some()
                || checked.previous_roots().is_some()
                || *state != crate::gc::runner::roots::initial(roots)
            {
                return Err(corrupt());
            }
            changes.push(LogicalChange {
                key: root_key,
                expected: None,
                new: Some(root_bytes),
            });
        }
        GcCheckpointPublication::Progress { revisions, state } => {
            let old = previous.as_ref().ok_or_else(corrupt)?;
            if checked.previous_roots() != Some(root_bytes.as_slice())
                || old.phase != Phase::Mark
                || state.phase != Phase::Mark
                || old.cycle != state.cycle
                || old.snapshot_at != state.snapshot_at
                || old.epoch > state.epoch
                || old.progress != state.progress
            {
                return Err(corrupt());
            }
            let mut pointers = old.checkpoints.clone();
            let mut last_shard = None;
            for revision in revisions {
                let pointer = revision.pointer();
                let mark = revision.mark();
                if last_shard.is_some_and(|last| last >= pointer.shard)
                    || mark.cycle() != state.cycle
                    || mark.epoch() != state.epoch
                    || mark.shard() != pointer.shard
                    || digest(&mark.encode()) != pointer.hash
                {
                    return Err(corrupt());
                }
                last_shard = Some(pointer.shard);
                match pointers.binary_search_by_key(&pointer.shard, |row| row.shard) {
                    Ok(position) => {
                        let before = &pointers[position];
                        if before.revision.checked_add(1) != Some(pointer.revision) {
                            return Err(corrupt());
                        }
                        let prior = revision_read(checked, before.shard, before.revision)?;
                        if digest(prior) != before.hash {
                            return Err(corrupt());
                        }
                        let old_mark = GcMark::decode(prior).map_err(|_| corrupt())?;
                        if old_mark.hashes().iter().any(|hash| !mark.contains(hash)) {
                            return Err(corrupt());
                        }
                        pointers[position] = pointer.clone();
                    }
                    Err(position) => {
                        if pointer.revision != 0 {
                            return Err(corrupt());
                        }
                        pointers.insert(position, pointer.clone());
                    }
                }
            }
            if pointers != state.checkpoints {
                return Err(corrupt());
            }
        }
        GcCheckpointPublication::FinishMark { final_marks, state } => {
            let old = previous.as_ref().ok_or_else(corrupt)?;
            let mut expected = old.clone();
            expected.epoch = state.epoch;
            expected.phase = Phase::Sweep;
            if checked.previous_roots() != Some(root_bytes.as_slice())
                || old.phase != Phase::Mark
                || !old.pending.is_empty()
                || old.epoch > state.epoch
                || *state != expected
                || !final_marks.is_empty()
            {
                return Err(corrupt());
            }
            for pointer in &state.checkpoints {
                let bytes = revision_read(checked, pointer.shard, pointer.revision)?;
                let prior = GcMark::decode(bytes).map_err(|_| corrupt())?;
                if digest(bytes) != pointer.hash
                    || prior.cycle() != state.cycle
                    || prior.epoch() > state.epoch
                    || prior.shard() != pointer.shard
                {
                    return Err(corrupt());
                }
            }
        }
    }
    changes.push(LogicalChange {
        key: state_key,
        expected: checked.previous_state().map(<[u8]>::to_vec),
        new: Some(state.encode().map_err(|_| corrupt())?),
    });
    checked.recheck_before_slot()?;
    Ok(changes)
}

fn revision_read<'a>(
    checked: &'a CheckedGcCheckpoint<'_, '_>,
    shard: u8,
    revision: u64,
) -> Result<&'a [u8], StoreFailure> {
    checked
        .reads()
        .marks()
        .iter()
        .find_map(|read| match read {
            GcMarkRead::Revision {
                shard: found,
                revision: number,
                record,
            } if *found == shard && *number == revision => record.bytes(),
            _ => None,
        })
        .ok_or_else(corrupt)
}

/// Publishes fixed collector records and their exact consecutive selected revision.
///
/// # Errors
/// Rejects changed lease/roots/state/preimages, missing genuine retained controls,
/// unsafe metadata, failed final clock checks, or unavailable durable native effects.
/// Failure after slot submission can leave selected progress awaiting recovery.
pub(crate) async fn publish_checked<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedGcCheckpoint<'_, '_>,
) -> Result<CheckedPublication, StoreFailure> {
    let changes = validate(checked)?;
    let observed = checked.observed();
    let context = checked.effect_context();
    let owner = observed.configured_operator_uid();
    if !observed.identity().writable() || context.controls().is_empty() {
        return Err(unsupported());
    }
    let mut exclusions = vec![duplicate(observed.identity().retained_namespace()?)?];
    let mut control_ranges = Vec::new();
    if context.controls().len() != context.control_owners().len() {
        return Err(corrupt());
    }
    for (controls, predicates) in context.controls().iter().zip(context.control_owners()) {
        let PhysicalRegistration::Local(registration) = predicates.registration() else {
            return Err(unsupported());
        };
        if controls.owner() != predicates.configured_operator_uid()
            || controls.records().is_empty()
            || controls.directory().as_os_str().as_encoded_bytes() != registration.control
            || controls.records().len() != predicates.pins().len()
            || predicates
                .pins()
                .iter()
                .zip(controls.records())
                .any(|(pin, record)| {
                    pin.owner != *predicates.registration()
                        || controls.directory().join(&pin.key) != record.path()
                        || pin.check_record(record.bytes()).is_err()
                })
        {
            return Err(corrupt());
        }
        let start = exclusions.len();
        let retained = controls.exclusions();
        for receipt in retained.iter() {
            exclusions.push(duplicate(receipt)?);
        }
        if exclusions.len() == start {
            return Err(unsupported());
        }
        control_ranges.push(start..exclusions.len());
    }
    let mut frame = Frame {
        exclusions: exclusions.into(),
        names: Vec::new(),
        reads: Vec::new(),
        parents: BTreeMap::new(),
        final_check: Some(context.final_check()),
        owner,
    };
    for controls in context.controls() {
        let owner = controls.owner();
        for ancestor in controls.ancestors() {
            let metadata = fs
                .symlink_metadata(ancestor.path())
                .await
                .map_err(io_failure)?;
            let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
            FencePolicy::ProtectedAncestor { owner }
                .validate(stamp)
                .map_err(io_failure)?;
            if stamp.identity != ancestor.identity()
                || (stamp.owner, stamp.mode & 0o7777) != ancestor.protection()
            {
                return Err(corrupt());
            }
            frame
                .parents
                .insert(ancestor.path().to_owned(), (stamp, owner));
        }
    }
    let control = frame.observation(fs, observed, 0).await?;
    for (controls, descriptors) in context.controls().iter().zip(control_ranges) {
        let owner = controls.owner();
        let (directory, lock) = controls.identities();
        frame
            .name(
                fs,
                controls.directory().to_owned(),
                directory,
                FencePolicy::PrivateControlDirectory { owner },
                None,
            )
            .await?;
        for descriptor in descriptors {
            frame
                .name(
                    fs,
                    controls.directory().join("retention.lock"),
                    lock,
                    FencePolicy::ProtectedRecord { owner },
                    Some(descriptor),
                )
                .await?;
        }
        for record in controls.records() {
            let metadata = fs
                .symlink_metadata(record.path())
                .await
                .map_err(io_failure)?;
            if MetadataStamp::checked(&metadata)
                .map_err(io_failure)?
                .identity
                != record.identity()
            {
                return Err(corrupt());
            }
            frame
                .observed_read(
                    fs,
                    record.path(),
                    Some(record.bytes()),
                    Some(&metadata),
                    FencePolicy::ProtectedRecord { owner },
                )
                .await?;
        }
    }
    if !checked.sources().is_empty() {
        return Err(unsupported());
    }
    observed.revalidate().await?;
    checked.recheck_before_slot()?;
    // Exact absent leaf reads require a real parent. Create only this fixed
    // cycle directory after all authority and closed-transition validation.
    let root = observed.identity().root();
    frame
        .directory(
            fs,
            &root.join("gc"),
            FencePolicy::NamespaceDirectory { owner },
        )
        .await?;
    frame
        .directory(
            fs,
            &root.join(format!("gc/{}", checked.roots().cycle)),
            FencePolicy::NamespaceDirectory { owner },
        )
        .await?;
    for read in std::iter::once(checked.reads().roots())
        .chain(std::iter::once(checked.reads().state()))
        .chain(checked.reads().inputs())
    {
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::Payload { owner },
            )
            .await?;
    }
    for mark in checked.reads().marks() {
        let (key, read) = match mark {
            GcMarkRead::Revision {
                shard,
                revision,
                record,
            } => (
                format!("gc/{}/mark/{shard}/{revision}", checked.roots().cycle),
                record,
            ),
            GcMarkRead::Final { shard, record } => {
                (format!("gc/{}/mark/{shard}", checked.roots().cycle), record)
            }
        };
        if read.path() != observed.identity().root().join(key) {
            return Err(corrupt());
        }
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::Payload { owner },
            )
            .await?;
    }
    observed.revalidate().await?;
    checked.recheck_before_slot()?;
    let root = observed.identity().root();
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;

    match checked.publication() {
        GcCheckpointPublication::Begin { .. } => {}
        GcCheckpointPublication::Progress { revisions, .. } => {
            for revision in revisions {
                let pointer = revision.pointer();
                let key = format!(
                    "gc/{}/mark/{}/{}",
                    checked.roots().cycle,
                    pointer.shard,
                    pointer.revision
                );
                frame
                    .install(
                        fs,
                        root,
                        &key,
                        &revision.mark().encode(),
                        FencePolicy::Payload { owner },
                        Mutability::Immutable,
                    )
                    .await?;
            }
        }
        GcCheckpointPublication::FinishMark { .. } => {}
    }

    let nonce: [u8; 32] = fs
        .random_bytes(32)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| unsupported())?;
    let operation = hex(&nonce);
    let snapshot = PortableSnapshot {
        revision: checked.next().revision,
        origin: checked.next().binding.clone(),
        projection: Vec::new(),
        predecessor: Some(observed.snapshot().clone()),
    };
    let snapshot_bytes = snapshot.encode().map_err(|_| corrupt())?;
    let pointer = PortableCurrent {
        key: format!(
            "publication/snapshots/{}:{operation}",
            checked.next().revision
        ),
        digest: digest(&snapshot_bytes),
    };
    let transaction = PublicationTransaction {
        nonce,
        old: Some(observed.state().clone()),
        new: checked.next().clone(),
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
    frame
        .install(
            fs,
            root,
            &pointer.key,
            &snapshot_bytes,
            FencePolicy::Payload { owner },
            Mutability::Immutable,
        )
        .await?;
    let transaction_key = format!("publication/transactions/{operation}");
    transaction
        .check_key(&transaction_key)
        .map_err(|_| corrupt())?;
    let transaction_bytes = transaction.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            &control,
            &transaction_key,
            &transaction_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::Immutable,
        )
        .await?;

    // The slot is the only selected-state linearization. Its native worker
    // repeats every consumed canonical control, selected exact read and actual
    // retained descriptor after staging and immediately before the syscall.
    let slot = PublicationCommit {
        revision: checked.next().revision,
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
            FencePolicy::ProtectedRecord { owner },
            Mutability::CreateOnce,
        )
        .await?;

    let mut logical = observed.logical().clone();
    for change in changes {
        logical.insert(change.key, change.new);
    }
    frame.project(fs, root, &pointer, &logical).await?;
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await?;
    Ok(CheckedPublication {
        revision: slot.revision,
        digest: digest(&slot_bytes),
    })
}
