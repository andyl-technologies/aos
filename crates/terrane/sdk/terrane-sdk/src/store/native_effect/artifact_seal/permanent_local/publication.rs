//! Closes permanent progress durability after actual selecting-slot installation.
//!
//! Immutable selected history supplies authority. The mutable operation cache
//! is an output repaired only after selection, never a selecting primitive.

use super::super::super::publication::CompletedWrites;
use super::super::publication_sync::SyncScope;
use super::super::publication_sync::outputs::{Inventory, Target, insert_target, synchronize};
use super::super::{FencePolicy, NativeEffectFailure, PathBuf, Plan, Worker};
use crate::selected_bridge::native_copied_placement::CheckedOwnedPlacement;
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, mpsc},
};
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationTransaction,
};
use terrane_format::gc::retirement::{PermanentDeleteOperation, PermanentDeletePass};

/// Carries only a fixed closed progress acknowledgment and actual producer outputs.
pub(in super::super::super) struct ProgressRequest {
    root: PathBuf,
    control: PathBuf,
    slot_path: PathBuf,
    records: BTreeMap<PathBuf, Target>,
    scopes: Vec<SyncScope>,
    original_directories: Vec<(PathBuf, u32)>,
    transaction: PublicationTransaction,
    slot: PublicationCommit,
    pass: PermanentDeletePass,
    operation: PermanentDeleteOperation,
    operation_key: String,
    pass_key: String,
    observation: Arc<super::NativePermanentObservation>,
    result: mpsc::Sender<DurableProgress>,
}

impl ProgressRequest {
    /// Borrows the actual selecting slot solely for native test fault dispatch.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super::super) fn path(&self) -> &std::path::Path {
        &self.slot_path
    }
}

struct DurableProgress;

/// Receives only actual native descriptor synchronization and final verification.
pub(in super::super::super) struct ProgressReceiver {
    result: mpsc::Receiver<DurableProgress>,
}

impl ProgressReceiver {
    /// Takes the private acknowledgment without converting unit success to a receipt.
    ///
    /// # Errors
    /// Refuses unexecuted, refused or incompletely durable native requests.
    pub(in super::super::super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result.try_recv().map(|_| ()).map_err(|_| {
            io::Error::other("native permanent progress acknowledgment unavailable").into()
        })
    }
}

/// Binds actual completed output data to the same current checked owner and DATA.
pub(in super::super::super) struct ProgressInputs<'a, 'operation, 'held> {
    /// Genuine same-held owner and current DATA carrier, without first-owner rights.
    pub(in super::super::super) checked: &'a CheckedOwnedPlacement<'operation, 'held>,
    /// Real completed native writes, including protected pass and cache repair.
    pub(in super::super::super) writes: &'a CompletedWrites,
    /// Canonical exact selecting slot installed by the closed producer.
    pub(in super::super::super) slot: &'a PublicationCommit,
    /// Whole selected predecessor and exact progress successor transaction.
    pub(in super::super::super) transaction: &'a PublicationTransaction,
    /// Canonical independently validated successor portable snapshot bytes.
    pub(in super::super::super) snapshot: &'a [u8],
    /// Actual complete native candidate observation retained through acknowledgment.
    pub(in super::super::super) observation: &'a Arc<super::NativePermanentObservation>,
    /// Canonical selected immutable progress event key and bytes.
    pub(in super::super::super) pass: (&'a str, &'a [u8]),
}

/// Fixes acknowledgment data after genuine progress selection and cache repair.
///
/// # Errors
/// Refuses changed owner, lease, predecessor, typed event association, output
/// scope, canonical transaction or missing actual completed output receipts.
pub(in super::super::super) fn plan(
    inputs: ProgressInputs<'_, '_, '_>,
) -> Result<(Plan, ProgressReceiver), NativeEffectFailure> {
    let ProgressInputs {
        checked,
        writes,
        slot,
        transaction,
        snapshot,
        observation,
        pass: (pass_key, bytes),
    } = inputs;
    let owner = checked.owner();
    let observed = owner.observed();
    let pass = PermanentDeletePass::decode(bytes).map_err(io::Error::other)?;
    pass.check_owner(owner.authorization(), owner.key(), owner.owner())
        .map_err(io::Error::other)?;
    pass.check_key(pass_key, owner.authorization().exclusion().cycle)
        .map_err(io::Error::other)?;
    if observation.pack() != owner.pack()
        || pass.observations != observation.progress()?
        || (pass.phase == terrane_format::gc::retirement::PassPhase::PassCompleted
            && !observation.candidate_traversal_completed())
        || pass.predecessor.revision != observed.stamp().0
        || pass.predecessor.digest != observed.stamp().1
        || pass.state != *observed.state()
        || &pass.lease != owner.session().lease()
        || transaction.old.as_ref() != Some(observed.state())
        || transaction
            .predecessor
            .as_ref()
            .is_none_or(|row| (row.revision, row.digest) != observed.stamp())
        || transaction.proof != PublicationProof::Raw
        || slot.predecessor != Some(observed.stamp().1)
        || slot.revision != transaction.new.revision
    {
        return Err(io::Error::other("permanent progress selected predecessor differs").into());
    }
    transaction
        .check_key(&slot.transaction_key)
        .map_err(io::Error::other)?;
    transaction
        .check_snapshot(snapshot)
        .map_err(io::Error::other)?;
    let transaction_bytes = transaction.encode().map_err(io::Error::other)?;
    if slot.transaction_digest != *blake3::hash(&transaction_bytes).as_bytes() {
        return Err(io::Error::other("permanent progress transaction digest differs").into());
    }
    let change = transaction
        .changes
        .iter()
        .find(|row| row.key == owner.key())
        .ok_or_else(|| io::Error::other("permanent progress operation change absent"))?;
    if observed.logical().get(owner.key()) != Some(&change.expected) {
        return Err(io::Error::other("permanent progress operation predecessor differs").into());
    }
    let operation_bytes = change
        .new
        .as_deref()
        .ok_or_else(|| io::Error::other("permanent progress operation absent"))?;
    let operation = PermanentDeleteOperation::decode(operation_bytes).map_err(io::Error::other)?;
    operation
        .check_pass(bytes, owner.key())
        .map_err(io::Error::other)?;
    if &operation.authorization != owner.authorization()
        || operation.owner.as_ref() != Some(owner.owner())
    {
        return Err(io::Error::other("permanent progress immutable owner differs").into());
    }
    let root = observed.identity().root().to_owned();
    let control = owner.backend_control().to_owned();
    let fence_pointer = pass
        .placement_fence
        .as_ref()
        .ok_or_else(|| io::Error::other("permanent progress current placement fence absent"))?;
    let fence_path = control.join(&fence_pointer.key);
    let fence_bytes = writes
        .records()
        .find(|(path, _)| **path == fence_path)
        .and_then(|(_, write)| write.expected())
        .ok_or_else(|| io::Error::other("permanent progress placement completion absent"))?;
    let fence = terrane_format::gc::retirement::CopiedPlacementFence::decode(fence_bytes)
        .map_err(io::Error::other)?;
    fence
        .check_pointer(fence_pointer)
        .map_err(io::Error::other)?;
    if fence.state != *observed.state()
        || fence.backend != observed.state().binding
        || fence.genesis != *owner.genesis()
    {
        return Err(io::Error::other("permanent progress current placement differs").into());
    }
    let uid = observed.configured_operator_uid();
    let mut scopes = vec![
        SyncScope {
            path: root.clone(),
            owner: uid,
            protected: false,
        },
        SyncScope {
            path: control.clone(),
            owner: uid,
            protected: true,
        },
    ];
    let mut original_directories = Vec::new();
    for controls in checked.data().effects().controls() {
        scopes.push(SyncScope {
            path: controls.directory().to_owned(),
            owner: controls.owner(),
            protected: true,
        });
        original_directories.push((controls.directory().to_owned(), controls.owner()));
    }
    let mut records = BTreeMap::new();
    for (path, write) in writes.records() {
        let (owner, protected) = match write.policy() {
            FencePolicy::Payload { owner } => (owner, false),
            FencePolicy::ProtectedRecord { owner } => (owner, true),
            _ => return Err(io::Error::other("permanent progress output policy differs").into()),
        };
        if !scopes.iter().any(|scope| {
            scope.path == write.root() && scope.owner == owner && scope.protected == protected
        }) {
            return Err(io::Error::other("permanent progress output boundary differs").into());
        }
        insert_target(
            &mut records,
            path.clone(),
            Target {
                root: write.root().to_owned(),
                owner,
                protected,
                expected: write.expected().map(<[u8]>::to_vec),
            },
        )?;
    }
    for controls in checked.data().effects().controls() {
        for record in controls.records() {
            insert_target(
                &mut records,
                record.path().to_owned(),
                Target {
                    root: controls.directory().to_owned(),
                    owner: controls.owner(),
                    protected: true,
                    expected: Some(record.bytes().to_vec()),
                },
            )?;
        }
    }
    for (path, expected, boundary, protected) in [
        (
            control.join(format!("publication/commits/{}", slot.revision)),
            slot.encode().map_err(io::Error::other)?,
            &control,
            true,
        ),
        (
            control.join(&slot.transaction_key),
            transaction_bytes,
            &control,
            true,
        ),
        (control.join(pass_key), bytes.to_vec(), &control, true),
        (
            control.join(owner.key()),
            operation_bytes.to_vec(),
            &control,
            true,
        ),
        (
            root.join(&transaction.snapshot.key),
            snapshot.to_vec(),
            &root,
            false,
        ),
        (
            root.join("publication/PORTABLE"),
            transaction.snapshot.encode().map_err(io::Error::other)?,
            &root,
            false,
        ),
    ] {
        // Required outputs must be genuine native completions, never inferred
        // from a caller's desired body or from proposed artifact bytes.
        if !writes
            .records()
            .any(|(actual, write)| actual == &path && write.expected() == Some(expected.as_slice()))
        {
            return Err(io::Error::other("permanent progress completion receipt absent").into());
        }
        insert_target(
            &mut records,
            path,
            Target {
                root: boundary.clone(),
                owner: uid,
                protected,
                expected: Some(expected),
            },
        )?;
    }
    let (result, receiver) = mpsc::channel();
    Ok((
        Plan::SealPermanentLocalProgress(Box::new(ProgressRequest {
            slot_path: control.join(format!("publication/commits/{}", slot.revision)),
            root,
            control,
            records,
            scopes,
            original_directories,
            transaction: transaction.clone(),
            slot: slot.clone(),
            pass,
            operation,
            operation_key: owner.key().to_owned(),
            pass_key: pass_key.to_owned(),
            observation: Arc::clone(observation),
            result,
        })),
        ProgressReceiver { result: receiver },
    ))
}

fn association(request: &ProgressRequest, worker: &Worker) -> Result<(), NativeEffectFailure> {
    for (path, target) in &request.records {
        worker.projection.exact(path, target.expected.as_deref())?;
    }
    request
        .operation
        .check_pass(
            &request.pass.encode().map_err(io::Error::other)?,
            &request.operation_key,
        )
        .map_err(io::Error::other)?;
    request
        .pass
        .check_key(
            &request.pass_key,
            request.operation.authorization.exclusion().cycle,
        )
        .map_err(io::Error::other)?;
    request
        .transaction
        .check_key(&request.slot.transaction_key)
        .map_err(io::Error::other)?;
    if request.slot_path
        != request
            .control
            .join(format!("publication/commits/{}", request.slot.revision))
        || request.slot.transaction_digest
            != *blake3::hash(&request.transaction.encode().map_err(io::Error::other)?).as_bytes()
        || !request
            .scopes
            .iter()
            .any(|scope| scope.path == request.root)
    {
        return Err(io::Error::other("permanent progress native association differs").into());
    }
    Ok(())
}

/// Synchronizes real retained descriptors and closes progress only after final refresh.
///
/// # Errors
/// Refuses any changed retained predicate, typed association, real sync failure,
/// current authority refusal or uncertain completion; no error fills the receiver.
///
/// # Panics
/// In test builds, panics if opt-in phase diagnostics cannot write to
/// standard error.
pub(in super::super) fn execute(
    request: ProgressRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    #[cfg(test)]
    let trace = crate::ref_advance::NativeTrace::new(&request.root, "permanent-progress-seal");
    #[cfg(test)]
    trace.mark(&format!(
        "inventory records={} scopes={} original_directories={} names={} preimages={}",
        request.records.len(),
        request.scopes.len(),
        request.original_directories.len(),
        worker.projection.names.len(),
        worker.projection.preimages.len(),
    ));
    #[cfg(test)]
    trace.mark("initial-selected-association-start");
    association(&request, &worker)?;
    #[cfg(test)]
    trace.mark("initial-selected-association-checked");
    #[cfg(test)]
    trace.mark("initial-full-traversal-start");
    request.observation.recheck_traversal(&worker)?;
    #[cfg(test)]
    trace.mark("initial-full-traversal-checked");
    #[cfg(test)]
    trace.mark("native-output-synchronization-start");
    synchronize(
        Inventory {
            scopes: &request.scopes,
            targets: request
                .records
                .iter()
                .map(|(path, target)| {
                    (
                        path.clone(),
                        Target {
                            root: target.root.clone(),
                            owner: target.owner,
                            protected: target.protected,
                            expected: target.expected.clone(),
                        },
                    )
                })
                .collect(),
            original_directories: &request.original_directories,
            #[cfg(all(test, feature = "tokio"))]
            completed_syncs: None,
        },
        &mut worker,
    )?;
    #[cfg(test)]
    trace.mark("native-output-synchronization-completed");
    #[cfg(test)]
    trace.mark("final-selected-association-start");
    association(&request, &worker)?;
    #[cfg(test)]
    trace.mark("final-selected-association-checked");
    #[cfg(test)]
    trace.mark("final-full-traversal-start");
    request.observation.recheck_traversal(&worker)?;
    #[cfg(test)]
    trace.mark("final-full-traversal-checked");
    #[cfg(test)]
    trace.mark("final-current-projection-refresh-start");
    worker.refresh(&[])?;
    #[cfg(test)]
    trace.mark("final-current-projection-refreshed");
    let _ = request.result.send(DurableProgress);
    #[cfg(test)]
    trace.mark("native-progress-acknowledgment-sent");
    Ok(())
}
