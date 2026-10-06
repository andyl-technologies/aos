//! Closes durability acknowledgment for genuinely checked Guard and ref mutations.
//!
//! The private channel starts empty. Only the native executor can fill it after
//! checking the selected slot/transaction/snapshot association, synchronizing
//! exact outputs, completed repairs and unique required directories, and refreshing all
//! real namespace/control exclusions and current operation checks. Receipt bytes
//! or unit-returning adapters cannot manufacture this acknowledgment.

use super::super::publication::CompletedWrites;
use super::publication_sync::SyncScope;

#[path = "mutation_publication/synchronize.rs"]
mod synchronization;
use super::{FencePolicy, MetadataStamp, NativeEffectFailure, PathBuf, Plan, Worker};
use std::{io, sync::mpsc};
use terrane_core::gc::publication::{PublicationCommit, PublicationTransaction};

/// Fixes canonical selected metadata while retaining a private executor-only result.
pub(in super::super) struct MutationRequest {
    root: PathBuf,
    control: PathBuf,
    owner: u32,
    scopes: Vec<SyncScope>,
    slot_path: PathBuf,
    slot: Vec<u8>,
    transaction_path: PathBuf,
    transaction: Vec<u8>,
    snapshot_path: PathBuf,
    snapshot: Vec<u8>,
    pointer: Vec<u8>,
    proofs: Vec<(PathBuf, Vec<u8>)>,
    selected_reads: Vec<(PathBuf, Vec<u8>, MetadataStamp, u32)>,
    writes: CompletedWrites,
    changes: Vec<(PathBuf, Option<Vec<u8>>)>,
    original_directories: Vec<(PathBuf, u32)>,
    #[cfg(all(test, feature = "tokio"))]
    completed_syncs: Option<mpsc::Sender<MutationSyncEvent>>,
    result: mpsc::Sender<DurableMutation>,
}

impl MutationRequest {
    /// Borrows the fixed selecting slot for native test fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &std::path::Path {
        &self.slot_path
    }
}

/// Reports successful actual sync syscalls to a fixture, never acknowledgment.
#[cfg(all(test, feature = "tokio"))]
pub(crate) use super::publication_sync::outputs::SyncEvent as MutationSyncEvent;

impl MutationRequest {
    /// Attaches a fixture-owned observation channel without changing the plan.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(in super::super) fn observe_syncs(&mut self, sender: mpsc::Sender<MutationSyncEvent>) {
        self.completed_syncs = Some(sender);
    }
}

/// Acknowledges actual durable completion without creating publication permission.
struct DurableMutation {
    _private: (),
}

/// Consumes one actual native acknowledgment without setters or caller constructors.
pub(in super::super) struct MutationReceiver {
    result: mpsc::Receiver<DurableMutation>,
}

impl MutationReceiver {
    /// Takes the executor's durable completion before reporting selected success.
    ///
    /// # Errors
    /// Refuses no-op success, swallowed physical failures and unexecuted requests.
    pub(in super::super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result.try_recv().map(|_| ()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native checked mutation acknowledgment unavailable",
            )
            .into()
        })
    }
}

/// Prepares an empty channel from the existing closed checked mutation producer.
///
/// No caller-supplied UID, record list, boundary or authorization callback enters
/// this factory. Scope owners and paths come from the actual selected observations
/// and already retained consumed Original controls. Native execution independently
/// checks their association with the genuine submitted Frame.
///
/// # Errors
/// Refuses changed predecessor, whole-value expectations, inconsistent successor
/// proof/slot/transaction/snapshot, missing configured controls or current refusal.
pub(in super::super) fn mutation_plan(
    checked: &crate::selected_bridge::CheckedMutation<'_, '_>,
    slot: &PublicationCommit,
    transaction: &PublicationTransaction,
    snapshot: &[u8],
    writes: &CompletedWrites,
) -> Result<(Plan, MutationReceiver), NativeEffectFailure> {
    let observed = checked.observed();
    let context = checked.effect_context().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "checked mutation lacks native controls",
        )
    })?;
    let revision = observed
        .state()
        .revision
        .checked_add(1)
        .ok_or_else(|| io::Error::other("checked mutation revision overflow"))?;
    if transaction.old.as_ref() != Some(observed.state())
        || transaction.new != *checked.next()
        || transaction.new.revision != revision
        || transaction.proof != checked.proof()
        || transaction.changes.as_slice() != checked.changes()
        || transaction
            .predecessor
            .as_ref()
            .is_none_or(|stamp| (stamp.revision, stamp.digest) != observed.stamp())
        || slot.revision != revision
        || slot.predecessor != transaction.predecessor.as_ref().map(|stamp| stamp.digest)
        || transaction.new.guard != Some(*blake3::hash(checked.guard_snapshot()).as_bytes())
        || context.controls().is_empty()
        || (observed.state().guard.is_some() && context.selected_reads().is_empty())
    {
        return Err(io::Error::other("checked mutation selected association differs").into());
    }
    for change in checked.changes() {
        if observed.logical().get(&change.key).cloned().flatten() != change.expected {
            return Err(io::Error::other("checked mutation whole predecessor differs").into());
        }
    }
    checked.recheck_before_slot()?;
    transaction
        .check_snapshot(snapshot)
        .map_err(io::Error::other)?;
    transaction
        .check_key(&slot.transaction_key)
        .map_err(io::Error::other)?;
    let transaction_bytes = transaction.encode().map_err(io::Error::other)?;
    if slot.transaction_digest != *blake3::hash(&transaction_bytes).as_bytes() {
        return Err(io::Error::other("checked mutation slot digest differs").into());
    }

    let mut scopes = Vec::new();
    let mut destination = None;
    for selection in std::iter::once(observed).chain(checked.sources().iter().copied()) {
        let owner = selection.configured_operator_uid();
        let root = selection.identity().root().to_owned();
        let registration = selection
            .physical_reads()
            .first()
            .filter(|read| {
                read.path()
                    .file_name()
                    .is_some_and(|name| name == "backend-registration.cbor")
            })
            .ok_or_else(|| io::Error::other("checked mutation backend registration missing"))?;
        let control = registration
            .path()
            .parent()
            .ok_or_else(|| io::Error::other("checked mutation control parent missing"))?
            .to_owned();
        if destination.is_none() {
            destination = Some((root.clone(), control.clone(), owner));
        }
        scopes.push(SyncScope {
            path: root,
            owner,
            protected: false,
        });
        scopes.push(SyncScope {
            path: control,
            owner,
            protected: true,
        });
    }
    for controls in context.controls() {
        scopes.push(SyncScope {
            path: controls.directory().to_owned(),
            owner: controls.owner(),
            protected: true,
        });
    }
    let mut selected_reads = Vec::new();
    for record in context.selected_reads() {
        if !scopes.iter().any(|scope| {
            scope.protected
                && scope.owner == record.owner()
                && record.record().path().starts_with(&scope.path)
        }) {
            return Err(
                io::Error::other("checked mutation selected control record differs").into(),
            );
        }
        let read = record.record();
        let bytes = read
            .bytes()
            .ok_or_else(|| io::Error::other("selected control bytes absent"))?;
        let metadata = read
            .metadata()
            .ok_or_else(|| io::Error::other("selected control metadata absent"))?;
        selected_reads.push((
            read.path().to_owned(),
            bytes.to_vec(),
            MetadataStamp::checked(metadata)?,
            record.owner(),
        ));
    }
    let (root, control, owner) =
        destination.ok_or_else(|| io::Error::other("checked mutation destination missing"))?;
    let mut proofs = vec![(
        control.join(format!(
            "publication/guards/{}",
            blake3::hash(checked.guard_snapshot()).to_hex()
        )),
        checked.guard_snapshot().to_vec(),
    )];
    if let Some(lineage) = checked.lineage() {
        proofs.push((
            control.join(format!(
                "publication/lineage/{}",
                blake3::hash(lineage).to_hex()
            )),
            lineage.to_vec(),
        ));
    }
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::SealMutationPublication(Box::new(MutationRequest {
            slot_path: control.join(format!("publication/commits/{}", slot.revision)),
            slot: slot.encode().map_err(io::Error::other)?,
            transaction_path: control.join(&slot.transaction_key),
            transaction: transaction_bytes,
            snapshot_path: root.join(&transaction.snapshot.key),
            snapshot: snapshot.to_vec(),
            pointer: transaction.snapshot.encode().map_err(io::Error::other)?,
            root,
            control,
            owner,
            scopes,
            proofs,
            selected_reads,
            writes: writes.clone(),
            changes: checked
                .changes()
                .iter()
                .map(|change| {
                    (
                        observed.identity().root().join(&change.key),
                        change.new.clone(),
                    )
                })
                .collect(),
            original_directories: context
                .controls()
                .iter()
                .map(|controls| (controls.directory().to_owned(), controls.owner()))
                .collect(),
            #[cfg(all(test, feature = "tokio"))]
            completed_syncs: None,
            result: sender,
        })),
        MutationReceiver { result: receiver },
    ))
}

fn association(request: &MutationRequest, worker: &Worker) -> Result<(), NativeEffectFailure> {
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    if worker.projection.final_check.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "checked mutation acknowledgment lacks genuine final refresh",
        )
        .into());
    }
    for (path, bytes, protected) in [
        (&request.slot_path, request.slot.as_slice(), true),
        (
            &request.transaction_path,
            request.transaction.as_slice(),
            true,
        ),
        (&request.snapshot_path, request.snapshot.as_slice(), false),
    ] {
        let read = worker.projection.exact(path, Some(bytes))?;
        let correct = match read.policy {
            FencePolicy::ProtectedRecord { owner } => protected && owner == request.owner,
            FencePolicy::Payload { owner } => !protected && owner == request.owner,
            _ => false,
        };
        if !correct {
            return Err(io::Error::other("checked mutation record policy differs").into());
        }
    }
    let pointer = worker.projection.exact(
        &request.root.join("publication/PORTABLE"),
        Some(&request.pointer),
    )?;
    if !matches!(pointer.policy, FencePolicy::Payload { owner } if owner == request.owner) {
        return Err(io::Error::other("checked mutation pointer policy differs").into());
    }
    for (path, bytes) in &request.proofs {
        let read = worker.projection.exact(path, Some(bytes))?;
        if !matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner)
        {
            return Err(io::Error::other("checked mutation proof policy differs").into());
        }
    }
    for (path, bytes, metadata, owner) in &request.selected_reads {
        let read = worker.projection.exact(path, Some(bytes))?;
        if read.metadata != Some(*metadata)
            || read.identity != Some(metadata.identity)
            || !matches!(read.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == *owner)
        {
            return Err(
                io::Error::other("checked mutation selected control preimage differs").into(),
            );
        }
    }
    worker.refresh(&[])
}

/// Populates the private result only after actual metadata durability and final refresh.
///
/// # Errors
/// Refuses changed native records, names, ancestors or held controls, expired
/// operation authority, mismatched fixed association and actual sync failures.
pub(super) fn execute(
    request: MutationRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    association(&request, &worker)?;
    synchronization::synchronize(&request, &mut worker)?;
    association(&request, &worker)?;
    let _ = request.result.send(DurableMutation { _private: () });
    Ok(())
}
