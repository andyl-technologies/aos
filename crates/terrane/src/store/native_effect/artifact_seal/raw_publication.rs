//! Closes durability acknowledgment for actual backend-only raw selection.
//!
//! The receiver begins empty. Only the native executor fills it after exact
//! Raw slot/transaction/snapshot association, same-descriptor output sync,
//! required directory sync and complete retained backend refresh. This result
//! creates no Guard, actor, lineage, collector or deletion authority.

use super::super::publication::CompletedWrites;
use super::publication_sync::SyncScope;
use super::publication_sync::outputs::{Inventory, Target, insert_target, synchronize};
use super::{FencePolicy, MetadataStamp, NativeEffectFailure, PathBuf, Plan, Worker};
use std::{collections::BTreeMap, io, sync::mpsc};
use terrane_core::gc::publication::{PublicationCommit, PublicationProof, PublicationTransaction};

/// Fixes actual backend outputs and the independently captured registration.
pub(in super::super) struct RawRequest {
    root: PathBuf,
    control: PathBuf,
    owner: u32,
    scopes: Vec<SyncScope>,
    original_directories: Vec<(PathBuf, u32)>,
    contextual: bool,
    registration: (PathBuf, Vec<u8>, MetadataStamp),
    slot_path: PathBuf,
    slot: Vec<u8>,
    transaction_path: PathBuf,
    transaction: Vec<u8>,
    snapshot_path: PathBuf,
    snapshot: Vec<u8>,
    pointer: Vec<u8>,
    changes: Vec<(PathBuf, Option<Vec<u8>>)>,
    writes: CompletedWrites,
    result: mpsc::Sender<DurableRaw>,
}

impl RawRequest {
    /// Borrows the actual fixed selecting slot for native test observation.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &std::path::Path {
        &self.slot_path
    }
}

struct DurableRaw;

/// Consumes actual native completion without allowing caller population.
pub(in super::super) struct RawReceiver {
    result: mpsc::Receiver<DurableRaw>,
}

impl RawReceiver {
    /// Takes the executor's result before selected publication success.
    ///
    /// # Errors
    /// Refuses no-op success, swallowed sync failures and unexecuted requests.
    pub(in super::super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result.try_recv().map(|_| ()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native raw publication acknowledgment unavailable",
            )
            .into()
        })
    }
}

/// Groups completed output data with its optional actual retained control context.
///
/// These borrows confer no authority and cannot populate the closed result.
pub(in super::super) struct RawDurabilityInputs<'input> {
    /// The actual producer's completed outputs and current Original records.
    pub(in super::super) writes: &'input CompletedWrites,
    /// The same closed control context used to build the submitted native Frame.
    pub(in super::super) context:
        Option<&'input crate::selected_bridge::native_guard::GuardEffectContext>,
}

/// Prepares a closed acknowledgment from actual held backend transition data.
///
/// # Errors
/// Refuses mismatched selected state, Raw proof, whole expectations, registered
/// slot/transaction/snapshot association or missing configured backend controls.
pub(in super::super) fn raw_plan(
    observed: &crate::bucket::publication::SelectedObservation<'_>,
    mutation: &crate::bucket::publication::RawMutation,
    slot: &PublicationCommit,
    transaction: &PublicationTransaction,
    snapshot: &[u8],
    durability: RawDurabilityInputs<'_>,
) -> Result<(Plan, RawReceiver), NativeEffectFailure> {
    let RawDurabilityInputs { writes, context } = durability;
    let revision = observed
        .state()
        .revision
        .checked_add(1)
        .ok_or_else(|| io::Error::other("raw revision overflow"))?;
    if mutation.previous() != observed.state()
        || mutation.predecessor() != observed.stamp().1
        || mutation.previous_logical() != observed.logical()
        || transaction.old.as_ref() != Some(observed.state())
        || transaction.new != *mutation.next()
        || transaction.new.revision != revision
        || transaction.new.binding != observed.state().binding
        || transaction.new.guard != observed.state().guard
        || transaction.new.burn_owners != observed.state().burn_owners
        || transaction.proof != PublicationProof::Raw
        || transaction.changes.as_slice() != mutation.changes()
        || transaction
            .predecessor
            .as_ref()
            .is_none_or(|stamp| (stamp.revision, stamp.digest) != observed.stamp())
        || slot.revision != revision
        || slot.predecessor != Some(observed.stamp().1)
    {
        return Err(io::Error::other("raw selected association differs").into());
    }
    for change in mutation.changes() {
        if observed.logical().get(&change.key).cloned().flatten() != change.expected {
            return Err(io::Error::other("raw whole predecessor differs").into());
        }
    }
    transaction
        .check_snapshot(snapshot)
        .map_err(io::Error::other)?;
    transaction
        .check_key(&slot.transaction_key)
        .map_err(io::Error::other)?;
    let transaction_bytes = transaction.encode().map_err(io::Error::other)?;
    if slot.transaction_digest != *blake3::hash(&transaction_bytes).as_bytes() {
        return Err(io::Error::other("raw slot digest differs").into());
    }
    let original = observed
        .physical_reads()
        .first()
        .filter(|read| {
            read.path()
                .file_name()
                .is_some_and(|name| name == "backend-registration.cbor")
        })
        .ok_or_else(|| io::Error::other("raw backend registration absent"))?;
    let bytes = original
        .bytes()
        .ok_or_else(|| io::Error::other("raw backend registration bytes absent"))?;
    let metadata = MetadataStamp::checked(
        original
            .metadata()
            .ok_or_else(|| io::Error::other("raw backend registration metadata absent"))?,
    )?;
    let control = original
        .path()
        .parent()
        .ok_or_else(|| io::Error::other("raw backend control absent"))?
        .to_owned();
    let root = observed.identity().root().to_owned();
    let owner = observed.configured_operator_uid();
    FencePolicy::ProtectedRecord { owner }.validate(metadata)?;
    let mut scopes = vec![
        SyncScope {
            path: root.clone(),
            owner,
            protected: false,
        },
        SyncScope {
            path: control.clone(),
            owner,
            protected: true,
        },
    ];
    let mut original_directories = Vec::new();
    if let Some(context) = context {
        if context
            .controls()
            .first()
            .is_none_or(|controls| controls.owner() != owner)
        {
            return Err(io::Error::other("raw contextual controls differ").into());
        }
        // Only the closed producer's actual retained controls extend durability
        // boundaries. Completed-write data cannot introduce a new scope.
        for controls in context.controls() {
            scopes.push(SyncScope {
                path: controls.directory().to_owned(),
                owner: controls.owner(),
                protected: true,
            });
            original_directories.push((controls.directory().to_owned(), controls.owner()));
        }
    }
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::SealRawPublication(Box::new(RawRequest {
            registration: (original.path().to_owned(), bytes.to_vec(), metadata),
            slot_path: control.join(format!("publication/commits/{}", slot.revision)),
            slot: slot.encode().map_err(io::Error::other)?,
            transaction_path: control.join(&slot.transaction_key),
            transaction: transaction_bytes,
            snapshot_path: root.join(&transaction.snapshot.key),
            snapshot: snapshot.to_vec(),
            pointer: transaction.snapshot.encode().map_err(io::Error::other)?,
            changes: mutation
                .changes()
                .iter()
                .map(|change| (root.join(&change.key), change.new.clone()))
                .collect(),
            root,
            control,
            owner,
            scopes,
            original_directories,
            contextual: context.is_some(),
            writes: writes.clone(),
            result: sender,
        })),
        RawReceiver { result: receiver },
    ))
}

fn association(request: &RawRequest, worker: &Worker) -> Result<(), NativeEffectFailure> {
    if request.contextual && worker.projection.final_check.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw contextual acknowledgment lacks genuine final refresh",
        )
        .into());
    }
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    for (path, bytes, protected) in [
        (&request.slot_path, &request.slot, true),
        (&request.transaction_path, &request.transaction, true),
        (&request.snapshot_path, &request.snapshot, false),
        (
            &request.root.join("publication/PORTABLE"),
            &request.pointer,
            false,
        ),
    ] {
        let read = worker.projection.exact(path, Some(bytes))?;
        let valid = match read.policy {
            FencePolicy::ProtectedRecord { owner } => protected && owner == request.owner,
            FencePolicy::Payload { owner } => !protected && owner == request.owner,
            _ => false,
        };
        if !valid {
            return Err(io::Error::other("raw output policy differs").into());
        }
    }
    let (path, bytes, metadata) = &request.registration;
    let read = worker.projection.exact(path, Some(bytes))?;
    if read.metadata != Some(*metadata)
        || read.identity != Some(metadata.identity)
        || !matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner)
    {
        return Err(io::Error::other("raw backend registration preimage differs").into());
    }
    worker.refresh(&[])
}

fn targets(request: &RawRequest) -> io::Result<BTreeMap<PathBuf, Target>> {
    let mut result = BTreeMap::new();
    for (path, bytes, root, protected) in [
        (&request.slot_path, &request.slot, &request.control, true),
        (
            &request.transaction_path,
            &request.transaction,
            &request.control,
            true,
        ),
        (
            &request.snapshot_path,
            &request.snapshot,
            &request.root,
            false,
        ),
        (
            &request.root.join("publication/PORTABLE"),
            &request.pointer,
            &request.root,
            false,
        ),
    ] {
        insert_target(
            &mut result,
            path.clone(),
            Target {
                root: root.clone(),
                owner: request.owner,
                protected,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, bytes) in &request.changes {
        insert_target(
            &mut result,
            path.clone(),
            Target {
                root: request.root.clone(),
                owner: request.owner,
                protected: false,
                expected: bytes.clone(),
            },
        )?;
    }
    for (path, write) in request.writes.records() {
        let (owner, protected) = match write.policy() {
            FencePolicy::Payload { owner } => (owner, false),
            FencePolicy::ProtectedRecord { owner } => (owner, true),
            _ => return Err(io::Error::other("raw completed output boundary differs")),
        };
        if !request.scopes.iter().any(|scope| {
            scope.path == write.root() && scope.owner == owner && scope.protected == protected
        }) {
            return Err(io::Error::other("raw completed output boundary differs"));
        }
        insert_target(
            &mut result,
            path.clone(),
            Target {
                root: write.root().to_owned(),
                owner,
                protected,
                expected: write.expected().map(<[u8]>::to_vec),
            },
        )?;
    }
    Ok(result)
}

/// Fills the private result only after exact output durability and final refresh.
///
/// # Errors
/// Refuses changed retained inputs, controls, names or ancestry, mismatched
/// backend association and actual descriptor/directory synchronization failure.
pub(super) fn execute(request: RawRequest, mut worker: Worker) -> Result<(), NativeEffectFailure> {
    association(&request, &worker)?;
    synchronize(
        Inventory {
            scopes: &request.scopes,
            targets: targets(&request)?,
            original_directories: &request.original_directories,
            #[cfg(all(test, feature = "tokio"))]
            completed_syncs: None,
        },
        &mut worker,
    )?;
    association(&request, &worker)?;
    let _ = request.result.send(DurableRaw);
    Ok(())
}
