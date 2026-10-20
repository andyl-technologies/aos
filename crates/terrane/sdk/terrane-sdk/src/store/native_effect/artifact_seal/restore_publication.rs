//! Acknowledges one genuinely qualified selected current restoration.
//!
//! The channel starts empty and only this native worker can populate it after
//! verifying the protected slot/transaction, portable snapshot/pointer,
//! actual native pair and complete refreshed Frame. It synchronizes the same
//! exact completed outputs, serving index and all consumed Original controls,
//! with unique required directories below the retained actual
//! namespace/control roots. Pack bodies are never read by this mechanic.

use super::super::publication::CompletedWrites;
use super::publication_sync::SyncScope;
use super::publication_sync::outputs::{Inventory, Target, insert_target, synchronize};
use super::restore_pair::PairHold;
use super::{FencePolicy, NativeEffectFailure, NativeExclusion, Path, PathBuf, Plan, Worker};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, mpsc},
};
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationTransaction,
};

/// Fixes one actual pair and exact canonical selected restoration artifacts.
pub(in super::super) struct RestoreRequest {
    root: PathBuf,
    control: PathBuf,
    slot_path: PathBuf,
    slot: Vec<u8>,
    transaction_path: PathBuf,
    transaction: Vec<u8>,
    snapshot_path: PathBuf,
    snapshot: Vec<u8>,
    pointer: Vec<u8>,
    pair: Arc<PairHold>,
    writes: CompletedWrites,
    scopes: Vec<SyncScope>,
    original_directories: Vec<(PathBuf, u32)>,
    required_records: Vec<(PathBuf, Vec<u8>, PathBuf, u32)>,
    outputs: Vec<(PathBuf, Vec<u8>)>,
    owner: u32,
    result: mpsc::Sender<DurableRestore>,
}

impl RestoreRequest {
    /// Borrows the fixed actual slot only for native fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &Path {
        &self.slot_path
    }
}

/// Acknowledges actual completed durability without granting any collection authority.
struct DurableRestore {
    _private: (),
}

/// Takes the one native restoration acknowledgment with no caller setter or constructor.
pub(in super::super) struct RestoreReceiver {
    result: mpsc::Receiver<DurableRestore>,
}

impl RestoreReceiver {
    /// Consumes one actual completed native acknowledgment.
    ///
    /// # Errors
    /// Refuses no-op unit success, swallowed native failures or an unexecuted request.
    pub(in super::super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result.try_recv().map(|_| ()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native restore publication acknowledgment unavailable",
            )
            .into()
        })
    }
}

/// Borrows fixed observations without creating a native result or destructive authority.
pub(in super::super) struct RestoreInputs<'a, 'operation, 'held> {
    /// Actual selected namespace retained by the Frame.
    pub(in super::super) root: &'a Path,
    /// Independently configured protected control retained by the Frame.
    pub(in super::super) control: &'a Path,
    /// Closed producer holding independently current qualification and actual pair.
    pub(in super::super) checked:
        &'a crate::selected_bridge::native_collection_restore::CheckedRestore<'operation, 'held>,
    /// Actual retained exclusions needed to bind the pair to the current Frame.
    pub(in super::super) exclusions: &'a [NativeExclusion],
    /// Exact executor-completed publication writes, without authority.
    pub(in super::super) writes: &'a CompletedWrites,
    /// Exact selecting slot after closed current-root producer validation.
    pub(in super::super) slot: &'a PublicationCommit,
    /// Exact proof-zero successor preserving loss generation and selected sources.
    pub(in super::super) transaction: &'a PublicationTransaction,
    /// Exact canonical successor portable snapshot body.
    pub(in super::super) snapshot: &'a [u8],
    /// Independently configured native backend owner.
    pub(in super::super) owner: u32,
}

/// Prepares a closed request from a genuine native pair and fixed publication bytes.
///
/// This creates no result or destructive authority. The executor independently
/// verifies all native observations, protection, exact bodies and durability.
///
/// # Errors
/// Refuses another pair/root/control/exclusion, inconsistent canonical slot,
/// transaction or snapshot, changed refs/Guard/loss/sources/inventory/burns,
/// or an exclusion change outside the exact qualified restoration.
pub(in super::super) fn restore_plan(
    inputs: RestoreInputs<'_, '_, '_>,
) -> Result<(Plan, RestoreReceiver), NativeEffectFailure> {
    let RestoreInputs {
        root,
        control,
        checked,
        exclusions,
        writes,
        slot,
        transaction,
        snapshot,
        owner,
    } = inputs;
    let pair = checked.pair();
    let observed = checked.current().observed();
    let mut next = observed.state().clone();
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or_else(|| io::Error::other("restore revision overflow"))?;
    if transaction.proof != PublicationProof::Raw
        || transaction.old.as_ref() != Some(observed.state())
        || transaction.new != next
        || checked.next() != &next
        || transaction.changes != checked.changes()
        || slot.revision != next.revision
        || slot.predecessor != transaction.predecessor.as_ref().map(|row| row.digest)
        || transaction
            .predecessor
            .as_ref()
            .is_none_or(|row| (row.revision, row.digest) != observed.stamp())
    {
        return Err(io::Error::other("restore selected association differs").into());
    }
    let old_cap = BucketCapabilities::decode(
        observed
            .logical()
            .get("CAPABILITIES")
            .and_then(Option::as_deref)
            .ok_or_else(|| io::Error::other("restore has no old capabilities"))?,
    )
    .map_err(io::Error::other)?;
    let cap = transaction
        .changes
        .iter()
        .find(|row| row.key == "CAPABILITIES")
        .ok_or_else(|| io::Error::other("restore has no new capabilities"))?;
    if cap.expected.as_deref()
        != observed
            .logical()
            .get("CAPABILITIES")
            .and_then(Option::as_deref)
    {
        return Err(io::Error::other("restore old capabilities differ").into());
    }
    let cap = BucketCapabilities::decode(
        cap.new
            .as_deref()
            .ok_or_else(|| io::Error::other("restore capabilities absent"))?,
    )
    .map_err(io::Error::other)?;
    let generation = cap
        .generation
        .ok_or_else(|| io::Error::other("restore generation absent"))?;
    let mut expected_cap = old_cap.clone();
    expected_cap.generation = Some(generation);
    if cap != expected_cap
        || generation
            <= old_cap
                .generation
                .ok_or_else(|| io::Error::other("restore old generation absent"))?
    {
        return Err(io::Error::other("restore capabilities changed unrelated fields").into());
    }
    let old_key = format!(
        "objects/index/{}/MANIFEST",
        old_cap
            .generation
            .ok_or_else(|| io::Error::other("restore old generation absent"))?
    );
    let previous = GenerationManifest::decode(
        observed
            .logical()
            .get(&old_key)
            .and_then(Option::as_deref)
            .ok_or_else(|| io::Error::other("restore old manifest absent"))?,
    )
    .map_err(io::Error::other)?;
    let key = format!("objects/index/{generation}/MANIFEST");
    let manifest = GenerationManifest::decode(
        transaction
            .changes
            .iter()
            .find(|row| row.key == key)
            .and_then(|row| row.new.as_deref())
            .ok_or_else(|| io::Error::other("restore manifest absent"))?,
    )
    .map_err(io::Error::other)?;
    let mut remaining = previous
        .exclusions
        .clone()
        .ok_or_else(|| io::Error::other("restore exclusions Unknown"))?;
    let position = remaining
        .binary_search_by_key(&pair.inventory().pack_id, |row| row.pack_id)
        .map_err(|_| io::Error::other("restore old active binding absent"))?;
    if &remaining[position] != checked.exclusion() {
        return Err(io::Error::other("restore old binding differs").into());
    }
    remaining.remove(position);
    if manifest.generation != generation
        || manifest.cycle != previous.cycle
        || manifest.inventory != previous.inventory
        || manifest.burns != previous.burns
        || manifest.exclusions.as_ref() != Some(&remaining)
        || manifest
            .inventory
            .as_ref()
            .is_none_or(|rows| !rows.contains(pair.inventory()))
        || manifest
            .burns
            .as_ref()
            .is_none_or(|rows| rows.binary_search(&pair.inventory().pack_id).is_ok())
        || next
            .burn_owners
            .as_ref()
            .is_none_or(|rows| rows.iter().any(|row| row.pack == pair.inventory().pack_id))
    {
        return Err(io::Error::other("restore manifest changed unrelated authority").into());
    }
    transaction
        .check_snapshot(snapshot)
        .map_err(io::Error::other)?;
    transaction
        .check_key(&slot.transaction_key)
        .map_err(io::Error::other)?;
    let transaction_bytes = transaction.encode().map_err(io::Error::other)?;
    if slot.transaction_digest != *blake3::hash(&transaction_bytes).as_bytes() {
        return Err(io::Error::other("restore slot digest differs").into());
    }
    let pair = pair.retention(root, control, exclusions)?;
    let mut scopes = vec![
        SyncScope {
            path: root.to_owned(),
            owner,
            protected: false,
        },
        SyncScope {
            path: control.to_owned(),
            owner,
            protected: true,
        },
    ];
    let mut original_directories = Vec::new();
    let mut required_records = Vec::new();
    let current = checked.current();
    let guard = current.guard_record();
    required_records.push((
        guard.path().to_owned(),
        guard
            .bytes()
            .ok_or_else(|| io::Error::other("restore current Guard absent"))?
            .to_vec(),
        control.to_owned(),
        owner,
    ));
    let registration = observed
        .physical_reads()
        .first()
        .filter(|read| read.path() == control.join("backend-registration.cbor"))
        .ok_or_else(|| io::Error::other("restore backend registration absent"))?;
    required_records.push((
        registration.path().to_owned(),
        registration
            .bytes()
            .ok_or_else(|| io::Error::other("restore registration body absent"))?
            .to_vec(),
        control.to_owned(),
        owner,
    ));
    // The real maintenance index is a serving dependency, even when unchanged.
    // Its bounded body comes from the producer's actual observed reads.
    let index_path = root.join(
        crate::pack::PackId::from_random_bytes(checked.pair().inventory().pack_id).index_key(),
    );
    let index = checked
        .reads()
        .iter()
        .chain(current.inputs())
        .find(|read| read.path() == index_path)
        .ok_or_else(|| io::Error::other("restore maintenance index observation absent"))?;
    let index_bytes = index
        .bytes()
        .ok_or_else(|| io::Error::other("restore maintenance index body absent"))?;
    // Payload records use the namespace scope, unlike protected Original rows.
    let mut outputs = vec![(index_path, index_bytes.to_vec())];
    for change in &transaction.changes {
        outputs.push((
            root.join(&change.key),
            change
                .new
                .as_ref()
                .ok_or_else(|| io::Error::other("restore selected output absent"))?
                .clone(),
        ));
    }
    for controls in current.effect_context().controls() {
        scopes.push(SyncScope {
            path: controls.directory().to_owned(),
            owner: controls.owner(),
            protected: true,
        });
        original_directories.push((controls.directory().to_owned(), controls.owner()));
        for record in controls.records() {
            required_records.push((
                record.path().to_owned(),
                record.bytes().to_vec(),
                controls.directory().to_owned(),
                controls.owner(),
            ));
        }
    }
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::SealRestorePublication(Box::new(RestoreRequest {
            root: root.to_owned(),
            control: control.to_owned(),
            slot_path: control.join(format!("publication/commits/{}", slot.revision)),
            slot: slot.encode().map_err(io::Error::other)?,
            transaction_path: control.join(&slot.transaction_key),
            transaction: transaction_bytes,
            snapshot_path: root.join(&transaction.snapshot.key),
            snapshot: snapshot.to_vec(),
            pointer: transaction.snapshot.encode().map_err(io::Error::other)?,
            pair,
            writes: writes.clone(),
            scopes,
            original_directories,
            required_records,
            outputs,
            owner,
            result: sender,
        })),
        RestoreReceiver { result: receiver },
    ))
}

fn association(request: &RestoreRequest, worker: &Worker) -> Result<(), NativeEffectFailure> {
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    if worker.projection.final_check.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "barrier lacks genuine current pair/final refresh",
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
        let matches = if protected {
            matches!(read.policy,FencePolicy::ProtectedRecord{owner} if owner==request.owner)
        } else {
            matches!(read.policy,FencePolicy::Payload{owner} if owner==request.owner)
        };
        if !matches {
            return Err(io::Error::other("barrier record policy differs").into());
        }
    }
    worker.projection.exact(
        &request.root.join("publication/PORTABLE"),
        Some(&request.pointer),
    )?;
    request.pair.recheck()?;
    worker.refresh(&[])
}

/// Completes descriptor synchronization and required directory durability before acknowledgment.
///
/// # Errors
/// Refuses changed actual bodies/descriptors/names/ancestors, missing selected
/// associations or retained pair, current lease/control refusal and actual sync
/// failures. Unit return without this completion cannot populate the receiver.
pub(super) fn execute(
    request: RestoreRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    association(&request, &worker)?;
    let mut targets = BTreeMap::new();
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
            &mut targets,
            path.clone(),
            Target {
                root: root.clone(),
                owner: request.owner,
                protected,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, bytes) in &request.outputs {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: request.root.clone(),
                owner: request.owner,
                protected: false,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, bytes, root, owner) in &request.required_records {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: root.clone(),
                owner: *owner,
                protected: true,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, write) in request.writes.records() {
        let (owner, protected) = match write.policy() {
            FencePolicy::Payload { owner } => (owner, false),
            FencePolicy::ProtectedRecord { owner } => (owner, true),
            _ => return Err(io::Error::other("completed restore write policy differs").into()),
        };
        if !request.scopes.iter().any(|scope| {
            scope.path == write.root() && scope.owner == owner && scope.protected == protected
        }) {
            return Err(io::Error::other("completed restore write boundary differs").into());
        }
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: write.root().to_owned(),
                owner,
                protected,
                expected: write.expected().map(<[u8]>::to_vec),
            },
        )?;
    }
    // This inventory selects durability work only. Complete Worker refresh
    // still checks every retained input and the actual current/pair callback.
    synchronize(
        Inventory {
            scopes: &request.scopes,
            targets,
            original_directories: &request.original_directories,
            #[cfg(all(test, feature = "tokio"))]
            completed_syncs: None,
        },
        &mut worker,
    )?;
    association(&request, &worker)?;
    let _ = request.result.send(DurableRestore { _private: () });
    Ok(())
}
