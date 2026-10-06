//! Acknowledges one genuinely qualified selected whole collector lease.
//!
//! The channel starts empty and only this native worker can populate it after
//! verifying the protected slot/transaction, portable snapshot/pointer,
//! actual configured lease and complete refreshed Frame. It synchronizes the same
//! checked metadata descriptors and only directories below the retained actual
//! namespace/control roots. This mechanic grants no collection, ownership or
//! elapsed-age authority.

use super::publication_sync::{SyncScope, synchronize};
use super::{FencePolicy, NativeEffectFailure, Path, PathBuf, Plan, Worker};
use std::{io, sync::mpsc};
use terrane_core::gc::GcLease;
use terrane_core::gc::publication::{PublicationCommit, PublicationProof, PublicationTransaction};

/// Fixes the exact canonical artifacts of one configured collector lease transition.
pub(in super::super) struct LeaseRequest {
    root: PathBuf,
    control: PathBuf,
    slot_path: PathBuf,
    slot: Vec<u8>,
    transaction_path: PathBuf,
    transaction: Vec<u8>,
    snapshot_path: PathBuf,
    snapshot: Vec<u8>,
    pointer: Vec<u8>,
    owner: u32,
    result: mpsc::Sender<DurableLease>,
}

impl LeaseRequest {
    /// Borrows the fixed actual slot only for native fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &Path {
        &self.slot_path
    }
}

/// Acknowledges actual completed durability without granting any collection authority.
struct DurableLease {
    _private: (),
}

/// Takes the one native lease acknowledgment with no caller setter or constructor.
pub(in super::super) struct LeaseReceiver {
    result: mpsc::Receiver<DurableLease>,
}

impl LeaseReceiver {
    /// Consumes one actual completed native lease acknowledgment.
    ///
    /// # Errors
    /// Refuses no-op unit success, swallowed native failures or an unexecuted request.
    pub(in super::super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result.try_recv().map(|_| ()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native lease publication acknowledgment unavailable",
            )
            .into()
        })
    }
}

/// Borrows fixed observations without creating a native result or destructive authority.
pub(in super::super) struct LeaseInputs<'a, 'operation, 'held> {
    /// Actual selected namespace retained by the Frame.
    pub(in super::super) root: &'a Path,
    /// Independently configured protected control retained by the Frame.
    pub(in super::super) control: &'a Path,
    /// Closed producer retaining genuine configured lease and consumed controls.
    pub(in super::super) checked: &'a crate::selected_bridge::CheckedGcLease<'operation, 'held>,
    /// Exact selecting slot after closed configured lease producer validation.
    pub(in super::super) slot: &'a PublicationCommit,
    /// Exact lease-only successor preserving all other selected authority.
    pub(in super::super) transaction: &'a PublicationTransaction,
    /// Exact canonical successor portable snapshot body.
    pub(in super::super) snapshot: &'a [u8],
    /// Independently configured native backend owner.
    pub(in super::super) owner: u32,
}

/// Prepares a closed request from a genuine checked lease and fixed publication bytes.
///
/// This creates no result or destructive authority. The executor independently
/// verifies all native observations, protection, exact bodies and durability.
///
/// # Errors
/// Refuses inconsistent canonical slot, transaction or snapshot, changed whole
/// predecessor, a non-lease change or unavailable genuine retained controls.
pub(in super::super) fn lease_plan(
    inputs: LeaseInputs<'_, '_, '_>,
) -> Result<(Plan, LeaseReceiver), NativeEffectFailure> {
    let LeaseInputs {
        root,
        control,
        checked,
        slot,
        transaction,
        snapshot,
        owner,
    } = inputs;
    let observed = checked.observed();
    let mut next = observed.state().clone();
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or_else(|| io::Error::other("lease revision overflow"))?;
    if transaction.proof != PublicationProof::Raw
        || transaction.old.as_ref() != Some(observed.state())
        || transaction.new != next
        || checked.next() != &next
        || transaction.changes.as_slice() != std::slice::from_ref(checked.change())
        || slot.revision != next.revision
        || slot.predecessor != transaction.predecessor.as_ref().map(|row| row.digest)
        || transaction
            .predecessor
            .as_ref()
            .is_none_or(|row| (row.revision, row.digest) != observed.stamp())
    {
        return Err(io::Error::other("lease selected association differs").into());
    }
    let change = checked.change();
    if change.key != "gc/lease"
        || observed.logical().get("gc/lease") != Some(&change.expected)
        || observed.state().guard.is_none()
        || checked.effect_context().controls().is_empty()
    {
        return Err(io::Error::other("lease whole predecessor differs").into());
    }
    let next_lease = GcLease::decode(
        change
            .new
            .as_deref()
            .ok_or_else(|| io::Error::other("lease successor absent"))?,
    )
    .map_err(io::Error::other)?;
    let old_lease = change
        .expected
        .as_deref()
        .map(GcLease::decode)
        .transpose()
        .map_err(io::Error::other)?;
    let valid = match old_lease {
        None => next_lease.epoch == 1,
        Some(old) => {
            next_lease.expiry > old.expiry
                && ((next_lease.epoch == old.epoch && next_lease.holder == old.holder)
                    || old.epoch.checked_add(1) == Some(next_lease.epoch))
        }
    };
    if !valid || next_lease.epoch == 0 || next_lease.expiry == 0 {
        return Err(
            io::Error::other("lease successor is not a whole conditional transition").into(),
        );
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
        return Err(io::Error::other("lease slot digest differs").into());
    }
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::SealLeasePublication(Box::new(LeaseRequest {
            root: root.to_owned(),
            control: control.to_owned(),
            slot_path: control.join(format!("publication/commits/{}", slot.revision)),
            slot: slot.encode().map_err(io::Error::other)?,
            transaction_path: control.join(&slot.transaction_key),
            transaction: transaction_bytes,
            snapshot_path: root.join(&transaction.snapshot.key),
            snapshot: snapshot.to_vec(),
            pointer: transaction.snapshot.encode().map_err(io::Error::other)?,
            owner,
            result: sender,
        })),
        LeaseReceiver { result: receiver },
    ))
}

fn association(request: &LeaseRequest, worker: &Worker) -> Result<(), NativeEffectFailure> {
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    if worker.projection.final_check.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lease acknowledgment lacks genuine final refresh",
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
            matches!(
                read.policy,
                FencePolicy::ProtectedRecord { owner } if owner == request.owner
            )
        } else {
            matches!(
                read.policy,
                FencePolicy::Payload { owner } if owner == request.owner
            )
        };
        if !matches {
            return Err(io::Error::other("lease record policy differs").into());
        }
    }
    worker.projection.exact(
        &request.root.join("publication/PORTABLE"),
        Some(&request.pointer),
    )?;
    worker.refresh(&[])
}

/// Completes descriptor synchronization and required directory durability before acknowledgment.
///
/// # Errors
/// Refuses changed actual bodies/descriptors/names/ancestors, missing selected
/// associations, current lease/control refusal and actual sync
/// failures. Unit return without this completion cannot populate the receiver.
pub(super) fn execute(
    request: LeaseRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    association(&request, &worker)?;
    synchronize(
        &mut worker,
        &[
            SyncScope {
                path: request.root.clone(),
                owner: request.owner,
                protected: false,
            },
            SyncScope {
                path: request.control.clone(),
                owner: request.owner,
                protected: true,
            },
        ],
    )?;
    association(&request, &worker)?;
    let _ = request.result.send(DurableLease { _private: () });
    Ok(())
}
