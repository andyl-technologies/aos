//! Funds missing-index writes and retains physical resources through completion.
//!
//! The original source pin and future hold survive every failed write or reply
//! cancellation. A repair result describes one synchronized native index; it
//! grants no serving, complete-recovery or publisher Resume authority.

use super::super::{
    RETAINED_LEASE_DEADLINE,
    index_io::{IndexWriteCompletion, PendingIndexWrite, write_missing_index},
};
use super::{Custody, NativeIndexRepairReport, NativeOwnerExecutor, hex, invalid};
use crate::{
    host_cache::{DerivedIndexRepair, DetachedIndexStatus},
    host_quota::{NativeProject, synchronized_allocated_bytes},
};
use std::{
    fs::File,
    io::{self, Read},
    sync::Arc,
};
use terrane_sdk::host::cache::{LeaseRecord, PinRecord, ReservationRecord};

/// Retains the actual source, uncertain scratch and completed canonical inode.
pub(super) struct IndexRepairCustody {
    source: Arc<DerivedIndexRepair>,
    pending: Option<PendingIndexWrite>,
    completed: Option<IndexWriteCompletion>,
}

/// Repairs a missing index only after funding and retaining its original source.
///
/// # Errors
/// Refuses unresolved recovery, foreign or changed source custody, disabled or
/// insufficient capacity, failed native writes, synchronization or accounting.
pub(super) async fn run(
    executor: &NativeOwnerExecutor,
    source: DerivedIndexRepair,
) -> io::Result<NativeIndexRepairReport> {
    let custody = Arc::clone(executor.custody());
    let (source, id, future, reserved_write) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        if owner.faulted || owner.recovery_required {
            return Err(io::Error::other(
                "index repair requires failed-operation recovery",
            ));
        }
        owner.check_current()?;
        let hold = owner
            .preparation
            .config
            .index_repair_hold(source.index_bytes().len())?;
        if source.detached_index_status() != DetachedIndexStatus::Missing
            || !source.matches_client(owner.preparation.publisher())
            || !Arc::ptr_eq(source.layout(), owner.preparation.layout())
        {
            return Err(invalid(
                "index repair has foreign or ineligible source evidence",
            ));
        }
        source.check_pack_current()?;
        for file in [source.pack_file(), source.parent_file()] {
            if NativeProject::inspect(file)?.project_id != owner.preparation.config.project_id {
                return Err(invalid(
                    "index repair source differs from the charged project",
                ));
            }
        }

        // InspectPending can itself reconcile publisher custody. Authenticate fresh
        // actual charges here, even if inspection performed no local cache writes.
        owner.preparation.recheck()?;
        let future = owner
            .state
            .reservations
            .iter()
            .try_fold(hold, |total, reservation| {
                total
                    .checked_add(reservation.bytes)
                    .ok_or_else(|| invalid("index repair future holds overflow"))
            })?;
        check_future_charge(&owner, future)?;
        let mut id = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut id)?;
        let token = hex(&id);
        if owner.sources.contains_key(&id)
            || owner.index_repairs.contains_key(&id)
            || owner
                .state
                .reservations
                .iter()
                .any(|record| record.id == token)
        {
            return Err(io::Error::other("random index repair identifier collision"));
        }
        let pin_owner = format!("index-repair:{token}");
        let mut next = owner.state.clone();
        next.reservations.push(ReservationRecord {
            id: token,
            owner: owner.preparation.config.quota_owner.clone(),
            bytes: hold,
        });
        next.leases.push(LeaseRecord {
            owner: pin_owner.clone(),
            expires: RETAINED_LEASE_DEADLINE,
        });
        next.pins.push(PinRecord {
            owner: pin_owner,
            hash: hex(source.pack_identity().digest()),
            expires: RETAINED_LEASE_DEADLINE,
        });
        next.encoded_len(owner.preparation.config.state)
            .map_err(io::Error::other)?;

        let source = Arc::new(source);
        owner.begin_mutation()?;
        owner.index_repairs.insert(
            id,
            IndexRepairCustody {
                source: Arc::clone(&source),
                pending: None,
                completed: None,
            },
        );
        owner.state = next;
        owner.faulted = true;
        // No index allocation begins before the actual source pin and future hold
        // survive state snapshot/parent synchronization. Every subsequent failure
        // leaves those records and the source in the physical owner's registry.
        let write = super::super::snapshot::prepare(executor, &mut owner)?;
        (source, id, future, write)
    };
    super::super::snapshot::persist(executor, reserved_write).await?;
    let (allocated_bytes, completion_write) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        owner.check_current()?;
        source.pack_file().sync_all()?;
        source.parent_file().sync_all()?;
        source.check_pack_current()?;
        let result = write_missing_index(&source);
        let entry = owner
            .index_repairs
            .get_mut(&id)
            .ok_or_else(|| invalid("registered index source custody is absent"))?;
        let allocated_bytes = match result {
            Ok(completion) => {
                let bytes = completion.allocated_bytes;
                entry.completed = Some(completion);
                bytes
            }
            Err(failure) => {
                entry.pending = Some(failure.pending);
                return Err(failure.error);
            }
        };

        // A second durable snapshot and fresh authenticated charge observation are
        // part of command completion, not tasks detached from the caller's waiter.
        let write = super::super::snapshot::prepare(executor, &mut owner)?;
        (allocated_bytes, write)
    };
    super::super::snapshot::persist(executor, completion_write).await?;
    let mut owner = custody
        .lock()
        .map_err(|_| io::Error::other("metadata custody poisoned"))?;
    owner.check_current()?;
    owner.snapshot_allocated_bytes = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("index repair policy snapshot is absent"))
        .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
    owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
    owner.preparation.recheck()?;
    check_future_charge(&owner, future)?;
    let retained = owner
        .index_repairs
        .get(&id)
        .ok_or_else(|| invalid("completed index source custody is absent"))?;
    retained.source.check_pack_current()?;
    let completed = retained
        .completed
        .as_ref()
        .ok_or_else(|| invalid("completed canonical index custody is absent"))?;
    completed.check_current(&retained.source)?;
    owner.check_current()?;
    owner.faulted = false;
    Ok(NativeIndexRepairReport {
        pack_id: source.pack_id(),
        synchronized_index_bytes: allocated_bytes,
    })
}

fn check_future_charge(owner: &Custody, future: u64) -> io::Result<()> {
    if owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes
        .checked_add(future)
        .is_none_or(|total| total > owner.preparation.config.policy.capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "actual charge and retained index repair holds exceed policy",
        ));
    }
    Ok(())
}
