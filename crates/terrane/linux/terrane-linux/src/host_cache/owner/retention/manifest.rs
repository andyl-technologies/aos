//! Synchronizes native reconstruction metadata under retained physical custody.

use super::*;
use crate::host_cache::owner::RETAINED_LEASE_DEADLINE;

/// Synchronizes verified metadata under the ordinary recovered-owner phase.
///
/// # Errors
/// Refuses recovery-required/faulted custody, corrupt source, absent native
/// proof, unavailable capacity and failed durability or quota reconciliation.
pub(super) async fn retain(
    executor: &NativeOwnerExecutor,
    identity: Identity,
) -> io::Result<RetainedManifest> {
    retain_with_authority(identity, Authority::Ordinary(executor)).await
}

/// Captures this physical worker's actual acknowledged Running context.
///
/// # Errors
/// Refuses a stale/faulted owner, absent Resume acknowledgment, corrupt metadata,
/// unavailable capacity or failed native synchronization and quota reconciliation.
pub(super) async fn retain_running(
    executor: &NativeOwnerExecutor,
    identity: Identity,
) -> io::Result<RetainedManifest> {
    let context = executor.admission_context()?;
    match super::super::admission::metadata_reads::AdmittedMetadataRead::prepare_retention(
        executor,
        identity.clone(),
    ) {
        Ok(source) => {
            source.read_verified()?;
        }
        Err(error) if super::super::admission::metadata_reads::cache_absent(&error) => {}
        Err(error) => return Err(error),
    }
    retain_with_authority(identity, Authority::Running { executor, context }).await
}

/// Retains actual metadata under the unforgeable exclusive recovery turn.
///
/// # Errors
/// Refuses stale recovery custody and every ordinary verification/durability or
/// accounting failure. This never relaxes the ordinary retention entry point.
pub(super) async fn retain_recovery(
    custody: &Arc<Mutex<Custody>>,
    identity: Identity,
    live: &mut super::recovery_manifest::LiveManifestRecoveryContext<'_>,
) -> io::Result<RetainedManifest> {
    if !Arc::ptr_eq(custody, live.snapshot_executor().custody()) {
        return Err(io::Error::other(
            "recovery retention has another physical owner",
        ));
    }
    retain_with_authority(identity, Authority::Recovery(live)).await
}

/// Keeps recovered, acknowledged Running and live-recovery custody distinct.
enum Authority<'phase, 'executor> {
    Ordinary(&'phase NativeOwnerExecutor),
    Running {
        executor: &'phase NativeOwnerExecutor,
        context: Arc<crate::publisher_local::client::PublisherRunningContext>,
    },
    Recovery(&'phase mut super::recovery_manifest::LiveManifestRecoveryContext<'executor>),
}

impl Authority<'_, '_> {
    fn executor(&self) -> &NativeOwnerExecutor {
        match self {
            Self::Ordinary(executor) | Self::Running { executor, .. } => executor,
            Self::Recovery(live) => live.snapshot_executor(),
        }
    }

    // Publisher-phase checks precede each embedded-owner lock. Holding the
    // physical executor borrow keeps metadata commands from interleaving across
    // source or snapshot awaits; no publisher RPC lock nests under embedded state.
    fn check_context(&self) -> io::Result<()> {
        self.executor().check_physical_worker()?;
        if let Self::Running { context, .. } = self {
            context.check_current().map_err(io::Error::other)?;
        }
        Ok(())
    }

    fn check_session(&self, owner: &Custody) -> io::Result<()> {
        if let Self::Running { context, .. } = self
            && !Arc::ptr_eq(
                context.publisher_session(),
                &owner.preparation.publisher_session(),
            )
        {
            return Err(io::Error::other(
                "running retention belongs to another actual session",
            ));
        }
        Ok(())
    }

    fn check_owner(&self, owner: &Custody) -> io::Result<()> {
        self.check_session(owner)?;
        match self {
            Self::Recovery(live) => live.check_producer_owner(owner),
            Self::Ordinary(_) | Self::Running { .. }
                if owner.faulted || owner.recovery_required =>
            {
                Err(io::Error::other(
                    "metadata owner requires failed-operation recovery",
                ))
            }
            Self::Ordinary(_) | Self::Running { .. } => Ok(()),
        }
    }

    fn check_registered(
        &self,
        owner: &Custody,
        source: &Arc<NativeManifestSource>,
        id: &[u8; 16],
        generation: u64,
    ) -> io::Result<()> {
        self.check_session(owner)?;
        if let Self::Recovery(live) = self {
            live.check_producer_owner(owner)?;
        } else if owner.recovery_required || !owner.faulted {
            return Err(io::Error::other(
                "ordinary retention lost its active write phase",
            ));
        }
        if owner.generation != generation
            || !owner
                .sources
                .get(id)
                .is_some_and(|actual| Arc::ptr_eq(actual, source))
            || !owner.state.reservations.iter().any(|hold| {
                hold.id == hex(id)
                    && hold.owner == owner.preparation.config.quota_owner
                    && hold.bytes == owner.preparation.config.metadata_sync_hold_bytes
            })
        {
            return Err(io::Error::other(
                "retention write lost its source or funded registration",
            ));
        }
        Ok(())
    }
}

async fn retain_with_authority(
    identity: Identity,
    mut authority: Authority<'_, '_>,
) -> io::Result<RetainedManifest> {
    authority.check_context()?;
    let custody = Arc::clone(authority.executor().custody());
    let (layout, limits, original_generation) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        authority.check_owner(&owner)?;
        owner.check_current()?;
        owner.preparation.recheck()?;
        (
            Arc::clone(owner.preparation.layout()),
            owner.preparation.config.reads,
            owner.generation,
        )
    };
    // Read-only native lookup owns its inputs; no embedded guard crosses either
    // await. Revalidate the exact physical generation before registering effects.
    let reader = NativeHostMetadataReader::open(layout, limits)
        .await
        .map_err(io::Error::other)?;
    let source = Arc::new(NativeManifestSource::open(&reader, &identity, limits).await?);
    authority.check_context()?;
    if let Authority::Running { executor, .. } = &authority {
        let owner = custody
            .lock()
            .map_err(|_| invalid("metadata binding custody poisoned"))?;
        super::super::admission::reads::metadata_activity_order(executor, &owner, &source)?;
    }
    let (pinned, retention_id, future, registered_generation, reservation_write) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        authority.check_owner(&owner)?;
        owner.check_current()?;
        if owner.generation != original_generation {
            return Err(io::Error::other(
                "metadata source lookup changed physical generation",
            ));
        }
        for file in [source.files().0, source.files().1] {
            if NativeProject::inspect(file)?.project_id != owner.preparation.config.project_id {
                return Err(invalid("retained metadata has another native project"));
            }
        }
        owner.preparation.recheck()?;
        let future = owner.state.reservations.iter().try_fold(
            owner.preparation.config.metadata_sync_hold_bytes,
            |total, reservation| {
                total
                    .checked_add(reservation.bytes)
                    .ok_or_else(|| invalid("future hold sum overflow"))
            },
        )?;
        let charged = owner
            .preparation
            .quota()
            .observation()
            .charged_reserved_bytes;
        if charged
            .checked_add(future)
            .is_none_or(|total| total > owner.preparation.config.policy.capacity)
        {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "native metadata future hold exceeds available charge budget",
            ));
        }
        let mut retention_id = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut retention_id)?;
        if owner.sources.contains_key(&retention_id)
            || owner.index_repairs.contains_key(&retention_id)
        {
            return Err(io::Error::other(
                "random metadata retention identifier collision",
            ));
        }
        let token = hex(&retention_id);
        let pin_owner = format!("metadata:{token}");
        let reservation = ReservationRecord {
            id: token,
            owner: owner.preparation.config.quota_owner.clone(),
            bytes: owner.preparation.config.metadata_sync_hold_bytes,
        };
        let mut next = owner.state.clone();
        next.reservations.push(reservation);
        let mut pinned = next.clone();
        pinned.leases.push(LeaseRecord {
            owner: pin_owner.clone(),
            expires: RETAINED_LEASE_DEADLINE,
        });
        for hash in [hex(identity.digest()), hex(source.pack_identity().digest())] {
            pinned.pins.push(PinRecord {
                owner: pin_owner.clone(),
                hash,
                expires: RETAINED_LEASE_DEADLINE,
            });
        }
        next.encoded_len(owner.preparation.config.state)
            .map_err(io::Error::other)?;
        pinned
            .encoded_len(owner.preparation.config.state)
            .map_err(io::Error::other)?;
        if let Authority::Recovery(context) = &mut authority {
            context.retain_source(Arc::clone(&source))?;
        }
        owner.begin_mutation()?;
        if let Authority::Recovery(context) = &authority {
            context.advance_generation(&owner);
        }
        owner.sources.insert(retention_id, Arc::clone(&source));
        owner.state = next;
        // From the first attempted snapshot onward, all failure paths keep this
        // source and hold registered and refuse subsequent mutations. Once this
        // reservation snapshot is durable, later failures remain visible on disk.
        owner.faulted = true;
        let write = super::super::snapshot::prepare(authority.executor(), &mut owner)?;
        (pinned, retention_id, future, owner.generation, write)
    };
    super::super::snapshot::persist(authority.executor(), reservation_write).await?;
    authority.check_context()?;
    let pinned_write = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        authority.check_registered(&owner, &source, &retention_id, registered_generation)?;
        owner.check_current()?;
        source.synchronize()?;
        owner.state = pinned;
        super::super::snapshot::prepare(authority.executor(), &mut owner)?
    };
    super::super::snapshot::persist(authority.executor(), pinned_write).await?;
    authority.check_context()?;
    let mut owner = custody
        .lock()
        .map_err(|_| io::Error::other("metadata custody poisoned"))?;
    authority.check_registered(&owner, &source, &retention_id, registered_generation)?;
    owner.check_current()?;
    let mut allocated = BTreeMap::new();
    for file in [source.files().0, source.files().1] {
        let bytes = synchronized_allocated_bytes(file)?;
        let metadata = file.metadata()?;
        allocated.insert((metadata.dev(), metadata.ino()), bytes);
    }
    let synchronized_source_bytes = allocated.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(*bytes)
            .ok_or_else(|| invalid("source allocation overflow"))
    })?;
    let snapshot_bytes = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("completed metadata pin snapshot is absent"))
        .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
    owner.snapshot_allocated_bytes = snapshot_bytes;
    owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
    owner.preparation.recheck()?;
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
            "reconciled charge and retained holds exceed cache policy",
        ));
    }
    source.recheck()?;
    owner.check_current()?;
    // The policy hold remains durable for the dependent metadata's entire
    // lifetime. Only actual retirement/recovery can release it; waiter or receipt
    // destruction never does. Allocation and kernel charge remain separate.
    let cache_incarnation = *owner.preparation.publisher().cache_incarnation();
    let session = owner.preparation.publisher_session();
    let retained = RetainedManifest {
        source,
        custody: Arc::clone(&custody),
        retention_id,
        cache_incarnation,
        session,
        synchronized_source_bytes,
    };
    drop(owner);
    if let Authority::Running { executor, .. } = &authority
        && let Some(activity) = executor.manifest_read_activity(&retained)?
    {
        activity.record()?;
    }
    authority.check_context()?;
    if !matches!(&authority, Authority::Recovery(_)) {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("metadata completion custody poisoned"))?;
        authority.check_registered(
            &owner,
            &retained.source,
            &retention_id,
            registered_generation,
        )?;
        owner.check_current()?;
        retained.source.recheck()?;
        // New fallible activity/registration checks belong to this original
        // operation. A failure must retain its active phase and durable pins.
        owner.faulted = false;
    }
    Ok(retained)
}
