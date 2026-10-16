//! Synchronizes native reconstruction metadata under retained physical custody.

use super::*;

/// Synchronizes verified metadata under the ordinary recovered-owner phase.
///
/// # Errors
/// Refuses recovery-required/faulted custody, corrupt source, absent native
/// proof, unavailable capacity and failed durability or quota reconciliation.
pub(super) async fn retain(
    custody: &Arc<Mutex<Custody>>,
    identity: Identity,
) -> io::Result<RetainedManifest> {
    retain_with_authority(custody, identity, None).await
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
    retain_with_authority(custody, identity, Some(live)).await
}

async fn retain_with_authority(
    custody: &Arc<Mutex<Custody>>,
    identity: Identity,
    mut live: Option<&mut super::recovery_manifest::LiveManifestRecoveryContext<'_>>,
) -> io::Result<RetainedManifest> {
    let mut owner = custody
        .lock()
        .map_err(|_| io::Error::other("metadata custody poisoned"))?;
    if let Some(context) = live.as_ref() {
        context.check_owner(&owner)?;
    } else if owner.faulted || owner.recovery_required {
        return Err(io::Error::other(
            "metadata owner requires failed-operation recovery",
        ));
    }
    owner.check_current()?;
    owner.preparation.recheck()?;
    let reader = NativeHostMetadataReader::open(
        Arc::clone(owner.preparation.layout()),
        owner.preparation.config.reads,
    )
    .await
    .map_err(io::Error::other)?;
    let source = Arc::new(
        NativeManifestSource::open(&reader, &identity, owner.preparation.config.reads).await?,
    );
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
    if owner.sources.contains_key(&retention_id) || owner.index_repairs.contains_key(&retention_id)
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
        expires: u64::MAX,
    });
    for hash in [hex(identity.digest()), hex(source.pack_identity().digest())] {
        pinned.pins.push(PinRecord {
            owner: pin_owner.clone(),
            hash,
            expires: u64::MAX,
        });
    }
    next.encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    pinned
        .encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    if let Some(context) = live.as_mut() {
        context.retain_source(Arc::clone(&source))?;
    }
    owner.begin_mutation()?;
    if let Some(context) = live.as_ref() {
        context.advance_generation(&owner);
    }
    owner.sources.insert(retention_id, Arc::clone(&source));
    owner.state = next;
    // From the first attempted snapshot onward, all failure paths keep this
    // source and hold registered and refuse subsequent mutations. Once this
    // reservation snapshot is durable, later failures remain visible on disk.
    owner.faulted = true;
    owner.persist().await?;
    source.synchronize()?;
    owner.state = pinned;
    owner.persist().await?;
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
    if live.is_none() {
        owner.faulted = false;
    }
    let cache_incarnation = *owner.preparation.publisher().cache_incarnation();
    let session = owner.preparation.publisher_session();
    Ok(RetainedManifest {
        source,
        custody: Arc::clone(custody),
        retention_id,
        cache_incarnation,
        session,
        synchronized_source_bytes,
    })
}
