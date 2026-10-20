//! Reconciles actual recovery effect allocation before releasing its live turn.
//!
//! A whole-filesystem syncfs barrier may wait for unrelated writers. Measured
//! inode blocks cover only retained source, backing and policy inodes; fresh
//! authenticated charged-and-reserved quota remains the separate owner total.

use super::*;
use crate::publisher_local::client::PeerPublishedObject;

/// Reports scoped synchronized inodes separately from full owner quota charge.
pub(super) struct EffectMeasurement {
    /// Deduplicated synchronized blocks for the retained source and body inodes.
    pub(super) retained_source_and_body_bytes: u64,
    /// Separate fresh authenticated charged-and-reserved usage for the full owner.
    pub(super) charged_reserved_bytes: u64,
}

/// Synchronizes retained effect inodes and reconciles actual quota with holds.
///
/// The downstream owner must already retain the adopted body and its actual
/// same-response canonical inode/lifecycle observation. A matching private body
/// receipt alone does not establish that response correlation.
///
/// # Errors
/// Refuses changed phase/source/body/root custody, failed synchronization,
/// overflow, unavailable quota observations and charge exceeding policy.
pub(super) fn complete_effect(
    effect: &RecoveryManifestEffect<'_, '_>,
    body: &PeerPublishedObject<HostDomainLocation>,
) -> io::Result<EffectMeasurement> {
    effect.check_current()?;
    let receipt = &effect.receipt;
    if body.claim().descriptor() != receipt.claim().descriptor()
        || body.claim().domain() != receipt.claim().domain()
        || !Arc::ptr_eq(body.layout(), receipt.layout())
    {
        return Err(invalid("recovery effect returned another manifest or root"));
    }
    let mut owner = receipt
        .live
        .executor
        .custody()
        .lock()
        .map_err(|_| io::Error::other("metadata custody poisoned"))?;
    receipt
        .live
        .check_owner_phase(&owner, RecoveryPhase::EffectInFlight)?;
    receipt.retained.check_registration(&owner)?;
    let body_project = check_body_project(body.handle(), &owner)?;
    let layout = owner.preparation.layout();
    let readable = File::from(openat(
        &layout.root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = readable.metadata()?;
    if (metadata.dev(), metadata.ino()) != layout.directory_binding("layout-root")? {
        return Err(invalid(
            "effect synchronization root differs from actual layout",
        ));
    }
    body.handle().sync_all()?;
    receipt.retained.source.synchronize()?;
    rustix::fs::syncfs(&readable)?;
    let mut allocated = BTreeMap::new();
    for file in [
        receipt.retained.source.files().0,
        receipt.retained.source.files().1,
        body.handle(),
    ] {
        let before = file.metadata()?;
        let bytes = synchronized_allocated_bytes(file)?;
        if !same_file(&before, &file.metadata()?) {
            return Err(invalid("recovery effect inode changed during measurement"));
        }
        allocated.insert((before.dev(), before.ino()), bytes);
    }
    // Keep inode deduplication and overflow checks explicit even though this
    // scoped observation is never presented as the full project quota charge.
    let retained_source_and_body_bytes = allocated.values().try_fold(0_u64, |sum, bytes| {
        sum.checked_add(*bytes)
            .ok_or_else(|| invalid("effect allocation sum overflow"))
    })?;
    owner.snapshot_allocated_bytes = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("effect snapshot absent"))
        .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
    owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
    owner.preparation.recheck()?;
    let future = owner
        .state
        .reservations
        .iter()
        .try_fold(0_u64, |sum, hold| {
            sum.checked_add(hold.bytes)
                .ok_or_else(|| invalid("effect future holds overflow"))
        })?;
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
            "recovery effect charge and retained future holds exceed policy",
        ));
    }
    receipt
        .live
        .check_owner_phase(&owner, RecoveryPhase::EffectInFlight)?;
    receipt.retained.check_registration(&owner)?;
    if check_body_project(body.handle(), &owner)? != body_project {
        return Err(invalid(
            "adopted manifest project or inode changed during reconciliation",
        ));
    }
    let charged_reserved_bytes = owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes;
    drop(owner);
    // No embedded guard crosses the final original-context client check.
    effect.check_current()?;
    Ok(EffectMeasurement {
        retained_source_and_body_bytes,
        charged_reserved_bytes,
    })
}

/// Checks the actual body inode against retained native charge-owner authority.
fn check_body_project(file: &File, owner: &Custody) -> io::Result<NativeProject> {
    let project = NativeProject::inspect(file)?;
    let metadata = file.metadata()?;
    let expected_device = owner
        .preparation
        .layout()
        .directory_binding("layout-root")?
        .0;
    if project.project_id != owner.preparation.config.project_id
        || project.device != expected_device
        || (project.device, project.inode) != (metadata.dev(), metadata.ino())
        || !metadata.is_file()
    {
        return Err(invalid(
            "adopted manifest body has another native charge owner or device",
        ));
    }
    Ok(project)
}
