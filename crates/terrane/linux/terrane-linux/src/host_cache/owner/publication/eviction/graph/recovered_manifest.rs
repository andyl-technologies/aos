//! Correlates original recovered manifests and their exact metadata custody.
//!
//! Verified registry entries supply real adopted bodies and metadata packs. Old
//! policy groups are comparison data only; they remain protected unless their
//! complete unchanged closure matches that actual body/pack pair.

use super::{Unit, invalid, state};
use crate::host_cache::{
    owner::retention::{Custody, NativeOwnerExecutor},
    recovery_inspection::VerifiedRecoveryManifest,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    os::unix::fs::MetadataExt,
    sync::Arc,
};

/// Adds original recovered manifests without inventing publication jobs.
///
/// # Errors
/// Refuses lost registry custody, changed metadata and conflicting body aliases.
pub(super) fn extend(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    units: &mut Vec<Unit>,
    by_inode: &mut BTreeMap<(u64, u64), usize>,
) -> io::Result<()> {
    for manifest in executor.verified_manifests() {
        check(executor, owner, manifest)?;
        let retained = manifest.body().retained();
        let body = retained.body_arc();
        let metadata = body.handle().metadata()?;
        let inode = (metadata.dev(), metadata.ino());
        let hash = state::hex(manifest.claim().descriptor().digest());
        let index = if let Some(index) = by_inode.get(&inode) {
            *index
        } else {
            let index = units.len();
            by_inode.insert(inode, index);
            units.push(Unit {
                order: executor.recovered_sealed_order(body.incarnation())?,
                key: format!("{}:{}", inode.0, inode.1),
                body: Arc::clone(&body),
                members: Vec::new(),
                recovered_inline: Vec::new(),
                recovered_manifests: Vec::new(),
                allocated: 0,
                protected: false,
                shared_chunks: BTreeSet::new(),
                metadata: BTreeMap::new(),
                cold_metadata: BTreeSet::new(),
                reconstruction: BTreeSet::new(),
                chunks: owner
                    .state
                    .residences
                    .iter()
                    .filter(|row| row.object == hash)
                    .map(|row| row.chunk.clone())
                    .collect(),
            });
            index
        };
        let unit = &mut units[index];
        if unit.body.claim().descriptor() != body.claim().descriptor()
            || unit.body.incarnation() != body.incarnation()
        {
            return Err(invalid("recovered manifest aliases changed original body"));
        }
        unit.reconstruction.insert(format!(
            "metadata:{}",
            state::hex(retained.backing().retention_id())
        ));
        for token in cold_holds(owner, manifest) {
            unit.reconstruction.insert(format!("metadata:{token}"));
            unit.cold_metadata.insert(token);
        }
        unit.recovered_manifests.push(Arc::clone(manifest));
    }
    Ok(())
}

/// Compares cold promise data only after the caller validates actual native custody.
pub(super) fn cold_holds(owner: &Custody, manifest: &VerifiedRecoveryManifest) -> BTreeSet<String> {
    let Some(cold) = &owner.recovery_cold else {
        return BTreeSet::new();
    };
    let backing = manifest.body().retained().backing();
    let object = state::hex(manifest.claim().descriptor().digest());
    let pack = state::hex(backing.pack_identity().digest());
    cold.retained_metadata_holds(
        &owner.state,
        &owner.preparation.config.quota_owner,
        owner.preparation.config.metadata_sync_hold_bytes,
        &object,
        &pack,
    )
}

/// Rechecks original verified registry and metadata registration under Running custody.
///
/// # Errors
/// Refuses another worker, registry, layout, canonical claim or metadata promise.
pub(in crate::host_cache::owner::publication::eviction) fn check(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    manifest: &Arc<VerifiedRecoveryManifest>,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    let retained = manifest.body().retained();
    let body = retained.body();
    if !executor
        .verified_manifests()
        .iter()
        .any(|registered| Arc::ptr_eq(registered, manifest))
        || !Arc::ptr_eq(body.layout(), owner.preparation.layout())
        || manifest.claim().manifest().is_none()
        || body.claim().domain() != owner.preparation.config.location.domain()
        || body.claim().descriptor() != manifest.claim().descriptor()
        || body.claim().canonical_manifest() != manifest.claim().canonical_manifest()
    {
        return Err(invalid(
            "cache retirement lost original recovered manifest custody",
        ));
    }
    retained.backing().check_recovery_registration(owner)
}
