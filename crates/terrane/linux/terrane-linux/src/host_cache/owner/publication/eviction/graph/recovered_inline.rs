//! Selects actual recovered inline bodies without synthesizing producer jobs.
//!
//! The original physical registry and acknowledged Running barrier supply native
//! provenance. Durable rows protect these bodies but cannot create candidates.
//! Recovered probation order never infers historical FIFO age or popularity.

use super::{Unit, invalid, state};
use crate::{
    host_cache::owner::retention::{Custody, NativeOwnerExecutor},
    publisher_local::client::PeerPublishedObject,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    os::unix::fs::MetadataExt,
    sync::Arc,
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Adds only original inline bodies reconciled before this owner's actual Resume.
///
/// # Errors
/// Refuses lost registry custody, foreign layout or conflicting inode aliases.
pub(super) fn extend(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    units: &mut Vec<Unit>,
    by_inode: &mut BTreeMap<(u64, u64), usize>,
) -> io::Result<()> {
    for body in executor.inline_registry() {
        check(executor, owner, body)?;
        let metadata = body.handle().metadata()?;
        let inode = (metadata.dev(), metadata.ino());
        let hash = state::hex(body.claim().descriptor().digest());
        let index = if let Some(index) = by_inode.get(&inode) {
            *index
        } else {
            let index = units.len();
            by_inode.insert(inode, index);
            units.push(Unit {
                order: executor.recovered_sealed_order(body.incarnation())?,
                key: format!("{}:{}", inode.0, inode.1),
                body: Arc::clone(body),
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
            return Err(invalid(
                "recovered inline aliases disagree about original body",
            ));
        }
        unit.recovered_inline.push(Arc::clone(body));
    }
    Ok(())
}

/// Rechecks the actual adopted registry before an original native transition.
///
/// # Errors
/// Refuses another worker, lost original registry, layout or inline claim.
pub(in crate::host_cache::owner::publication::eviction) fn check(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    body: &Arc<PeerPublishedObject<HostDomainLocation>>,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    if !executor
        .inline_registry()
        .iter()
        .any(|registered| Arc::ptr_eq(registered, body))
        || !Arc::ptr_eq(body.layout(), owner.preparation.layout())
        || body.claim().domain() != owner.preparation.config.location.domain()
        || body.claim().manifest().is_some()
    {
        return Err(invalid(
            "cache retirement lost original adopted inline custody",
        ));
    }
    Ok(())
}
