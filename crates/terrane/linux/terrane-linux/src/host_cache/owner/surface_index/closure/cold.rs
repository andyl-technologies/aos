//! Reconciles already retired cold exposures before funding native recovery.
//!
//! No native backing is reconstructed from policy rows. The authenticated helper
//! must prove every recorded original inode closed before the recovery bootstrap
//! can omit an exposure. A failed observation leaves the original snapshot intact.

use crate::{
    host_cache::owner::{consumer::state, recovery_cold::ColdPolicy, retention::Custody},
    host_quota::{MAX_CENSUS_EXCLUSIONS, ProjectInode},
};
use std::{collections::BTreeSet, io};

/// Returns checked recovery candidates without changing any physical policy.
pub(in crate::host_cache::owner) fn capture(owner: &mut Custody) -> io::Result<ColdPolicy> {
    owner
        .state
        .encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    if owner.state.exposures.is_empty() {
        return ColdPolicy::capture(&owner.preparation.config, &owner.state);
    }
    let filesystem = state::hex(&owner.preparation.config.filesystem_uuid);
    let project = owner.preparation.config.project_id;
    let mut excluded = BTreeSet::new();
    let mut pin_owners = BTreeSet::new();
    for row in &owner.state.exposures {
        if row.backings.is_empty() {
            return Err(unresolved(
                "cold exposure has no original native closure bindings",
            ));
        }
        pin_owners.insert(row.pin_owner());
        for backing in &row.backings {
            if backing.filesystem_uuid != filesystem || backing.project_id != project {
                return Err(unresolved(
                    "cold exposure belongs to another native partition",
                ));
            }
            excluded.insert(ProjectInode {
                device: backing.device,
                inode: backing.inode,
            });
            if excluded.len() > MAX_CENSUS_EXCLUSIONS {
                return Err(unresolved(
                    "cold exposure closure exceeds authenticated census bounds",
                ));
            }
        }
    }
    let excluded: Vec<_> = excluded.into_iter().collect();
    if !owner.preparation.exposure_inodes_closed(&excluded)? {
        return Err(unresolved(
            "cold exposure retains unresolved native kernel custody",
        ));
    }

    // Closure is monotonic, independently of the old phase. A crashed owner
    // may leave an Active record after its original backing has disappeared.
    // Only this complete native proof permits omission; neither phase nor
    // expiry establishes closure. The ordinary funded bootstrap persists it.
    let mut next = owner.state.clone();
    next.exposures.clear();
    next.pins.retain(|pin| !pin_owners.contains(&pin.owner));
    next.leases
        .retain(|lease| !pin_owners.contains(&lease.owner));
    ColdPolicy::capture(&owner.preparation.config, &next)
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}
