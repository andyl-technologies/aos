//! Selects closed or durably draining exposure candidates for funded recovery.
//!
//! No native backing is reconstructed from policy rows. The authenticated helper
//! must prove every recorded original inode closed before the recovery bootstrap
//! can omit an exposure. Explicit draining recovery retains every unresolved
//! obligation. A failed observation leaves the original snapshot intact.

use crate::{
    host_cache::owner::{
        consumer::state, recovery::ExposureRecovery, recovery_cold::ColdPolicy, retention::Custody,
    },
    host_quota::{MAX_CENSUS_EXCLUSIONS, ProjectInode},
};
use std::{collections::BTreeSet, io};

/// Returns checked recovery candidates without changing any physical policy.
pub(in crate::host_cache::owner) fn capture(
    owner: &mut Custody,
    policy: ExposureRecovery,
) -> io::Result<ColdPolicy> {
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
        if policy == ExposureRecovery::RequireClosed {
            return Err(unresolved(
                "cold exposure retains unresolved native kernel custody",
            ));
        }

        // This keeps every physical obligation; it proves no backing closed and
        // adopts no source. The funded bootstrap persists the phase transition
        // before native recovery may complete or Resume may be acknowledged.
        let mut next = owner.state.clone();
        for exposure in &mut next.exposures {
            exposure.phase = terrane_sdk::host::cache::ExposurePhase::Draining;
        }
        return ColdPolicy::capture_draining(&owner.preparation.config, &next);
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
