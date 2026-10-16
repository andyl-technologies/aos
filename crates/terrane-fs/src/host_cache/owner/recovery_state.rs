//! Prepares bounded recovery policy records without treating them as proof.
//!
//! Cold records are candidate evidence, never silently cleared. The first
//! implemented completion case starts with no records and retains its actual
//! future hold after synchronization. Other reconstruction belongs to later
//! verified reconciliation, not a default or an assumed expired lease.

use super::NativeCacheOwnerConfig;
use std::{
    fs::File,
    io::{self, Read},
};
use terrane::host::cache::{CacheState, ReservationRecord};

/// Contains policy data awaiting actual owner synchronization and reconciliation.
pub(super) struct BootstrapState {
    /// Actual native random identifier of the sole bootstrap future hold.
    pub(super) id: [u8; 16],
    /// Bounded candidate snapshot; possession alone proves no durable write.
    pub(super) snapshot: CacheState,
}

/// Prepares one actual random hold only when no cold policy requires reconciliation.
///
/// This is policy data only; filesystem durability, quota, namespace and current
/// publisher barrier checks remain mandatory before any completion receipt.
///
/// # Errors
/// Refuses every existing record, unavailable randomness and snapshots exceeding
/// configured limits. No cold pin, lease, reservation or residence is removed.
pub(super) fn bootstrap(
    config: &NativeCacheOwnerConfig,
    current: &CacheState,
) -> io::Result<BootstrapState> {
    require_empty(current)?;
    let mut id = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut id)?;
    let mut snapshot = current.clone();
    snapshot.reservations.push(ReservationRecord {
        id: token(&id),
        owner: config.quota_owner.clone(),
        bytes: config.metadata_sync_hold_bytes,
    });
    snapshot
        .encoded_len(config.state)
        .map_err(io::Error::other)?;
    Ok(BootstrapState { id, snapshot })
}

/// Refuses unresolved records without interpreting absence of bodies as release.
///
/// # Errors
/// Returns would-block for any pin, reservation, lease or residence candidate.
pub(super) fn require_empty(state: &CacheState) -> io::Result<()> {
    if !state.pins.is_empty()
        || !state.leases.is_empty()
        || !state.reservations.is_empty()
        || !state.residences.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "cold policy records require actual native reconciliation",
        ));
    }
    Ok(())
}

/// Validates the exact producer's sole synchronized bootstrap hold.
///
/// # Errors
/// Refuses missing/changed holds and any newly present policy category.
pub(super) fn check_bootstrap(
    config: &NativeCacheOwnerConfig,
    state: &CacheState,
    id: &[u8; 16],
) -> io::Result<()> {
    if !state.pins.is_empty()
        || !state.leases.is_empty()
        || !state.residences.is_empty()
        || state.reservations.len() != 1
        || !state.reservations.iter().any(|record| {
            record.id == token(id)
                && record.owner == config.quota_owner
                && record.bytes == config.metadata_sync_hold_bytes
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery bootstrap hold changed",
        ));
    }
    state.encoded_len(config.state).map_err(io::Error::other)?;
    Ok(())
}

fn token(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrane::host::cache::{LeaseRecord, PinRecord, ResidenceRecord};

    #[test]
    fn cold_policy_categories_never_disappear_during_empty_recovery_preflight() {
        let mut state = CacheState::default();
        state.pins.push(PinRecord {
            owner: "surface".into(),
            hash: "00".repeat(32),
            expires: 0,
        });
        assert!(require_empty(&state).is_err());
        assert_eq!(state.pins.len(), 1);

        let mut state = CacheState::default();
        state.leases.push(LeaseRecord {
            owner: "surface".into(),
            expires: 0,
        });
        assert!(require_empty(&state).is_err());
        assert_eq!(state.leases.len(), 1);

        let mut state = CacheState::default();
        state.reservations.push(ReservationRecord {
            id: "old".into(),
            owner: "owner".into(),
            bytes: 1,
        });
        assert!(require_empty(&state).is_err());
        assert_eq!(state.reservations.len(), 1);

        let mut state = CacheState::default();
        state.residences.push(ResidenceRecord {
            chunk: "00".repeat(32),
            object: "11".repeat(32),
            offset: 0,
            length: 1,
        });
        assert!(require_empty(&state).is_err());
        assert_eq!(state.residences.len(), 1);
    }
}
