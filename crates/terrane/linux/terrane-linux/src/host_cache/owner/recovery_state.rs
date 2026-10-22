//! Funds recovery while preserving the original bounded cold policy candidates.
//!
//! The actual random bootstrap hold precedes adoption and snapshot effects.
//! Existing records remain comparison data until independently verified native
//! ranges and metadata reconcile their complete backing closure.

use super::{NativeCacheOwnerConfig, recovery_cold::ColdPolicy, recovery_manifest_state};
use std::{
    fs::File,
    io::{self, Read},
};
use terrane_sdk::host::cache::{CacheState, ResidenceRecord};

/// Contains original comparison data and one genuinely generated recovery hold.
pub(super) struct BootstrapState {
    /// Actual native random identifier of the new bootstrap future hold.
    pub(super) id: [u8; 16],
    /// Bounded candidate snapshot; possession alone proves no durable write.
    pub(super) snapshot: CacheState,
    /// Original records retained independently of subsequent snapshot mutations.
    pub(super) cold: ColdPolicy,
}

/// Funds validated cold candidates after any authenticated closure reconciliation.
///
/// # Errors
/// Refuses unavailable randomness, identifier collisions and
/// snapshots exceeding configured limits. No cold record is acknowledged here.
pub(super) fn bootstrap(
    config: &NativeCacheOwnerConfig,
    cold: ColdPolicy,
) -> io::Result<BootstrapState> {
    let mut id = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut id)?;
    let snapshot = cold.bootstrap(config, &id)?;
    Ok(BootstrapState { id, snapshot, cold })
}

/// Checks exact original records, the new hold and independently rebuilt ranges.
///
/// # Errors
/// Refuses changed holds, unbacked cold pins, changed ranges and state bounds.
pub(super) fn check_reconciled(
    config: &NativeCacheOwnerConfig,
    state: &CacheState,
    id: &[u8; 16],
    cold: &ColdPolicy,
    residences: &[ResidenceRecord],
    verified_hashes: &[String],
) -> io::Result<()> {
    cold.reconcile(residences, verified_hashes)?;
    let mut expected = cold.bootstrap(config, id)?;
    expected.residences = residences.to_vec();
    recovery_manifest_state::require_same(state, &expected)?;
    state.encoded_len(config.state).map_err(io::Error::other)?;
    Ok(())
}
