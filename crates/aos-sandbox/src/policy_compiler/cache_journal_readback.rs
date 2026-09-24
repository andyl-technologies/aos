//! Root policy precursor for fixed-name Cache journal replay.
//!
//! The readback checks the root-only mount and delegates complete Cache
//! verification to the Cache owner code. It does not issue policy binding or
//! public Create authority.

use crate::cache_residency::{
    CacheResidencyProtectedJournalErrorV1, CacheResidencyRootReadOnlyReplayV1,
    replay_fixed_root_read_only_cache_journals_v1,
};

/// Replays the root policy Cache view as nonauthorizing diagnostic evidence.
///
/// The fixed physical names and authority checks are owned by Cache code. A
/// Controller cut must be established separately before any Q04 admission.
///
/// # Errors
///
/// Rejects an unsafe mount, changed physical name, malformed journal or Cache
/// authority, expired manifest, or invalid typed replay.
pub fn read_fixed_policy_cache_journals_v1()
-> Result<CacheResidencyRootReadOnlyReplayV1, CacheResidencyProtectedJournalErrorV1> {
    replay_fixed_root_read_only_cache_journals_v1()
}
