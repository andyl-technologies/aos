//! Reconciles only actual manifest-retention records with rebuilt residences.
//!
//! Cold records stay unchanged through this phase. The new metadata pins and
//! holds come from genuine registered backing receipts, never manifest names or
//! length estimates. No record is cleared to force a supported recovery case.

use super::retention::{Custody, RecoveryManifestBodyRetention};
use crate::host_cache::owner::RETAINED_LEASE_DEADLINE;
use std::io;
use terrane_sdk::host::cache::{
    CacheState, LeaseRecord, PinRecord, ReservationRecord, ResidenceRecord,
};

/// Reconstructs exact policy rows from actual retained native backing custody.
///
/// # Errors
/// Refuses foreign/stale native registration, unresolved effect measurements,
/// unexpected policy rows, duplicate registration and configured state limits.
pub(super) fn reconstruct(
    owner: &Custody,
    bootstrap_id: &[u8; 16],
    bodies: &[RecoveryManifestBodyRetention],
    residences: Vec<ResidenceRecord>,
) -> io::Result<CacheState> {
    let config = &owner.preparation.config;
    let cold = owner
        .recovery_cold
        .as_ref()
        .ok_or_else(|| invalid("manifest recovery lost original cold policy candidates"))?;
    let mut expected = cold.bootstrap(config, bootstrap_id)?;
    let mut metadata_hashes = Vec::new();
    for body in bodies {
        let backing = body.backing();
        backing.check_recovery_registration(owner)?;
        if backing.synchronized_source_and_body_bytes().is_none()
            || backing.charged_reserved_bytes().is_none()
        {
            return Err(invalid(
                "unreconciled effect cannot reconstruct retained metadata policy",
            ));
        }
        let id = token(backing.retention_id());
        let pin_owner = format!("metadata:{id}");
        expected.reservations.push(ReservationRecord {
            id,
            owner: config.quota_owner.clone(),
            bytes: config.metadata_sync_hold_bytes,
        });
        expected.leases.push(LeaseRecord {
            owner: pin_owner.clone(),
            expires: RETAINED_LEASE_DEADLINE,
        });
        for hash in [
            token(backing.claim().descriptor().digest()),
            token(backing.pack_identity().digest()),
        ] {
            metadata_hashes.push(hash.clone());
            expected.pins.push(PinRecord {
                owner: pin_owner.clone(),
                hash,
                expires: RETAINED_LEASE_DEADLINE,
            });
        }
    }
    // No row is removed or replaced to manufacture closure. Existing policy
    // must match its original snapshot, and every old pin/range must reconcile
    // with genuinely adopted bodies or independently verified metadata packs.
    require_same(&owner.state, &expected)?;
    cold.reconcile(&residences, &metadata_hashes)?;
    expected.residences = residences;
    expected
        .encoded_len(config.state)
        .map_err(io::Error::other)?;
    Ok(expected)
}

/// Compares complete expected policy rows without interpreting record absence.
///
/// # Errors
/// Refuses any unexpected or changed pin, reservation, lease or residence.
pub(super) fn require_same(actual: &CacheState, expected: &CacheState) -> io::Result<()> {
    let pins = actual.pins.len() == expected.pins.len()
        && actual
            .pins
            .iter()
            .zip(&expected.pins)
            .all(|(a, b)| a.owner == b.owner && a.hash == b.hash && a.expires == b.expires);
    let reservations = actual.reservations.len() == expected.reservations.len()
        && actual
            .reservations
            .iter()
            .zip(&expected.reservations)
            .all(|(a, b)| a.id == b.id && a.owner == b.owner && a.bytes == b.bytes);
    let leases = actual.leases.len() == expected.leases.len()
        && actual
            .leases
            .iter()
            .zip(&expected.leases)
            .all(|(a, b)| a.owner == b.owner && a.expires == b.expires);
    let residences = actual.residences.len() == expected.residences.len()
        && actual
            .residences
            .iter()
            .zip(&expected.residences)
            .all(|(a, b)| {
                a.chunk == b.chunk
                    && a.object == b.object
                    && a.offset == b.offset
                    && a.length == b.length
            });
    if !pins || !reservations || !leases || !residences {
        return Err(invalid(
            "actual recovery policy contains changed or unresolved records",
        ));
    }
    Ok(())
}

fn token(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_cold_rows_are_refused_and_preserved() {
        // Policy-only comparison: no native pin, lease or recovery receipt.
        let expected = CacheState::default();
        let mut actual = expected.clone();
        actual.reservations.push(ReservationRecord {
            id: "old".into(),
            owner: "owner".into(),
            bytes: 1,
        });
        assert!(require_same(&actual, &expected).is_err());
        assert_eq!(actual.reservations.len(), 1);
        actual.leases.push(LeaseRecord {
            owner: "old".into(),
            expires: 0,
        });
        assert!(require_same(&actual, &expected).is_err());
        assert_eq!(actual.leases.len(), 1);
    }

    #[test]
    fn changed_residence_cannot_pass_a_policy_snapshot_comparison() {
        let mut expected = CacheState::default();
        expected.residences.push(ResidenceRecord {
            chunk: "chunk".into(),
            object: "body".into(),
            offset: 0,
            length: 3,
        });
        let mut actual = expected.clone();
        assert!(require_same(&actual, &expected).is_ok());
        actual.residences[0].offset = 1;
        assert!(require_same(&actual, &expected).is_err());
    }
}
