//! Preserves unrelated cold policy when disposable surface holds retire.

#![allow(clippy::unwrap_used)]

use super::*;
use terrane_sdk::host::cache::{ExposureBackingRecord, ExposureRecord, StateLimits};

#[test]
fn draining_file_pins_retain_policy_without_adoption_or_content_proof() {
    // Synthetic policy candidates only. No record below represents an observed
    // inode, publisher acknowledgment, read capability or native recovery proof.
    let hash = "12".repeat(32);
    let root = "34".repeat(32);
    let exposure = ExposureRecord {
        id: "ab".repeat(16),
        generation: 1,
        commit: "cd".repeat(32),
        root: root.clone(),
        index_version: 2,
        deadline: 100,
        phase: ExposurePhase::Active,
        backings: vec![
            obligation(ExposureBackingKind::Index, root.clone(), 100),
            obligation(ExposureBackingKind::Inline, hash.clone(), 101),
        ],
    };
    let pin_owner = exposure.pin_owner();
    let mut original = CacheState::default();
    original
        .retain_exposure(
            exposure,
            std::slice::from_ref(&hash),
            99,
            StateLimits {
                bytes: 8192,
                records: 16,
            },
        )
        .unwrap();
    let active = ColdPolicy {
        state: Arc::new(original.clone()),
    };
    assert!(active.requires_backing());
    assert!(active.reconcile(&[], &[]).is_err());

    assert_eq!(original.drain_expired_exposures(100), 1);
    let draining = ColdPolicy {
        state: Arc::new(original.clone()),
    };
    assert!(!draining.requires_backing());
    assert!(draining.reconcile(&[], &[]).is_ok());
    assert!(require_same(&draining.state, &original).is_ok());
    assert_eq!(draining.state.pins[0].expires, i64::MAX as u64);
    assert_eq!(draining.state.leases[0].expires, i64::MAX as u64);
    assert_eq!(draining.state.exposures[0].backings.len(), 2);

    // A matching digest alone cannot turn an ordinary content promise into a
    // retained exposure obligation. Nor can an index or unbound hash qualify.
    for (owner, digest) in [
        ("ordinary".to_owned(), hash.clone()),
        (pin_owner.clone(), root),
        (pin_owner, "56".repeat(32)),
    ] {
        let mut additional = original.clone();
        additional.pins.push(PinRecord {
            owner,
            hash: digest,
            expires: i64::MAX as u64,
        });
        let cold = ColdPolicy {
            state: Arc::new(additional),
        };
        assert!(cold.requires_backing());
        assert!(cold.reconcile(&[], &[]).is_err());
    }

    let mut residence = original.clone();
    residence.residences.push(ResidenceRecord {
        chunk: hash.clone(),
        object: hash,
        offset: 0,
        length: 1,
    });
    let cold = ColdPolicy {
        state: Arc::new(residence),
    };
    assert!(cold.requires_backing());
    assert!(cold.reconcile(&[], &[]).is_err());
    assert!(require_same(&draining.state, &original).is_ok());
}

fn obligation(kind: ExposureBackingKind, hash: String, inode: u64) -> ExposureBackingRecord {
    ExposureBackingRecord {
        kind,
        hash,
        filesystem_uuid: "01".repeat(16),
        device: 7,
        inode,
        birth_seconds: None,
        birth_nanoseconds: None,
        project_id: 79,
        uid: 840,
        gid: 845,
        mode: 0o400,
        size: 512,
        allocated: 8192,
        verity_algorithm: 1,
        verity_digest: "78".repeat(32),
    }
}

#[test]
fn retired_surface_holds_preserve_all_other_cold_candidates_and_refuse_dependencies() {
    let cold = candidates();
    let original = cold.state.as_ref().clone();
    let mut state = original.clone();
    let id = format!("surface-index:{}", "ab".repeat(16));
    state.reservations.push(ReservationRecord {
        id: id.clone(),
        owner: "original-owner".into(),
        bytes: 8192,
    });
    let cold = ColdPolicy {
        state: Arc::new(state.clone()),
    };
    let retired = cold.without_surface_reservations().unwrap().unwrap();
    assert!(require_same(retired.state.as_ref(), &original).is_ok());
    assert!(require_same(cold.state.as_ref(), &state).is_ok());
    assert!(retired.without_surface_reservations().unwrap().is_none());

    state.leases.push(LeaseRecord {
        owner: id,
        expires: 100,
    });
    assert!(
        ColdPolicy {
            state: Arc::new(state)
        }
        .without_surface_reservations()
        .is_err()
    );
    let mut malformed = original;
    malformed.reservations.push(ReservationRecord {
        id: "surface-index:bad".into(),
        owner: "original-owner".into(),
        bytes: 8192,
    });
    assert!(
        ColdPolicy {
            state: Arc::new(malformed)
        }
        .without_surface_reservations()
        .is_err()
    );
}
