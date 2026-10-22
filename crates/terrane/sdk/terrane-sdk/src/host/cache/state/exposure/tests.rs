//! Checks durable exposure expiry, strict versioning and bounded atomic refusal.

use super::*;

fn limits() -> StateLimits {
    StateLimits {
        bytes: 8192,
        records: 16,
    }
}

fn record() -> ExposureRecord {
    ExposureRecord {
        id: "ab".repeat(16),
        generation: 1,
        commit: "cd".repeat(32),
        root: "ef".repeat(32),
        index_version: 2,
        deadline: 100,
        phase: ExposurePhase::Active,
    }
}

#[test]
fn exposure_deadline_drains_but_never_expires_physical_pins() {
    let exposure = record();
    let mut state = CacheState::default();
    state
        .retain_exposure(exposure.clone(), &["12".repeat(32)], 99, limits())
        .unwrap();
    state.leases.push(LeaseRecord {
        owner: "ordinary".into(),
        expires: 100,
    });
    state.pins.push(PinRecord {
        owner: "ordinary".into(),
        hash: "34".repeat(32),
        expires: 100,
    });

    assert!(state.sweep_expired(99).is_empty());
    assert!(state.exposures[0].accepts_work(1, 99));
    assert!(!state.exposures[0].accepts_work(2, 99));
    assert_eq!(state.sweep_expired(100), vec!["34".repeat(32)]);
    assert_eq!(state.exposures[0].phase, ExposurePhase::Draining);
    assert!(!state.exposures[0].accepts_work(1, 99));
    assert_eq!(state.drain_expired_exposures(100), 0);

    assert!(state.sweep_expired(u64::MAX).is_empty());
    assert_eq!(state.pins.len(), 1);
    assert_eq!(state.pins[0].owner, exposure.pin_owner());
    state.validate(limits()).unwrap();

    let encoded = toml::to_string(&state).unwrap();
    let recovered: CacheState = toml::from_str(&encoded).unwrap();
    recovered.validate(limits()).unwrap();
    assert_eq!(recovered.exposures, state.exposures);
    assert_eq!(recovered.pins[0].hash, state.pins[0].hash);
}

#[test]
fn exposure_snapshot_requires_explicit_version_and_complete_immortal_pin_context() {
    let legacy: CacheState =
        toml::from_str("version = 1\npins = []\nleases = []\nreservations = []\nresidences = []\n")
            .unwrap();
    legacy.validate(limits()).unwrap();
    assert!(!toml::to_string(&legacy).unwrap().contains("exposures"));

    let mut valid = legacy;
    valid
        .retain_exposure(record(), &["12".repeat(32)], 99, limits())
        .unwrap();
    assert!(toml::to_string(&valid).unwrap().starts_with("version = 2"));
    for damage in 0..7 {
        let mut broken = valid.clone();
        match damage {
            0 => broken.version = 1,
            1 => broken.leases.clear(),
            2 => broken.pins[0].expires = 100,
            3 => broken.exposures[0].generation = 0,
            4 => broken.exposures[0].id = "AB".repeat(16),
            5 => broken.exposures.clear(),
            _ => broken.exposures.push(broken.exposures[0].clone()),
        }
        assert!(broken.validate(limits()).is_err(), "damage {damage}");
    }
}

#[test]
fn exposure_duplicate_expiry_and_capacity_refusals_preserve_original_state() {
    let mut state = CacheState::default();
    let before = toml::to_string(&state).unwrap();
    for now in [100, u64::MAX] {
        assert!(state.retain_exposure(record(), &[], now, limits()).is_err());
        assert_eq!(toml::to_string(&state).unwrap(), before);
    }
    for bound in [
        StateLimits {
            bytes: 1,
            records: 16,
        },
        StateLimits {
            bytes: 8192,
            records: 1,
        },
    ] {
        assert!(state.retain_exposure(record(), &[], 99, bound).is_err());
        assert_eq!(toml::to_string(&state).unwrap(), before);
    }
    state.retain_exposure(record(), &[], 99, limits()).unwrap();
    let before = toml::to_string(&state).unwrap();
    assert!(state.retain_exposure(record(), &[], 99, limits()).is_err());
    assert_eq!(toml::to_string(&state).unwrap(), before);
}
