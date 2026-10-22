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
        backings: Vec::new(),
    }
}

#[test]
fn exposure_deadline_drains_but_never_expires_physical_pins()
-> Result<(), Box<dyn std::error::Error>> {
    let exposure = record();
    let mut state = CacheState::default();
    state.retain_exposure(exposure.clone(), &["12".repeat(32)], 99, limits())?;
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
    state.validate(limits())?;

    let encoded = toml::to_string(&state)?;
    let recovered: CacheState = toml::from_str(&encoded)?;
    recovered.validate(limits())?;
    assert_eq!(recovered.exposures, state.exposures);
    assert_eq!(recovered.pins[0].hash, state.pins[0].hash);
    Ok(())
}

#[test]
fn exposure_snapshot_requires_explicit_version_and_complete_immortal_pin_context()
-> Result<(), Box<dyn std::error::Error>> {
    let legacy: CacheState = toml::from_str(
        "version = 1\npins = []\nleases = []\nreservations = []\nresidences = []\n",
    )?;
    legacy.validate(limits())?;
    assert!(!toml::to_string(&legacy)?.contains("exposures"));

    let mut valid = legacy;
    valid.retain_exposure(record(), &["12".repeat(32)], 99, limits())?;
    assert!(toml::to_string(&valid)?.starts_with("version = 2"));
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
    Ok(())
}

#[test]
fn exposure_duplicate_expiry_and_capacity_refusals_preserve_original_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut state = CacheState::default();
    let before = toml::to_string(&state)?;
    for now in [100, u64::MAX] {
        assert!(state.retain_exposure(record(), &[], now, limits()).is_err());
        assert_eq!(toml::to_string(&state)?, before);
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
        assert_eq!(toml::to_string(&state)?, before);
    }
    state.retain_exposure(record(), &[], 99, limits())?;
    let before = toml::to_string(&state)?;
    assert!(state.retain_exposure(record(), &[], 99, limits()).is_err());
    assert_eq!(toml::to_string(&state)?, before);
    Ok(())
}

fn index_binding() -> ExposureBackingRecord {
    ExposureBackingRecord {
        kind: ExposureBackingKind::Index,
        hash: record().root,
        filesystem_uuid: "12".repeat(16),
        device: 7,
        inode: 100,
        project_id: 79,
        uid: 840,
        gid: 845,
        mode: 0o400,
        size: 512,
        allocated: 8192,
        verity_algorithm: 1,
        verity_digest: "34".repeat(32),
    }
}

#[test]
fn exposure_original_backings_require_version_three_and_complete_native_context()
-> Result<(), Box<dyn std::error::Error>> {
    let mut exposure = record();
    exposure.backings.push(index_binding());
    let mut object = index_binding();
    object.kind = ExposureBackingKind::Manifest;
    object.hash = "56".repeat(32);
    object.inode += 1;
    object.uid = 841;
    object.size = 0;
    object.allocated = 0;
    exposure.backings.push(object);
    let mut state = CacheState::default();
    state.retain_exposure(exposure.clone(), &["56".repeat(32)], 99, limits())?;

    let encoded = toml::to_string(&state)?;
    assert!(encoded.starts_with("version = 3"));
    let recovered: CacheState = toml::from_str(&encoded)?;
    recovered.validate(limits())?;
    assert_eq!(recovered.exposures, state.exposures);

    for invalid in [
        "\"7\"",
        "\"000000000000000A\"",
        "7",
        "\"10000000000000000\"",
    ] {
        let damaged = encoded.replace(
            "device = \"0000000000000007\"",
            &format!("device = {invalid}"),
        );
        assert_ne!(damaged, encoded);
        assert!(toml::from_str::<CacheState>(&damaged).is_err());
    }

    for damage in 0..16 {
        let mut broken = recovered.clone();
        let exposure = &mut broken.exposures[0];
        match damage {
            0 => broken.version = 2,
            1 => broken.version = 4,
            2 => exposure.backings[0].hash = "78".repeat(32),
            3 => exposure.backings[0].device = 0,
            4 => exposure.backings[0].inode = 0,
            5 => exposure.backings[0].project_id = 0,
            6 => exposure.backings[0].mode = 0o600,
            7 => exposure.backings[0].filesystem_uuid = "AB".repeat(16),
            8 => exposure.backings[0].verity_algorithm = 3,
            9 => {
                exposure.backings[0].verity_digest.pop();
            }
            10 => exposure.backings[0].size = u64::MAX,
            11 => exposure.backings[0].mode = 0o100400,
            12 => exposure.backings[1].inode = exposure.backings[0].inode,
            13 => exposure.backings.push(exposure.backings[0].clone()),
            14 => {
                exposure.backings.remove(0);
            }
            _ => broken.pins.clear(),
        }
        assert!(broken.validate(limits()).is_err(), "damage {damage}");
    }
    let mut full_width = state.clone();
    full_width.exposures[0].backings[0].device = u64::MAX;
    full_width.exposures[0].backings[0].inode = u64::MAX;
    full_width.validate(limits())?;
    let encoded = toml::to_string(&full_width)?;
    let decoded: CacheState = toml::from_str(&encoded)?;
    assert_eq!(decoded.exposures, full_width.exposures);

    assert!(state.sweep_expired(u64::MAX).is_empty());
    assert_eq!(state.exposures[0].backings, exposure.backings);
    Ok(())
}

#[test]
fn exposure_original_backings_count_toward_atomic_snapshot_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let mut exposure = record();
    exposure.backings.push(index_binding());
    let mut state = CacheState::default();
    let before = toml::to_string(&state)?;
    for bound in [
        StateLimits {
            bytes: 8192,
            records: 2,
        },
        StateLimits {
            bytes: 256,
            records: 16,
        },
    ] {
        assert!(
            state
                .retain_exposure(exposure.clone(), &[], 99, bound)
                .is_err()
        );
        assert_eq!(toml::to_string(&state)?, before);
    }
    let mut object_without_pin = index_binding();
    object_without_pin.kind = ExposureBackingKind::Inline;
    object_without_pin.hash = "56".repeat(32);
    object_without_pin.inode += 1;
    exposure.backings.push(object_without_pin);
    assert!(state.retain_exposure(exposure, &[], 99, limits()).is_err());
    assert_eq!(toml::to_string(&state)?, before);
    Ok(())
}
