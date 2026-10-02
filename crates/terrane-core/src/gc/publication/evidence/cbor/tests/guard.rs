//! Checks Guard configuration and interpretation fences independently.
use super::*;

#[test]
fn guard_records_match_independent_nonzero_seed_fixture() {
    assert_eq!(profile().encode().unwrap(), profile_fixture());
    assert_eq!(
        SeededChunkProfile::decode(&profile_fixture()).unwrap(),
        profile()
    );
    assert_eq!(config().encode().unwrap(), config_fixture());
    assert_eq!(
        TrustedGuardConfig::decode(&config_fixture()).unwrap(),
        config()
    );
    assert_eq!(registries().encode().unwrap(), registry_fixture());
    assert_eq!(
        ConfiguredRegistryInputs::decode(&registry_fixture()).unwrap(),
        registries()
    );
    assert_eq!(guard().encode().unwrap(), guard_fixture());
    assert_eq!(GuardSnapshot::decode(&guard_fixture()).unwrap(), guard());
}

#[test]
fn represented_guard_domain_must_match_storage_domain() {
    let mut bytes = guard_fixture();
    let domain = bytes.windows(6).position(|part| part == b"public").unwrap();
    bytes.splice(
        domain - 1..domain + 6,
        [0x67, b'g', b'r', b'o', b'u', b'p', b':', b'x'],
    );
    assert!(matches!(
        GuardSnapshot::decode(&bytes),
        Err(EvidenceError::Contradiction)
    ));
}

#[test]
fn profile_and_registry_revisions_fail_closed() {
    let mut bytes = profile_fixture();
    bytes[18] = 47;
    assert!(SeededChunkProfile::decode(&bytes).is_err());

    let mut bytes = registry_fixture();
    bytes[4] = 3;
    assert!(matches!(
        ConfiguredRegistryInputs::decode(&bytes),
        Err(EvidenceError::UnsupportedRevision)
    ));

    let mut bytes = registry_fixture();
    bytes.pop();
    bytes.extend_from_slice(&[0x81, 0x61, b'z']);
    let decoded = ConfiguredRegistryInputs::decode(&bytes).unwrap();
    assert_eq!(decoded.later_properties, vec!["z"]);
    assert_eq!(decoded.encode().unwrap(), bytes);
}

#[test]
fn property_revisions_preserve_legacy_and_bind_index_roots_exactly() {
    let legacy = registries();
    assert_eq!(legacy.encode().unwrap(), registry_fixture());
    assert_eq!(
        ConfiguredRegistryInputs::property_revision_for(&legacy.behavioral_properties).unwrap(),
        1
    );

    let mut current = legacy.clone();
    current.property_revision = 2;
    current.behavioral_properties.push("index-roots".into());
    current.behavioral_properties.sort();
    let mut fixture = vec![0xa9, 0, 1, 1, 2, 2, 0x98, 0x22];
    for name in BEHAVIOR_NAMES {
        fixture_string(&mut fixture, 0x60, name.as_bytes());
        if *name == "index" {
            fixture.extend_from_slice(b"\x6bindex-roots");
        }
    }
    fixture.extend_from_slice(&[3, 1, 4, 1, 5, 1, 6, 1, 7, 0x6a]);
    fixture.extend_from_slice(b"terrane-v1");
    fixture.extend_from_slice(&[8, 0x80]);

    assert_eq!(current.encode().unwrap(), fixture);
    assert_eq!(ConfiguredRegistryInputs::decode(&fixture).unwrap(), current);
    assert_eq!(
        ConfiguredRegistryInputs::property_revision_for(&current.behavioral_properties).unwrap(),
        2
    );
    assert_eq!(legacy.encode().unwrap(), registry_fixture());
}

#[test]
fn property_revision_vocabulary_mismatches_refuse() {
    let mut wrong = registries();
    wrong.property_revision = 2;
    assert_eq!(wrong.encode(), Err(EvidenceError::Contradiction));

    wrong.property_revision = 1;
    wrong.behavioral_properties.push("index-roots".into());
    wrong.behavioral_properties.sort();
    assert_eq!(wrong.encode(), Err(EvidenceError::Contradiction));

    wrong.property_revision = 3;
    assert_eq!(wrong.encode(), Err(EvidenceError::UnsupportedRevision));
    wrong.behavioral_properties.pop();
    assert_eq!(
        ConfiguredRegistryInputs::property_revision_for(&wrong.behavioral_properties),
        Err(EvidenceError::Contradiction)
    );
}
