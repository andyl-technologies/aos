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
    bytes[4] = 2;
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
