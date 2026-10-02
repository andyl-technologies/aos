//! Checks consumed evidence without granting verified lineage.
use super::*;

#[test]
fn pins_and_used_inputs_match_independent_bytes() {
    assert_eq!(registration_pin().encode().unwrap(), pin_fixture());
    assert_eq!(
        RequiredControlPin::decode(&pin_fixture()).unwrap(),
        registration_pin()
    );
    registration_pin().check_record(&local_fixture()).unwrap();
    assert_eq!(used().encode().unwrap(), used_fixture());
    assert_eq!(LineageUsedInputs::decode(&used_fixture()).unwrap(), used());
}

#[test]
fn legacy_lineage_identity_is_structural_and_allows_source_alias() {
    assert_eq!(checked_lineage().encode().unwrap(), lineage_fixture());
    assert_eq!(
        CheckedLineage::decode(&lineage_fixture()).unwrap(),
        checked_lineage()
    );
    checked_lineage()
        .check_guard_snapshot(&guard_fixture())
        .unwrap();
}

#[test]
fn lineage_rejects_identity_and_used_pin_disagreement() {
    let mut lineage = checked_lineage();
    lineage.commit_id[0] ^= 1;
    assert!(lineage.encode().is_err());

    let mut lineage = checked_lineage();
    lineage.used.controls.clear();
    assert!(matches!(
        lineage.encode(),
        Err(EvidenceError::Contradiction)
    ));

    let mut pin = registration_pin();
    pin.digest[0] ^= 1;
    assert!(pin.check_record(&local_fixture()).is_err());
}

#[test]
fn root_policy_has_absolute_path_and_bounded_layers() {
    let mut bytes = vec![0x83];
    fixture_digest(&mut bytes, &[8; 32]);
    bytes.extend_from_slice(&[0x41, b'/', 0x81, 0x82, 0x41, 0xa0, 0x41, 0xa0]);
    let root = ConsumedRootPolicy::decode(&bytes).unwrap();
    assert_eq!(root.path, b"/");
    assert_eq!(root.encode().unwrap(), bytes);

    let mut bad_path = bytes.clone();
    bad_path[36] = b'r';
    assert!(ConsumedRootPolicy::decode(&bad_path).is_err());

    let mut enormous = vec![0x83];
    fixture_digest(&mut enormous, &[8; 32]);
    enormous.extend_from_slice(&[
        0x41, b'/', 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
    assert!(ConsumedRootPolicy::decode(&enormous).is_err());
}

#[test]
fn view_policy_preserves_root_occurrences_and_property_fences() {
    let mut root_bytes = vec![0x83];
    fixture_digest(&mut root_bytes, &[8; 32]);
    root_bytes.extend_from_slice(&[
        0x41, b'/', 0x81, 0x82, 0x44, 0xa1, 0x61, b'z', 1, 0x41, 0xa0,
    ]);
    let mut bytes = vec![0x83];
    fixture_digest(&mut bytes, &[9; 32]);
    fixture_string(&mut bytes, 0x60, b"public");
    bytes.push(0x81);
    bytes.extend_from_slice(&root_bytes);
    let view = ConsumedViewPolicy::decode(&bytes).unwrap();
    assert_eq!(view.encode().unwrap(), bytes);

    let mut inputs = used();
    inputs.views.push(view.clone());
    assert!(inputs.encode().is_err());
    inputs.registries.later_properties.push("z".into());
    assert!(inputs.encode().is_ok());

    let mut view = view;
    let mut other_occurrence = view.roots[0].clone();
    other_occurrence.path = b"/other".to_vec();
    view.roots.push(other_occurrence);
    assert!(view.encode().is_ok());
    let mut conflicting = view.roots[0].clone();
    conflicting.root = [7; 32];
    view.roots.push(conflicting);
    assert!(view.encode().is_err());
}

#[test]
fn enclosing_lineage_preserves_recorded_inert_property_names() {
    let properties = b"\xa1\x6bindex-roots\x00";
    let root = ConsumedRootPolicy {
        root: [8; 32],
        path: b"/".to_vec(),
        layers: vec![ConsumedRootLayer {
            properties: properties.to_vec(),
            overrides: vec![0xa0],
        }],
    };
    let view = ConsumedViewPolicy {
        view: [9; 32],
        default_domain: "public".into(),
        roots: vec![root],
    };
    let mut inputs = used();
    inputs
        .registries
        .later_properties
        .push("index-roots".into());
    inputs.views.push(view);

    let mut registry_bytes = registry_fixture();
    registry_bytes.pop();
    registry_bytes.push(0x81);
    fixture_string(&mut registry_bytes, 0x60, b"index-roots");
    let mut root_bytes = vec![0x83];
    fixture_digest(&mut root_bytes, &[8; 32]);
    root_bytes.extend_from_slice(&[0x41, b'/', 0x81, 0x82]);
    fixture_string(&mut root_bytes, 0x40, properties);
    root_bytes.extend_from_slice(&[0x41, 0xa0]);
    let mut view_bytes = vec![0x83];
    fixture_digest(&mut view_bytes, &[9; 32]);
    fixture_string(&mut view_bytes, 0x60, b"public");
    view_bytes.push(0x81);
    view_bytes.extend_from_slice(&root_bytes);
    let mut used_bytes = vec![0xa7, 0, 1, 1, 0x80, 2, 0x80, 3, 0x81];
    used_bytes.extend_from_slice(&pin_fixture());
    used_bytes.push(4);
    used_bytes.extend_from_slice(&registry_bytes);
    used_bytes.push(5);
    used_bytes.extend_from_slice(&config_fixture());
    used_bytes.extend_from_slice(&[6, 0x81]);
    used_bytes.extend_from_slice(&view_bytes);

    assert_eq!(inputs.encode().unwrap(), used_bytes);
    assert_eq!(LineageUsedInputs::decode(&used_bytes).unwrap(), inputs);
    let mut lineage = checked_lineage();
    lineage.used = inputs.clone();
    let old_fixture = lineage_fixture();
    let mut lineage_bytes = old_fixture[..old_fixture.len() - used_fixture().len()].to_vec();
    lineage_bytes.extend_from_slice(&used_bytes);
    assert_eq!(lineage.encode().unwrap(), lineage_bytes);
    assert_eq!(CheckedLineage::decode(&lineage_bytes).unwrap(), lineage);

    inputs.registries.later_properties.clear();
    assert!(inputs.encode().is_err());
    inputs.registries.property_revision = 2;
    inputs
        .registries
        .behavioral_properties
        .push("index-roots".into());
    inputs.registries.behavioral_properties.sort();
    assert!(inputs.encode().is_err());
}

#[test]
fn contextual_signed_commit_accepts_distinct_selected_tag() {
    use crate::refs::Commit;
    use ed25519_dalek::{Signer, SigningKey};

    // Hand-assembled key-eight context preserves the legacy surrounding fields.
    // The primitive signature authenticates these bytes only; no token, policy,
    // tree witnesses or physical owner are certified by this format test.
    let legacy = legacy_commit_fixture();
    let mut unsigned = legacy[..legacy.len() - 67].to_vec();
    unsigned[0] = 0xa6;
    let profile_position = unsigned
        .windows(5)
        .position(|part| part == [6, 0xa2, 1, 1, 2])
        .unwrap();
    unsigned[profile_position + 1] = 0xa3;
    unsigned.extend_from_slice(&[8, 0xa4, 1]);
    fixture_string(&mut unsigned, 0x60, b"refs/heads/_/authored");
    unsigned.extend_from_slice(&[
        2, 0x63, b'a', b'p', b'i', 3, 0xa0, 4, 0x81, 0x82, 0x41, b'/',
    ]);
    fixture_string(&mut unsigned, 0x60, b"public");

    let key = SigningKey::from_bytes(&[11; 32]);
    let signature = key.sign(&unsigned);
    let mut signed = unsigned.clone();
    signed[0] = 0xa7;
    signed.extend_from_slice(&[8, 0x58, 0x40]);
    signed.extend_from_slice(&signature.to_bytes());
    let commit = Commit::decode(&signed).unwrap();
    assert_eq!(commit.signature_preimage().unwrap(), unsigned);
    key.verifying_key()
        .verify_strict(&unsigned, &signature)
        .unwrap();
    assert_eq!(commit.encode().unwrap(), signed);
    assert_eq!(
        commit
            .profile_pair
            .commit_context
            .as_ref()
            .unwrap()
            .reference(),
        "refs/heads/_/authored"
    );

    let mut lineage = checked_lineage();
    lineage.commit_id = commit.identity().unwrap();
    lineage.source.commit = lineage.commit_id;
    lineage.commit_bytes = signed;
    let encoded = lineage.encode().unwrap();
    assert_eq!(CheckedLineage::decode(&encoded).unwrap(), lineage);
    assert_ne!(
        lineage.source_name,
        commit
            .profile_pair
            .commit_context
            .as_ref()
            .unwrap()
            .reference()
    );
}
