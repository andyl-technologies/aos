//! Checks unchanged local bytes and represented import consistency.
use super::*;

#[test]
fn local_original_and_ordered_baseline_have_independent_bytes() {
    assert_eq!(local().encode().unwrap(), local_fixture());
    assert_eq!(
        LocalOriginalRegistration::decode(&local_fixture()).unwrap(),
        local()
    );
    assert_eq!(bootstrap().encode().unwrap(), bootstrap_fixture());
    assert_eq!(
        OriginalBootstrap::decode(&bootstrap_fixture()).unwrap(),
        bootstrap()
    );
    assert_eq!(association().encode().unwrap(), association_fixture());
    assert_eq!(
        OriginalAssociation::decode(&association_fixture()).unwrap(),
        association()
    );
    assert_eq!(import().encode().unwrap(), import_fixture());
    assert_eq!(OriginalImport::decode(&import_fixture()).unwrap(), import());
}

#[test]
fn original_records_reject_noncanonical_and_contradictory_claims() {
    let mut noncanonical = local_fixture();
    noncanonical.splice(1..2, [0x18, 1]);
    assert!(LocalOriginalRegistration::decode(&noncanonical).is_err());

    let mut contradictory = import_fixture();
    let association_offset = 2 + local_fixture().len() + bootstrap_fixture().len();
    contradictory[association_offset + 37] = 9;
    assert!(OriginalImport::decode(&contradictory).is_err());

    let mut relative = local();
    relative.root = b"r".to_vec();
    assert!(relative.encode().is_err());

    let mut bad_acl = bootstrap();
    bad_acl.acl[0].verbs = 32;
    assert!(bad_acl.encode().is_err());
}

#[test]
fn trust_rows_have_independent_bytes_and_reject_invalid_intervals() {
    assert_eq!(issuer().encode().unwrap(), issuer_fixture());
    assert_eq!(IssuerRow::decode(&issuer_fixture()).unwrap(), issuer());
    assert_eq!(disclosure().encode().unwrap(), disclosure_fixture());
    assert_eq!(
        DisclosureRow::decode(&disclosure_fixture()).unwrap(),
        disclosure()
    );

    let mut bad_interval = disclosure_fixture();
    *bad_interval.last_mut().unwrap() = 1;
    assert!(DisclosureRow::decode(&bad_interval).is_err());
}

#[test]
fn import_binding_and_retained_trust_use_raw_import_digest() {
    let raw = *blake3::hash(&import_fixture()).as_bytes();
    let binding = OriginalImportBinding {
        commit: [2; 32],
        source: [1; 32],
        destination: [9; 32],
        import_digest: raw,
    };
    let mut binding_bytes = vec![0x85, 1];
    for digest in [[2; 32], [1; 32], [9; 32], raw] {
        fixture_digest(&mut binding_bytes, &digest);
    }
    assert_eq!(binding.encode().unwrap(), binding_bytes);
    assert_eq!(
        OriginalImportBinding::decode(&binding_bytes).unwrap(),
        binding
    );
    binding.check_import(&import_fixture()).unwrap();

    let trust = OriginalImportTrust {
        import_digest: raw,
        source: [1; 32],
        destination: [9; 32],
        issuers: vec![issuer()],
        disclosures: vec![disclosure()],
    };
    let mut trust_bytes = vec![0x86, 1];
    for digest in [raw, [1; 32], [9; 32]] {
        fixture_digest(&mut trust_bytes, &digest);
    }
    trust_bytes.push(0x81);
    trust_bytes.extend_from_slice(&issuer_fixture());
    trust_bytes.push(0x81);
    trust_bytes.extend_from_slice(&disclosure_fixture());
    assert_eq!(trust.encode().unwrap(), trust_bytes);
    assert_eq!(OriginalImportTrust::decode(&trust_bytes).unwrap(), trust);
    trust.check_binding(&binding, &import_fixture()).unwrap();

    let mut contradictory = trust.clone();
    contradictory.destination = [8; 32];
    assert!(
        contradictory
            .check_binding(&binding, &import_fixture())
            .is_err()
    );
    let mut duplicate = trust;
    duplicate.issuers.push(issuer());
    assert!(duplicate.encode().is_err());
}

#[test]
fn remote_registration_and_version_two_import_are_disjoint_from_local_v1() {
    let mut bytes = vec![0x85, 2];
    fixture_digest(&mut bytes, &[1; 32]);
    fixture_string(&mut bytes, 0x60, b"public");
    bytes.extend_from_slice(&[
        0x84, 1, 0x62, b's', b'3', 0x84, 0x61, b'e', 0x61, b'b', 0x40,
    ]);
    fixture_digest(&mut bytes, &[3; 32]);
    bytes.extend_from_slice(&[0x82, 0x41, b'k']);
    fixture_digest(&mut bytes, &[4; 32]);
    bytes.extend_from_slice(&[0x41, b'c']);
    let remote = PhysicalRegistration::Remote(RemoteOriginalRegistration {
        original_id: [1; 32],
        domain: "public".into(),
        control: b"c".to_vec(),
        binding: BackendBinding::Remote {
            provider: super::super::super::super::RemoteProvider::S3,
            endpoint: "e".into(),
            bucket: "b".into(),
            prefix: vec![],
            resource_nonce: [3; 32],
            coordination_key: b"k".to_vec(),
            coordination_nonce: [4; 32],
        },
    });
    assert_eq!(remote.encode().unwrap(), bytes);
    assert_eq!(PhysicalRegistration::decode(&bytes).unwrap(), remote);
    assert!(LocalOriginalRegistration::decode(&bytes).is_err());

    let mut import_bytes = vec![0x84, 2];
    import_bytes.extend_from_slice(&bytes);
    import_bytes.extend_from_slice(&bootstrap_fixture());
    import_bytes.extend_from_slice(&association_fixture());
    let decoded = OriginalImport::decode(&import_bytes).unwrap();
    assert_eq!(decoded.version, ImportVersion::PhysicalV2);
    assert_eq!(decoded.encode().unwrap(), import_bytes);

    import_bytes[1] = 1;
    assert!(OriginalImport::decode(&import_bytes).is_err());
}
