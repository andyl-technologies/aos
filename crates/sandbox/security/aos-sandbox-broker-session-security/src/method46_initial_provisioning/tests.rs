//! Exercises approval substitution, canonical boundaries and initial recovery.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn request(purpose: Method46InitialPurposeV1) -> Method46InitialRequestDataV1 {
    let mut salt_name = [4; 34];
    salt_name[..2].copy_from_slice(&[0, 0x0b]);
    Method46InitialRequestDataV1::new(purpose, [1; 16], [2; 16], [3; 32], salt_name, 4, [5; 32])
        .unwrap()
}

fn approve(request: Method46InitialRequestDataV1) -> Method46InitialIntentDataV1 {
    let key = SigningKey::from_bytes(&[6; 32]);
    Method46InitialIntentDataV1::from_approval(
        request,
        key.sign(&request.encode()).to_bytes(),
        key.verifying_key().to_bytes(),
    )
    .unwrap()
}

#[test]
fn initial_requests_use_existing_canonical_checkpoint_and_nv_equation() {
    for purpose in [
        Method46InitialPurposeV1::ControllerStorageClient,
        Method46InitialPurposeV1::StorageBroker,
    ] {
        let request = request(purpose);
        assert_eq!(
            Method46InitialRequestDataV1::decode(&request.encode()).unwrap(),
            request
        );
        assert_eq!(request.purpose(), purpose);

        let checkpoint = FloorCheckpointV1::decode(&request.checkpoint()).unwrap();
        assert_eq!(checkpoint.ordinal(), 1);
        assert_eq!(checkpoint.cut(), FloorCutV1::new(4, [5; 32]).unwrap());
        assert_eq!(request.extend_input(), checkpoint.extend_input());
        assert_eq!(
            request.expected_nv(),
            Sha256::digest([[0; 32], request.extend_input()].concat()).as_slice()
        );
        assert_eq!(purpose.nv_index(), purpose.endpoint().nv_index());
    }
}

#[test]
fn requests_reject_every_truncation_and_noncanonical_derived_field() {
    let bytes = request(Method46InitialPurposeV1::ControllerStorageClient).encode();
    for length in 0..bytes.len() {
        assert!(
            Method46InitialRequestDataV1::decode(&bytes[..length]).is_err(),
            "length {length}"
        );
    }
    assert!(Method46InitialRequestDataV1::decode(&[bytes.as_slice(), &[0]].concat()).is_err());

    // Header/version/reserved bytes, profile framing/role, salt algorithm and
    // commitment, fixed handles, checkpoint ordinal/scope/cut and sentinels.
    for offset in [
        0, 8, 9, 10, 11, 12, 20, 24, 25, 124, 125, 126, 158, 161, 162, 165, 166, 174, 177, 185,
        186, 217, 258, 290, 321,
    ] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(
            Method46InitialRequestDataV1::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn initial_request_rejects_empty_or_exhausted_cut_and_sentinel_fields() {
    let mut salt = [4; 34];
    salt[..2].copy_from_slice(&[0, 0x0b]);
    let new = |node, epoch, endpoint, salt, sequence, head| {
        Method46InitialRequestDataV1::new(
            Method46InitialPurposeV1::StorageBroker,
            node,
            epoch,
            endpoint,
            salt,
            sequence,
            head,
        )
    };
    for sequence in [0, 1, u64::MAX] {
        assert!(new([1; 16], [2; 16], [3; 32], salt, sequence, [5; 32]).is_err());
    }
    assert!(new([0; 16], [2; 16], [3; 32], salt, 4, [5; 32]).is_err());
    assert!(new([1; 16], [0; 16], [3; 32], salt, 4, [5; 32]).is_err());
    assert!(new([1; 16], [2; 16], [0; 32], salt, 4, [5; 32]).is_err());
    assert!(new([1; 16], [2; 16], [3; 32], salt, 4, [0; 32]).is_err());
    salt[2..].fill(0);
    assert!(new([1; 16], [2; 16], [3; 32], salt, 4, [5; 32]).is_err());
}

#[test]
fn approval_rejects_wrong_key_and_every_changed_signed_byte() {
    let request = request(Method46InitialPurposeV1::ControllerStorageClient);
    let key = SigningKey::from_bytes(&[6; 32]);
    let public = key.verifying_key().to_bytes();
    let signature = key.sign(&request.encode()).to_bytes();
    let intent = Method46InitialIntentDataV1::from_approval(request, signature, public).unwrap();
    assert_eq!(
        Method46InitialIntentDataV1::decode(&intent.encode(), public).unwrap(),
        intent
    );
    assert_eq!(intent.request(), request);
    assert_eq!(
        Method46InitialIntentDataV1::from_approval(
            request,
            signature,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
        ),
        Err(Method46InitialDataErrorV1::Approval)
    );

    let bytes = intent.encode();
    for offset in 0..bytes.len() {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(
            Method46InitialIntentDataV1::decode(&changed, public).is_err(),
            "offset {offset}"
        );
    }
    for length in 0..bytes.len() {
        assert!(
            Method46InitialIntentDataV1::decode(&bytes[..length], public).is_err(),
            "length {length}"
        );
    }
    assert!(
        Method46InitialIntentDataV1::decode(&[bytes.as_slice(), &[0]].concat(), public).is_err()
    );
}

#[test]
fn initial_approval_cannot_cross_roles_epochs_salts_or_main_cuts() {
    let original = request(Method46InitialPurposeV1::ControllerStorageClient);
    let signature = SigningKey::from_bytes(&[6; 32])
        .sign(&original.encode())
        .to_bytes();
    let public = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
    let mut salt = original.salt_name;
    salt[2] ^= 1;
    let changed = [
        request(Method46InitialPurposeV1::StorageBroker),
        Method46InitialRequestDataV1::new(
            original.purpose(),
            [8; 16],
            [2; 16],
            [3; 32],
            original.salt_name,
            4,
            [5; 32],
        )
        .unwrap(),
        Method46InitialRequestDataV1::new(
            original.purpose(),
            [1; 16],
            [8; 16],
            [3; 32],
            original.salt_name,
            4,
            [5; 32],
        )
        .unwrap(),
        Method46InitialRequestDataV1::new(
            original.purpose(),
            [1; 16],
            [2; 16],
            [8; 32],
            original.salt_name,
            4,
            [5; 32],
        )
        .unwrap(),
        Method46InitialRequestDataV1::new(
            original.purpose(),
            [1; 16],
            [2; 16],
            [3; 32],
            salt,
            4,
            [5; 32],
        )
        .unwrap(),
        Method46InitialRequestDataV1::new(
            original.purpose(),
            [1; 16],
            [2; 16],
            [3; 32],
            original.salt_name,
            7,
            [5; 32],
        )
        .unwrap(),
        Method46InitialRequestDataV1::new(
            original.purpose(),
            [1; 16],
            [2; 16],
            [3; 32],
            original.salt_name,
            4,
            [8; 32],
        )
        .unwrap(),
    ];
    for request in changed {
        assert_eq!(
            Method46InitialIntentDataV1::from_approval(request, signature, public),
            Err(Method46InitialDataErrorV1::Approval)
        );
        assert_eq!(
            approve(original).compare_recovery(request, Method46InitialNvDataV1::Unwritten),
            Err(Method46InitialDataErrorV1::Conflict)
        );
    }
}

#[test]
fn cold_initial_comparison_never_extends_a_written_index() {
    for purpose in [
        Method46InitialPurposeV1::ControllerStorageClient,
        Method46InitialPurposeV1::StorageBroker,
    ] {
        let request = request(purpose);
        let intent = approve(request);
        assert_eq!(
            intent
                .compare_recovery(request, Method46InitialNvDataV1::Unwritten)
                .unwrap(),
            Method46InitialRecoveryDataV1::ExtendInitial
        );
        assert_eq!(
            intent
                .compare_recovery(
                    request,
                    Method46InitialNvDataV1::Written(request.expected_nv())
                )
                .unwrap(),
            Method46InitialRecoveryDataV1::CheckpointInitial
        );
        for value in [[0; 32], [9; 32]] {
            assert_eq!(
                intent.compare_recovery(request, Method46InitialNvDataV1::Written(value)),
                Err(Method46InitialDataErrorV1::Conflict)
            );
        }
    }
}

#[test]
fn weak_approval_keys_and_runtime_record_formats_are_rejected() {
    let request = request(Method46InitialPurposeV1::StorageBroker);
    let mut identity_key = [0; 32];
    identity_key[0] = 1;
    assert_eq!(
        Method46InitialIntentDataV1::from_approval(request, [0; 64], identity_key),
        Err(Method46InitialDataErrorV1::Approval)
    );
    let intent = approve(request);
    let mut encoded = intent.encode();
    for magic in [b"AOSBTI01", b"AOSBTF01", b"AOSRDI01", b"AOSNXI01"] {
        encoded[..8].copy_from_slice(magic);
        assert!(
            Method46InitialIntentDataV1::decode(
                &encoded,
                SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes()
            )
            .is_err()
        );
    }
    assert!(FloorCheckpointV1::decode(&intent.encode()).is_err());
    assert!(
        crate::tpm_nv_custody::FloorIntentV1::decode(request.profile, &intent.encode()).is_err()
    );
}
