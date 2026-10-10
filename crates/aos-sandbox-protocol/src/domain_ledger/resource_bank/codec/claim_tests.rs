//! Tests the closed historical resource-claim families and framing.

use sha2::{Digest as _, Sha256};

use super::{
    CLAIM_BYTES, Claim, ClaimCut, ClaimPurpose, ClaimState, EnrollmentIdentity,
    ResourceBankDataError, ResourceDimension, ResourceVector, encode_claim,
};

const PURPOSES: [(ClaimPurpose, &[u8; 8], u8); 12] = [
    (ClaimPurpose::ControllerBootstrap, b"AOSRSC02", 1),
    (ClaimPurpose::ComponentEnvelope, b"AOSRSC02", 2),
    (ClaimPurpose::InclusiveGrant, b"AOSRSC02", 3),
    (ClaimPurpose::Snapshot, b"AOSRSC02", 4),
    (ClaimPurpose::ProjectPreparation, b"AOSRSC02", 5),
    (ClaimPurpose::Q04Preparation, b"AOSRSC02", 6),
    (ClaimPurpose::HostComponentBootstrap, b"AOSRSC03", 7),
    (ClaimPurpose::HostControlInterval, b"AOSRSC03", 8),
    (ClaimPurpose::ControllerFirstGlobalPrefix, b"AOSRSC04", 9),
    (ClaimPurpose::NixOriginalStartIntake, b"AOSRSC06", 11),
    (ClaimPurpose::Q04OriginalIntake, b"AOSRSC07", 12),
    (ClaimPurpose::RootReceiving, b"AOSRSC08", 13),
];

// Historical DATA alone creates no original resource or paid owner.
fn fixture(purpose: ClaimPurpose) -> Claim {
    let enrollment = EnrollmentIdentity {
        node: [1; 16],
        epoch: [2; 16],
        boot: [3; 16],
        invocation: [4; 16],
        manifest: [5; 32],
    };
    let mut claim = Claim {
        enrollment,
        id: [6; 16],
        account: [7; 16],
        child: [8; 16],
        owner: enrollment.manifest,
        purpose,
        operation: [0; 16],
        project: [0; 16],
        sandbox: [0; 16],
        tree_revision: [0; 32],
        cut: ClaimCut::BootLifetime,
        genesis_instance: [0; 32],
        amount: ResourceVector::new([1; ResourceDimension::COUNT]),
        state: ClaimState::Reserved,
    };

    match purpose {
        ClaimPurpose::ControllerBootstrap
        | ClaimPurpose::ComponentEnvelope
        | ClaimPurpose::HostComponentBootstrap => {}
        ClaimPurpose::HostControlInterval
        | ClaimPurpose::ControllerFirstGlobalPrefix
        | ClaimPurpose::NixOriginalStartIntake
        | ClaimPurpose::Q04OriginalIntake
        | ClaimPurpose::RootReceiving => claim.child = [0; 16],
        ClaimPurpose::InclusiveGrant
        | ClaimPurpose::Snapshot
        | ClaimPurpose::ProjectPreparation
        | ClaimPurpose::Q04Preparation => {
            claim.operation = [9; 16];
            claim.project = [10; 16];
            claim.tree_revision = [11; 32];
            claim.cut = ClaimCut::Operation {
                original_wall_seconds: 1,
                original_boottime_nanoseconds: 2,
                deadline_boottime_nanoseconds: 3,
            };
            claim.genesis_instance = [12; 32];
            if purpose != ClaimPurpose::InclusiveGrant {
                claim.child = [0; 16];
            }
            if matches!(
                purpose,
                ClaimPurpose::Snapshot | ClaimPurpose::Q04Preparation
            ) {
                claim.sandbox = [13; 16];
            }
            if purpose == ClaimPurpose::Snapshot {
                claim.genesis_instance = [0; 32];
            }
        }
    }

    claim
}

fn refresh_checksum(bytes: &mut [u8; CLAIM_BYTES]) {
    let checksum = Sha256::digest(&bytes[..CLAIM_BYTES - 32]);
    bytes[CLAIM_BYTES - 32..].copy_from_slice(&checksum);
}

#[test]
fn all_claim_purposes_round_trip_in_their_closed_families() {
    for (purpose, magic, code) in PURPOSES {
        let expected = fixture(purpose);
        let bytes = encode_claim(expected).unwrap();

        assert_eq!(bytes.len(), 531);
        assert_eq!(&bytes[..8], magic);
        assert_eq!(bytes[184], code);
        assert_eq!(Claim::decode(&bytes).unwrap(), expected);
    }
}

#[test]
fn every_claim_short_prefix_and_trailing_byte_is_corrupt() {
    for (purpose, _, _) in PURPOSES {
        let bytes = encode_claim(fixture(purpose)).unwrap();

        for end in 0..bytes.len() {
            assert!(
                matches!(
                    Claim::decode(&bytes[..end]),
                    Err(ResourceBankDataError::CorruptLedger)
                ),
                "purpose {purpose:?}, prefix {end}"
            );
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);

        assert!(matches!(
            Claim::decode(&trailing),
            Err(ResourceBankDataError::CorruptLedger)
        ));
    }
}

#[test]
fn claim_framing_refuses_unknown_headers_and_bad_checksums() {
    for (purpose, _, _) in PURPOSES {
        let bytes = encode_claim(fixture(purpose)).unwrap();

        for magic in [b"AOSRSC01", b"AOSRSC05", b"AOSRSC09"] {
            let mut unknown = bytes;
            unknown[..8].copy_from_slice(magic);
            refresh_checksum(&mut unknown);

            assert!(matches!(
                Claim::decode(&unknown),
                Err(ResourceBankDataError::CorruptLedger)
            ));
        }
        let mut bad_checksum = bytes;
        bad_checksum[CLAIM_BYTES - 1] ^= 1;

        assert!(matches!(
            Claim::decode(&bad_checksum),
            Err(ResourceBankDataError::CorruptLedger)
        ));
    }
}

#[test]
fn checksummed_claims_refuse_cross_family_and_unknown_purposes() {
    for (purpose, magic, _) in PURPOSES {
        let bytes = encode_claim(fixture(purpose)).unwrap();

        for other_magic in [
            b"AOSRSC02",
            b"AOSRSC03",
            b"AOSRSC04",
            b"AOSRSC06",
            b"AOSRSC07",
            b"AOSRSC08",
        ] {
            if other_magic == magic {
                continue;
            }
            let mut wrong_family = bytes;
            wrong_family[..8].copy_from_slice(other_magic);
            refresh_checksum(&mut wrong_family);

            assert!(matches!(
                Claim::decode(&wrong_family),
                Err(ResourceBankDataError::CorruptLedger)
            ));
        }
        for code in [0, 10, 14, 255] {
            let mut unknown_purpose = bytes;
            unknown_purpose[184] = code;
            refresh_checksum(&mut unknown_purpose);

            assert!(matches!(
                Claim::decode(&unknown_purpose),
                Err(ResourceBankDataError::CorruptLedger)
            ));
        }
    }
}
