//! Tests the closed historical resource-claim families and framing.

use sha2::{Digest as _, Sha256};

use super::{
    CLAIM_BYTES, Claim, ClaimCut, ClaimPurpose, ClaimState, EnrollmentIdentity,
    ResourceBankDataError, ResourceDimension, ResourceVector, encode_claim,
};

const PURPOSES: [(ClaimPurpose, &[u8; 8], u8); 19] = [
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
    (ClaimPurpose::CreateContinuationIntake, b"AOSRSC09", 14),
    (ClaimPurpose::StorageReceiving, b"AOSRSC10", 16),
    (ClaimPurpose::CreateStorageUse, b"AOSRSC11", 15),
    (ClaimPurpose::DeleteOperationIntake, b"AOSRSC12", 17),
    (ClaimPurpose::ExecutionOperationIntake, b"AOSRSC13", 18),
    (ClaimPurpose::HostExecutionPrepare, b"AOSRSC14", 19),
    (ClaimPurpose::HostExecutionAccept, b"AOSRSC15", 20),
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
        | ClaimPurpose::RootReceiving | ClaimPurpose::StorageReceiving
        | ClaimPurpose::DeleteOperationIntake | ClaimPurpose::ExecutionOperationIntake
        | ClaimPurpose::HostExecutionPrepare | ClaimPurpose::HostExecutionAccept
        | ClaimPurpose::CreateContinuationIntake => claim.child = [0; 16],
        ClaimPurpose::InclusiveGrant
        | ClaimPurpose::Snapshot
        | ClaimPurpose::ProjectPreparation
        | ClaimPurpose::Q04Preparation
        | ClaimPurpose::CreateStorageUse => {
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
                ClaimPurpose::Snapshot | ClaimPurpose::Q04Preparation | ClaimPurpose::CreateStorageUse
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

        for magic in [b"AOSRSC01", b"AOSRSC05", b"AOSRSC16"] {
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
            b"AOSRSC09",
            b"AOSRSC10",
            b"AOSRSC11",
            b"AOSRSC12",
            b"AOSRSC13",
            b"AOSRSC14",
            b"AOSRSC15",
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
        for code in [0, 10, 21, 255] {
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


use crate::domain_ledger::resource_bank::OperationIntakeFundingDataV1;

#[test]
fn fresh_delete_controller_frame_preserves_the_complete_c17_claim() {
    use crate::domain_ledger::delete_root::controller_cut::{
        DeleteRootControllerCutDataV3, DELETE_ROOT_CONTROLLER_CUT_BYTES_V3,
    };
    let expected = DeleteRootControllerCutDataV3 {
        challenge: [23; 32], funding: OperationIntakeFundingDataV1::InitialReservedClaim(fixture(ClaimPurpose::DeleteOperationIntake)), next: 41, end: 8192,
    };
    let bytes = expected.encode_v3().unwrap();

    assert_eq!(bytes.len(), DELETE_ROOT_CONTROLLER_CUT_BYTES_V3);
    assert_eq!(DeleteRootControllerCutDataV3::decode_v3(&bytes).unwrap(), expected);
    assert_eq!(&bytes[64..64 + CLAIM_BYTES], &encode_claim(fixture(ClaimPurpose::DeleteOperationIntake)).unwrap());
    let mut retired = bytes;
    retired[..8].copy_from_slice(b"AOSDRC01");
    retired[8..10].copy_from_slice(&1u16.to_be_bytes());
    assert!(DeleteRootControllerCutDataV3::decode_v3(&retired).is_err());
    for end in 0..bytes.len() { assert!(DeleteRootControllerCutDataV3::decode_v3(&bytes[..end]).is_err()); }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(DeleteRootControllerCutDataV3::decode_v3(&trailing).is_err());
}

#[test]
fn fresh_delete_frame_refuses_other_purposes_and_spent_claims() {
    use crate::domain_ledger::delete_root::controller_cut::DeleteRootControllerCutDataV3;
    let mut frame = DeleteRootControllerCutDataV3 {
        challenge: [23; 32], funding: OperationIntakeFundingDataV1::InitialReservedClaim(fixture(ClaimPurpose::ExecutionOperationIntake)), next: 41, end: 8192,
    };
    assert!(frame.encode_v3().is_err());

    let mut claim = fixture(ClaimPurpose::DeleteOperationIntake);
    for state in [ClaimState::Committed, ClaimState::Released, ClaimState::Reserved] {
        claim.state = state;
        frame.funding = OperationIntakeFundingDataV1::InitialReservedClaim(claim);
        assert_eq!(frame.encode_v3().is_ok(), state == ClaimState::Reserved);
    }
}

#[test]
fn planning_frames_use_only_v3_without_a_retired_encoder() {
    use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
    use crate::domain_ledger::delete_root::planning::{
        DeleteRootPlanningOpenDataV3, DeleteRootPlanningChallengeDataV3,
    };
    let sample = |wall, boot| RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16], wall, boot,
    ).unwrap();
    // Plain codec DATA provides neither the claimed account nor native cuts.
    let open = DeleteRootPlanningOpenDataV3 {
        project: [3; 16], caller: [4; 16], input: [5; 32],
        authorization_clock: sample(100, 10_000_000_000), authorization_expires: 500,
        controller_nonce: [6; 16], controller_cutoff: 15_000_000_000,
        controller_next: 7, controller_end: 4096, source_next: 8, source_end: 8192,
        funding: OperationIntakeFundingDataV1::InitialReservedClaim(fixture(ClaimPurpose::DeleteOperationIntake)),
    };
    let bytes = open.encode_v3().unwrap();
    assert_eq!(DeleteRootPlanningOpenDataV3::decode_v3(&bytes).unwrap(), open);
    let challenge = DeleteRootPlanningChallengeDataV3 {
        open: open.digest_v3().unwrap(), clock: sample(101, 11_000_000_000),
        nonce: [9; 16], cutoff: 15_000_000_000,
    };
    assert!(challenge.require_open_v3(open).is_ok());
    let reply = challenge.encode_v3().unwrap();
    assert_eq!(DeleteRootPlanningChallengeDataV3::decode_v3(&reply).unwrap(), challenge);

    let mut retired_open = bytes;
    retired_open[..8].copy_from_slice(b"AOSDRP01");
    retired_open[8..10].copy_from_slice(&1u16.to_be_bytes());
    let mut retired_reply = reply;
    retired_reply[..8].copy_from_slice(b"AOSDPC01");
    retired_reply[8..10].copy_from_slice(&1u16.to_be_bytes());
    assert!(DeleteRootPlanningOpenDataV3::decode_v3(&retired_open).is_err());
    retired_open[..8].copy_from_slice(b"AOSDRP02");
    retired_open[8..10].copy_from_slice(&2u16.to_be_bytes());
    assert!(DeleteRootPlanningOpenDataV3::decode_v3(&retired_open).is_err());
    assert!(DeleteRootPlanningChallengeDataV3::decode_v3(&retired_reply).is_err());
}
