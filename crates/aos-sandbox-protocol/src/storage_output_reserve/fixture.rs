//! Synthetic canonical output-registration DATA shared by signed fixtures.
//!
//! These constructors issue no protected role, native owner or effect grant.

use super::*;
use aos_proto::aos::sandbox::local::v1::RequestHeader;

pub(crate) fn seal(domain: &[u8], bytes: &mut [u8], digest_start: usize) {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(&bytes[..digest_start])
        .finalize();
    bytes[digest_start..digest_start + 32].copy_from_slice(&digest);
}

pub(crate) fn fixture() -> (ReserveStorageExecutionOutputRequestV1, BrokerAssignment) {
    let mut source = [0_u8; 688];
    source[..8].copy_from_slice(b"AOSCIR01");
    source[8..16].copy_from_slice(b"AOSCIP01");
    source[16..32].fill(1);
    source[32..48].fill(2);
    source[48..80].fill(3);
    source[96..104].copy_from_slice(&1_u64.to_be_bytes());
    source[104..120].fill(4);
    source[120..128].copy_from_slice(&1_000_u64.to_be_bytes());
    source[128..160].fill(5);
    let preissue_digest = Sha256::new()
        .chain_update(PREISSUE_DOMAIN)
        .chain_update(&source[8..160])
        .finalize();
    source[160..192].copy_from_slice(&preissue_digest);

    source[192..200].copy_from_slice(b"AOSEOR02");
    source[200..216].fill(1);
    source[216..232].fill(2);
    for offset in [232, 264, 328, 360, 392, 456] {
        source[offset..offset + 32].fill(6);
    }
    source[296..328].fill(7);
    source[432..440].copy_from_slice(&100_u64.to_be_bytes());
    let claim_checksum = Sha256::digest(&source[192..488]);
    source[488..520].copy_from_slice(&claim_checksum);
    source[520..552].fill(8);
    source[552..568].fill(9);
    source[568..584].fill(10);
    source[584..600].fill(11);
    for offset in [600, 608, 616] {
        source[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
    }
    source[624..656].fill(7);
    seal(SOURCE_DOMAIN, &mut source, 656);

    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes([9; 16]),
        IncarnationId::from_bytes([10; 16]),
        AssignmentEpoch::new(1),
        DesiredGeneration::new(1),
        ObjectDigest::from_bytes([7; 32]),
    )
    .unwrap();
    let semantic = host_output_reserve_grant_v1(assignment, [12; 16], &source).unwrap();

    let mut attempt = [0_u8; CONTROLLER_OUTPUT_ATTEMPT_BYTES_V1];
    attempt[..8].copy_from_slice(b"AOSCIA01");
    attempt[8..696].copy_from_slice(&source);
    attempt[696..712].fill(12);
    attempt[712..744].fill(13);
    attempt[744..776].copy_from_slice(semantic.commitment().digest().as_bytes());
    attempt[776..784].copy_from_slice(&900_u64.to_be_bytes());
    seal(ATTEMPT_DOMAIN, &mut attempt, 784);

    let mut settlement = [0_u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1];
    settlement[..8].copy_from_slice(b"AOSCIS01");
    settlement[8..24].fill(1);
    settlement[24..40].fill(2);
    settlement[40..72].copy_from_slice(&attempt[784..816]);
    settlement[72..104].fill(15);
    settlement[104..112].copy_from_slice(&1_u64.to_be_bytes());
    settlement[112..144].fill(16);
    settlement[144..176].fill(17);
    seal(SETTLEMENT_DOMAIN, &mut settlement, 176);

    let request = ReserveStorageExecutionOutputRequestV1 {
        header: Some(RequestHeader {
            protocol_major: 1,
            request_id: vec![18; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 950,
            maximum_response_bytes: 4_096,
            ..Default::default()
        })
        .into(),
        canonical_controller_attempt: attempt.to_vec(),
        canonical_controller_settlement: settlement.to_vec(),
        ..Default::default()
    };
    (request, assignment)
}

pub(crate) fn captured_fixture() -> (ReserveStorageExecutionOutputRequestV1, BrokerAssignment) {
    let (mut request, assignment) = fixture();
    let mut source: [u8; 688] =
        request.canonical_controller_attempt[8..696].try_into().unwrap();
    for (offset, value) in [(80, 60_u64), (88, 40), (424, 100), (440, 60), (448, 40)] {
        source[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    let digest = Sha256::new()
        .chain_update(PREISSUE_DOMAIN)
        .chain_update(&source[8..160])
        .finalize();
    source[160..192].copy_from_slice(&digest);
    let digest = Sha256::digest(&source[192..488]);
    source[488..520].copy_from_slice(&digest);
    seal(SOURCE_DOMAIN, &mut source, 656);
    let semantic = host_output_reserve_grant_v1(assignment, [12; 16], &source).unwrap();

    let attempt = &mut request.canonical_controller_attempt;
    attempt[8..696].copy_from_slice(&source);
    attempt[744..776].copy_from_slice(semantic.commitment().digest().as_bytes());
    seal(ATTEMPT_DOMAIN, attempt, 784);
    request.canonical_controller_settlement[40..72].copy_from_slice(&attempt[784..816]);
    seal(SETTLEMENT_DOMAIN, &mut request.canonical_controller_settlement, 176);
    (request, assignment)
}

