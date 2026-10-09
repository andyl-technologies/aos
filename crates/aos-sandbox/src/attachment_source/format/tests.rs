//! Checks attachment-record framing and semantic validation without admission.

use super::*;

fn rejects_incomplete_or_changed_digest<T>(
    bytes: &[u8],
    decode: fn(&[u8]) -> Result<T, AttachmentSourceError>,
) {
    for length in 0..bytes.len() {
        assert!(
            matches!(
                decode(&bytes[..length]),
                Err(AttachmentSourceError::CorruptState)
            ),
            "prefix length {length}"
        );
    }

    let mut changed = bytes.to_vec();
    changed.push(0);
    assert!(matches!(
        decode(&changed),
        Err(AttachmentSourceError::CorruptState)
    ));

    changed.truncate(bytes.len());
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(matches!(
        decode(&changed),
        Err(AttachmentSourceError::CorruptState)
    ));
}

fn rejects_rehashed_mutations<T>(
    bytes: &[u8],
    domain: &[u8],
    mutations: &[(usize, u8)],
    decode: fn(&[u8]) -> Result<T, AttachmentSourceError>,
) {
    for &(offset, value) in mutations {
        let mut changed = bytes.to_vec();
        changed[offset] = value;

        // A valid checksum isolates grammar and model refusals from digest failure.
        let body_end = changed.len() - 32;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(domain)
            .chain_update(&changed[..body_end])
            .finalize()
            .into();
        changed[body_end..].copy_from_slice(&digest);

        assert!(
            matches!(decode(&changed), Err(AttachmentSourceError::CorruptState)),
            "mutation at byte {offset} with a repaired digest"
        );
    }
}

#[test]
fn attempt_codec_preserves_exact_fields_and_refuses_malformed_records() {
    let mut record = AttemptRecord {
        kind: AttachmentSourceAttemptKindV1::Acquire,
        operation_id: [1; 16],
        request_digest: [2; 32],
        attachment_id: [3; 16],
        desired_generation: 1,
        desired_digest: [4; 32],
        acquisition_id: [5; 32],
        predecessor: None,
        mount_completion_digest: None,
        plan_digest: [6; 32],
        request_body: vec![7; 3],
        plan_bytes: vec![8; PLAN_BYTES],
        digest: [0; 32],
    };
    record.digest = record.compute_digest();

    let bytes = record.encode();
    assert_eq!(bytes.len(), ATTEMPT_FIXED_BYTES + 3 + PLAN_BYTES);
    assert_eq!(&bytes[..8], ATTEMPT_MAGIC);
    assert_eq!(&bytes[244..248], &3_u32.to_be_bytes());
    assert_eq!(&bytes[248..252], &(PLAN_BYTES as u32).to_be_bytes());
    assert_eq!(AttemptRecord::decode(&bytes).unwrap(), record);

    rejects_incomplete_or_changed_digest(&bytes, AttemptRecord::decode);
    rejects_rehashed_mutations(
        &bytes,
        ATTEMPT_DOMAIN,
        &[
            (0, b'X'),
            (8, 0),
            (9, 128),
            (10, 1),
            (83, 0),    // Zero desired generation.
            (148, 1),   // Predecessor bytes without their presence bit.
            (244, 255), // Request length exceeds the remaining body.
            (248, 255), // Plan length violates the fixed wire size.
        ],
        AttemptRecord::decode,
    );

    record.kind = AttachmentSourceAttemptKindV1::Consume;
    record.request_body.clear();
    record.predecessor = Some([9; 32]);
    record.mount_completion_digest = Some([10; 32]);
    record.digest = record.compute_digest();
    assert_eq!(AttemptRecord::decode(&record.encode()).unwrap(), record);
}

#[test]
fn completion_codec_preserves_optional_resources_and_refuses_malformed_records() {
    let mut record = CompletionRecord {
        kind: AttachmentSourceAttemptKindV1::Acquire,
        operation_id: [1; 16],
        attempt_digest: [2; 32],
        predecessor: None,
        attachment_id: [3; 16],
        desired_generation: 1,
        acquisition_id: [4; 32],
        acquisition_revision: 1,
        acquisition_record_digest: [5; 32],
        acquisition_phase: MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE,
        resource_snapshot_digest: [6; 32],
        source_snapshot_digest: [7; 32],
        mount_handle: None,
        resource_revision: None,
        resource_lifecycle: None,
        mount_completion_digest: None,
        verification_digest: None,
        digest: [0; 32],
    };
    record.digest = record.compute_digest();

    let bytes = record.encode();
    assert_eq!(bytes.len(), COMPLETION_FIXED_BYTES);
    assert_eq!(&bytes[..8], COMPLETION_MAGIC);
    assert_eq!(CompletionRecord::decode(&bytes).unwrap(), record);

    rejects_incomplete_or_changed_digest(&bytes, CompletionRecord::decode);
    rejects_rehashed_mutations(
        &bytes,
        COMPLETION_DOMAIN,
        &[
            (0, b'X'),
            (8, 0),
            (9, 128),
            (10, 1),
            (60, 1),    // Predecessor bytes without their presence bit.
            (155, 0),   // Zero acquisition revision on an active Acquire.
            (188, 255), // Unknown acquisition phase.
            (253, 1),   // Mount handle without the resource presence bit.
            (293, 1),   // Resource lifecycle without the resource presence bit.
        ],
        CompletionRecord::decode,
    );

    record.kind = AttachmentSourceAttemptKindV1::Consume;
    record.acquisition_phase = MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED;
    record.mount_handle = Some([8; 32]);
    record.resource_revision = Some(9);
    record.resource_lifecycle = Some(MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
    record.mount_completion_digest = Some([10; 32]);
    record.verification_digest = Some([11; 32]);
    record.digest = record.compute_digest();
    assert_eq!(CompletionRecord::decode(&record.encode()).unwrap(), record);
}
