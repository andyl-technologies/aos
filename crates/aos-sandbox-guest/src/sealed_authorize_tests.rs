//! Linux descriptor-transport tests for the portable sealed-authorize frame.

use std::time::{Duration, Instant};

use aos_sandbox_core::{AuditId, ExecutionId, ObjectDigest, PrincipalId};
use aos_sandbox_linux::immutable_file::{SealedMemfdMapping, SealedReadOnlyCredential};
use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};
use sha2::{Digest as _, Sha256};

use aos_sandbox_agent::{
    AgentFrameV1, AgentOperationIdV1, AgentOperationSequenceV1, AgentProtocolError,
    AgentSealedAuthorizeReferenceV1, AgentSessionBindingV1, MAX_AGENT_SEALED_SPEC_BYTES_V1,
    decode_frame_v1, encode_frame_v1,
};

fn reference(content: &[u8]) -> AgentSealedAuthorizeReferenceV1 {
    AgentSealedAuthorizeReferenceV1 {
        session: AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([1; 32])).unwrap(),
        sequence: AgentOperationSequenceV1::new(1).unwrap(),
        operation_id: AgentOperationIdV1::new([2; 16]).unwrap(),
        backend_request_binding: ObjectDigest::from_bytes([3; 32]),
        execution: ExecutionId::from_bytes([4; 16]),
        content_bytes: content.len() as u64,
        content_digest: ObjectDigest::from_bytes(Sha256::digest(content).into()),
        specification_digest: ObjectDigest::from_bytes([5; 32]),
        admission_commitment: ObjectDigest::from_bytes([6; 32]),
        principal: PrincipalId::from_bytes([7; 16]),
        audit: AuditId::from_bytes([8; 16]),
        request_commitment: ObjectDigest::from_bytes([9; 32]),
    }
}

#[test]
fn sealed_reference_is_small_and_rejects_changed_length_or_hash() {
    let reference = reference(b"x");
    let frame = encode_frame_v1(&AgentFrameV1::SealedAuthorizeRequest(reference));
    assert!(frame.len() < 512);
    assert_eq!(
        decode_frame_v1(&frame),
        Ok(AgentFrameV1::SealedAuthorizeRequest(reference))
    );
    assert_eq!(
        reference.reconstruct(b"y"),
        Err(AgentProtocolError::CommitmentMismatch)
    );
    assert_eq!(
        reference.reconstruct(b"xx"),
        Err(AgentProtocolError::CommitmentMismatch)
    );
    assert!(matches!(
        reference.reconstruct(b"x"),
        Err(AgentProtocolError::Model(_))
    ));

    let content_size_offset = 8 + 1 + 32 + 8 + 16 + 32 + 16;
    let mut zero_length = frame.clone();
    zero_length[content_size_offset..content_size_offset + 8].fill(0);
    assert_eq!(
        decode_frame_v1(&zero_length),
        Err(AgentProtocolError::InvalidLength)
    );
    let mut oversized = frame;
    oversized[content_size_offset..content_size_offset + 8]
        .copy_from_slice(&(MAX_AGENT_SEALED_SPEC_BYTES_V1 as u64 + 1).to_be_bytes());
    assert_eq!(
        decode_frame_v1(&oversized),
        Err(AgentProtocolError::InvalidLength)
    );
}

#[test]
fn maximum_size_content_crosses_one_sealed_descriptor_not_a_large_datagram() {
    let content = vec![0xa5; MAX_AGENT_SEALED_SPEC_BYTES_V1];
    let reference = reference(&content);
    let frame = encode_frame_v1(&AgentFrameV1::SealedAuthorizeRequest(reference));
    let credential = SealedReadOnlyCredential::create(
        "agent-spec-maximum-test",
        &content,
        MAX_AGENT_SEALED_SPEC_BYTES_V1,
    )
    .unwrap();
    let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
    let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
    sender
        .send_with_descriptors(&frame, &[credential.as_fd()])
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let record = loop {
        match receiver.receive_with_optional_descriptor(512) {
            Ok(record) => break record,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                assert!(Instant::now() < deadline, "descriptor receive timed out");
                std::thread::yield_now();
            }
            Err(error) => panic!("descriptor receive failed: {error}"),
        }
    };
    let (received, _, mut descriptors) = record.into_parts();
    assert_eq!(
        decode_frame_v1(&received),
        Ok(AgentFrameV1::SealedAuthorizeRequest(reference))
    );
    assert_eq!(descriptors.len(), 1);
    let descriptor = descriptors.pop().unwrap();
    let actual_digest = SealedMemfdMapping::run(
        descriptor,
        reference.content_bytes(),
        MAX_AGENT_SEALED_SPEC_BYTES_V1 as u64,
        |bytes, _| ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
    )
    .unwrap();
    assert_eq!(actual_digest, reference.content_digest);
}
