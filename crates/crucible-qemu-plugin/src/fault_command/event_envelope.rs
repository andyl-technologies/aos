//! Restorable QEMU node-event request and evidence envelopes.

use super::*;

pub(super) const NODE_EVENT_ENVELOPE_VERSION: c_int = 1;
const NODE_EVENT_ENVELOPE_MAGIC: &[u8; 8] = b"CRUCEVQ1";
const NODE_EVENT_ENVELOPE_HEADER_BYTES: usize = 192;

pub(super) fn node_event_envelope_maximum_bytes() -> Result<usize, FaultCommandBridgeError> {
    usize::try_from(HARD_FAULT_PAYLOAD_BYTES)
        .ok()
        .and_then(|length| length.checked_mul(2))
        .and_then(|length| length.checked_add(NODE_EVENT_ENVELOPE_HEADER_BYTES))
        .ok_or(FaultCommandBridgeError::EventEnvelope)
}

pub(super) struct NodeEventEnvelope<'a> {
    pub(super) request: &'a [u8],
    pub(super) evidence: &'a [u8],
}

#[cfg(test)]
pub(super) fn encode_test_node_event_envelope(
    request: &[u8],
    evidence: &[u8],
    event: &QemuFaultEvent,
    target_node_hash: [u8; 32],
) -> Vec<u8> {
    let mut envelope = vec![0; NODE_EVENT_ENVELOPE_HEADER_BYTES];
    envelope[..8].copy_from_slice(NODE_EVENT_ENVELOPE_MAGIC);
    envelope[8..10].copy_from_slice(&(NODE_EVENT_ENVELOPE_VERSION as u16).to_le_bytes());
    envelope[12..16].copy_from_slice(&(request.len() as u32).to_le_bytes());
    envelope[16..20].copy_from_slice(&(evidence.len() as u32).to_le_bytes());
    envelope[24..56].copy_from_slice(&sha2::Sha256::digest(request));
    envelope[56..88].copy_from_slice(&sha2::Sha256::digest(evidence));
    envelope[88..120].copy_from_slice(&event.binding_hash);
    envelope[120..128].copy_from_slice(&event.rule_command_sequence.to_le_bytes());
    envelope[128..160].copy_from_slice(&target_node_hash);
    envelope[160..192].copy_from_slice(&event.opportunity_hash);
    envelope.extend_from_slice(request);
    envelope.extend_from_slice(evidence);
    envelope
}

pub(super) fn decode_node_event_envelope<'a>(
    bytes: &'a [u8],
    event: &QemuFaultEvent,
    target_node_hash: [u8; 32],
) -> Result<NodeEventEnvelope<'a>, FaultCommandBridgeError> {
    let hard_limit = usize::try_from(HARD_FAULT_PAYLOAD_BYTES)
        .map_err(|_source| FaultCommandBridgeError::EventEnvelope)?;
    let maximum = node_event_envelope_maximum_bytes()?;
    if bytes.len() < NODE_EVENT_ENVELOPE_HEADER_BYTES
        || bytes.len() > maximum
        || bytes.get(..8) != Some(NODE_EVENT_ENVELOPE_MAGIC)
        || read_u16(bytes, 8)? != NODE_EVENT_ENVELOPE_VERSION as u16
        || read_u16(bytes, 10)? != 0
        || read_u32(bytes, 20)? != 0
    {
        return Err(FaultCommandBridgeError::EventEnvelope);
    }

    let request_length = usize::try_from(read_u32(bytes, 12)?)
        .map_err(|_source| FaultCommandBridgeError::EventEnvelope)?;
    let evidence_length = usize::try_from(read_u32(bytes, 16)?)
        .map_err(|_source| FaultCommandBridgeError::EventEnvelope)?;
    let request_end = NODE_EVENT_ENVELOPE_HEADER_BYTES
        .checked_add(request_length)
        .ok_or(FaultCommandBridgeError::EventEnvelope)?;
    let evidence_end = request_end
        .checked_add(evidence_length)
        .ok_or(FaultCommandBridgeError::EventEnvelope)?;
    if request_length == 0
        || request_length > hard_limit
        || evidence_length == 0
        || evidence_length > hard_limit
        || evidence_length != event.evidence_length as usize
        || evidence_end != bytes.len()
    {
        return Err(FaultCommandBridgeError::EventEnvelope);
    }

    let request = bytes
        .get(NODE_EVENT_ENVELOPE_HEADER_BYTES..request_end)
        .ok_or(FaultCommandBridgeError::EventEnvelope)?;
    let evidence = bytes
        .get(request_end..evidence_end)
        .ok_or(FaultCommandBridgeError::EventEnvelope)?;
    let decoded = NodeFaultPayloadV1::decode(request)
        .map_err(|_source| FaultCommandBridgeError::EventEnvelope)?;
    if bytes.get(24..56) != Some(sha2::Sha256::digest(request).as_slice())
        || bytes.get(56..88) != Some(sha2::Sha256::digest(evidence).as_slice())
        || bytes.get(88..120) != Some(event.binding_hash.as_slice())
        || read_u64(bytes, 120)? != event.rule_command_sequence
        || bytes.get(128..160) != Some(target_node_hash.as_slice())
        || (event.command_kind == FaultCommandKind::AcceleratorResultTransform as u16
            && bytes.get(160..192) != Some(event.opportunity_hash.as_slice()))
        || decoded.command_kind as u16 != event.command_kind
        || decoded.target_kind as u16 != event.target_kind
        || decoded.model_phase != event.model_phase
        || decoded.generation != event.generation
        || decoded.action_hash != event.action_hash
        || decoded.target_hash != event.target_hash
    {
        return Err(FaultCommandBridgeError::EventEnvelope);
    }

    Ok(NodeEventEnvelope { request, evidence })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FaultCommandBridgeError::EventEnvelope)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FaultCommandBridgeError::EventEnvelope)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(FaultCommandBridgeError::EventEnvelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_shmem::NodeFaultFieldV1;

    fn policy(json: &[u8]) -> Vec<u8> {
        let mut bytes = b"CRUCJSN1".to_vec();
        bytes.extend_from_slice(json);
        bytes
    }

    fn fixture() -> (Vec<u8>, QemuFaultEvent, [u8; 32]) {
        let target_node_hash = [9; 32];
        let request = NodeFaultPayloadV1 {
            command_kind: FaultCommandKind::CpuService,
            operation: NodeFaultOperationV1::Upsert,
            target_kind: NodeFaultTargetKindV1::Node,
            model_phase: 10,
            generation: 7,
            action_hash: [3; 32],
            target_hash: [4; 32],
            schema_hash: [5; 32],
            fields: vec![
                NodeFaultFieldV1::bytes(node_fault_field::P1, policy(b"[0]")),
                NodeFaultFieldV1::ratio(node_fault_field::P2, 1, 2),
                NodeFaultFieldV1::u64(node_fault_field::P3, 100),
                NodeFaultFieldV1::u32(node_fault_field::P4, 1),
            ],
        }
        .encode()
        .unwrap_or_else(|error| panic!("fixture request: {error}"));
        let evidence = b"authenticated occurrence";
        let event = QemuFaultEvent {
            command_kind: FaultCommandKind::CpuService as u16,
            outcome: FaultEventOutcomeV1::Applied as u16,
            model_phase: 10,
            target_kind: NodeFaultTargetKindV1::Node as u16,
            evidence_length: evidence.len() as u32,
            event_sequence: 8,
            rule_command_sequence: 6,
            observed_icount: 100,
            generation: 7,
            binding_hash: [2; 32],
            opportunity_hash: [8; 32],
            action_hash: [3; 32],
            target_hash: [4; 32],
            before_hash: [6; 32],
            after_hash: [7; 32],
        };
        let envelope =
            encode_test_node_event_envelope(&request, evidence, &event, target_node_hash);
        (envelope, event, target_node_hash)
    }

    #[test]
    fn mandatory_envelope_round_trips_and_rejects_raw_legacy_evidence() {
        let (envelope, event, target_node_hash) = fixture();
        let decoded = decode_node_event_envelope(&envelope, &event, target_node_hash)
            .unwrap_or_else(|error| panic!("valid envelope: {error}"));
        assert_eq!(decoded.evidence, b"authenticated occurrence");
        assert!(decode_node_event_envelope(decoded.evidence, &event, target_node_hash).is_err());
    }

    #[test]
    fn envelope_rejects_every_authenticated_identity_mismatch() {
        for offset in [24, 56, 88, 120, 128] {
            let (mut envelope, event, target_node_hash) = fixture();
            envelope[offset] ^= 1;
            assert!(decode_node_event_envelope(&envelope, &event, target_node_hash).is_err());
        }
        let (envelope, mut event, target_node_hash) = fixture();
        event.action_hash[0] ^= 1;
        assert!(decode_node_event_envelope(&envelope, &event, target_node_hash).is_err());
    }

    #[test]
    fn accelerator_envelope_binds_the_selected_opportunity() {
        let target_node_hash = [9; 32];
        let request = NodeFaultPayloadV1 {
            command_kind: FaultCommandKind::AcceleratorResultTransform,
            operation: NodeFaultOperationV1::Apply,
            target_kind: NodeFaultTargetKindV1::Accelerator,
            model_phase: 8,
            generation: 7,
            action_hash: [3; 32],
            target_hash: [4; 32],
            schema_hash: [5; 32],
            fields: vec![
                NodeFaultFieldV1::bytes(
                    node_fault_field::P1,
                    policy(
                        br#"{"job_kind":"matrix-multiply","occurrence":{"kind":"every"},"queue":null}"#,
                    ),
                ),
                NodeFaultFieldV1::bytes(
                    node_fault_field::P2,
                    policy(br#"{"mask":"01","offset":0,"value":"01"}"#),
                ),
                NodeFaultFieldV1::u64(node_fault_field::P3, 2),
                NodeFaultFieldV1::hash(node_fault_field::P4, [10; 32]),
                NodeFaultFieldV1::hash(node_fault_field::T1, [11; 32]),
            ],
        }
        .encode()
        .unwrap_or_else(|error| panic!("accelerator fixture request: {error}"));
        let event = QemuFaultEvent {
            command_kind: FaultCommandKind::AcceleratorResultTransform as u16,
            outcome: FaultEventOutcomeV1::Applied as u16,
            model_phase: 8,
            target_kind: NodeFaultTargetKindV1::Accelerator as u16,
            evidence_length: 1,
            event_sequence: 8,
            rule_command_sequence: 6,
            observed_icount: 100,
            generation: 7,
            binding_hash: [2; 32],
            opportunity_hash: [8; 32],
            action_hash: [3; 32],
            target_hash: [4; 32],
            before_hash: [6; 32],
            after_hash: [7; 32],
        };
        let mut encoded = encode_test_node_event_envelope(&request, &[1], &event, target_node_hash);
        assert!(decode_node_event_envelope(&encoded, &event, target_node_hash).is_ok());
        encoded[160] ^= 1;
        assert!(decode_node_event_envelope(&encoded, &event, target_node_hash).is_err());
    }
}
