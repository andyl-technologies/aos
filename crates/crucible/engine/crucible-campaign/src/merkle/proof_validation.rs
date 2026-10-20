//! Bounded Merkle proof decoding and validation.

use super::*;

pub(super) fn finish_scan_page(
    mut entries: Vec<(CampaignHash, ContentId)>,
    limit: usize,
) -> MerkleMapPage {
    let has_more = entries.len() > limit;
    if has_more {
        entries.truncate(limit);
    }
    let next_after = has_more.then(|| entries[entries.len() - 1].0);
    MerkleMapPage {
        entries,
        next_after,
    }
}

pub(super) fn decode_node_bytes(
    content_id: ContentId,
    expected_depth: u8,
    bytes: &[u8],
) -> Result<MerkleNode, CampaignStoreError> {
    if content_id.kind() != ObjectKind::MerkleNode {
        return Err(invalid("root-or-child-kind"));
    }
    if bytes.len() > MAX_MERKLE_NODE_ENVELOPE_BYTES {
        return Err(invalid("merkle-node-envelope-byte-limit"));
    }
    let envelope = ObjectEnvelope::from_canonical_bytes_for_owner(bytes)?;
    if envelope.record_kind() != CampaignRecordKind::MerkleNode
        || envelope.content_id() != content_id
    {
        return Err(invalid("node-envelope-kind-or-identity"));
    }
    let node = codec::decode::<MerkleNode>(envelope.body())?;
    node.validate()?;
    if node.depth != expected_depth {
        return Err(invalid("node-depth-mismatch"));
    }
    if node.child_references()? != *envelope.children() {
        return Err(invalid("node-child-table-mismatch"));
    }
    Ok(node)
}

pub(super) fn validate_page_proof_nodes(
    nodes: &BTreeMap<ContentId, Vec<u8>>,
) -> Result<(), CampaignStoreError> {
    validate_proof_nodes(
        nodes,
        MAX_PAGE_PROOF_NODES,
        MAX_PAGE_PROOF_BYTES,
        "page-proof-node-limit",
        "page-proof-byte-limit",
    )
}

pub(super) fn validate_proof_nodes(
    nodes: &BTreeMap<ContentId, Vec<u8>>,
    maximum_nodes: usize,
    maximum_bytes: usize,
    node_limit_reason: &'static str,
    byte_limit_reason: &'static str,
) -> Result<(), CampaignStoreError> {
    if nodes.len() > maximum_nodes {
        return Err(invalid(node_limit_reason));
    }
    let mut bytes = 0_usize;
    for (id, node) in nodes {
        bytes = bytes
            .checked_add(node.len())
            .ok_or_else(|| invalid(byte_limit_reason))?;
        if bytes > maximum_bytes || node.len() > MAX_MERKLE_NODE_ENVELOPE_BYTES {
            return Err(invalid(byte_limit_reason));
        }
        let envelope = ObjectEnvelope::from_canonical_bytes_for_owner(node)?;
        if envelope.record_kind() != CampaignRecordKind::MerkleNode || envelope.content_id() != *id
        {
            return Err(invalid("page-proof-node-identity"));
        }
    }
    Ok(())
}

pub(super) struct ProofDecodeLimits {
    pub(super) maximum_nodes: usize,
    pub(super) maximum_bytes: usize,
    pub(super) count_limit: &'static str,
    pub(super) node_bytes_limit: &'static str,
    pub(super) total_bytes_limit: &'static str,
    pub(super) duplicate_reason: &'static str,
}

pub(super) fn decode_proof_nodes(
    decoder: &mut Decoder<'_>,
    limits: ProofDecodeLimits,
) -> Result<BTreeMap<ContentId, Vec<u8>>, CampaignCodecError> {
    let mut aggregate_bytes = 0_usize;
    let entries =
        decoder.sequence_bounded(limits.maximum_nodes, limits.count_limit, |decoder| {
            let id = ContentId::decode(decoder)?;
            let bytes = decoder.byte_sequence_bounded_charged(
                MAX_MERKLE_NODE_ENVELOPE_BYTES,
                limits.node_bytes_limit,
                &mut aggregate_bytes,
                limits.maximum_bytes,
                limits.total_bytes_limit,
            )?;
            Ok((id, bytes))
        })?;
    let mut nodes = BTreeMap::new();
    for (id, node) in entries {
        if nodes.insert(id, node).is_some() {
            return Err(CampaignCodecError::InvalidValue {
                reason: limits.duplicate_reason,
            });
        }
    }
    Ok(nodes)
}

pub(super) fn calculate_node_id(node: &MerkleNode) -> Result<ContentId, CampaignStoreError> {
    node.validate()?;
    let envelope = ObjectEnvelope::for_record(
        CampaignRecordKind::MerkleNode,
        node.child_references()?,
        codec::encode(node),
    )?;
    Ok(envelope.content_id())
}
