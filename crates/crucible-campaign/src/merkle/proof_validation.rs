//! Bounded Merkle proof decoding and validation.

use super::*;

#[cfg(test)]
mod child_table_tests;

mod node_body;

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
    // Envelope framing and canonical authentication are temporary. Keep their
    // loans under the same original authority until the envelope closes,
    // without accumulating them in the returned node's owning account.
    let envelope_budget =
        crucible_cas::owned_decode::current_child_budget().map_err(CampaignCodecError::from)?;
    let envelope = {
        let _scope = envelope_budget.as_ref().map(|budget| budget.enter());
        let envelope = ObjectEnvelope::from_canonical_bytes_for_owner(bytes)?;
        let authenticated_id = envelope.content_id();
        if let Some(budget) = &envelope_budget {
            budget.check().map_err(CampaignCodecError::from)?;
        }
        if envelope.record_kind() != CampaignRecordKind::MerkleNode
            || authenticated_id != content_id
        {
            return Err(invalid("node-envelope-kind-or-identity"));
        }
        envelope
    };
    // The returned map entries remain charged to the original outer account.
    let node = node_body::decode(envelope.body())?;
    node.validate()?;
    if node.depth != expected_depth {
        return Err(invalid("node-depth-mismatch"));
    }
    {
        let _scope = envelope_budget.as_ref().map(|budget| budget.enter());
        if !child_table_matches(&node, envelope.children()) {
            return Err(invalid("node-child-table-mismatch"));
        }
    }
    Ok(node)
}

/// Compares validated entries with the authenticated table without rebuilding it.
fn child_table_matches(node: &MerkleNode, children: &BTreeSet<ChildReference>) -> bool {
    if node.entries.len() != children.len() {
        return false;
    }

    // validate() has already bounded every slot to one hexadecimal nibble.
    // Zero-padded slot roles have the same order as the entry map; every
    // generated role is a valid identifier, so no role constructor can refuse.
    node.entries
        .iter()
        .zip(children)
        .all(|((slot, entry), child)| {
            let Some(hex) = b"0123456789abcdef".get(usize::from(*slot)) else {
                return false;
            };
            let prefix = [b's', b'l', b'o', b't', b'.', b'0', *hex, b'.'];
            let (suffix, id): (&[u8], ContentId) = match entry {
                MerkleEntry::Leaf { value, .. } => (b"value", *value),
                MerkleEntry::Node { content_id, .. } => (b"node", *content_id),
            };
            child.role().as_bytes().strip_prefix(&prefix) == Some(suffix) && child.id() == id
        })
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
        // Each borrowed proof node is authenticated independently; no envelope
        // or canonical scratch escapes into the caller's retained proof table.
        let authentication_budget =
            crucible_cas::owned_decode::current_child_budget().map_err(CampaignCodecError::from)?;
        let _scope = authentication_budget.as_ref().map(|budget| budget.enter());
        let envelope = ObjectEnvelope::from_canonical_bytes_for_owner(node)?;
        let authenticated_id = envelope.content_id();
        if let Some(budget) = &authentication_budget {
            budget.check().map_err(CampaignCodecError::from)?;
        }
        if envelope.record_kind() != CampaignRecordKind::MerkleNode || authenticated_id != *id {
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
