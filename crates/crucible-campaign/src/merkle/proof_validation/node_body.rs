//! Fixed Merkle body canonical verification against the still-owned input.
//!
//! Decoding and admission retain the ordinary codec's order. Canonical fields
//! compare directly with the borrowed body instead of owning a second image.

use super::*;

#[cfg(test)]
mod tests;

pub(super) fn decode(bytes: &[u8]) -> Result<MerkleNode, CampaignCodecError> {
    if bytes.len() > codec::MAX_CANONICAL_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "canonical-byte-count",
        });
    }
    let mut decoder = Decoder::new(bytes);
    let node = MerkleNode::decode(&mut decoder)?;
    decoder.finish()?;

    let canonical_budget = crucible_cas::owned_decode::current_child_budget()?;
    {
        let _scope = canonical_budget.as_ref().map(|budget| budget.enter());
        // Keep the same conservative image admission and all of its original
        // refusal cuts. Removing the actual Vec does not mint new entitlement.
        crucible_cas::owned_decode::charge_array::<u8>(bytes.len())?;
        let mut comparison = CanonicalComparison::new(bytes);
        comparison.node(&node);
        if let Some(budget) = &canonical_budget {
            budget.check()?;
        }
        if !comparison.matches() {
            return Err(CampaignCodecError::NonCanonical);
        }
    }
    if let Some(budget) = crucible_cas::owned_decode::current_budget() {
        budget.check()?;
    }
    Ok(node)
}

struct CanonicalComparison<'a> {
    remaining: &'a [u8],
    exceeded: bool,
    differs: bool,
}

impl<'a> CanonicalComparison<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            exceeded: false,
            differs: false,
        }
    }

    fn node(&mut self, node: &MerkleNode) {
        self.fixed(&node.schema_version.to_be_bytes());
        self.fixed(&[node.depth]);
        self.fixed(&node.entry_count.to_be_bytes());
        self.fixed(&(node.entries.len() as u64).to_be_bytes());
        for (slot, entry) in &node.entries {
            self.fixed(&[*slot]);
            match entry {
                MerkleEntry::Leaf { key, value } => {
                    self.fixed(&[0]);
                    self.fixed(&key.as_bytes());
                    self.content_id(*value);
                }
                MerkleEntry::Node {
                    content_id,
                    entry_count,
                } => {
                    self.fixed(&[1]);
                    self.content_id(*content_id);
                    self.fixed(&entry_count.to_be_bytes());
                }
            }
        }
    }

    fn content_id(&mut self, id: ContentId) {
        id.with_encoded_text(|text| {
            // The owning encoder charges this exact text before allocating.
            // Preserve that charge and its sticky empty-string failure path.
            let text = if crucible_cas::owned_decode::charge_array::<u8>(text.len()).is_ok() {
                text
            } else {
                &[]
            };
            self.fixed(&(text.len() as u64).to_be_bytes());
            self.fixed(text);
        });
    }

    fn fixed(&mut self, chunk: &[u8]) {
        if self.exceeded || chunk.len() > self.remaining.len() {
            self.exceeded = true;
            return;
        }
        self.differs |= !self.remaining.starts_with(chunk);
        self.remaining = &self.remaining[chunk.len()..];
    }

    fn matches(&self) -> bool {
        !self.exceeded && !self.differs && self.remaining.is_empty()
    }
}
