//! Sizes advertised hybrid batches against their private Native replies.
//!
//! External placements carry complete read and write authority snapshots. A
//! small public Begin request can therefore produce a much larger private
//! reply. Discovery accounts for those snapshots before clients choose a wave.

use super::*;

// Leave room for the signed context and batch bookkeeping. The per-item
// allowance covers both copies of the bounded owner/path declaration, session
// identity, counters, and authorization fields. Placement snapshots and their
// public status projections are counted separately from actual resolved data.
const ENVELOPE_RESERVE_BYTES: usize = 32 * 1024;
const ITEM_METADATA_RESERVE_BYTES: usize = 8 * 1024;

// A later object's final key can contain a 1024-byte path with JSON escapes,
// whereas discovery resolves only a short probe path under the same prefix.
const PLACEMENT_PATH_RESERVE_BYTES: usize = 2 * 1024;

#[derive(Default)]
pub(super) struct ReplyBudget {
    placement_bytes: usize,
}

impl ReplyBudget {
    pub(super) fn include(&mut self, placement: &DirectPlacement, deployment: &str) -> Result<()> {
        let private_bytes = encode_direct_control(placement)?.len();
        let public_bytes = encode_direct_control(&placement.public_ref(deployment)?)?.len();
        self.placement_bytes = self
            .placement_bytes
            .checked_add(private_bytes)
            .and_then(|bytes| bytes.checked_add(public_bytes))
            .and_then(|bytes| bytes.checked_add(PLACEMENT_PATH_RESERVE_BYTES))
            .context("direct reply placement budget overflow")?;
        Ok(())
    }

    pub(super) fn maximum_items(&self) -> Result<u32> {
        let item_bytes = self
            .placement_bytes
            .checked_add(ITEM_METADATA_RESERVE_BYTES)
            .context("direct reply item budget overflow")?;
        let count = (MAX_DIRECT_CONTROL_BYTES - ENVELOPE_RESERVE_BYTES) / item_bytes;
        ensure!(count > 0, "direct placement reply exceeds control budget");
        Ok(count.min(MAX_DIRECT_BATCH_ITEMS) as u32)
    }
}
