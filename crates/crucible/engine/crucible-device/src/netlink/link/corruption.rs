//! Deterministic link-payload corruption from recorded bit draws.

use super::*;

pub(super) fn corrupt_link_payload(faults: &LinkFaults, payload: &mut Vec<u8>, bit_draws: &[u64]) {
    let mut draw_offset = 0usize;
    for strategy in &faults.corruption_strategies {
        match *strategy {
            LinkCorruptionStrategy::BitFlip { max_bits } => {
                let count = max_bits as usize;
                let end = draw_offset.saturating_add(count).min(bit_draws.len());
                corrupt_payload(payload, &bit_draws[draw_offset..end], max_bits);
                draw_offset = draw_offset.saturating_add(count);
            }
            LinkCorruptionStrategy::FieldMutation => {
                let draw = bit_draws.get(draw_offset).copied().unwrap_or(0);
                draw_offset = draw_offset.saturating_add(1);
                if !payload.is_empty() {
                    let index = (draw % payload.len() as u64) as usize;
                    payload[index] ^= 0x80;
                }
            }
            LinkCorruptionStrategy::Truncation { max_bytes } => {
                let draw = bit_draws.get(draw_offset).copied().unwrap_or(0);
                draw_offset = draw_offset.saturating_add(1);
                let limit = usize::try_from(max_bytes)
                    .unwrap_or(usize::MAX)
                    .min(payload.len());
                if limit != 0 {
                    let remove = (draw % limit as u64) as usize + 1;
                    payload.truncate(payload.len().saturating_sub(remove));
                }
            }
        }
    }
}
