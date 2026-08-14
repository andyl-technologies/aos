//! Sparse flash-state mutation helpers.

use super::*;

pub(super) fn insert_page(
    continuation: &mut BlockFlashContinuation,
    page: u64,
    now_nanos: u64,
) -> Result<(), DeviceError> {
    if !continuation.pages.contains_key(&page)
        && continuation.pages.len() == HARD_BLOCK_FLASH_SPARSE_ENTRIES
    {
        return Err(limit("flash_pages", HARD_BLOCK_FLASH_SPARSE_ENTRIES));
    }
    continuation.pages.insert(
        page,
        BlockFlashPageState {
            programmed_nanos: now_nanos,
            reads_since_disturb: 0,
        },
    );
    Ok(())
}

pub(super) fn clear_changed_range(
    continuation: &mut BlockFlashContinuation,
    start: u64,
    length: u64,
) {
    let end = start.saturating_add(length);
    let selected = continuation
        .changed_bytes
        .range(start..end)
        .map(|(offset, _mask)| *offset)
        .collect::<Vec<_>>();
    for offset in selected {
        continuation.changed_bytes.remove(&offset);
    }
}

pub(super) fn clear_selected_erase_state(
    continuation: &mut BlockFlashContinuation,
    fragment_offset: u64,
    selected: &[bool],
    page_bytes: u64,
) {
    for (index, selected) in selected.iter().copied().enumerate() {
        if selected {
            continuation
                .changed_bytes
                .remove(&fragment_offset.saturating_add(u64::try_from(index).unwrap_or(u64::MAX)));
        }
    }
    let fragment_end = fragment_offset.saturating_add(u64::try_from(selected.len()).unwrap_or(0));
    if fragment_end == fragment_offset {
        return;
    }
    let first_page = fragment_offset / page_bytes;
    let last_page = fragment_end.saturating_sub(1) / page_bytes;
    for page in first_page..=last_page {
        let page_start = page.saturating_mul(page_bytes);
        let page_end = page_start.saturating_add(page_bytes);
        if page_start >= fragment_offset
            && page_end <= fragment_end
            && (page_start..page_end).all(|offset| {
                usize::try_from(offset - fragment_offset)
                    .ok()
                    .and_then(|index| selected.get(index))
                    .copied()
                    .unwrap_or(false)
            })
        {
            continuation.pages.remove(&page);
        }
    }
}

pub(super) fn selected_spans(selected: &[bool]) -> Result<Vec<BlockFaultByteSpan>, DeviceError> {
    let mut spans = Vec::new();
    let mut index = 0_usize;
    while index < selected.len() {
        if !selected[index] {
            index += 1;
            continue;
        }
        let start = index;
        while index < selected.len() && selected[index] {
            index += 1;
        }
        spans.push(BlockFaultByteSpan {
            start: u64::try_from(start)
                .map_err(|_error| invalid("flash erase span start overflow"))?,
            length: u64::try_from(index - start)
                .map_err(|_error| invalid("flash erase span length overflow"))?,
        });
    }
    Ok(spans)
}

pub(super) fn mutate_page(
    continuation: &mut BlockFlashContinuation,
    rule: &ResolvedBlockFlashRule,
    domain: &[u8],
    page: u64,
    probability: u32,
    maximum_changed_bits: u32,
) -> Result<(), DeviceError> {
    if probability == 0 || maximum_changed_bits == 0 {
        return Ok(());
    }
    let transition = continuation.transition_sequence;
    continuation.transition_sequence = transition
        .checked_add(1)
        .ok_or_else(|| invalid("flash transition sequence overflow"))?;
    let page_start = page
        .checked_mul(rule.program_page_bytes)
        .ok_or_else(|| invalid("flash page offset overflow"))?;
    let bit_count = rule
        .program_page_bytes
        .checked_mul(8)
        .ok_or_else(|| invalid("flash page bit count overflow"))?;
    let mut changed = 0_u32;
    for bit in 0..bit_count {
        if changed == maximum_changed_bits {
            break;
        }
        if !chosen(rule, domain, page, transition, bit, probability) {
            continue;
        }
        let offset = page_start.saturating_add(bit / 8);
        let mask = 1_u8 << u32::try_from(bit % 8).unwrap_or(0);
        if !continuation.changed_bytes.contains_key(&offset)
            && continuation.changed_bytes.len() == HARD_BLOCK_FLASH_SPARSE_ENTRIES
        {
            return Err(limit(
                "flash_changed_bytes",
                HARD_BLOCK_FLASH_SPARSE_ENTRIES,
            ));
        }
        let entry = continuation.changed_bytes.entry(offset).or_insert(0);
        *entry ^= mask;
        if *entry == 0 {
            continuation.changed_bytes.remove(&offset);
        }
        changed = changed.saturating_add(1);
    }
    Ok(())
}

pub(super) fn apply_changed_bytes(
    continuation: &BlockFlashContinuation,
    request_offset: u64,
    bytes: &mut [u8],
) -> Result<(), DeviceError> {
    let end = request_offset
        .checked_add(
            u64::try_from(bytes.len()).map_err(|_error| invalid("flash read length overflow"))?,
        )
        .ok_or_else(|| invalid("flash read range overflow"))?;
    for (offset, mask) in continuation.changed_bytes.range(request_offset..end) {
        let index = usize::try_from(*offset - request_offset)
            .map_err(|_error| invalid("flash changed-byte index overflow"))?;
        bytes[index] ^= mask;
    }
    Ok(())
}

pub(super) fn keyed_nonempty_prefix(
    rule: &ResolvedBlockFlashRule,
    domain: &[u8],
    page: u64,
    transition: u64,
    length: u64,
) -> u64 {
    keyed_word(rule, domain, page, transition, 0) % length + 1
}

pub(super) fn chosen(
    rule: &ResolvedBlockFlashRule,
    domain: &[u8],
    page: u64,
    transition: u64,
    item: u64,
    probability: u32,
) -> bool {
    probability >= 1_000_000
        || (probability != 0
            && keyed_word(rule, domain, page, transition, item) % 1_000_000
                < u64::from(probability))
}

pub(super) fn keyed_word(
    rule: &ResolvedBlockFlashRule,
    domain: &[u8],
    page: u64,
    transition: u64,
    item: u64,
) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.block-flash-choice.v1\0");
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&rule.choice_key);
    hasher.update(&rule.contributor);
    hasher.update(&page.to_be_bytes());
    hasher.update(&transition.to_be_bytes());
    hasher.update(&item.to_be_bytes());
    let digest = hasher.finalize();
    let mut word = [0_u8; 8];
    word.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(word)
}

pub(super) fn invalid(reason: &'static str) -> DeviceError {
    DeviceError::InvalidBlockFaultDirective { reason }
}

pub(super) fn limit(field: &'static str, hard: usize) -> DeviceError {
    DeviceError::BlockFaultStateLimit { field, hard }
}
