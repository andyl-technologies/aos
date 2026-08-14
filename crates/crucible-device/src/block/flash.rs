//! Sparse, deterministic flash wear and cell-state continuation.
//!
//! The block adapter keeps flash behavior separate from logical durability:
//! writes first pass the flash program rules, while reads apply persistent cell
//! mutations accumulated by retention and read-disturb transitions. Healthy
//! pages and erase blocks allocate no state. Every sparse counter and changed
//! byte is checkpointed as part of [`BlockFaultState`](super::BlockFaultState).

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeviceError;

use super::{BlockFaultByteSpan, BlockOp, BlockRequest};

/// Maximum independently configured flash continuations on one block device.
pub const HARD_BLOCK_FLASH_RULES: usize = 65_536;
/// Maximum sparse page, erase-block, or changed-byte records on one device.
pub const HARD_BLOCK_FLASH_SPARSE_ENTRIES: usize = 4_194_304;

mod types;

pub use types::*;

impl BlockFlashState {
    /// Returns continuations in canonical contributor order.
    #[must_use]
    pub const fn continuations(&self) -> &BTreeMap<[u8; 32], BlockFlashContinuation> {
        &self.continuations
    }

    /// Registers immutable rules without consuming a media opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid geometry, duplicate contributors,
    /// conflicting reuse of a contributor identity, or hard state exhaustion.
    pub fn register_rules(
        &mut self,
        device_length: u64,
        rules: &[ResolvedBlockFlashRule],
    ) -> Result<(), DeviceError> {
        self.register(device_length, rules)
    }

    /// Resolves a program opportunity from previously registered contributors.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when a contributor is absent or repeated, or
    /// under the same conditions as [`Self::program`].
    pub fn program_registered(
        &mut self,
        request: &BlockRequest,
        now_nanos: u64,
        device_length: u64,
        contributors: &[[u8; 32]],
    ) -> Result<BlockFlashMutationOutcome, DeviceError> {
        if contributors.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid("flash contributors are not in canonical order"));
        }
        let rules = contributors
            .iter()
            .map(|contributor| {
                self.continuations
                    .get(contributor)
                    .map(|continuation| continuation.rule.clone())
                    .ok_or_else(|| invalid("flash contributor is not registered"))
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        self.program(request, now_nanos, device_length, &rules)
    }

    /// Validates checkpointed keys, immutable rules, and sparse-state bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for a key mismatch, invalid rule, out-of-range
    /// sparse identity, zero XOR mask, or exceeded hard state ceiling.
    pub fn validate_restore(&self, device_length: u64) -> Result<(), DeviceError> {
        if self.continuations.len() > HARD_BLOCK_FLASH_RULES {
            return Err(limit("flash_rules", HARD_BLOCK_FLASH_RULES));
        }
        for (contributor, continuation) in &self.continuations {
            continuation.rule.validate(device_length)?;
            if contributor != &continuation.rule.contributor
                || continuation.erase_blocks.len() > HARD_BLOCK_FLASH_SPARSE_ENTRIES
                || continuation.pages.len() > HARD_BLOCK_FLASH_SPARSE_ENTRIES
                || continuation.changed_bytes.len() > HARD_BLOCK_FLASH_SPARSE_ENTRIES
                || continuation.erase_decisions.len() > HARD_BLOCK_FLASH_SPARSE_ENTRIES
                || continuation.erase_blocks.keys().any(|ordinal| {
                    ordinal
                        .checked_mul(continuation.rule.erase_block_bytes)
                        .is_none_or(|start| start >= device_length)
                })
                || continuation.pages.keys().any(|ordinal| {
                    ordinal
                        .checked_mul(continuation.rule.program_page_bytes)
                        .is_none_or(|start| start >= device_length)
                })
                || continuation
                    .changed_bytes
                    .iter()
                    .any(|(offset, mask)| *offset >= device_length || *mask == 0)
                || continuation
                    .erase_decisions
                    .iter()
                    .any(|((_operation, block), decision)| {
                        block
                            .checked_mul(continuation.rule.erase_block_bytes)
                            .is_none_or(|start| start >= device_length)
                            || decision.applied_prefix_bytes > continuation.rule.erase_block_bytes
                    })
            {
                return Err(invalid("invalid restored flash continuation"));
            }
        }
        Ok(())
    }

    /// Resolves program failure and advances sparse program state transactionally.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for malformed rules, conflicting contributor
    /// reuse, unaligned writes, overflow, or sparse-state exhaustion.
    pub fn program(
        &mut self,
        request: &BlockRequest,
        now_nanos: u64,
        device_length: u64,
        rules: &[ResolvedBlockFlashRule],
    ) -> Result<BlockFlashMutationOutcome, DeviceError> {
        if request.op != BlockOp::Write || request.count == 0 {
            return Err(invalid("flash program requires a nonempty write"));
        }
        self.register(device_length, rules)?;
        let mut next = self.clone();
        let mut selected_end = u64::from(request.count);
        let mut failed = false;
        for rule in rules {
            let continuation = next
                .continuations
                .get_mut(&rule.contributor)
                .ok_or_else(|| invalid("registered flash rule disappeared"))?;
            let request_end = request
                .offset
                .checked_add(u64::from(request.count))
                .ok_or_else(|| invalid("flash program range overflow"))?;
            let first_page = request.offset / rule.program_page_bytes;
            let last_page = request_end.saturating_sub(1) / rule.program_page_bytes;
            for page in first_page..=last_page {
                let erase_block =
                    page.saturating_mul(rule.program_page_bytes) / rule.erase_block_bytes;
                let erase_count = continuation
                    .erase_blocks
                    .get(&erase_block)
                    .map_or(0, |state| state.erase_count);
                let probability = if erase_count >= rule.endurance_cycles {
                    rule.program_erase.worn_probability_millionths
                } else {
                    rule.program_erase.program_probability_millionths
                };
                let transition = continuation.transition_sequence;
                continuation.transition_sequence = transition
                    .checked_add(1)
                    .ok_or_else(|| invalid("flash transition sequence overflow"))?;
                if chosen(rule, b"program", page, transition, 0, probability) {
                    failed = true;
                    let absolute_page_start = page.saturating_mul(rule.program_page_bytes);
                    let selected_start = absolute_page_start.max(request.offset);
                    let selected_length = absolute_page_start
                        .saturating_add(rule.program_page_bytes)
                        .min(request_end)
                        .saturating_sub(selected_start);
                    let relative_start = selected_start.saturating_sub(request.offset);
                    selected_end = selected_end.min(if rule.program_erase.partial_program {
                        let prefix = keyed_nonempty_prefix(
                            rule,
                            b"partial-program",
                            page,
                            transition,
                            selected_length,
                        );
                        relative_start.saturating_add(prefix)
                    } else {
                        relative_start
                    });
                    break;
                }
            }
        }
        for rule in rules {
            let continuation = next
                .continuations
                .get_mut(&rule.contributor)
                .ok_or_else(|| invalid("registered flash rule disappeared"))?;
            let programmed_end = request.offset.saturating_add(selected_end);
            if programmed_end == request.offset {
                continue;
            }
            let first_page = request.offset / rule.program_page_bytes;
            let last_page = programmed_end.saturating_sub(1) / rule.program_page_bytes;
            for page in first_page..=last_page {
                insert_page(continuation, page, now_nanos)?;
                let page_start = page.saturating_mul(rule.program_page_bytes);
                let clear_start = page_start.max(request.offset);
                let clear_end = page_start
                    .saturating_add(rule.program_page_bytes)
                    .min(programmed_end);
                clear_changed_range(
                    continuation,
                    clear_start,
                    clear_end.saturating_sub(clear_start),
                );
            }
        }
        let spans = (selected_end != 0)
            .then_some(BlockFaultByteSpan {
                start: 0,
                length: selected_end,
            })
            .into_iter()
            .collect();
        *self = next;
        Ok(BlockFlashMutationOutcome { spans, failed })
    }

    /// Resolves one physical erase fragment with request-wide frozen decisions.
    ///
    /// Every complete discard must be erase-block aligned for every active rule.
    /// The first fragment reaching a block freezes its success or partial-prefix
    /// decision and increments wear exactly once; later fragments reuse it even
    /// across checkpoint/restore. The last request fragment releases only the
    /// temporary decisions, retaining wear and changed-cell state.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid geometry/ranges, noncanonical
    /// contributors, overflow, or sparse-state exhaustion.
    #[allow(
        clippy::too_many_arguments,
        reason = "a registered erase fragment authenticates independent request, fragment, time, geometry, and contributor inputs"
    )]
    pub fn erase_fragment_registered(
        &mut self,
        operation_sequence: u64,
        request_offset: u64,
        request_count: u32,
        fragment_offset: u64,
        fragment_bytes: &[u8],
        now_nanos: u64,
        device_length: u64,
        contributors: &[[u8; 32]],
    ) -> Result<BlockFlashMutationOutcome, DeviceError> {
        if contributors.windows(2).any(|pair| pair[0] >= pair[1]) || fragment_bytes.is_empty() {
            return Err(invalid("invalid flash erase contributors or fragment"));
        }
        let request_end = request_offset
            .checked_add(u64::from(request_count))
            .ok_or_else(|| invalid("flash erase request range overflow"))?;
        let fragment_end = fragment_offset
            .checked_add(
                u64::try_from(fragment_bytes.len())
                    .map_err(|_error| invalid("flash erase fragment length overflow"))?,
            )
            .ok_or_else(|| invalid("flash erase fragment range overflow"))?;
        if fragment_offset < request_offset
            || fragment_end > request_end
            || request_end > device_length
            || fragment_bytes.iter().any(|byte| *byte != 0xff)
        {
            return Err(invalid("flash erase fragment differs from its request"));
        }
        let mut next = self.clone();
        let mut selected = vec![true; fragment_bytes.len()];
        let mut failed = false;
        for contributor in contributors {
            let continuation = next
                .continuations
                .get_mut(contributor)
                .ok_or_else(|| invalid("flash erase contributor is not registered"))?;
            let rule = continuation.rule.clone();
            if !request_offset.is_multiple_of(rule.erase_block_bytes)
                || !u64::from(request_count).is_multiple_of(rule.erase_block_bytes)
            {
                return Err(invalid("flash erase request is not erase-block aligned"));
            }
            let first_block = fragment_offset / rule.erase_block_bytes;
            let last_block = fragment_end.saturating_sub(1) / rule.erase_block_bytes;
            for block in first_block..=last_block {
                let key = (operation_sequence, block);
                let decision = match continuation.erase_decisions.get(&key).copied() {
                    Some(decision) => decision,
                    None => {
                        if continuation.erase_decisions.len() == HARD_BLOCK_FLASH_SPARSE_ENTRIES
                            || (!continuation.erase_blocks.contains_key(&block)
                                && continuation.erase_blocks.len()
                                    == HARD_BLOCK_FLASH_SPARSE_ENTRIES)
                        {
                            return Err(limit(
                                "flash_erase_decisions",
                                HARD_BLOCK_FLASH_SPARSE_ENTRIES,
                            ));
                        }
                        let state = continuation.erase_blocks.entry(block).or_default();
                        let probability = if state.erase_count >= rule.endurance_cycles {
                            rule.program_erase.worn_probability_millionths
                        } else {
                            rule.program_erase.erase_probability_millionths
                        };
                        let transition = continuation.transition_sequence;
                        continuation.transition_sequence = transition
                            .checked_add(1)
                            .ok_or_else(|| invalid("flash transition sequence overflow"))?;
                        let attempt_failed =
                            chosen(&rule, b"erase", block, transition, 0, probability);
                        let applied_prefix_bytes = if !attempt_failed {
                            rule.erase_block_bytes
                        } else if rule.program_erase.partial_erase {
                            keyed_nonempty_prefix(
                                &rule,
                                b"partial-erase",
                                block,
                                transition,
                                rule.erase_block_bytes,
                            )
                        } else {
                            0
                        };
                        state.erase_count = state
                            .erase_count
                            .checked_add(1)
                            .ok_or_else(|| invalid("flash erase count overflow"))?;
                        state.last_erase_nanos = now_nanos;
                        let decision = BlockFlashEraseDecision {
                            applied_prefix_bytes,
                            failed: attempt_failed,
                        };
                        continuation.erase_decisions.insert(key, decision);
                        decision
                    }
                };
                failed |= decision.failed;
                let block_start = block.saturating_mul(rule.erase_block_bytes);
                let applied_end = block_start.saturating_add(decision.applied_prefix_bytes);
                for (index, keep) in selected.iter_mut().enumerate() {
                    let absolute =
                        fragment_offset.saturating_add(u64::try_from(index).unwrap_or(u64::MAX));
                    if absolute >= block_start
                        && absolute < block_start.saturating_add(rule.erase_block_bytes)
                        && absolute >= applied_end
                    {
                        *keep = false;
                    }
                }
            }
        }
        for contributor in contributors {
            let continuation = next
                .continuations
                .get_mut(contributor)
                .ok_or_else(|| invalid("flash erase contributor is not registered"))?;
            let page_bytes = continuation.rule.program_page_bytes;
            clear_selected_erase_state(continuation, fragment_offset, &selected, page_bytes);
        }
        let spans = selected_spans(&selected)?;
        if fragment_end == request_end {
            for continuation in next.continuations.values_mut() {
                continuation
                    .erase_decisions
                    .retain(|(operation, _block), _decision| *operation != operation_sequence);
            }
        }
        *self = next;
        Ok(BlockFlashMutationOutcome { spans, failed })
    }

    /// Applies persistent retention/read-disturb cell state to returned bytes.
    ///
    /// The method mutates only sparse flash continuation and `bytes`; callers
    /// stage both before committing the surrounding block request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for rule conflicts, range mismatch, arithmetic
    /// overflow, or sparse-state exhaustion.
    pub fn read(
        &mut self,
        request: &BlockRequest,
        now_nanos: u64,
        device_length: u64,
        rules: &[ResolvedBlockFlashRule],
        bytes: &mut [u8],
    ) -> Result<(), DeviceError> {
        if request.op != BlockOp::Read
            || bytes.len() != usize::try_from(request.count).unwrap_or(usize::MAX)
        {
            return Err(invalid("flash read bytes differ from the request"));
        }
        self.register(device_length, rules)?;
        let mut next = self.clone();
        for rule in rules {
            let continuation = next
                .continuations
                .get_mut(&rule.contributor)
                .ok_or_else(|| invalid("registered flash rule disappeared"))?;
            let request_end = request
                .offset
                .checked_add(u64::from(request.count))
                .ok_or_else(|| invalid("flash read range overflow"))?;
            if request_end > device_length {
                return Err(invalid("flash read exceeds device"));
            }
            let first_page = request.offset / rule.program_page_bytes;
            let last_page = request_end.saturating_sub(1) / rule.program_page_bytes;
            for page in first_page..=last_page {
                let (programmed_nanos, disturb_due) = {
                    let state = continuation.pages.entry(page).or_default();
                    state.reads_since_disturb = state
                        .reads_since_disturb
                        .checked_add(1)
                        .ok_or_else(|| invalid("flash read counter overflow"))?;
                    let disturb_due = state.reads_since_disturb >= rule.read_disturb.read_threshold;
                    if disturb_due {
                        state.reads_since_disturb = 0;
                    }
                    (state.programmed_nanos, disturb_due)
                };
                let erase_block =
                    page.saturating_mul(rule.program_page_bytes) / rule.erase_block_bytes;
                let erase_count = continuation
                    .erase_blocks
                    .get(&erase_block)
                    .map_or(0, |state| state.erase_count);
                let eligible_age = rule
                    .retention
                    .wear_age_nanos
                    .saturating_mul(erase_count)
                    .saturating_add(rule.retention.minimum_age_nanos);
                if now_nanos.saturating_sub(programmed_nanos) >= eligible_age {
                    mutate_page(
                        continuation,
                        rule,
                        b"retention",
                        page,
                        rule.retention.bit_probability_millionths,
                        rule.retention.maximum_changed_bits,
                    )?;
                }
                if disturb_due {
                    let distance = u64::from(rule.read_disturb.neighbor_pages);
                    let start = page.saturating_sub(distance);
                    let end = page.saturating_add(distance);
                    for neighbor in start..=end {
                        if neighbor != page
                            && neighbor
                                .checked_mul(rule.program_page_bytes)
                                .is_some_and(|offset| offset < device_length)
                        {
                            mutate_page(
                                continuation,
                                rule,
                                b"read-disturb",
                                neighbor,
                                rule.read_disturb.bit_probability_millionths,
                                rule.read_disturb.maximum_changed_bits,
                            )?;
                        }
                    }
                }
            }
        }
        *self = next;
        Ok(())
    }

    /// Applies every previously materialized physical cell mutation to a read.
    ///
    /// This remains active when no flash effect is currently selected: removing
    /// a signal contribution stops new retention/disturb transitions but cannot
    /// heal physical cells that already changed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the read range overflows the device width.
    pub fn apply_persistent_read(
        &self,
        request_offset: u64,
        bytes: &mut [u8],
    ) -> Result<(), DeviceError> {
        for continuation in self.continuations.values() {
            apply_changed_bytes(continuation, request_offset, bytes)?;
        }
        Ok(())
    }

    fn register(
        &mut self,
        device_length: u64,
        rules: &[ResolvedBlockFlashRule],
    ) -> Result<(), DeviceError> {
        let mut seen = BTreeSet::new();
        for rule in rules {
            rule.validate(device_length)?;
            if !seen.insert(rule.contributor) {
                return Err(invalid("duplicate flash contributor"));
            }
            match self.continuations.get(&rule.contributor) {
                Some(existing) if existing.rule != *rule => {
                    return Err(invalid("flash contributor changed immutable rule"));
                }
                Some(_) => {}
                None if self.continuations.len() == HARD_BLOCK_FLASH_RULES => {
                    return Err(limit("flash_rules", HARD_BLOCK_FLASH_RULES));
                }
                None => {
                    self.continuations.insert(
                        rule.contributor,
                        BlockFlashContinuation {
                            rule: rule.clone(),
                            erase_blocks: BTreeMap::new(),
                            pages: BTreeMap::new(),
                            changed_bytes: BTreeMap::new(),
                            erase_decisions: BTreeMap::new(),
                            transition_sequence: 0,
                        },
                    );
                }
            }
        }
        Ok(())
    }
}

mod helpers;

use helpers::*;

#[cfg(test)]
#[path = "flash_test.rs"]
mod tests;
