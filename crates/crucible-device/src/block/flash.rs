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

/// A resolved retention transition policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedBlockFlashRetention {
    /// Minimum programmed age before a cell is eligible.
    pub minimum_age_nanos: u64,
    /// Extra eligible age added for each erase cycle.
    pub wear_age_nanos: u64,
    /// Per-bit probability in millionths.
    pub bit_probability_millionths: u32,
    /// Maximum changed bits in one page and opportunity.
    pub maximum_changed_bits: u32,
}

/// A resolved neighboring-page read-disturb policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedBlockFlashReadDisturb {
    /// Reads of an aggressor page required for one disturbance transition.
    pub read_threshold: u64,
    /// Symmetric neighboring-page distance.
    pub neighbor_pages: u32,
    /// Per-bit probability in millionths.
    pub bit_probability_millionths: u32,
    /// Maximum changed bits in each affected page and opportunity.
    pub maximum_changed_bits: u32,
}

/// A resolved program/erase failure policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedBlockFlashProgramErase {
    /// Program failure probability before rated endurance.
    pub program_probability_millionths: u32,
    /// Erase failure probability before rated endurance.
    pub erase_probability_millionths: u32,
    /// Program or erase failure probability at rated endurance.
    pub worn_probability_millionths: u32,
    /// Whether a failed program applies a canonical nonempty prefix.
    pub partial_program: bool,
    /// Whether a failed erase applies a canonical nonempty block prefix.
    pub partial_erase: bool,
}

/// One complete resolved flash-device contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBlockFlashRule {
    /// Stable resolved binding-action identity.
    pub contributor: [u8; 32],
    /// Scenario- and action-bound key for every physical choice.
    pub choice_key: [u8; 32],
    /// Erase-block size in bytes.
    pub erase_block_bytes: u64,
    /// Program-page size in bytes.
    pub program_page_bytes: u64,
    /// Rated erase cycles before the worn probability applies.
    pub endurance_cycles: u64,
    /// Retention transition policy.
    pub retention: ResolvedBlockFlashRetention,
    /// Read-disturb transition policy.
    pub read_disturb: ResolvedBlockFlashReadDisturb,
    /// Program and erase failure policy.
    pub program_erase: ResolvedBlockFlashProgramErase,
}

impl ResolvedBlockFlashRule {
    /// Validates geometry and bounded probability fields.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when geometry is zero, inconsistent with the
    /// device, or a probability exceeds one million millionths.
    pub fn validate(&self, device_length: u64) -> Result<(), DeviceError> {
        if self.erase_block_bytes == 0
            || self.program_page_bytes == 0
            || self.endurance_cycles == 0
            || self.erase_block_bytes % self.program_page_bytes != 0
            || device_length % self.erase_block_bytes != 0
            || self.retention.minimum_age_nanos == 0
            || self.read_disturb.read_threshold == 0
            || self.retention.maximum_changed_bits == 0
            || self.read_disturb.maximum_changed_bits == 0
            || self.retention.bit_probability_millionths > 1_000_000
            || self.read_disturb.bit_probability_millionths > 1_000_000
            || self.program_erase.program_probability_millionths > 1_000_000
            || self.program_erase.erase_probability_millionths > 1_000_000
            || self.program_erase.worn_probability_millionths > 1_000_000
        {
            return Err(invalid("invalid flash geometry or probability"));
        }
        Ok(())
    }
}

/// Sparse state for one touched erase block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockFlashEraseBlockState {
    /// Successful erase transitions applied to this block.
    pub erase_count: u64,
    /// Virtual time of the last successful erase.
    pub last_erase_nanos: u64,
}

/// Sparse state for one touched program page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockFlashPageState {
    /// Virtual time of the most recent successful program.
    pub programmed_nanos: u64,
    /// Reads since the most recent disturb threshold transition.
    pub reads_since_disturb: u64,
}

/// Checkpointed continuation for one flash rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFlashContinuation {
    /// Immutable rule authenticated whenever it is observed again.
    pub rule: ResolvedBlockFlashRule,
    /// Sparse erase-block counters keyed by block ordinal.
    pub erase_blocks: BTreeMap<u64, BlockFlashEraseBlockState>,
    /// Sparse program/read counters keyed by page ordinal.
    pub pages: BTreeMap<u64, BlockFlashPageState>,
    /// Persistent physical-cell XOR masks keyed by absolute byte offset.
    pub changed_bytes: BTreeMap<u64, u8>,
    /// Monotone physical transition sequence used in keyed choices.
    pub transition_sequence: u64,
}

/// Exact result of a flash program opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFlashProgramOutcome {
    /// Request-relative spans that physically programmed.
    pub spans: Vec<BlockFaultByteSpan>,
    /// Whether the device reports a program failure after applying `spans`.
    pub failed: bool,
}

/// Canonical sparse flash state owned by one block device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockFlashState {
    continuations: BTreeMap<[u8; 32], BlockFlashContinuation>,
}

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
    ) -> Result<BlockFlashProgramOutcome, DeviceError> {
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
    ) -> Result<BlockFlashProgramOutcome, DeviceError> {
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
        Ok(BlockFlashProgramOutcome { spans, failed })
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
                            transition_sequence: 0,
                        },
                    );
                }
            }
        }
        Ok(())
    }
}

fn insert_page(
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

fn clear_changed_range(continuation: &mut BlockFlashContinuation, start: u64, length: u64) {
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

fn mutate_page(
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

fn apply_changed_bytes(
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

fn keyed_nonempty_prefix(
    rule: &ResolvedBlockFlashRule,
    domain: &[u8],
    page: u64,
    transition: u64,
    length: u64,
) -> u64 {
    keyed_word(rule, domain, page, transition, 0) % length + 1
}

fn chosen(
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

fn keyed_word(
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

fn invalid(reason: &'static str) -> DeviceError {
    DeviceError::InvalidBlockFaultDirective { reason }
}

fn limit(field: &'static str, hard: usize) -> DeviceError {
    DeviceError::BlockFaultStateLimit { field, hard }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> ResolvedBlockFlashRule {
        ResolvedBlockFlashRule {
            contributor: [1; 32],
            choice_key: [2; 32],
            erase_block_bytes: 4096,
            program_page_bytes: 512,
            endurance_cycles: 10,
            retention: ResolvedBlockFlashRetention {
                minimum_age_nanos: 10,
                wear_age_nanos: 0,
                bit_probability_millionths: 1_000_000,
                maximum_changed_bits: 1,
            },
            read_disturb: ResolvedBlockFlashReadDisturb {
                read_threshold: 2,
                neighbor_pages: 1,
                bit_probability_millionths: 1_000_000,
                maximum_changed_bits: 1,
            },
            program_erase: ResolvedBlockFlashProgramErase {
                program_probability_millionths: 0,
                erase_probability_millionths: 0,
                worn_probability_millionths: 0,
                partial_program: false,
                partial_erase: false,
            },
        }
    }

    #[test]
    fn retention_and_disturb_are_sparse_persistent_and_restorable() {
        let mut state = BlockFlashState::default();
        let write = BlockRequest::write(1, 512, vec![0; 512]);
        let programmed = state
            .program(&write, 5, 8192, &[rule()])
            .unwrap_or_else(|error| panic!("program should succeed: {error}"));
        assert!(!programmed.failed);

        let read = BlockRequest::read(2, 512, 512);
        let mut first = vec![0; 512];
        state
            .read(&read, 15, 8192, &[rule()], &mut first)
            .unwrap_or_else(|error| panic!("retention read should succeed: {error}"));
        state
            .apply_persistent_read(read.offset, &mut first)
            .unwrap_or_else(|error| panic!("cell changes should apply: {error}"));
        assert_ne!(first, vec![0; 512]);

        let checkpoint = state.clone();
        checkpoint
            .validate_restore(8192)
            .unwrap_or_else(|error| panic!("checkpoint should validate: {error}"));
        let mut second = vec![0; 512];
        state
            .read(&read, 15, 8192, &[rule()], &mut second)
            .unwrap_or_else(|error| panic!("disturb read should succeed: {error}"));
        assert_ne!(state, checkpoint);
    }

    #[test]
    fn failed_program_applies_only_the_keyed_prefix() {
        let mut failing = rule();
        failing.program_erase.program_probability_millionths = 1_000_000;
        failing.program_erase.partial_program = true;
        let mut state = BlockFlashState::default();
        let request = BlockRequest::write(3, 0, vec![0; 512]);
        let outcome = state
            .program(&request, 0, 8192, &[failing])
            .unwrap_or_else(|error| panic!("program resolution should succeed: {error}"));
        assert!(outcome.failed);
        assert_eq!(outcome.spans.len(), 1);
        assert!(outcome.spans[0].length > 0 && outcome.spans[0].length <= 512);
    }
}
