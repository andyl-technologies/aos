//! Stateful block-media range overlays and activation thresholds.
//!
//! Signal evaluation resolves authored media effects into exact rules before a
//! request reaches this module. The device then owns the access counters and
//! activation decision so retries, checkpoint/restore, and locked replay see
//! the same physical-media continuation. Counters advance only for requests
//! that reach the media stage and intersect the selected range.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeviceError;

use super::{BlockErrorCode, BlockOp, BlockRequest};

/// Hard maximum independently stateful media-range contributors per device.
pub const HARD_BLOCK_MEDIA_RULES: usize = 1_048_576;

/// Closed physical-media state applied to one logical byte range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockMediaRangeState {
    /// Applicable accesses fail immediately after activation.
    Bad,
    /// Applicable accesses fail only after the declared thresholds activate.
    Latent,
    /// Reads report uncorrectable integrity failure after activation.
    Poisoned,
    /// Writes report a read-only medium after activation.
    ReadOnly,
}

/// One fully resolved stateful media-range contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBlockMediaRule {
    /// Stable resolved binding-action identity.
    pub contributor: [u8; 32],
    /// First absolute device byte selected by the rule.
    pub start: u64,
    /// Positive selected byte length.
    pub length: u64,
    /// Physical-media state produced after activation.
    pub state: BlockMediaRangeState,
    /// Canonical nonempty operation set.
    pub operations: Vec<BlockOp>,
    /// Access count at which a latent rule becomes active.
    pub count_threshold: Option<u64>,
    /// Virtual nanosecond at which a latent rule becomes active.
    pub time_threshold_nanos: Option<u64>,
}

impl ResolvedBlockMediaRule {
    /// Validates immutable rule geometry and canonical operation ownership.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for an empty or overflowing range, an empty,
    /// repeated, or non-canonical operation set, or thresholds on a non-latent
    /// state.
    pub fn validate(&self, device_length: u64) -> Result<(), DeviceError> {
        let end = self.start.checked_add(self.length).ok_or_else(invalid)?;
        let operation_order = |operation: BlockOp| match operation {
            BlockOp::Read => 0,
            BlockOp::Write => 1,
            BlockOp::Flush => 2,
            BlockOp::GetLength => 3,
        };
        if self.length == 0
            || end > device_length
            || self.operations.is_empty()
            || self
                .operations
                .windows(2)
                .any(|pair| operation_order(pair[0]) >= operation_order(pair[1]))
            || self.count_threshold == Some(0)
            || self.time_threshold_nanos == Some(0)
            || (self.state != BlockMediaRangeState::Latent
                && (self.count_threshold.is_some() || self.time_threshold_nanos.is_some()))
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn applies_to(&self, request: &BlockRequest) -> bool {
        if !self.operations.contains(&request.op) {
            return false;
        }
        match request.op {
            BlockOp::Read | BlockOp::Write => {
                let Some(request_end) = request.offset.checked_add(u64::from(request.count)) else {
                    return false;
                };
                let Some(rule_end) = self.start.checked_add(self.length) else {
                    return false;
                };
                request.offset < rule_end && self.start < request_end
            }
            BlockOp::Flush | BlockOp::GetLength => true,
        }
    }
}

/// Checkpointed continuation of one media-range contributor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockMediaRuleContinuation {
    /// Immutable resolved rule authenticated on every subsequent use.
    pub rule: ResolvedBlockMediaRule,
    /// Number of selected requests that reached the media stage.
    pub access_count: u64,
}

/// Canonical checkpointed media overlay and threshold counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockMediaState {
    rules: BTreeMap<[u8; 32], BlockMediaRuleContinuation>,
}

impl BlockMediaState {
    /// Returns continuations in stable contributor order.
    #[must_use]
    pub const fn rules(&self) -> &BTreeMap<[u8; 32], BlockMediaRuleContinuation> {
        &self.rules
    }

    /// Returns a canonical digest of all media-rule state.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.block-media-state.v1\0");
        for (contributor, continuation) in &self.rules {
            let rule = &continuation.rule;
            hasher.update(contributor);
            hasher.update(&rule.start.to_be_bytes());
            hasher.update(&rule.length.to_be_bytes());
            hasher.update(&[state_tag(rule.state)]);
            hasher.update(&continuation.access_count.to_be_bytes());
            hash_optional(&mut hasher, rule.count_threshold);
            hash_optional(&mut hasher, rule.time_threshold_nanos);
            for operation in &rule.operations {
                hasher.update(&[operation_tag(*operation)]);
            }
            hasher.update(&[0xff]);
        }
        *hasher.finalize().as_bytes()
    }

    /// Validates checkpointed bounds, keys, geometry, and counter reachability.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when restored state is too large or contains a
    /// rule whose contributor key or geometry is malformed.
    pub fn validate_restore(&self, device_length: u64) -> Result<(), DeviceError> {
        if self.rules.len() > HARD_BLOCK_MEDIA_RULES {
            return Err(invalid());
        }
        for (contributor, continuation) in &self.rules {
            continuation.rule.validate(device_length)?;
            if contributor != &continuation.rule.contributor {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Applies the complete resolved overlay at one media opportunity.
    ///
    /// The update is transactional. Every rule is validated and contributor
    /// identity conflict is detected before access counters change. Applicable
    /// contributors all advance even when a more severe contributor determines
    /// the returned result.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid rules, contributor identity reuse,
    /// hard state exhaustion, or access-counter overflow.
    pub fn apply(
        &mut self,
        request: &BlockRequest,
        now_nanos: u64,
        device_length: u64,
        resolved: &[ResolvedBlockMediaRule],
    ) -> Result<Option<BlockErrorCode>, DeviceError> {
        let mut seen = BTreeSet::new();
        for rule in resolved {
            rule.validate(device_length)?;
            if !seen.insert(rule.contributor) {
                return Err(invalid());
            }
            if let Some(existing) = self.rules.get(&rule.contributor) {
                if existing.rule != *rule {
                    return Err(invalid());
                }
            } else if self.rules.len() == HARD_BLOCK_MEDIA_RULES {
                return Err(DeviceError::BlockFaultStateLimit {
                    field: "media_rules",
                    hard: HARD_BLOCK_MEDIA_RULES,
                });
            }
        }

        let mut next = self.clone();
        let mut result = None;
        for rule in resolved {
            let continuation =
                next.rules
                    .entry(rule.contributor)
                    .or_insert_with(|| BlockMediaRuleContinuation {
                        rule: rule.clone(),
                        access_count: 0,
                    });
            if !rule.applies_to(request) {
                continue;
            }
            continuation.access_count = continuation
                .access_count
                .checked_add(1)
                .ok_or_else(invalid)?;
            if rule_active(rule, continuation.access_count, now_nanos) {
                result = most_severe(result, outcome(rule.state, request.op));
            }
        }
        *self = next;
        Ok(result)
    }
}

fn rule_active(rule: &ResolvedBlockMediaRule, access_count: u64, now_nanos: u64) -> bool {
    rule.state != BlockMediaRangeState::Latent
        || (rule
            .count_threshold
            .is_none_or(|threshold| access_count >= threshold)
            && rule
                .time_threshold_nanos
                .is_none_or(|threshold| now_nanos >= threshold))
}

fn outcome(state: BlockMediaRangeState, operation: BlockOp) -> Option<BlockErrorCode> {
    match (state, operation) {
        (BlockMediaRangeState::Bad | BlockMediaRangeState::Latent, _) => {
            Some(BlockErrorCode::MediumError)
        }
        (BlockMediaRangeState::Poisoned, BlockOp::Read) => Some(BlockErrorCode::IntegrityError),
        (BlockMediaRangeState::ReadOnly, BlockOp::Write) => Some(BlockErrorCode::ReadOnly),
        (BlockMediaRangeState::Poisoned | BlockMediaRangeState::ReadOnly, _) => None,
    }
}

fn most_severe(
    left: Option<BlockErrorCode>,
    right: Option<BlockErrorCode>,
) -> Option<BlockErrorCode> {
    let severity = |result: BlockErrorCode| match result {
        BlockErrorCode::ReadOnly => 1,
        BlockErrorCode::MediumError => 2,
        BlockErrorCode::IntegrityError => 3,
        _ => 0,
    };
    match (left, right) {
        (Some(left), Some(right)) if severity(left) >= severity(right) => Some(left),
        (Some(_), Some(right)) => Some(right),
        (Some(left), None) => Some(left),
        (None, right) => right,
    }
}

fn hash_optional(hasher: &mut blake3::Hasher, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&value.to_be_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

const fn operation_tag(operation: BlockOp) -> u8 {
    match operation {
        BlockOp::Read => 1,
        BlockOp::Write => 2,
        BlockOp::Flush => 3,
        BlockOp::GetLength => 4,
    }
}

const fn state_tag(state: BlockMediaRangeState) -> u8 {
    match state {
        BlockMediaRangeState::Bad => 1,
        BlockMediaRangeState::Latent => 2,
        BlockMediaRangeState::Poisoned => 3,
        BlockMediaRangeState::ReadOnly => 4,
    }
}

fn invalid() -> DeviceError {
    DeviceError::InvalidBlockFaultDirective {
        reason: "invalid stateful block-media rule",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(state: BlockMediaRangeState) -> ResolvedBlockMediaRule {
        ResolvedBlockMediaRule {
            contributor: [7; 32],
            start: 512,
            length: 512,
            state,
            operations: vec![BlockOp::Read],
            count_threshold: None,
            time_threshold_nanos: None,
        }
    }

    #[test]
    fn latent_rule_counts_only_intersecting_media_opportunities() {
        let mut state = BlockMediaState::default();
        let mut latent = rule(BlockMediaRangeState::Latent);
        latent.count_threshold = Some(2);
        latent.time_threshold_nanos = Some(10);

        let outside = BlockRequest::read(1, 0, 512);
        assert_eq!(state.apply(&outside, 20, 4096, &[latent.clone()]), Ok(None));
        assert_eq!(state.rules()[&[7; 32]].access_count, 0);

        let selected = BlockRequest::read(2, 512, 512);
        assert_eq!(state.apply(&selected, 9, 4096, &[latent.clone()]), Ok(None));
        assert_eq!(
            state.apply(&selected, 10, 4096, &[latent]),
            Ok(Some(BlockErrorCode::MediumError))
        );
        assert_eq!(state.rules()[&[7; 32]].access_count, 2);
    }

    #[test]
    fn contributor_redefinition_is_atomic() {
        let mut state = BlockMediaState::default();
        let selected = BlockRequest::read(1, 512, 512);
        let original = rule(BlockMediaRangeState::Bad);
        assert_eq!(
            state.apply(&selected, 0, 4096, &[original]),
            Ok(Some(BlockErrorCode::MediumError))
        );
        let before = state.clone();
        let changed = rule(BlockMediaRangeState::Poisoned);
        assert!(state.apply(&selected, 0, 4096, &[changed]).is_err());
        assert_eq!(state, before);
    }

    #[test]
    fn overlapping_rules_advance_independently_and_compose_by_severity() {
        let mut state = BlockMediaState::default();
        let bad = rule(BlockMediaRangeState::Bad);
        let mut poisoned = rule(BlockMediaRangeState::Poisoned);
        poisoned.contributor = [8; 32];
        let selected = BlockRequest::read(1, 512, 512);
        assert_eq!(
            state.apply(&selected, 0, 4096, &[bad, poisoned]),
            Ok(Some(BlockErrorCode::IntegrityError))
        );
        assert_eq!(state.rules()[&[7; 32]].access_count, 1);
        assert_eq!(state.rules()[&[8; 32]].access_count, 1);
    }
}
