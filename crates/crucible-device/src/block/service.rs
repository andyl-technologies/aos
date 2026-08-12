//! Deterministic integrated byte/IOPS service for block request queues.
//!
//! Each persistent contributor owns an independent non-preemptive server. A
//! request must complete every contributing server, so simultaneous rate
//! limits compose as minimum available service. Busy-epoch accounting uses
//! cumulative integer work, avoiding per-request rounding drift.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeviceError;

use super::BlockOp;

/// Maximum independently checkpointed storage-service contributors.
pub const HARD_BLOCK_SERVICE_RULES: usize = 4_096;
/// Maximum requests retained by all storage-service queues.
pub const HARD_BLOCK_SERVICE_JOBS: usize = 1_048_576;

/// Queue selection discipline for one storage service contributor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockServiceDiscipline {
    /// Selects the earliest admitted request, then its stable sequence.
    Fifo,
    /// Selects the lowest numeric class priority, then admission order.
    StrictPriority,
    /// Serves each nonempty class for its declared request weight per round.
    WeightedRoundRobin,
}

/// One operation class in a storage service policy.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockServiceClass {
    /// Stable class identity used for canonical ordering.
    pub class: [u8; 32],
    /// Canonically wire-code-ordered operations assigned to this class.
    pub operations: Vec<BlockOp>,
    /// Lower values have higher strict-priority precedence.
    pub priority: u16,
    /// Requests served from this class in each weighted round.
    pub weight: u64,
}

/// Service rule sampled from one active binding at request admission.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockServiceRule {
    /// Binding/action-derived contributor identity.
    pub contributor: [u8; 32],
    /// Positive foreground byte service rate.
    pub bytes_per_second: u64,
    /// Optional positive foreground operation service rate.
    pub iops: Option<u64>,
    /// Maximum active plus queued requests for this contributor.
    pub queue_depth: u32,
    /// Non-preemptive queue selection discipline.
    pub discipline: BlockServiceDiscipline,
    /// Canonically class-ID-ordered, operation-disjoint classes.
    pub classes: Vec<ResolvedBlockServiceClass>,
    /// Whether array rebuild work consumes this same service budget.
    pub rebuild_shares_service: bool,
}

impl ResolvedBlockServiceRule {
    /// Validates rates, queue bounds, class order, and operation assignment.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when any field is zero/out of bounds, class IDs
    /// or operation codes are noncanonical, or an operation appears twice.
    pub fn validate(&self) -> Result<(), DeviceError> {
        if self.bytes_per_second == 0
            || self.iops == Some(0)
            || self.queue_depth == 0
            || usize::try_from(self.queue_depth).unwrap_or(usize::MAX) > HARD_BLOCK_SERVICE_JOBS
            || self
                .classes
                .windows(2)
                .any(|pair| pair[0].class >= pair[1].class)
            || (self.discipline != BlockServiceDiscipline::Fifo && self.classes.is_empty())
        {
            return Err(invalid("invalid block service rule"));
        }
        let mut operations = BTreeSet::new();
        for class in &self.classes {
            if class.weight == 0
                || class
                    .operations
                    .windows(2)
                    .any(|pair| pair[0].to_wire() >= pair[1].to_wire())
                || class
                    .operations
                    .iter()
                    .any(|operation| !operations.insert(operation.to_wire()))
            {
                return Err(invalid("invalid block service class"));
            }
        }
        Ok(())
    }

    fn class_index(&self, operation: BlockOp) -> Result<Option<usize>, DeviceError> {
        let found = self
            .classes
            .iter()
            .position(|class| class.operations.contains(&operation));
        if self.discipline != BlockServiceDiscipline::Fifo && found.is_none() {
            return Err(invalid("block operation has no service class"));
        }
        Ok(found)
    }
}

/// Stable identity and work size for one service-queued request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockServiceJob {
    /// Adapter-owned monotone request sequence.
    pub sequence: u64,
    /// Guest operation serviced by the queue.
    pub operation: BlockOp,
    /// Exact transferred byte count; zero-byte commands rely on optional IOPS.
    pub bytes: u64,
    /// Exact virtual coordinate at queue admission.
    pub admitted_nanos: u64,
}

/// Evidence emitted when one contributor finishes one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockServiceCompletion {
    /// Contributor whose server completed the work.
    pub contributor: [u8; 32],
    /// Request sequence completed by this server.
    pub sequence: u64,
    /// Exact non-preemptive service start coordinate.
    pub started_nanos: u64,
    /// Exact service completion coordinate.
    pub finished_nanos: u64,
    /// Cumulative bytes serviced in the current continuously busy epoch.
    pub busy_epoch_bytes: u128,
    /// Cumulative operations serviced in the current continuously busy epoch.
    pub busy_epoch_operations: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct QueuedJob {
    job: BlockServiceJob,
    class_index: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ActiveJob {
    queued: QueuedJob,
    started_nanos: u64,
    finished_nanos: u64,
}

/// Checkpointed continuation for one service contributor.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockServiceContinuation {
    /// Immutable contributed rule.
    pub rule: ResolvedBlockServiceRule,
    pending: BTreeMap<u64, QueuedJob>,
    active: Option<ActiveJob>,
    busy_origin_nanos: u64,
    busy_epoch_bytes: u128,
    busy_epoch_operations: u128,
    weighted_cursor: usize,
    weighted_used: u64,
}

/// Canonical service state for one block device.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockServiceState {
    continuations: BTreeMap<[u8; 32], BlockServiceContinuation>,
}

impl BlockServiceState {
    /// Returns contributor continuations in canonical identity order.
    #[must_use]
    pub const fn continuations(&self) -> &BTreeMap<[u8; 32], BlockServiceContinuation> {
        &self.continuations
    }

    /// Returns every live `(contributor, request sequence)` join canonically.
    #[must_use]
    pub fn live_job_keys(&self) -> Vec<([u8; 32], u64)> {
        let mut keys = self
            .continuations
            .iter()
            .flat_map(|(contributor, continuation)| {
                continuation
                    .pending
                    .keys()
                    .copied()
                    .chain(continuation.active.map(|active| active.queued.job.sequence))
                    .map(|sequence| (*contributor, sequence))
            })
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

    /// Atomically admits one request to every supplied service constraint.
    ///
    /// An empty rule list means unconstrained service. A contributor identity
    /// names one immutable sampled rule version; a changed signal value therefore
    /// arrives under a new action identity and never rewrites consumed service.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid/noncanonical rules, duplicate job
    /// identity, queue overflow, arithmetic overflow, or hard-state exhaustion.
    pub fn admit(
        &mut self,
        job: BlockServiceJob,
        rules: &[ResolvedBlockServiceRule],
    ) -> Result<(), DeviceError> {
        if rules
            .windows(2)
            .any(|pair| pair[0].contributor >= pair[1].contributor)
        {
            return Err(invalid("block service contributors are not canonical"));
        }
        let mut next = self.clone();
        for rule in rules {
            rule.validate()?;
            if !next.continuations.contains_key(&rule.contributor)
                && next.continuations.len() == HARD_BLOCK_SERVICE_RULES
            {
                return Err(limit("block_service_rules", HARD_BLOCK_SERVICE_RULES));
            }
            let continuation = next
                .continuations
                .entry(rule.contributor)
                .or_insert_with(|| BlockServiceContinuation::new(rule.clone()));
            if continuation.rule != *rule {
                return Err(invalid("block service contributor changed immutable rule"));
            }
            continuation.admit(job)?;
        }
        if next.live_jobs() > HARD_BLOCK_SERVICE_JOBS {
            return Err(limit("block_service_jobs", HARD_BLOCK_SERVICE_JOBS));
        }
        *self = next;
        Ok(())
    }

    /// Advances every contributor through completions at or before `now_nanos`.
    ///
    /// Returned evidence is sorted by completion coordinate, contributor, then
    /// request sequence, independent of map insertion order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if checkpointed arithmetic cannot produce the
    /// next exact service boundary.
    pub fn advance_to(
        &mut self,
        now_nanos: u64,
    ) -> Result<Vec<BlockServiceCompletion>, DeviceError> {
        let mut completed = Vec::new();
        for (contributor, continuation) in &mut self.continuations {
            completed.extend(continuation.advance_to(now_nanos)?.into_iter().map(
                |mut completion| {
                    completion.contributor = *contributor;
                    completion
                },
            ));
        }
        self.continuations
            .retain(|_contributor, continuation| !continuation.is_idle());
        completed.sort_by_key(|completion| {
            (
                completion.finished_nanos,
                completion.contributor,
                completion.sequence,
            )
        });
        Ok(completed)
    }

    /// Returns the earliest active service completion coordinate.
    #[must_use]
    pub fn next_completion_nanos(&self) -> Option<u64> {
        self.continuations
            .values()
            .filter_map(|continuation| continuation.active.map(|active| active.finished_nanos))
            .min()
    }

    /// Validates canonical checkpoint state and recomputes every bound.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for malformed rules, queue/accounting mismatch,
    /// invalid active deadlines, or exceeded hard bounds.
    pub fn validate_restore(&self) -> Result<(), DeviceError> {
        if self.continuations.len() > HARD_BLOCK_SERVICE_RULES
            || self.live_jobs() > HARD_BLOCK_SERVICE_JOBS
        {
            return Err(limit("block_service_state", HARD_BLOCK_SERVICE_JOBS));
        }
        for (contributor, continuation) in &self.continuations {
            continuation.rule.validate()?;
            if *contributor != continuation.rule.contributor {
                return Err(invalid(
                    "restored block service contributor differs from its key",
                ));
            }
            continuation.validate_restore()?;
        }
        Ok(())
    }

    fn live_jobs(&self) -> usize {
        self.continuations
            .values()
            .map(|continuation| {
                continuation.pending.len() + usize::from(continuation.active.is_some())
            })
            .sum()
    }
}

impl BlockServiceContinuation {
    fn is_idle(&self) -> bool {
        self.active.is_none() && self.pending.is_empty()
    }
    fn new(rule: ResolvedBlockServiceRule) -> Self {
        Self {
            rule,
            pending: BTreeMap::new(),
            active: None,
            busy_origin_nanos: 0,
            busy_epoch_bytes: 0,
            busy_epoch_operations: 0,
            weighted_cursor: 0,
            weighted_used: 0,
        }
    }

    fn admit(&mut self, job: BlockServiceJob) -> Result<(), DeviceError> {
        let depth = self.pending.len() + usize::from(self.active.is_some());
        if depth >= usize::try_from(self.rule.queue_depth).unwrap_or(usize::MAX) {
            return Err(DeviceError::BlockServiceQueueFull {
                contributor: self.rule.contributor,
                depth: self.rule.queue_depth,
            });
        }
        if self.pending.contains_key(&job.sequence)
            || self
                .active
                .is_some_and(|active| active.queued.job.sequence == job.sequence)
        {
            return Err(invalid("duplicate block service request sequence"));
        }
        let queued = QueuedJob {
            job,
            class_index: self.rule.class_index(job.operation)?,
        };
        if self.active.is_none() {
            self.start(queued, job.admitted_nanos)?;
        } else {
            self.pending.insert(job.sequence, queued);
        }
        Ok(())
    }

    fn advance_to(&mut self, now_nanos: u64) -> Result<Vec<BlockServiceCompletion>, DeviceError> {
        let mut completed = Vec::new();
        while let Some(active) = self.active {
            if active.finished_nanos > now_nanos {
                break;
            }
            self.active = None;
            completed.push(BlockServiceCompletion {
                contributor: [0; 32],
                sequence: active.queued.job.sequence,
                started_nanos: active.started_nanos,
                finished_nanos: active.finished_nanos,
                busy_epoch_bytes: self.busy_epoch_bytes,
                busy_epoch_operations: self.busy_epoch_operations,
            });
            if let Some(next) = self.select_next() {
                self.start(next, active.finished_nanos)?;
            } else {
                self.busy_epoch_bytes = 0;
                self.busy_epoch_operations = 0;
                self.weighted_used = 0;
            }
        }
        Ok(completed)
    }

    fn start(&mut self, queued: QueuedJob, start_nanos: u64) -> Result<(), DeviceError> {
        if self.busy_epoch_bytes == 0 && self.busy_epoch_operations == 0 {
            self.busy_origin_nanos = start_nanos;
        }
        self.busy_epoch_bytes = self
            .busy_epoch_bytes
            .checked_add(u128::from(queued.job.bytes))
            .ok_or_else(|| invalid("block service byte ledger overflow"))?;
        self.busy_epoch_operations = self
            .busy_epoch_operations
            .checked_add(1)
            .ok_or_else(|| invalid("block service operation ledger overflow"))?;
        let finished_nanos = self.cumulative_deadline()?;
        if finished_nanos < start_nanos {
            return Err(invalid(
                "block service cumulative deadline precedes its start",
            ));
        }
        self.active = Some(ActiveJob {
            queued,
            started_nanos: start_nanos,
            finished_nanos,
        });
        Ok(())
    }

    fn select_next(&mut self) -> Option<QueuedJob> {
        let sequence = match self.rule.discipline {
            BlockServiceDiscipline::Fifo => self
                .pending
                .values()
                .min_by_key(|queued| (queued.job.admitted_nanos, queued.job.sequence))
                .map(|queued| queued.job.sequence),
            BlockServiceDiscipline::StrictPriority => self
                .pending
                .values()
                .min_by_key(|queued| {
                    let class = queued
                        .class_index
                        .and_then(|index| self.rule.classes.get(index));
                    (
                        class.map_or(u16::MAX, |class| class.priority),
                        queued.job.admitted_nanos,
                        queued.job.sequence,
                    )
                })
                .map(|queued| queued.job.sequence),
            BlockServiceDiscipline::WeightedRoundRobin => self.select_weighted_sequence(),
        }?;
        self.pending.remove(&sequence)
    }

    fn select_weighted_sequence(&mut self) -> Option<u64> {
        let class_count = self.rule.classes.len();
        if class_count == 0 || self.pending.is_empty() {
            return None;
        }
        for _ in 0..=class_count {
            let class = &self.rule.classes[self.weighted_cursor];
            let selected = self
                .pending
                .values()
                .filter(|queued| queued.class_index == Some(self.weighted_cursor))
                .min_by_key(|queued| (queued.job.admitted_nanos, queued.job.sequence))
                .map(|queued| queued.job.sequence);
            if let Some(sequence) = selected
                && self.weighted_used < class.weight
            {
                self.weighted_used += 1;
                if self.weighted_used == class.weight {
                    self.weighted_cursor = (self.weighted_cursor + 1) % class_count;
                    self.weighted_used = 0;
                }
                return Some(sequence);
            }
            self.weighted_cursor = (self.weighted_cursor + 1) % class_count;
            self.weighted_used = 0;
        }
        None
    }

    fn validate_restore(&self) -> Result<(), DeviceError> {
        let depth = self.pending.len() + usize::from(self.active.is_some());
        if depth > usize::try_from(self.rule.queue_depth).unwrap_or(usize::MAX)
            || self.weighted_cursor >= self.rule.classes.len().max(1)
            || (self.rule.discipline != BlockServiceDiscipline::WeightedRoundRobin
                && (self.weighted_cursor != 0 || self.weighted_used != 0))
            || self.active.is_some_and(|active| {
                active.finished_nanos < active.started_nanos
                    || active.started_nanos < active.queued.job.admitted_nanos
                    || self.busy_origin_nanos > active.started_nanos
                    || self.busy_epoch_operations == 0
                    || self.busy_epoch_bytes < u128::from(active.queued.job.bytes)
                    || self.cumulative_deadline().ok() != Some(active.finished_nanos)
            })
        {
            return Err(invalid("invalid restored block service continuation"));
        }
        let mut sequences = self.pending.keys().copied().collect::<BTreeSet<_>>();
        if let Some(active) = self.active
            && !sequences.insert(active.queued.job.sequence)
        {
            return Err(invalid("restored block service sequence is repeated"));
        }
        for queued in self
            .pending
            .values()
            .copied()
            .chain(self.active.map(|active| active.queued))
        {
            if queued.class_index != self.rule.class_index(queued.job.operation)? {
                return Err(invalid(
                    "restored block service class differs from its operation",
                ));
            }
        }
        Ok(())
    }

    fn cumulative_deadline(&self) -> Result<u64, DeviceError> {
        let byte_offset = ceil_ratio(
            self.busy_epoch_bytes
                .checked_mul(1_000_000_000)
                .ok_or_else(|| invalid("block service byte-time product overflow"))?,
            u128::from(self.rule.bytes_per_second),
        )?;
        let operation_offset = self.rule.iops.map_or(Ok(0), |iops| {
            ceil_ratio(
                self.busy_epoch_operations
                    .checked_mul(1_000_000_000)
                    .ok_or_else(|| invalid("block service IOPS-time product overflow"))?,
                u128::from(iops),
            )
        })?;
        let offset = byte_offset.max(operation_offset);
        self.busy_origin_nanos
            .checked_add(
                u64::try_from(offset).map_err(|_error| {
                    invalid("block service completion exceeds virtual-time width")
                })?,
            )
            .ok_or_else(|| invalid("block service completion coordinate overflow"))
    }
}

fn ceil_ratio(numerator: u128, denominator: u128) -> Result<u128, DeviceError> {
    numerator
        .checked_add(denominator.saturating_sub(1))
        .map(|rounded| rounded / denominator)
        .ok_or_else(|| invalid("block service ratio rounding overflow"))
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

    fn class(id: u8, operation: BlockOp, priority: u16, weight: u64) -> ResolvedBlockServiceClass {
        ResolvedBlockServiceClass {
            class: [id; 32],
            operations: vec![operation],
            priority,
            weight,
        }
    }

    fn rule(discipline: BlockServiceDiscipline) -> ResolvedBlockServiceRule {
        ResolvedBlockServiceRule {
            contributor: [1; 32],
            bytes_per_second: 1_000_000_000,
            iops: Some(1_000_000_000),
            queue_depth: 8,
            discipline,
            classes: vec![
                class(1, BlockOp::Read, 1, 2),
                class(2, BlockOp::Write, 0, 1),
            ],
            rebuild_shares_service: true,
        }
    }

    fn job(sequence: u64, operation: BlockOp, bytes: u64) -> BlockServiceJob {
        BlockServiceJob {
            sequence,
            operation,
            bytes,
            admitted_nanos: 0,
        }
    }

    #[test]
    fn cumulative_busy_epoch_has_no_per_request_rounding_drift() {
        let mut state = BlockServiceState::default();
        let mut service = rule(BlockServiceDiscipline::Fifo);
        service.bytes_per_second = 3;
        service.iops = None;
        state
            .admit(job(1, BlockOp::Read, 1), &[service.clone()])
            .unwrap_or_else(|error| panic!("first job should admit: {error}"));
        state
            .admit(job(2, BlockOp::Read, 1), &[service.clone()])
            .unwrap_or_else(|error| panic!("second job should admit: {error}"));
        state
            .admit(job(3, BlockOp::Read, 1), &[service])
            .unwrap_or_else(|error| panic!("third job should admit: {error}"));

        assert_eq!(state.next_completion_nanos(), Some(333_333_334));
        assert_eq!(state.advance_to(333_333_334).unwrap_or_default().len(), 1);
        assert_eq!(state.next_completion_nanos(), Some(666_666_667));
        assert_eq!(state.advance_to(1_000_000_000).unwrap_or_default().len(), 2);
    }

    #[test]
    fn strict_priority_reorders_only_requests_waiting_behind_active_work() {
        let mut state = BlockServiceState::default();
        let service = rule(BlockServiceDiscipline::StrictPriority);
        state
            .admit(job(1, BlockOp::Read, 10), std::slice::from_ref(&service))
            .unwrap_or_else(|error| panic!("active read should admit: {error}"));
        state
            .admit(job(2, BlockOp::Read, 1), std::slice::from_ref(&service))
            .unwrap_or_else(|error| panic!("queued read should admit: {error}"));
        state
            .admit(job(3, BlockOp::Write, 1), &[service])
            .unwrap_or_else(|error| panic!("queued write should admit: {error}"));

        let first = state.advance_to(10).unwrap_or_default();
        assert_eq!(first[0].sequence, 1);
        let second = state.advance_to(11).unwrap_or_default();
        assert_eq!(second[0].sequence, 3);
        let third = state.advance_to(12).unwrap_or_default();
        assert_eq!(third[0].sequence, 2);
    }

    #[test]
    fn weighted_round_robin_uses_canonical_class_weights() {
        let mut state = BlockServiceState::default();
        let service = rule(BlockServiceDiscipline::WeightedRoundRobin);
        state
            .admit(job(0, BlockOp::Write, 1), std::slice::from_ref(&service))
            .unwrap_or_else(|error| panic!("active seed should admit: {error}"));
        for (sequence, operation) in [
            (1, BlockOp::Read),
            (2, BlockOp::Write),
            (3, BlockOp::Read),
            (4, BlockOp::Write),
        ] {
            state
                .admit(job(sequence, operation, 1), std::slice::from_ref(&service))
                .unwrap_or_else(|error| panic!("queued job should admit: {error}"));
        }
        let completed = state.advance_to(10).unwrap_or_default();
        assert_eq!(
            completed
                .iter()
                .map(|completion| completion.sequence)
                .collect::<Vec<_>>(),
            vec![0, 1, 3, 2, 4]
        );
    }

    #[test]
    fn admission_is_atomic_across_contributors() {
        let mut state = BlockServiceState::default();
        let first = rule(BlockServiceDiscipline::Fifo);
        let mut full = first.clone();
        full.contributor = [2; 32];
        full.queue_depth = 1;
        state
            .admit(job(1, BlockOp::Read, 1), &[first.clone(), full.clone()])
            .unwrap_or_else(|error| panic!("first job should admit: {error}"));
        let before = state.clone();
        assert!(
            state
                .admit(job(2, BlockOp::Read, 1), &[first, full])
                .is_err()
        );
        assert_eq!(state, before);
    }
}
