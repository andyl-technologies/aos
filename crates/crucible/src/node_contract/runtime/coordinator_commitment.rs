//! Owns separately funded ordered coordinator attempts and semantic commitments.
//!
//! A slot is retained before its callback. Failed or uncertain attempts keep
//! their used sequence and any future semantic reservation. Inspection and
//! Capture never increment the semantic ordinal. A complete live safe-point
//! issuer additionally checks Runtime/Scheduler/native custody; this log is not
//! a ticket and does not turn requested coordinates into eligibility.

use super::*;
use crucible_node_contract::{ContentRef, Position, U64};
use crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::{
    CoordinatorCommitmentCheckpoint17, CoordinatorCommitmentEntry17, CoordinatorCommitmentKind17,
    CoordinatorCommitmentState17,
};
use std::mem::size_of;

#[path = "coordinator_commitment/construction.rs"]
mod construction;

pub(crate) use construction::OriginalRestoredCoordinator17ConstructionData;

#[path = "coordinator_commitment/boundary.rs"]
mod boundary;

pub(crate) use boundary::OriginalRestoredCoordinatorBoundary17;

#[path = "coordinator_commitment/checkpoint_owner.rs"]
mod checkpoint_owner;

pub(crate) use checkpoint_owner::OriginalRestoredCoordinatorCheckpointOwner17;

#[path = "coordinator_commitment/initial.rs"]
mod initial;

pub use initial::OriginalCoordinator17ConstructionData;

/// Selects an explicit new17 lifetime policy, independently of native ingress.
///
/// The actual immutable original capability/checkpoint binds this ceiling. A
/// fresh incarnation retains the same cumulative maximum and consumed sequence;
/// neither process restart nor new Vec backing replenishes this policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitmentPolicy17 {
    maximum_records: usize,
}

impl CoordinatorCommitmentPolicy17 {
    /// Validates a finite caller-owned construction policy without issuing work.
    ///
    /// # Errors
    /// Refuses zero or a ceiling unrepresentable by the portable sequence type.
    pub(crate) fn new(maximum_records: usize) -> Result<Self, RuntimeError> {
        if maximum_records == 0 || u64::try_from(maximum_records).is_err() {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(Self { maximum_records })
    }

    /// Returns requested layout for the complete future fixed bank and clones.
    ///
    /// Complete Id backing is bounded by its real 128-byte grammar; a valid
    /// ContentRef owns the fixed hash strings plus up to128 printable media
    /// bytes. These terms price actual future constructors, not serialized-byte
    /// estimates of arbitrary existing String capacity. Current owners still
    /// undergo their separate complete raw census.
    ///
    /// # Errors
    /// Refuses checked requested-layout arithmetic overflow.
    pub(crate) fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        let backing = 2usize
            .checked_mul(128)
            .and_then(|n| n.checked_add("blake3-256".len()))
            .and_then(|n| n.checked_add("cnp.blob.v1".len()))
            .and_then(|n| n.checked_add(64 + 128))
            .ok_or(RuntimeError::ResourceLimit)?;
        self.maximum_records
            .checked_mul(size_of::<CoordinatorCommitmentEntry17>())
            .and_then(|n| n.checked_add(self.maximum_records.checked_mul(backing)?))
            .and_then(|n| n.checked_add(self.maximum_records.checked_mul(size_of::<usize>())?))
            .and_then(|n| n.checked_add(size_of::<CoordinatorCommitments17>()))
            .ok_or(RuntimeError::ResourceLimit)
    }
}

/// Identifies one actual retained attempt, not a caller-chosen operation number.
#[derive(Clone, Copy)]
pub(crate) struct CoordinatorAttempt17 {
    index: usize,
    sequence: U64,
}

/// Retains the actual fixed bank and cumulative counters across every failure.
pub(crate) struct CoordinatorCommitments17 {
    policy: CoordinatorCommitmentPolicy17,
    activation_attempt: Option<CoordinatorAttempt17>,
    parent: Option<ContentRef>,
    first_sequence: U64,
    next_sequence: U64,
    first_event_ordinal: U64,
    next_event_ordinal: U64,
    entries: Vec<CoordinatorCommitmentEntry17>,
    future_semantic: Vec<usize>,
    reserved_semantic: usize,
    initialized: bool,
    failed: bool,
}

impl CoordinatorCommitments17 {
    /// Installs an unallocated owner before either fixed bank is reserved.
    pub(crate) fn unallocated(policy: CoordinatorCommitmentPolicy17) -> Self {
        Self {
            policy,
            activation_attempt: None,
            parent: None,
            first_sequence: U64::new(0),
            next_sequence: U64::new(0),
            first_event_ordinal: U64::new(0),
            next_event_ordinal: U64::new(0),
            entries: Vec::new(),
            future_semantic: Vec::new(),
            reserved_semantic: 0,
            initialized: false,
            failed: false,
        }
    }

    /// Retains inherited counters before allocating any fresh local bank.
    /// Only the genuine Source-bound installer supplies this verified parent.
    fn unallocated_for_checkpoint_data(
        policy: CoordinatorCommitmentPolicy17,
        checkpoint: &CoordinatorCommitmentCheckpoint17,
    ) -> Result<Self, RuntimeError> {
        if u64::try_from(policy.maximum_records).map_err(|_| RuntimeError::ResourceLimit)?
            != checkpoint.maximum_records.get()
            || checkpoint.next_sequence > checkpoint.maximum_records
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut log = Self::unallocated(policy);
        log.first_sequence = checkpoint.next_sequence;
        log.next_sequence = checkpoint.next_sequence;
        log.first_event_ordinal = checkpoint.safe_point.event_ordinal;
        log.next_event_ordinal = checkpoint.safe_point.event_ordinal;
        Ok(log)
    }

    /// Retains the authenticated immutable parent after the row admitted its clone.
    pub(super) fn retain_parent_data(&mut self, parent: &ContentRef) -> Result<(), RuntimeError> {
        if !self.initialized || self.failed || self.parent.is_some() || !self.entries.is_empty() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.failed = true;
        self.parent = Some(clone_reference(parent)?);
        self.failed = false;
        Ok(())
    }

    /// Reserves both complete banks once under the caller's independent policy.
    /// A partial reserve remains owned, spent and unavailable for retry.
    pub(crate) fn initialize_data(&mut self, maximum: usize) -> Result<(), RuntimeError> {
        if self.initialized || self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.failed = true;
        let requested = self.policy.requested_bytes_data()?;
        if requested > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.entries
            .try_reserve_exact(self.policy.maximum_records)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.future_semantic
            .try_reserve_exact(self.policy.maximum_records)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.entries.capacity() != self.policy.maximum_records
            || self.future_semantic.capacity() != self.policy.maximum_records
        {
            return Err(RuntimeError::ResourceLimit);
        }
        self.initialized = true;
        self.failed = false;
        Ok(())
    }

    /// Retains a used slot before cloning keys or invoking the actual effect.
    pub(crate) fn reserve_data(
        &mut self,
        kind: CoordinatorCommitmentKind17,
        operation: Option<&Id>,
        node: Option<&Id>,
        position: Option<Position>,
        maximum_semantic_events: usize,
    ) -> Result<CoordinatorAttempt17, RuntimeError> {
        if !self.initialized || self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let count = usize::try_from(self.next_sequence.get())
            .map_err(|_| RuntimeError::ResourceLimit)?
            .checked_add(1)
            .and_then(|n| n.checked_add(self.reserved_semantic))
            .and_then(|n| n.checked_add(maximum_semantic_events))
            .ok_or(RuntimeError::ResourceLimit)?;
        if count > self.policy.maximum_records
            || self.entries.len() == self.entries.capacity()
            || self.future_semantic.len() == self.future_semantic.capacity()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let next = self
            .next_sequence
            .checked_add(U64::new(1))
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let future = self
            .reserved_semantic
            .checked_add(maximum_semantic_events)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.next_event_ordinal
            .get()
            .checked_add(u64::try_from(future).map_err(|_| RuntimeError::ResourceLimit)?)
            .ok_or(RuntimeError::ResourceLimit)?;
        let attempt = CoordinatorAttempt17 {
            index: self.entries.len(),
            sequence: self.next_sequence,
        };
        self.entries.push(CoordinatorCommitmentEntry17 {
            sequence: self.next_sequence,
            kind,
            operation: None,
            node: None,
            position,
            evidence: None,
            state: CoordinatorCommitmentState17::Reserved,
            event_ordinal: None,
        });
        self.future_semantic.push(maximum_semantic_events);
        self.next_sequence = next;
        self.reserved_semantic = future;
        // If either fallible clone fails, this used slot and its outstanding
        // reservation remain live. No effect or replacement identity is issued.
        self.failed = true;
        self.entries[attempt.index].operation = operation.map(clone_id).transpose()?;
        self.entries[attempt.index].node = node.map(clone_id).transpose()?;
        self.failed = false;
        Ok(attempt)
    }

    fn entry_data(
        &mut self,
        attempt: CoordinatorAttempt17,
    ) -> Result<&mut CoordinatorCommitmentEntry17, RuntimeError> {
        if !self.initialized || self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.entries
            .get_mut(attempt.index)
            .filter(|entry| entry.sequence == attempt.sequence)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    /// Records the positively established disposition without resetting credit.
    pub(crate) fn finish_data(
        &mut self,
        attempt: CoordinatorAttempt17,
        state: CoordinatorCommitmentState17,
    ) -> Result<(), RuntimeError> {
        let entry = self.entry_data(attempt)?;
        if entry.state != CoordinatorCommitmentState17::Reserved
            || state == CoordinatorCommitmentState17::Reserved
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        entry.state = state;
        if state == CoordinatorCommitmentState17::Refused {
            self.release_future_data(attempt)?;
        }
        Ok(())
    }

    /// Emits one actual Scheduler-accepted semantic commitment under prior credit.
    ///
    /// Only the defining Runtime/Scheduler caller supplies this after its real
    /// receipt/consumed-input validation. Observe/Capture callers never use it.
    pub(crate) fn stage_semantic_data(
        &mut self,
        attempt: CoordinatorAttempt17,
        kind: CoordinatorCommitmentKind17,
        operation: &Id,
        node: &Id,
        position: Position,
        evidence: Option<&ContentRef>,
    ) -> Result<usize, RuntimeError> {
        let original = self.entry_data(attempt)?;
        if original.operation.as_ref() != Some(operation)
            || original.node.as_ref() != Some(node)
            || !matches!(
                original.state,
                CoordinatorCommitmentState17::Committed | CoordinatorCommitmentState17::Uncertain
            )
            || !matches!(
                kind,
                CoordinatorCommitmentKind17::SchedulingCommit
                    | CoordinatorCommitmentKind17::InputCommit
                    | CoordinatorCommitmentKind17::Control
            )
            || self
                .future_semantic
                .get(attempt.index)
                .copied()
                .unwrap_or(0)
                == 0
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.entries.len() == self.entries.capacity()
            || self.future_semantic.len() == self.future_semantic.capacity()
            || self.next_sequence.get()
                >= u64::try_from(self.policy.maximum_records)
                    .map_err(|_| RuntimeError::ResourceLimit)?
        {
            self.failed = true;
            return Err(RuntimeError::ResourceLimit);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(U64::new(1))
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.failed = true;
        let index = self.entries.len();
        self.entries.push(CoordinatorCommitmentEntry17 {
            sequence: self.next_sequence,
            kind,
            operation: None,
            node: None,
            position: Some(position),
            evidence: None,
            state: CoordinatorCommitmentState17::Reserved,
            event_ordinal: None,
        });
        self.future_semantic.push(0);
        self.next_sequence = next_sequence;
        self.future_semantic[attempt.index] -= 1;
        self.reserved_semantic -= 1;
        self.entries[index].operation = Some(clone_id(operation)?);
        self.entries[index].node = Some(clone_id(node)?);
        self.entries[index].evidence = evidence.map(clone_reference).transpose()?;
        self.failed = false;
        Ok(index)
    }

    /// Keeps a failed pre-apply transaction permanently in its actual owner.
    /// Staged entries and consumed reservation credit are never renewed.
    pub(crate) fn fail_semantic_transaction_data(&mut self) {
        self.failed = true;
    }

    /// Captures the first local index of a forthcoming atomic Scheduler update.
    pub(crate) fn next_entry_index_data(&self) -> usize {
        self.entries.len()
    }

    /// Publishes staged ordinals only after the actual Scheduler update applies.
    /// No allocation, callback or modeled execution occurs in this final step.
    pub(crate) fn publish_semantic_range_data(&mut self, start: usize) -> Result<(), RuntimeError> {
        if self.failed || !self.initialized {
            return Err(RuntimeError::OutstandingObligations);
        }
        let entries = self
            .entries
            .get_mut(start..)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let final_ordinal = self
            .next_event_ordinal
            .checked_add(U64::new(
                u64::try_from(entries.len()).map_err(|_| RuntimeError::ResourceLimit)?,
            ))
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if entries.iter().any(|entry| {
            entry.state != CoordinatorCommitmentState17::Reserved
                || entry.event_ordinal.is_some()
                || !matches!(
                    entry.kind,
                    CoordinatorCommitmentKind17::SchedulingCommit
                        | CoordinatorCommitmentKind17::InputCommit
                        | CoordinatorCommitmentKind17::Control
                )
        }) {
            self.failed = true;
            return Err(RuntimeError::ForeignAuthority);
        }
        for entry in entries {
            entry.event_ordinal = Some(self.next_event_ordinal);
            entry.state = CoordinatorCommitmentState17::Committed;
            self.next_event_ordinal = self
                .next_event_ordinal
                .checked_add(U64::new(1))
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        if self.next_event_ordinal != final_ordinal {
            self.failed = true;
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Closes unused prospective slots only after actual operation obligations end.
    pub(crate) fn release_future_data(
        &mut self,
        attempt: CoordinatorAttempt17,
    ) -> Result<(), RuntimeError> {
        self.entry_data(attempt)?;
        let remaining = self
            .future_semantic
            .get_mut(attempt.index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.reserved_semantic = self
            .reserved_semantic
            .checked_sub(*remaining)
            .ok_or(RuntimeError::ForeignAuthority)?;
        *remaining = 0;
        Ok(())
    }

    /// Borrows the original real Begin reservation for a retained operation.
    pub(crate) fn operation_attempt_data(
        &self,
        operation: &Id,
        node: &Id,
    ) -> Result<CoordinatorAttempt17, RuntimeError> {
        let index = self
            .entries
            .iter()
            .position(|entry| {
                entry.kind == CoordinatorCommitmentKind17::Begin
                    && entry.operation.as_ref() == Some(operation)
                    && entry.node.as_ref() == Some(node)
            })
            .ok_or(RuntimeError::ForeignAuthority)?;
        Ok(CoordinatorAttempt17 {
            index,
            sequence: self.entries[index].sequence,
        })
    }

    /// Keeps all not-yet-materialized fixed-grammar backing independently funded.
    pub(crate) fn future_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        // Each appended slot is an actual disjoint element of the same bank.
        // Its initialized backing is counted above; only still-unmaterialized
        // elements keep future backing. This changes no cumulative ID/limit.
        self.policy
            .maximum_records
            .checked_sub(
                usize::try_from(self.next_sequence.get())
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )
            .and_then(|n| {
                n.checked_mul(2 * 128 + "blake3-256".len() + "cnp.blob.v1".len() + 64 + 128)
            })
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Counts both actual fixed banks and every initialized dynamic child.
    pub(crate) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let mut bytes = self
            .entries
            .capacity()
            .checked_mul(size_of::<CoordinatorCommitmentEntry17>())
            .and_then(|n| {
                n.checked_add(
                    self.future_semantic
                        .capacity()
                        .checked_mul(size_of::<usize>())?,
                )
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        if let Some(parent) = &self.parent {
            bytes = bytes
                .checked_add(NodeRuntime::capture_reference_storage(parent)?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        for entry in &self.entries {
            for id in entry.operation.iter().chain(entry.node.iter()) {
                bytes = bytes
                    .checked_add(id.allocated_capacity())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            if let Some(reference) = &entry.evidence {
                bytes = bytes
                    .checked_add(NodeRuntime::capture_reference_storage(reference)?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        Ok(bytes)
    }

    /// Resolves earlier Begin/Poll uncertainty from one actually validated result.
    /// Only the Runtime's retained Complete/Acknowledged branch calls this.
    fn reconcile_completed_data(&mut self, operation: &Id, node: &Id) -> Result<(), RuntimeError> {
        if self.failed || !self.initialized {
            return Err(RuntimeError::OutstandingObligations);
        }
        for entry in &mut self.entries {
            if entry.operation.as_ref() == Some(operation)
                && entry.node.as_ref() == Some(node)
                && matches!(
                    entry.kind,
                    CoordinatorCommitmentKind17::Begin | CoordinatorCommitmentKind17::Poll
                )
                && entry.state == CoordinatorCommitmentState17::Uncertain
            {
                entry.state = CoordinatorCommitmentState17::Committed;
            }
        }
        Ok(())
    }

    /// Resolves previous uncertain Retire attempts only from the real native ACK.
    fn reconcile_retired_data(&mut self, operation: &Id, node: &Id) -> Result<(), RuntimeError> {
        self.reconcile_completed_data(operation, node)?;
        for entry in &mut self.entries {
            if entry.operation.as_ref() == Some(operation)
                && entry.node.as_ref() == Some(node)
                && entry.kind == CoordinatorCommitmentKind17::Retire
                && entry.state == CoordinatorCommitmentState17::Uncertain
            {
                entry.state = CoordinatorCommitmentState17::Committed;
            }
        }
        Ok(())
    }

    /// Refuses a historical prefix with any unfinished or uncertain custody.
    pub(crate) fn require_settled_data(&self) -> Result<(), RuntimeError> {
        if !self.initialized
            || self.failed
            || self.reserved_semantic != 0
            || self.entries.iter().any(|entry| {
                matches!(
                    entry.state,
                    CoordinatorCommitmentState17::Reserved
                        | CoordinatorCommitmentState17::Uncertain
                )
            })
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

fn clone_id(value: &Id) -> Result<Id, RuntimeError> {
    let mut text = String::new();
    text.try_reserve_exact(value.as_str().len())
        .map_err(|_| RuntimeError::ResourceLimit)?;
    text.push_str(value.as_str());
    Id::new(text).map_err(|_| RuntimeError::ForeignAuthority)
}

fn clone_reference(value: &ContentRef) -> Result<ContentRef, RuntimeError> {
    use crucible_node_contract::Validate;
    value.validate().map_err(|_| RuntimeError::InvalidReceipt)?;
    let clone = |text: &str| -> Result<String, RuntimeError> {
        let mut result = String::new();
        result
            .try_reserve_exact(text.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        result.push_str(text);
        Ok(result)
    };
    Ok(ContentRef {
        hash: crucible_node_contract::HashRef {
            algorithm: clone(&value.hash.algorithm)?,
            domain: clone(&value.hash.domain)?,
            digest: clone(&value.hash.digest)?,
        },
        length: value.length,
        media_type: clone(&value.media_type)?,
    })
}

impl NodeRuntime {
    /// Reserves one real boundary before an adapter callback is invoked.
    /// Old Worlds without an explicitly installed new17 policy remain exact.
    pub(crate) fn reserve_coordinator_attempt_data(
        &self,
        kind: CoordinatorCommitmentKind17,
        operation: Option<&Id>,
        node: Option<&Id>,
        position: Option<Position>,
        maximum_semantic_events: usize,
    ) -> Result<Option<CoordinatorAttempt17>, RuntimeError> {
        let Some(state) = self.scheduler.as_ref() else {
            return Ok(None);
        };
        state.with_coordinator17_data(|log| {
            log.map(|log| {
                log.reserve_data(kind, operation, node, position, maximum_semantic_events)
            })
            .transpose()
        })
    }

    /// Records disposition in the same retained log; no semantic event is emitted.
    pub(crate) fn finish_coordinator_attempt_data(
        &self,
        attempt: Option<CoordinatorAttempt17>,
        state: CoordinatorCommitmentState17,
    ) -> Result<(), RuntimeError> {
        let Some(attempt) = attempt else {
            return Ok(());
        };
        let Some(scheduling) = self.scheduler.as_ref() else {
            return Err(RuntimeError::ForeignAuthority);
        };
        scheduling.with_coordinator17_data(|log| {
            log.ok_or(RuntimeError::ForeignAuthority)?
                .finish_data(attempt, state)
        })
    }

    /// Resolves prior polling attempts only after actual full receipt validation.
    pub(super) fn reconcile_coordinator_poll_data(
        &self,
        token: &OperationToken,
    ) -> Result<(), RuntimeError> {
        self.validate_token(token)?;
        if !self.operations.get(token.operation()).is_some_and(|entry| {
            matches!(
                entry.result,
                RetainedResult::Complete(_) | RetainedResult::Acknowledged(_)
            )
        }) {
            return Err(RuntimeError::OutstandingObligations);
        }
        let Some(state) = self.scheduler.as_ref() else {
            return Ok(());
        };
        state.with_coordinator17_data(|log| {
            if let Some(log) = log {
                log.reconcile_completed_data(token.operation(), &token.route.node)?;
            }
            Ok(())
        })
    }

    /// Closes prospective semantic allowance only after the actual native ACK.
    pub(crate) fn finish_coordinator_operation_data(
        &self,
        operation: &Id,
        node: &Id,
    ) -> Result<(), RuntimeError> {
        let Some(state) = self.scheduler.as_ref() else {
            return Ok(());
        };
        state.with_coordinator17_data(|log| {
            if let Some(log) = log {
                log.reconcile_retired_data(operation, node)?;
                let attempt = log.operation_attempt_data(operation, node)?;
                log.release_future_data(attempt)?;
            }
            Ok(())
        })
    }
}

/// Names the defining fixed log/entry/counter and actual borrow/clone views.
pub(crate) fn counter_scratch_data() -> usize {
    size_of::<CoordinatorCommitmentPolicy17>()
        + size_of::<CoordinatorCommitments17>()
        + size_of::<CoordinatorAttempt17>()
        + size_of::<Option<CoordinatorAttempt17>>()
        + size_of::<Result<Option<CoordinatorAttempt17>, RuntimeError>>()
        + size_of::<Result<CoordinatorAttempt17, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<Id, RuntimeError>>()
        + size_of::<Result<ContentRef, RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<Option<u64>>()
        + size_of::<Option<Position>>()
        + size_of::<&CoordinatorCommitments17>()
        + size_of::<&mut CoordinatorCommitments17>()
        + size_of::<Option<&mut CoordinatorCommitments17>>()
        + size_of::<std::cell::RefMut<'static, Option<CoordinatorCommitments17>>>()
        + size_of::<Result<std::cell::RefMut<'static, Option<CoordinatorCommitments17>>, RuntimeError>>()
        + size_of::<std::cell::BorrowMutError>()
        + size_of::<std::slice::Iter<'static, CoordinatorCommitmentEntry17>>()
        + size_of::<std::slice::IterMut<'static, CoordinatorCommitmentEntry17>>()
        + size_of::<std::iter::Chain<std::option::Iter<'static, Id>, std::option::Iter<'static, Id>>>()
        + size_of::<&CoordinatorCommitmentEntry17>()
        + size_of::<&mut CoordinatorCommitmentEntry17>()
        + size_of::<Option<&mut CoordinatorCommitmentEntry17>>()
        + size_of::<Result<&mut CoordinatorCommitmentEntry17, RuntimeError>>()
        + size_of::<Option<&Id>>() * 2
        + size_of::<Option<&ContentRef>>()
        + size_of::<Option<&usize>>()
        + size_of::<Option<&mut usize>>()
        + size_of::<Result<&mut usize, RuntimeError>>()
        + size_of::<&Id>() * 2
        + size_of::<&ContentRef>()
        + size_of::<String>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + checkpoint_owner::checkpoint_owner_counter_scratch_data()
        + boundary::boundary_counter_scratch_data()
        + crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17::counter_scratch_data()
}

impl NodeRuntime {
    /// Settles operational evidence without assigning a modeled event ordinal.
    pub(crate) fn finish_coordinator_attempt_with_evidence_data(
        &self,
        attempt: Option<CoordinatorAttempt17>,
        state: CoordinatorCommitmentState17,
        evidence: Option<&ContentRef>,
    ) -> Result<(), RuntimeError> {
        let Some(attempt) = attempt else {
            return Ok(());
        };
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .with_coordinator17_data(|log| {
                let log = log.ok_or(RuntimeError::ForeignAuthority)?;
                if let Some(evidence) = evidence {
                    log.entry_data(attempt)?;
                    log.failed = true;
                    log.entries[attempt.index].evidence = Some(clone_reference(evidence)?);
                    log.failed = false;
                }
                log.finish_data(attempt, state)
            })
    }

    /// Preserves uncertainty when a completed callback cannot be authenticated.
    pub(crate) fn finish_coordinator_runtime_result_data<T>(
        &self,
        attempt: Option<CoordinatorAttempt17>,
        result: &Result<T, RuntimePollFailure>,
    ) -> Result<(), RuntimeError> {
        let state = match result {
            Ok(_) => CoordinatorCommitmentState17::Committed,
            Err(RuntimePollFailure::Native(failure))
                if failure.effects == EffectKnowledge::None =>
            {
                CoordinatorCommitmentState17::Refused
            }
            _ => CoordinatorCommitmentState17::Uncertain,
        };
        self.finish_coordinator_attempt_data(attempt, state)
    }
}

impl NodeRuntime {
    pub(crate) fn reconcile_coordinator_stored_result_data(
        &self,
        token: &OperationToken,
    ) -> Result<(), RuntimeError> {
        self.validate_token(token)?;
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .with_coordinator17_data(|log| {
                if let Some(log) = log {
                    for entry in &mut log.entries {
                        if entry.kind == CoordinatorCommitmentKind17::StoredResult
                            && entry.operation.as_ref() == Some(token.operation())
                            && entry.node.as_ref() == Some(&token.route.node)
                            && entry.state == CoordinatorCommitmentState17::Uncertain
                        {
                            entry.state = CoordinatorCommitmentState17::Committed;
                        }
                    }
                }
                Ok(())
            })
    }

    pub(crate) fn reconcile_coordinator_input_commit_data(
        &self,
        commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), RuntimeError> {
        self.validate_activation(commit.activation())?;
        if !self
            .input_batches
            .get(commit.stage_operation())
            .is_some_and(|input| input.committed)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .with_coordinator17_data(|log| {
                if let Some(log) = log {
                    for entry in &mut log.entries {
                        if entry.kind == CoordinatorCommitmentKind17::InputCommit
                            && entry.operation.as_ref() == Some(commit.stage_operation())
                            && entry.node.as_ref() == Some(commit.node())
                            && entry.state == CoordinatorCommitmentState17::Uncertain
                        {
                            entry.state = CoordinatorCommitmentState17::Committed;
                        }
                    }
                }
                Ok(())
            })
    }
}

#[cfg(test)]
mod coordinator_bank_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn refused_attempts_spend_ids_and_uncertain_effects_block_capture() -> TestResult {
        let policy = CoordinatorCommitmentPolicy17::new(3)?;
        let mut log = CoordinatorCommitments17::unallocated(policy);
        log.initialize_data(policy.requested_bytes_data()?)?;
        let operation = Id::new("original-operation")?;
        let node = Id::new("original-node")?;
        let first = log.reserve_data(
            CoordinatorCommitmentKind17::Begin,
            Some(&operation),
            Some(&node),
            None,
            1,
        )?;
        log.finish_data(first, CoordinatorCommitmentState17::Refused)?;
        assert_eq!(log.next_sequence, U64::new(1));
        assert_eq!(log.next_event_ordinal, U64::new(0));
        assert_eq!(log.reserved_semantic, 0);
        log.require_settled_data()?;

        let second = log.reserve_data(
            CoordinatorCommitmentKind17::Observe,
            None,
            Some(&node),
            None,
            0,
        )?;
        log.finish_data(second, CoordinatorCommitmentState17::Uncertain)?;
        assert_eq!(log.next_sequence, U64::new(2));
        assert_eq!(log.next_event_ordinal, U64::new(0));
        assert!(log.require_settled_data().is_err());
        let last = log.reserve_data(
            CoordinatorCommitmentKind17::Observe,
            None,
            Some(&node),
            None,
            0,
        )?;
        log.finish_data(last, CoordinatorCommitmentState17::Refused)?;
        assert!(
            log.reserve_data(
                CoordinatorCommitmentKind17::Observe,
                None,
                Some(&node),
                None,
                0
            )
            .is_err()
        );
        assert_eq!(log.entries.len(), 3);
        assert_eq!(log.entries[0].sequence, U64::new(0));
        assert_eq!(log.entries[1].sequence, U64::new(1));
        assert_eq!(log.entries[2].sequence, U64::new(2));
        Ok(())
    }

    #[test]
    fn administrative_input_transfer_never_spends_a_semantic_ordinal() -> TestResult {
        let policy = CoordinatorCommitmentPolicy17::new(4)?;
        let mut log = CoordinatorCommitments17::unallocated(policy);
        log.initialize_data(policy.requested_bytes_data()?)?;
        let operation = Id::new("input-stage")?;
        let node = Id::new("consumer")?;
        for kind in [
            CoordinatorCommitmentKind17::InputStage,
            CoordinatorCommitmentKind17::InputAcknowledgement,
            CoordinatorCommitmentKind17::InputCommit,
        ] {
            let attempt = log.reserve_data(kind, Some(&operation), Some(&node), None, 0)?;
            log.finish_data(attempt, CoordinatorCommitmentState17::Committed)?;
        }
        assert_eq!(log.next_event_ordinal, U64::new(0));
        assert!(
            log.entries
                .iter()
                .all(|entry| entry.event_ordinal.is_none())
        );
        log.require_settled_data()?;
        Ok(())
    }
}
