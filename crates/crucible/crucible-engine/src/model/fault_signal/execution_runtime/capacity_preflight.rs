//! Allocation-bounded checkpoint capacity preflight.
//!
//! An owned continuation commits a boundary to its live backend before it
//! records the boundary's work item, so a checkpoint that would exceed
//! `fat_checkpoint_bytes` must be refused before the commit. The preflight
//! measures the complete candidate checkpoint without re-encoding the recorded
//! trace: sealed work items are not part of the checkpoint, and the open
//! tail's encoded length is tracked by the writer as items are appended.
//! Digests not known before the commit are measured at their widest encoding,
//! so the measurement is an upper bound that refuses early by at most a few
//! digest widths and never admits a checkpoint beyond the limit.

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

use super::*;

/// Coordinates of the one work item an evaluation would record.
pub(super) struct CapacityWorkItemContext<'a> {
    pub(super) coordinate: FaultCoordinate,
    pub(super) same_coordinate_sequence: u64,
    pub(super) opportunity: Option<&'a FaultOpportunity>,
    pub(super) derivation_fingerprint: ContentHash,
    pub(super) precondition_digest: ContentHash,
    pub(super) evidence_digest: ContentHash,
}

/// Refuses an evaluation whose recorded work item would make the complete
/// checkpoint exceed its byte or replay-counter limits.
///
/// `candidate` is the bounded checkpoint after the previewed evaluation; the
/// trace position and replay cursor come from `trace`.
pub(super) fn preflight_checkpoint_with_actions(
    candidate: &FaultRuntimeCheckpoint,
    trace: &FaultTraceState,
    actions: &[ResolvedBindingAction],
    context: CapacityWorkItemContext<'_>,
) -> Result<(), FaultRuntimeError> {
    let _ = candidate_checkpoint_len(candidate, trace, actions, &context)?;
    Ok(())
}

/// Returns an upper bound on the encoded length of the checkpoint after
/// recording one work item for `actions`.
fn candidate_checkpoint_len(
    candidate: &FaultRuntimeCheckpoint,
    trace: &FaultTraceState,
    actions: &[ResolvedBindingAction],
    context: &CapacityWorkItemContext<'_>,
) -> Result<u64, FaultRuntimeError> {
    if actions
        .iter()
        .any(|action| action.opportunity != context.opportunity.map(FaultOpportunity::id))
    {
        return Err(FaultRuntimeError::InvalidReplayTrace);
    }
    let records = u64::try_from(actions.len())
        .map_err(|_| FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
    trace.recorded.reserve(records)?;

    let work_item = CapacityWorkItem {
        coordinate: context.coordinate,
        same_coordinate_sequence: context.same_coordinate_sequence,
        opportunity: context.opportunity,
        derivation_fingerprint: context.derivation_fingerprint,
        actions,
        precondition_digest: context.precondition_digest,
        evidence_digest: context.evidence_digest,
    };
    let item_bytes = encoded_len(&work_item)?;
    if item_bytes > MAX_RESOLVED_EFFECT_TRACE_ITEM_BYTES as u64 {
        return Err(FaultRuntimeError::TraceItemTooLarge { bytes: item_bytes });
    }
    let item_bytes =
        usize::try_from(item_bytes).map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
    let shell = trace.recorded.capacity_shell(item_bytes, records)?;

    let mut measured = candidate.clone();
    measured.recorded = shell.position.clone();
    measured.replay = trace
        .replay
        .as_ref()
        .map(ResolvedEffectTraceReader::replay_cursor);
    let length = shell.encoded_len(encoded_len(&measured)?);

    let configured = candidate.resource_limits.fat_checkpoint_bytes;
    let hard = FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes;
    if length > configured || length > hard {
        return Err(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "fat_checkpoint_bytes",
                current: 0,
                requested: length,
                configured,
                hard,
            },
        ));
    }
    Ok(length)
}

/// Counts a value's CBOR encoding without retaining the bytes.
fn encoded_len(value: &impl Serialize) -> Result<u64, FaultRuntimeError> {
    let mut counter = ByteCounter(0);
    ciborium::ser::into_writer(value, &mut counter)
        .map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
    Ok(counter.0)
}

struct ByteCounter(u64);

impl std::io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct CapacityWorkItem<'a> {
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    opportunity: Option<&'a FaultOpportunity>,
    derivation_fingerprint: ContentHash,
    actions: &'a [ResolvedBindingAction],
    precondition_digest: ContentHash,
    evidence_digest: ContentHash,
}

impl Serialize for CapacityWorkItem<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            coordinate: FaultCoordinate,
            same_coordinate_sequence: u64,
            opportunity: Option<ContentHash>,
            target: Option<&'a ResolvedFaultTarget>,
            operation: Option<FaultOperation>,
            direction: Option<FaultDirection>,
            phase: Option<FaultPhase>,
            network_frame_key: Option<ContentHash>,
            network_producer_direction_key: Option<ContentHash>,
            derivation_fingerprint: ContentHash,
            records: CapacityRecords<'a>,
        }
        let opportunity = self.opportunity;
        Wire {
            coordinate: self.coordinate,
            same_coordinate_sequence: self.same_coordinate_sequence,
            opportunity: opportunity.map(FaultOpportunity::id),
            target: opportunity.map(FaultOpportunity::target),
            operation: opportunity.map(FaultOpportunity::operation),
            direction: opportunity.and_then(FaultOpportunity::direction),
            phase: opportunity.map(FaultOpportunity::phase),
            network_frame_key: opportunity.and_then(FaultOpportunity::network_frame_key),
            network_producer_direction_key: opportunity
                .and_then(FaultOpportunity::network_producer_direction_key),
            derivation_fingerprint: self.derivation_fingerprint,
            records: CapacityRecords {
                actions: self.actions,
                opportunity,
                same_coordinate_sequence: self.same_coordinate_sequence,
                derivation_fingerprint: self.derivation_fingerprint,
                precondition_digest: self.precondition_digest,
                evidence_digest: self.evidence_digest,
            },
        }
        .serialize(serializer)
    }
}

struct CapacityRecords<'a> {
    actions: &'a [ResolvedBindingAction],
    opportunity: Option<&'a FaultOpportunity>,
    same_coordinate_sequence: u64,
    derivation_fingerprint: ContentHash,
    precondition_digest: ContentHash,
    evidence_digest: ContentHash,
}

impl Serialize for CapacityRecords<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.actions.len()))?;
        for action in self.actions {
            sequence.serialize_element(&CapacityRecord {
                action,
                opportunity: self.opportunity,
                same_coordinate_sequence: self.same_coordinate_sequence,
                derivation_fingerprint: self.derivation_fingerprint,
                precondition_digest: self.precondition_digest,
                evidence_digest: self.evidence_digest,
            })?;
        }
        sequence.end()
    }
}

struct CapacityRecord<'a> {
    action: &'a ResolvedBindingAction,
    opportunity: Option<&'a FaultOpportunity>,
    same_coordinate_sequence: u64,
    derivation_fingerprint: ContentHash,
    precondition_digest: ContentHash,
    evidence_digest: ContentHash,
}

impl Serialize for CapacityRecord<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Contributor<'a> {
            binding: &'a FaultObjectId,
            contribution_digest: ContentHash,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            effect: EffectKind,
            semantic_version: u16,
            action_kind: BindingActionKind,
            binding: &'a FaultObjectId,
            target: &'a ResolvedFaultTarget,
            opportunity: Option<ContentHash>,
            operation: Option<FaultOperation>,
            direction: Option<FaultDirection>,
            network_frame_key: Option<ContentHash>,
            network_producer_direction_key: Option<ContentHash>,
            coordinate: FaultCoordinate,
            same_coordinate_sequence: u64,
            phase: FaultPhase,
            lifetime: EffectLifetime,
            request: &'a EffectRequest,
            mapping_output: &'a ResolvedMappingOutput,
            parameters_digest: ContentHash,
            transition_sequence: u64,
            cause: &'a BindingActionCause,
            derivation_fingerprint: ContentHash,
            contributors: [Contributor<'a>; 1],
            capability: &'static str,
            precondition_digest: Option<ContentHash>,
            evidence_digest: ContentHash,
        }
        let action = self.action;
        let opportunity = self.opportunity;
        let mut coordinate = action.coordinate;
        if action.effect.kind().descriptor().adapter == FaultAdapter::Node
            && coordinate.retired_instructions.is_none()
        {
            coordinate.retired_instructions = Some(u64::MAX);
        }
        Wire {
            effect: action.effect.kind(),
            semantic_version: EFFECT_SEMANTIC_VERSION,
            action_kind: action.kind,
            binding: &action.binding,
            target: &action.target,
            opportunity: action.opportunity,
            operation: opportunity.map(FaultOpportunity::operation),
            direction: opportunity.and_then(FaultOpportunity::direction),
            network_frame_key: opportunity.and_then(FaultOpportunity::network_frame_key),
            network_producer_direction_key: opportunity
                .and_then(FaultOpportunity::network_producer_direction_key),
            coordinate,
            same_coordinate_sequence: self.same_coordinate_sequence,
            phase: action.phase,
            lifetime: action.effect.lifetime(),
            request: action.effect.as_ref(),
            mapping_output: action.mapping_output.as_ref(),
            parameters_digest: action.mapped_digest,
            transition_sequence: action.transition_sequence,
            cause: &action.cause,
            derivation_fingerprint: self.derivation_fingerprint,
            contributors: [Contributor {
                binding: &action.binding,
                contribution_digest: action.mapped_digest,
            }],
            capability: action.effect.capability(),
            precondition_digest: Some(self.precondition_digest),
            evidence_digest: self.evidence_digest,
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;

    fn context(coordinate: FaultCoordinate) -> CapacityWorkItemContext<'static> {
        CapacityWorkItemContext {
            coordinate,
            same_coordinate_sequence: 0,
            opportunity: None,
            derivation_fingerprint: crate::model::fault_signal::runtime::WIDEST_CONTENT_HASH,
            precondition_digest: crate::model::fault_signal::runtime::WIDEST_CONTENT_HASH,
            evidence_digest: crate::model::fault_signal::runtime::WIDEST_CONTENT_HASH,
        }
    }

    #[test]
    fn measured_candidate_length_bounds_the_checkpoint_after_recording() {
        let plan = test_plan();
        let seed = ContentHash::from_bytes(b"capacity-length-equivalence");
        let coordinate = FaultCoordinate {
            virtual_ticks: 0,
            retired_instructions: None,
        };
        let mut runtime = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("runtime: {error}"));
        let mut preview = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("preview runtime: {error}"));
        let evaluation = preview
            .preview_boundary(coordinate, 0)
            .unwrap_or_else(|error| panic!("preview: {error}"));
        assert_eq!(evaluation.actions.len(), 1);
        let candidate = preview
            .bounded_checkpoint()
            .unwrap_or_else(|error| panic!("bounded checkpoint: {error}"));

        let measured = candidate_checkpoint_len(
            &candidate,
            &runtime.trace,
            &evaluation.actions,
            &context(coordinate),
        )
        .unwrap_or_else(|error| panic!("measured candidate: {error}"));

        // The widest placeholder digests bound the committed digests' width:
        // a work item carries one derivation digest and each record carries
        // derivation, precondition, and evidence digests.
        runtime
            .evaluate_boundary(coordinate, 0)
            .unwrap_or_else(|error| panic!("boundary: {error}"));
        let actual = runtime
            .checkpoint()
            .unwrap_or_else(|error| panic!("checkpoint: {error}"))
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("checkpoint bytes: {error}"));
        assert_eq!(runtime.trace.recorded.position().tail().len(), 1);
        let actual = actual.len() as u64;
        let placeholder_slack = 32 * (1 + 3 * evaluation.actions.len() as u64);
        assert!(measured >= actual, "{measured} < {actual}");
        assert!(
            measured <= actual + placeholder_slack,
            "{measured} >> {actual}"
        );
    }
}
