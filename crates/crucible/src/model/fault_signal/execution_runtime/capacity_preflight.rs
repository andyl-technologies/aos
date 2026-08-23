//! Borrowed, allocation-bounded checkpoint capacity preflight.

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn preflight_checkpoint_with_actions(
    checkpoint: &FaultRuntimeCheckpoint,
    actions: &[ResolvedBindingAction],
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    opportunity: Option<&FaultOpportunity>,
    derivation_fingerprint: ContentHash,
    precondition_digest: ContentHash,
    evidence_digest: ContentHash,
) -> Result<(), FaultRuntimeError> {
    let work_items = u64::try_from(checkpoint.recorded_work_items.len())
        .map_err(|_| FaultRuntimeError::CountOverflow("thin_replay_events"))?;
    checkpoint
        .resource_limits
        .reserve("thin_replay_events", work_items, 1)
        .map_err(FaultRuntimeError::ResourceLimit)?;
    let existing_records = checkpoint
        .recorded_work_items
        .iter()
        .try_fold(0_u64, |total, item| {
            total.checked_add(u64::try_from(item.records.len()).ok()?)
        })
        .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
    checkpoint
        .resource_limits
        .reserve(
            "resolved_effect_records",
            existing_records,
            u64::try_from(actions.len())
                .map_err(|_| FaultRuntimeError::CountOverflow("resolved_effect_records"))?,
        )
        .map_err(FaultRuntimeError::ResourceLimit)?;
    if actions
        .iter()
        .any(|action| action.opportunity != opportunity.map(FaultOpportunity::id))
    {
        return Err(FaultRuntimeError::InvalidReplayTrace);
    }

    let work_item = CapacityWorkItem {
        coordinate,
        same_coordinate_sequence,
        opportunity,
        derivation_fingerprint,
        actions,
        precondition_digest,
        evidence_digest,
    };
    let wire = CapacityCheckpoint {
        semantic_version: checkpoint.semantic_version,
        signal_plan: checkpoint.signal_plan,
        resource_limits: &checkpoint.resource_limits,
        binding_runtime: &checkpoint.binding_runtime,
        adapters: &checkpoint.adapters,
        replay: checkpoint.replay.as_ref(),
        recorded_work_items: RecordedWorkItems {
            existing: &checkpoint.recorded_work_items,
            appended: work_item,
        },
        retained_effects: &checkpoint.retained_effects,
        branch_parent: checkpoint.branch_parent,
        poisoned: checkpoint.poisoned,
    };
    let _ = super::super::runtime::checkpoint_codec::encode(&wire, checkpoint.resource_limits)?;
    Ok(())
}

#[derive(Serialize)]
struct CapacityCheckpoint<'a> {
    semantic_version: u16,
    signal_plan: ContentHash,
    resource_limits: &'a FaultResourceLimits,
    binding_runtime: &'a BindingRuntimeCheckpoint,
    adapters: &'a BTreeMap<FaultAdapter, AdapterCheckpointState>,
    replay: Option<&'a ResolvedEffectTrace>,
    recorded_work_items: RecordedWorkItems<'a>,
    retained_effects: &'a BTreeSet<ContentHash>,
    branch_parent: Option<ContentHash>,
    poisoned: bool,
}

struct RecordedWorkItems<'a> {
    existing: &'a [ResolvedReplayWorkItem],
    appended: CapacityWorkItem<'a>,
}

impl Serialize for RecordedWorkItems<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let length = self
            .existing
            .len()
            .checked_add(1)
            .ok_or_else(|| serde::ser::Error::custom("work-item count overflow"))?;
        let mut sequence = serializer.serialize_seq(Some(length))?;
        for item in self.existing {
            sequence.serialize_element(item)?;
        }
        sequence.serialize_element(&self.appended)?;
        sequence.end()
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
