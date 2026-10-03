//! Strict conversions from enriched public protobuf observations.
//!
//! These conversions are pure and allocation-bounded by the checked resource
//! limits. They neither query controller state nor grant authority.

use aos_proto::aos::sandbox::v1::{
    AttachmentHealth, ConditionFreshness, ConditionReason, GuardianState, Operation,
    OwnershipState, OwnershipTransactionState, Sandbox, Timestamp,
};

use super::observation::{
    ActiveExecutionSetV1, AdditiveControllerObservationV1, AttachmentGenerationSetV1,
    AttachmentGenerationStatusV1, AttachmentHealthV1, AuditEventCursorV1, CacheDomainIdentityV1,
    CacheStatusV1, CheckedConditionObservationV1, CheckedOperationObservationV1,
    CheckedSandboxObservationV1, ConditionFreshnessV1, ConditionReasonV1,
    DisclosureDomainIdentityV1, DisclosureStatusV1, GuardianEvidenceV1, GuardianStatusV1,
    InvalidObservationMetadata, LogicalUsageStatusV1, OwnershipEvidenceV1, OwnershipLeaseStatusV1,
    OwnershipTransactionStateV1, OwnershipTransactionStatusV1, PublicTimestampV1,
    RealizedRootStatusV1,
};
use super::portable::CheckedObjectDescriptorV1;
use super::resource::{
    CheckedOperationResourceV1, CheckedPlacementV1, CheckedSandboxResourceV1, checked_results,
};

impl TryFrom<Sandbox> for CheckedSandboxObservationV1 {
    type Error = InvalidObservationMetadata;

    fn try_from(wire: Sandbox) -> Result<Self, Self::Error> {
        let observed = wire
            .observed
            .as_option()
            .ok_or(InvalidObservationMetadata::Unspecified)?
            .clone();
        let resource = CheckedSandboxResourceV1::try_from(wire)
            .map_err(|_| InvalidObservationMetadata::InvalidStatus)?;
        let conditions = checked_condition_observations(
            resource.conditions(),
            &observed.conditions,
            resource.desired_generation(),
            resource.observation_sequence(),
        )?;
        let placement = resource.placement().copied();
        let ownership = checked_ownership(&observed, placement)?;
        let guardian = checked_guardian(&observed, placement)?;
        let transaction = checked_transaction(&observed)?;
        let realized_root = observed
            .realized_root
            .as_option()
            .map(|root| {
                let descriptor = CheckedObjectDescriptorV1::try_from(
                    root.descriptor
                        .as_option()
                        .ok_or(InvalidObservationMetadata::Unspecified)?
                        .clone(),
                )
                .map_err(|_| InvalidObservationMetadata::InvalidStatus)?;
                RealizedRootStatusV1::new(root.generation, descriptor)
            })
            .transpose()?;
        let attachments = observed
            .attachments
            .as_option()
            .map(|set| checked_attachments(&set.attachments))
            .transpose()?;
        let active_executions = ActiveExecutionSetV1::new(
            checked_results(&observed.active_executions)
                .map_err(|_| InvalidObservationMetadata::InvalidStatus)?,
        )?;
        let pinned_references = checked_results(&observed.pinned_references)
            .map_err(|_| InvalidObservationMetadata::InvalidStatus)?;
        let cache = observed.cache.as_option().map(checked_cache).transpose()?;
        let disclosure = observed
            .disclosure
            .as_option()
            .map(checked_disclosure)
            .transpose()?;
        let logical_usage = observed.logical_usage.as_option().map(|usage| {
            LogicalUsageStatusV1::new(
                usage.cpu_nanoseconds,
                usage.memory_bytes,
                usage.storage_bytes,
                usage.process_count,
            )
        });
        let audit_cursor = if observed.audit_event_cursor.is_empty() {
            None
        } else {
            Some(AuditEventCursorV1::from_authenticated(
                observed.audit_event_cursor.clone(),
            )?)
        };
        let last_reconciliation = checked_timestamp(
            observed
                .last_successful_reconciliation_time
                .as_option()
                .ok_or(InvalidObservationMetadata::Unspecified)?,
        )?;
        let capability_generation = nonzero_optional(observed.capability_generation);
        let environment_generation = nonzero_optional(observed.environment_generation);
        let additive = AdditiveControllerObservationV1::new(
            ownership,
            guardian,
            capability_generation,
            realized_root,
            transaction,
            environment_generation,
            attachments,
            active_executions,
            pinned_references,
            cache,
            disclosure,
            logical_usage,
            audit_cursor,
            last_reconciliation,
        )?;

        Self::new(resource, conditions, additive)
    }
}

impl TryFrom<Operation> for CheckedOperationObservationV1 {
    type Error = InvalidObservationMetadata;

    fn try_from(wire: Operation) -> Result<Self, Self::Error> {
        let accepted_generation = wire.accepted_generation;
        let observation_sequence = wire.observation_sequence;
        let last_reconciliation = wire
            .last_successful_reconciliation_time
            .as_option()
            .ok_or(InvalidObservationMetadata::Unspecified)?;
        checked_timestamp(last_reconciliation)?;
        let raw_conditions = wire.conditions.clone();
        let resource = CheckedOperationResourceV1::try_from(wire)
            .map_err(|_| InvalidObservationMetadata::InvalidStatus)?;
        let conditions = checked_condition_observations(
            resource.conditions(),
            &raw_conditions,
            accepted_generation,
            observation_sequence,
        )?;

        Self::new(resource, observation_sequence, conditions)
    }
}

pub(super) fn checked_condition_observations(
    checked: &[super::resource::CheckedConditionV1],
    wire: &[aos_proto::aos::sandbox::v1::Condition],
    desired_generation: u64,
    resource_sequence: u64,
) -> Result<Vec<CheckedConditionObservationV1>, InvalidObservationMetadata> {
    if checked.len() != wire.len() {
        return Err(InvalidObservationMetadata::ConditionMismatch);
    }

    checked
        .iter()
        .cloned()
        .zip(wire)
        .map(|(condition, raw)| {
            if raw.desired_generation != desired_generation
                || raw.observation_sequence == 0
                || raw.observation_sequence > resource_sequence
            {
                return Err(InvalidObservationMetadata::ConditionMismatch);
            }
            let reason = match raw.reason.as_known() {
                Some(ConditionReason::CONDITION_REASON_VERIFIED) => ConditionReasonV1::Verified,
                Some(ConditionReason::CONDITION_REASON_PENDING) => ConditionReasonV1::Pending,
                Some(ConditionReason::CONDITION_REASON_DEPENDENCY_UNAVAILABLE) => {
                    ConditionReasonV1::DependencyUnavailable
                }
                Some(ConditionReason::CONDITION_REASON_CAPACITY_UNAVAILABLE) => {
                    ConditionReasonV1::CapacityUnavailable
                }
                Some(ConditionReason::CONDITION_REASON_POLICY_REJECTED) => {
                    ConditionReasonV1::PolicyRejected
                }
                Some(ConditionReason::CONDITION_REASON_AUTHORITY_PENDING) => {
                    ConditionReasonV1::AuthorityPending
                }
                Some(ConditionReason::CONDITION_REASON_AUTHORITY_FENCED) => {
                    ConditionReasonV1::AuthorityFenced
                }
                Some(ConditionReason::CONDITION_REASON_RESIDUAL_CLEANUP) => {
                    ConditionReasonV1::ResidualCleanup
                }
                Some(ConditionReason::CONDITION_REASON_UNSPECIFIED) | None => {
                    return Err(InvalidObservationMetadata::Unspecified);
                }
            };
            let freshness = match raw.freshness.as_known() {
                Some(ConditionFreshness::CONDITION_FRESHNESS_CURRENT) => {
                    ConditionFreshnessV1::Current
                }
                Some(ConditionFreshness::CONDITION_FRESHNESS_STALE) => ConditionFreshnessV1::Stale,
                Some(ConditionFreshness::CONDITION_FRESHNESS_UNSPECIFIED) | None => {
                    return Err(InvalidObservationMetadata::Unspecified);
                }
            };

            CheckedConditionObservationV1::new(
                condition,
                raw.desired_generation,
                raw.observation_sequence,
                reason,
                freshness,
            )
        })
        .collect()
}

fn checked_ownership(
    observed: &aos_proto::aos::sandbox::v1::SandboxObservedState,
    placement: Option<CheckedPlacementV1>,
) -> Result<OwnershipEvidenceV1, InvalidObservationMetadata> {
    let status = observed
        .ownership
        .as_option()
        .ok_or(InvalidObservationMetadata::Unspecified)?;
    let state = status
        .state
        .as_known()
        .ok_or(InvalidObservationMetadata::Unspecified)?;
    match state {
        OwnershipState::OWNERSHIP_STATE_UNASSIGNED => {
            if placement.is_some()
                || !status.node_id.is_empty()
                || status.assignment_epoch != 0
                || status.lease_generation != 0
                || status.expires_at.as_option().is_some()
                || !status.incarnation_id.is_empty()
            {
                Err(InvalidObservationMetadata::InvalidStatus)
            } else {
                Ok(OwnershipEvidenceV1::Unassigned)
            }
        }
        OwnershipState::OWNERSHIP_STATE_AWAITING => {
            let placement = correlated_placement(
                status.node_id.as_slice(),
                status.incarnation_id.as_slice(),
                status.assignment_epoch,
                placement,
            )?;
            if status.lease_generation != 0 || status.expires_at.as_option().is_some() {
                Err(InvalidObservationMetadata::InvalidStatus)
            } else {
                Ok(OwnershipEvidenceV1::AwaitingOwnership(placement))
            }
        }
        OwnershipState::OWNERSHIP_STATE_OWNED | OwnershipState::OWNERSHIP_STATE_EXPIRED => {
            let placement = correlated_placement(
                status.node_id.as_slice(),
                status.incarnation_id.as_slice(),
                status.assignment_epoch,
                placement,
            )?;
            let expires_at = checked_timestamp(
                status
                    .expires_at
                    .as_option()
                    .ok_or(InvalidObservationMetadata::Unspecified)?,
            )?;
            let lease =
                OwnershipLeaseStatusV1::new(placement, status.lease_generation, expires_at)?;
            if state == OwnershipState::OWNERSHIP_STATE_OWNED {
                Ok(OwnershipEvidenceV1::Owned(lease))
            } else {
                Ok(OwnershipEvidenceV1::Expired(lease))
            }
        }
        OwnershipState::OWNERSHIP_STATE_UNSPECIFIED => Err(InvalidObservationMetadata::Unspecified),
    }
}

fn checked_guardian(
    observed: &aos_proto::aos::sandbox::v1::SandboxObservedState,
    placement: Option<CheckedPlacementV1>,
) -> Result<GuardianEvidenceV1, InvalidObservationMetadata> {
    let status = observed
        .guardian
        .as_option()
        .ok_or(InvalidObservationMetadata::Unspecified)?;
    let state = status
        .state
        .as_known()
        .ok_or(InvalidObservationMetadata::Unspecified)?;
    if state == GuardianState::GUARDIAN_STATE_DISARMED {
        return if !status.node_id.is_empty()
            || status.assignment_epoch != 0
            || status.guardian_generation != 0
            || status.lease_generation != 0
            || !status.incarnation_id.is_empty()
        {
            Err(InvalidObservationMetadata::InvalidStatus)
        } else {
            Ok(GuardianEvidenceV1::Disarmed)
        };
    }
    if state == GuardianState::GUARDIAN_STATE_UNSPECIFIED {
        return Err(InvalidObservationMetadata::Unspecified);
    }

    let placement = correlated_placement(
        status.node_id.as_slice(),
        status.incarnation_id.as_slice(),
        status.assignment_epoch,
        placement,
    )?;
    let checked = GuardianStatusV1::new(
        placement,
        status.guardian_generation,
        status.lease_generation,
    )?;
    match state {
        GuardianState::GUARDIAN_STATE_ARMING => Ok(GuardianEvidenceV1::Arming(checked)),
        GuardianState::GUARDIAN_STATE_ARMED => Ok(GuardianEvidenceV1::Armed(checked)),
        GuardianState::GUARDIAN_STATE_CONTAINED => Ok(GuardianEvidenceV1::Contained(checked)),
        GuardianState::GUARDIAN_STATE_DISARMED | GuardianState::GUARDIAN_STATE_UNSPECIFIED => {
            Err(InvalidObservationMetadata::InvalidStatus)
        }
    }
}

fn checked_transaction(
    observed: &aos_proto::aos::sandbox::v1::SandboxObservedState,
) -> Result<OwnershipTransactionStatusV1, InvalidObservationMetadata> {
    let status = observed
        .root_transaction
        .as_option()
        .ok_or(InvalidObservationMetadata::Unspecified)?;
    let state = match status.state.as_known() {
        Some(OwnershipTransactionState::OWNERSHIP_TRANSACTION_STATE_ABSENT) => {
            OwnershipTransactionStateV1::Absent
        }
        Some(OwnershipTransactionState::OWNERSHIP_TRANSACTION_STATE_PREPARED) => {
            OwnershipTransactionStateV1::Prepared
        }
        Some(OwnershipTransactionState::OWNERSHIP_TRANSACTION_STATE_COMMITTED) => {
            OwnershipTransactionStateV1::Committed
        }
        Some(OwnershipTransactionState::OWNERSHIP_TRANSACTION_STATE_ROLLED_BACK) => {
            OwnershipTransactionStateV1::RolledBack
        }
        Some(OwnershipTransactionState::OWNERSHIP_TRANSACTION_STATE_UNSPECIFIED) | None => {
            return Err(InvalidObservationMetadata::Unspecified);
        }
    };
    let transaction_id = exact_optional_id(&status.transaction_id)?;
    OwnershipTransactionStatusV1::new(state, status.generation, transaction_id)
}

fn checked_attachments(
    wire: &[aos_proto::aos::sandbox::v1::AttachmentStatus],
) -> Result<AttachmentGenerationSetV1, InvalidObservationMetadata> {
    let mut checked = Vec::with_capacity(wire.len());
    for status in wire {
        let reference = status
            .attachment
            .as_option()
            .ok_or(InvalidObservationMetadata::Unspecified)?;
        let mut references = checked_results(std::slice::from_ref(reference))
            .map_err(|_| InvalidObservationMetadata::InvalidStatus)?;
        let reference = references
            .pop()
            .ok_or(InvalidObservationMetadata::Unspecified)?;
        let health = match status.health.as_known() {
            Some(AttachmentHealth::ATTACHMENT_HEALTH_READY) => AttachmentHealthV1::Ready,
            Some(AttachmentHealth::ATTACHMENT_HEALTH_DEGRADED) => AttachmentHealthV1::Degraded,
            Some(AttachmentHealth::ATTACHMENT_HEALTH_BLOCKED) => AttachmentHealthV1::Blocked,
            Some(AttachmentHealth::ATTACHMENT_HEALTH_UNSPECIFIED) | None => {
                return Err(InvalidObservationMetadata::Unspecified);
            }
        };
        checked.push(AttachmentGenerationStatusV1::new(
            reference,
            status.generation,
            health,
        )?);
    }
    AttachmentGenerationSetV1::new(checked)
}

fn checked_cache(
    status: &aos_proto::aos::sandbox::v1::CacheStatus,
) -> Result<CacheStatusV1, InvalidObservationMetadata> {
    CacheStatusV1::new(
        CacheDomainIdentityV1::new(exact_id(&status.domain_id)?)?,
        status.admitted_bytes,
        status.pinned_bytes,
        status.pinned_objects,
    )
}

fn checked_disclosure(
    status: &aos_proto::aos::sandbox::v1::DisclosureStatus,
) -> Result<DisclosureStatusV1, InvalidObservationMetadata> {
    Ok(DisclosureStatusV1::new(
        DisclosureDomainIdentityV1::new(exact_id(&status.domain_id)?)?,
        status.visible_resources,
        status.redacted_resources,
    ))
}

fn correlated_placement(
    node_id: &[u8],
    incarnation_id: &[u8],
    assignment_epoch: u64,
    placement: Option<CheckedPlacementV1>,
) -> Result<CheckedPlacementV1, InvalidObservationMetadata> {
    let placement = placement.ok_or(InvalidObservationMetadata::InvalidStatus)?;
    if exact_id(node_id)? != placement.node_id()
        || exact_id(incarnation_id)? != placement.incarnation_id()
        || assignment_epoch != placement.assignment_epoch()
    {
        Err(InvalidObservationMetadata::InvalidStatus)
    } else {
        Ok(placement)
    }
}

fn checked_timestamp(value: &Timestamp) -> Result<PublicTimestampV1, InvalidObservationMetadata> {
    PublicTimestampV1::new(value.seconds, value.nanoseconds)
}

fn exact_id(value: &[u8]) -> Result<[u8; 16], InvalidObservationMetadata> {
    let identifier = value
        .try_into()
        .map_err(|_| InvalidObservationMetadata::InvalidStatus)?;
    if identifier == [0; 16] {
        Err(InvalidObservationMetadata::Unspecified)
    } else {
        Ok(identifier)
    }
}

fn exact_optional_id(value: &[u8]) -> Result<Option<[u8; 16]>, InvalidObservationMetadata> {
    if value.is_empty() {
        Ok(None)
    } else {
        exact_id(value).map(Some)
    }
}

const fn nonzero_optional(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}
