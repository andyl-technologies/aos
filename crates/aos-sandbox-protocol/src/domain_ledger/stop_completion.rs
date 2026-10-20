//! Retains independently settled Stop cleanup without rewriting its old attempt.
//!
//! ```text
//! AOSLSC01 | evidence-kind:u8 | reserved7 | old-public-Stop16 |
//! old-Source-operation32 | A7-dispatch-record32 | current-Recover16 |
//! accepted-Recover-request32 | current-Source-root32 | new-cleanup-request16 |
//! final-Host3-request16 | Session32 | signed-request32 | signed-outcome32 |
//! exact-body32 | Root-query32 | Root-decision32 | Root-purpose3-completion48 |
//! exact V7-Complete409 or cleanup-lineage648
//! ```
//!
//! The A8 Source pair supplies protected provenance separately. These immutable
//! comparisons supply neither native absence nor Source, Session or append
//! authority. In particular, observed prior cleanup keeps its prior Recover ID.

use aos_sandbox_core::{ObjectDigest, OperationId};

use super::lifecycle_model::LifecycleModelError;
use super::stop_dispatch::LifecycleStopDispatchDataV1;
use crate::{
    host_cleanup_lineage::{HOST_CLEANUP_LINEAGE_BYTES_V1, HostCleanupLineageDataV1},
    host_recovered_namespace::{
        HOST_RECOVERED_NAMESPACE_BYTES_V7, HostRecoveredNamespaceDataV7,
        HostRecoveryStopPhaseDataV7,
    },
    host_stopped_namespace::HostStoppedNamespaceDataV4,
};

const MAGIC: &[u8; 8] = b"AOSLSC01";
const HEADER_BYTES: usize = 448;

/// Bounds the complete fixed completion comparison without an embedded packet.
pub const MAXIMUM_STOP_COMPLETION_BYTES_V1: usize = HEADER_BYTES + HOST_CLEANUP_LINEAGE_BYTES_V1;

/// Selects the exact historical evidence without adopting native custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleStopCompletionEvidenceDataV1 {
    /// Observes a genuinely completed old Stop through a fresh V7 query.
    ObservedComplete(HostRecoveredNamespaceDataV7),
    /// Observes a prior Recover's immutable completed cleanup lineage.
    ObservedLineage(HostCleanupLineageDataV1),
    /// Retains this Recover's newly issued cleanup and its final observation.
    ExecutedLineage(HostCleanupLineageDataV1),
}

impl LifecycleStopCompletionEvidenceDataV1 {
    /// Borrows the unchanged old Launch/Stop scope.
    pub const fn historical_scope_v1(&self) -> &HostStoppedNamespaceDataV4 {
        match self {
            Self::ObservedComplete(value) => value.historical_scope_v7(),
            Self::ObservedLineage(value) | Self::ExecutedLineage(value) => {
                value.subject_v1().historical_scope_v1()
            }
        }
    }

    fn kind(self) -> u8 {
        match self {
            Self::ObservedComplete(_) => 1,
            Self::ObservedLineage(_) => 2,
            Self::ExecutedLineage(_) => 3,
        }
    }

    fn encoded_length(self) -> usize {
        match self {
            Self::ObservedComplete(_) => HOST_RECOVERED_NAMESPACE_BYTES_V7,
            Self::ObservedLineage(_) | Self::ExecutedLineage(_) => HOST_CLEANUP_LINEAGE_BYTES_V1,
        }
    }
}

/// Gives nonauthorizing identities retained by one actual completion original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleStopCompletionBindingDataV1 {
    /// Unchanged public old Stop identity, distinct from its SDK request.
    pub operation: OperationId,
    /// Exact unchanged old Source Operation member at completion admission.
    pub operation_record: ObjectDigest,
    /// Complete protected A7 Dispatch auxiliary-record commitment.
    pub dispatch_record: ObjectDigest,
    /// Fresh accepted kind2 Recover operation, independent of observed history.
    pub recovery: OperationId,
    /// Canonical accepted Recover request commitment.
    pub recovery_request: ObjectDigest,
    /// Same Source projection root immediately before the A8 append.
    pub source_root: ObjectDigest,
    /// New cleanup request identity reserved by this Recover's finite purpose.
    pub cleanup_request: [u8; 16],
    /// Actual completed fresh Host3 SDK request/Session/signed-request triple.
    pub query: ([u8; 16], [u8; 32], [u8; 32]),
    /// Commitment to the complete authenticated final Host3 signed packet.
    pub outcome: [u8; 32],
    /// Exact method-body commitment held by its sole inventory decoder.
    pub body: [u8; 32],
    /// Canonical Root purpose3 query commitment.
    pub root_query: [u8; 32],
    /// Exact Root effect subject or observational decision commitment.
    pub root_decision: [u8; 32],
    /// Actual canonical purpose3 completion comparison; never native proof.
    pub root_completion: [u8; 48],
}

/// Preserves complete old history and separately authenticated cleanup DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleStopCompletionDataV1 {
    binding: LifecycleStopCompletionBindingDataV1,
    evidence: LifecycleStopCompletionEvidenceDataV1,
}

impl LifecycleStopCompletionDataV1 {
    /// Checks finite DATA associations without adopting any receipt or grant.
    ///
    /// # Errors
    /// Refuses sentinel identities, noncomplete V7, foreign fresh queries,
    /// reused historical requests or changed Root purpose3 comparisons.
    pub fn from_data_v1(
        binding: LifecycleStopCompletionBindingDataV1,
        evidence: LifecycleStopCompletionEvidenceDataV1,
    ) -> Result<Self, LifecycleModelError> {
        let invalid = LifecycleModelError::InvalidModel;
        let historical = evidence.historical_scope_v1();
        if [binding.operation.as_bytes(), binding.recovery.as_bytes()]
            .iter().any(|value| **value == [0; 16])
            || binding.operation == binding.recovery
            || [binding.operation_record, binding.dispatch_record, binding.recovery_request,
                binding.source_root].iter().any(|value| value.as_bytes() == &[0; 32])
            || binding.cleanup_request == [0; 16]
            || binding.query.0 == [0; 16]
            || [binding.query.1, binding.query.2, binding.outcome, binding.body,
                binding.root_query, binding.root_decision].contains(&[0; 32])
            || [*binding.operation.as_bytes(), *binding.recovery.as_bytes(),
                binding.cleanup_request, historical.launch_v4().0, historical.stop_v4().0]
                .contains(&binding.query.0)
            || binding.root_completion != crate::root_policy_completion::
                stop_cleanup_positive_completion_bytes_v1(
                    binding.root_query, binding.root_decision, binding.outcome)
        {
            return Err(invalid);
        }
        let (observation, decision) = match evidence {
            LifecycleStopCompletionEvidenceDataV1::ObservedComplete(value) => {
                if value.saved_phase_v7() != HostRecoveryStopPhaseDataV7::Complete {
                    return Err(invalid);
                }
                // The Root observation decision commits the first Host3 row.
                // This row is the distinct second query; its new nonce and
                // native interval must never be relabelled as that decision.
                (*value.observation_v7(), None)
            }
            LifecycleStopCompletionEvidenceDataV1::ObservedLineage(value) => {
                (*value.observation_v1(), None)
            }
            LifecycleStopCompletionEvidenceDataV1::ExecutedLineage(value) => {
                let subject = value.subject_v1();
                if subject.recovery_operation_v1() != binding.recovery.as_bytes()
                    || subject.recovery_request_digest_v1() != binding.recovery_request.as_bytes()
                    || subject.cleanup_request_v1() != &binding.cleanup_request
                {
                    return Err(invalid);
                }
                (*value.observation_v1(), Some(subject.digest_data_v1()))
            }
        };
        if observation.request_id_v5() != &binding.query.0
            || decision.is_some_and(|decision| decision != binding.root_decision)
        {
            return Err(invalid);
        }
        Ok(Self { binding, evidence })
    }

    /// Compares the original SDK triple without reconstructing an old result.
    ///
    /// # Errors
    /// Refuses another public Stop or any changed original signed SDK request.
    pub fn require_dispatch_data_v1(
        &self,
        dispatch: &LifecycleStopDispatchDataV1,
    ) -> Result<(), LifecycleModelError> {
        if self.binding.operation != dispatch.operation()
            || self.evidence.historical_scope_v1().stop_v4() != dispatch.sdk_request_data_v1()
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        Ok(())
    }

    /// Returns the public old Stop identity without changing its attempt state.
    pub const fn operation(&self) -> OperationId { self.binding.operation }

    /// Borrows all immutable comparison coordinates.
    pub const fn binding_v1(&self) -> &LifecycleStopCompletionBindingDataV1 { &self.binding }

    /// Borrows the exact observed or newly executed historical evidence.
    pub const fn evidence_v1(&self) -> &LifecycleStopCompletionEvidenceDataV1 { &self.evidence }

    /// Returns the complete canonical fixed width for this evidence branch.
    pub fn encoded_length(&self) -> usize { HEADER_BYTES + self.evidence.encoded_length() }

    /// Encodes checked DATA without copying the old signed dispatch packet.
    ///
    /// # Errors
    /// Refuses an allocation failure; field checks were completed at construction.
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleModelError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(self.encoded_length()).map_err(|_| LifecycleModelError::Allocation)?;
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.evidence.kind());
        bytes.extend_from_slice(&[0; 7]);
        let binding = &self.binding;
        bytes.extend_from_slice(binding.operation.as_bytes());
        bytes.extend_from_slice(binding.operation_record.as_bytes());
        bytes.extend_from_slice(binding.dispatch_record.as_bytes());
        bytes.extend_from_slice(binding.recovery.as_bytes());
        bytes.extend_from_slice(binding.recovery_request.as_bytes());
        bytes.extend_from_slice(binding.source_root.as_bytes());
        bytes.extend_from_slice(&binding.cleanup_request);
        bytes.extend_from_slice(&binding.query.0);
        bytes.extend_from_slice(&binding.query.1);
        bytes.extend_from_slice(&binding.query.2);
        bytes.extend_from_slice(&binding.outcome);
        bytes.extend_from_slice(&binding.body);
        bytes.extend_from_slice(&binding.root_query);
        bytes.extend_from_slice(&binding.root_decision);
        bytes.extend_from_slice(&binding.root_completion);
        match self.evidence {
            LifecycleStopCompletionEvidenceDataV1::ObservedComplete(value) => {
                bytes.extend_from_slice(&value.encode_v7());
            }
            LifecycleStopCompletionEvidenceDataV1::ObservedLineage(value)
            | LifecycleStopCompletionEvidenceDataV1::ExecutedLineage(value) => {
                bytes.extend_from_slice(&value.encode_v1());
            }
        }
        Ok(bytes)
    }

    /// Decodes one exact branch through the existing nested canonical codecs.
    ///
    /// # Errors
    /// Refuses truncation, trailing bytes, unknown kind/reserved fields,
    /// malformed nested evidence or inconsistent finite bindings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LifecycleModelError> {
        let invalid = || LifecycleModelError::CorruptEncoding;
        if bytes.len() < HEADER_BYTES || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[9..16] != [0; 7]
        {
            return Err(invalid());
        }
        let evidence = match bytes[8] {
            1 => LifecycleStopCompletionEvidenceDataV1::ObservedComplete(
                HostRecoveredNamespaceDataV7::decode_v7(&bytes[HEADER_BYTES..]).map_err(|_| invalid())?),
            2 => LifecycleStopCompletionEvidenceDataV1::ObservedLineage(
                HostCleanupLineageDataV1::decode_v1(&bytes[HEADER_BYTES..]).map_err(|_| invalid())?),
            3 => LifecycleStopCompletionEvidenceDataV1::ExecutedLineage(
                HostCleanupLineageDataV1::decode_v1(&bytes[HEADER_BYTES..]).map_err(|_| invalid())?),
            _ => return Err(invalid()),
        };
        Self::from_data_v1(LifecycleStopCompletionBindingDataV1 {
            operation: OperationId::from_bytes(field(bytes, 16)?),
            operation_record: ObjectDigest::from_bytes(field(bytes, 32)?),
            dispatch_record: ObjectDigest::from_bytes(field(bytes, 64)?),
            recovery: OperationId::from_bytes(field(bytes, 96)?),
            recovery_request: ObjectDigest::from_bytes(field(bytes, 112)?),
            source_root: ObjectDigest::from_bytes(field(bytes, 144)?),
            cleanup_request: field(bytes, 176)?,
            query: (field(bytes, 192)?, field(bytes, 208)?, field(bytes, 240)?),
            outcome: field(bytes, 272)?,
            body: field(bytes, 304)?,
            root_query: field(bytes, 336)?,
            root_decision: field(bytes, 368)?,
            root_completion: field(bytes, 400)?,
        }, evidence).map_err(|_| invalid())
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], LifecycleModelError> {
    bytes.get(offset..offset + N).and_then(|value| value.try_into().ok())
        .ok_or(LifecycleModelError::CorruptEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_inventory_absence::HostInventoryAbsenceDataV5;
    use crate::host_stop_cleanup::HostStopCleanupSubjectDataV1;
    use crate::root_policy_completion::{
        StopCleanupObservationDataV1, stop_cleanup_observation_decision_digest_v1,
        stop_cleanup_positive_completion_bytes_v1,
    };

    fn evidence(executed: bool) -> (LifecycleStopCompletionBindingDataV1, HostCleanupLineageDataV1) {
        let historical = HostStoppedNamespaceDataV4::from_data_v4(
            [1; 16], crate::ValidatedAssignmentFence {
                sandbox_id: [2; 16], incarnation_id: [3; 16], assignment_epoch: 4,
                desired_generation: 5, assignment_digest: [6; 32],
            }, [7; 32], ([8; 16], [9; 32], [10; 32]),
            ([11; 16], [12; 32], [13; 32]),
        ).unwrap();
        let subject = HostStopCleanupSubjectDataV1::from_data_v1(
            historical, if executed { [14; 16] } else { [15; 16] },
            if executed { [16; 16] } else { [17; 16] },
            if executed { [18; 32] } else { [19; 32] }, [20; 16], [21; 32], 22,
        ).unwrap();
        let observation = HostInventoryAbsenceDataV5::from_data_v5(
            [23; 16], [20; 16], [24; 16], 25, 26,
        ).unwrap();
        let row = HostCleanupLineageDataV1::from_data_v1(
            subject, (*subject.cleanup_request_v1(), [27; 32], [28; 32]),
            observation, [29; 32],
        ).unwrap();
        let decision = if executed { subject.digest_data_v1() } else {
            stop_cleanup_observation_decision_digest_v1(StopCleanupObservationDataV1::Cleanup(row)).unwrap()
        };
        (LifecycleStopCompletionBindingDataV1 {
            operation: OperationId::from_bytes([30; 16]),
            operation_record: ObjectDigest::from_bytes([31; 32]),
            dispatch_record: ObjectDigest::from_bytes([32; 32]),
            recovery: OperationId::from_bytes([14; 16]),
            recovery_request: ObjectDigest::from_bytes([18; 32]),
            source_root: ObjectDigest::from_bytes([33; 32]), cleanup_request: [16; 16],
            query: ([23; 16], [34; 32], [35; 32]), outcome: [36; 32], body: [37; 32],
            root_query: [38; 32], root_decision: decision,
            root_completion: stop_cleanup_positive_completion_bytes_v1([38; 32], decision, [36; 32]),
        }, row)
    }

    #[test]
    fn prior_recovery_and_new_cleanup_are_distinct_canonical_branches() {
        for executed in [false, true] {
            let (binding, row) = evidence(executed);
            let selected = if executed {
                LifecycleStopCompletionEvidenceDataV1::ExecutedLineage(row)
            } else { LifecycleStopCompletionEvidenceDataV1::ObservedLineage(row) };

            let value = LifecycleStopCompletionDataV1::from_data_v1(binding, selected).unwrap();
            let bytes = value.encode().unwrap();

            assert_eq!(bytes.len(), MAXIMUM_STOP_COMPLETION_BYTES_V1);
            assert_eq!(LifecycleStopCompletionDataV1::from_bytes(&bytes).unwrap(), value);
            assert_eq!(&bytes[HEADER_BYTES..], &row.encode_v1());
            if !executed {
                assert_ne!(row.subject_v1().recovery_operation_v1(), binding.recovery.as_bytes());
                assert!(LifecycleStopCompletionDataV1::from_data_v1(binding,
                    LifecycleStopCompletionEvidenceDataV1::ExecutedLineage(row)).is_err());
            }
        }
    }

    #[test]
    fn historical_observation_requires_complete_without_new_child_identity() {
        let (mut binding, row) = evidence(false);
        let historical = HostRecoveredNamespaceDataV7::from_data_v7(
            *row.subject_v1().historical_scope_v1(), *row.observation_v1(),
            HostRecoveryStopPhaseDataV7::Complete,
        );
        binding.root_decision = stop_cleanup_observation_decision_digest_v1(
            StopCleanupObservationDataV1::Historical(historical)).unwrap();
        binding.root_completion = stop_cleanup_positive_completion_bytes_v1(
            binding.root_query, binding.root_decision, binding.outcome);
        let value = LifecycleStopCompletionDataV1::from_data_v1(binding,
            LifecycleStopCompletionEvidenceDataV1::ObservedComplete(historical)).unwrap();
        assert_eq!(LifecycleStopCompletionDataV1::from_bytes(&value.encode().unwrap()).unwrap(), value);

        let pending = HostRecoveredNamespaceDataV7::from_data_v7(
            *historical.historical_scope_v7(), *historical.observation_v7(),
            HostRecoveryStopPhaseDataV7::PayloadPending,
        );
        assert!(LifecycleStopCompletionDataV1::from_data_v1(binding,
            LifecycleStopCompletionEvidenceDataV1::ObservedComplete(pending)).is_err());
    }

    #[test]
    fn changed_query_decision_purpose_and_noncanonical_frames_refuse() {
        let (binding, row) = evidence(true);
        let value = LifecycleStopCompletionDataV1::from_data_v1(binding,
            LifecycleStopCompletionEvidenceDataV1::ExecutedLineage(row)).unwrap();
        let bytes = value.encode().unwrap();
        for offset in [8, 9, 192, 272, 336, 368, 415, 447] {
            let mut changed = bytes.clone();
            changed[offset] ^= 4;
            assert!(LifecycleStopCompletionDataV1::from_bytes(&changed).is_err(), "offset {offset}");
        }
        assert!(LifecycleStopCompletionDataV1::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(LifecycleStopCompletionDataV1::from_bytes(&trailing).is_err());
    }

    #[test]
    fn first_observation_decision_is_separate_from_second_query_evidence() {
        let (mut binding, first) = evidence(false);
        let final_observation = HostInventoryAbsenceDataV5::from_data_v5(
            [40; 16], [20; 16], [24; 16], 41, 42,
        ).unwrap();
        let final_row = HostCleanupLineageDataV1::from_data_v1(
            *first.subject_v1(), first.child_v1(), final_observation,
            *first.chain_commitment_v1(),
        ).unwrap();
        binding.query.0 = [40; 16];
        binding.outcome = [43; 32];
        binding.body = [44; 32];
        binding.root_completion = stop_cleanup_positive_completion_bytes_v1(
            binding.root_query, binding.root_decision, binding.outcome);
        assert_ne!(binding.root_decision, stop_cleanup_observation_decision_digest_v1(
            StopCleanupObservationDataV1::Cleanup(final_row)).unwrap());

        let value = LifecycleStopCompletionDataV1::from_data_v1(binding,
            LifecycleStopCompletionEvidenceDataV1::ObservedLineage(final_row)).unwrap();

        assert_eq!(LifecycleStopCompletionDataV1::from_bytes(&value.encode().unwrap()).unwrap(), value);
        assert_ne!(first.observation_v1().request_id_v5(), final_row.observation_v1().request_id_v5());
    }
}
