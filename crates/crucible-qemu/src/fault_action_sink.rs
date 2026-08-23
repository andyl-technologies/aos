//! Production signal-driven node actions backed by live patched QEMU.
//!
//! Preparation performs only closed-schema and admitted-capability validation.
//! Commit publishes exact-boundary commands and derives durable observations
//! from authenticated QEMU results. Any ambiguous visibility is fatal; it is
//! never converted into an unchanged adapter rejection.

use crate::{QemuNodeSet, qemu_fault_target_hash};
use crucible::model::{
    BindingActionKind, ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION,
    FaultActionCommitError, FaultActionSink, FaultObservation, FaultObservationKind, FaultPhase,
    FaultResourceLimitError, FaultResourceLimits, FaultRuntimeError, MemoryAddressSpace,
    MemoryMutationAtomicity as ModelMemoryMutationAtomicity, MemoryMutationKind,
    NodeEffectSpecification, NodeId, PreparedActionBatch, PreparedActionResult,
    RejectedActionBatch, ResolvedBindingAction, ResolvedFaultTarget,
};
use crucible_shmem::{
    DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_FLAG_NONE,
    FAULT_COMMAND_FLAG_PREPARE_ONLY, FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase,
    FaultCommandHeaderV1, FaultCommandKind, FaultResultStatus,
    MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET, MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET,
    MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_ACTION_HASH_OFFSET,
    MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_BODY_OFFSET,
    MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_LENGTH_OFFSET, MEMORY_MUTATION_NO_VCPU,
    MemoryMutationAddressSpace, MemoryMutationAtomicity, MemoryMutationBatchActionV1,
    MemoryMutationBatchEvidenceV1, MemoryMutationBatchV1, MemoryMutationEvidenceV1,
    MemoryMutationPayloadV1, MemoryMutationTransformKind, NODE_FAULT_EVIDENCE_V1_BYTES,
    NodeFaultEvidenceV1, NodeFaultPayloadV1,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

#[path = "fault_action_sink/evidence.rs"]
mod evidence;
#[path = "fault_action_sink/memory_payload.rs"]
mod memory_payload;
#[path = "fault_action_sink/node_payload.rs"]
mod node_payload;
#[path = "fault_action_sink/result_validation.rs"]
mod result_validation;
use evidence::*;
use memory_payload::{memory_batch, memory_batch_evidence_matches, prepare_memory_action_payload};
pub(crate) use result_validation::validate_typed_node_result;
use result_validation::{reserve_fault_result_storage, validate_typed_node_result_decoded};

#[derive(Clone)]
struct PreparedMemoryAction {
    action: ResolvedBindingAction,
    node: NodeId,
    coordinate: u64,
    payload: MemoryMutationPayloadV1,
}

#[derive(Clone)]
struct PreparedQemuBatch {
    transaction: ContentHash,
    results: Vec<PreparedActionResult>,
    nodes: Vec<PreparedQemuNodeBatch>,
    typed_actions: Vec<PreparedTypedNodeAction>,
}

#[derive(Clone)]
struct PreparedQemuNodeBatch {
    node: NodeId,
    coordinate: u64,
    actions: Vec<PreparedMemoryAction>,
}

#[derive(Clone)]
struct PreparedTypedNodeAction {
    action: ResolvedBindingAction,
    node: NodeId,
    coordinate: u64,
    command_kind: FaultCommandKind,
    payload: Vec<u8>,
}

struct AuthorizedQemuNodeBatch {
    prepared: PreparedQemuNodeBatch,
    preparation: MemoryMutationBatchEvidenceV1,
    preparation_evidence_sha256: [u8; 32],
    preparation_evidence_len: usize,
    result_buffer: Vec<u8>,
    mutation_payload: Vec<u8>,
}

struct AuthorizedTypedNodeAction {
    prepared: PreparedTypedNodeAction,
    preparation: NodeFaultEvidenceV1,
    request: NodeFaultPayloadV1,
    result_buffer: Vec<u8>,
}

/// Authenticated APPLY-result identity retained for occurrence correlation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CommittedQemuActionEvidence {
    /// Exact QEMU command sequence that installed or applied the action.
    pub(crate) command_sequence: u64,
    /// Numeric [`FaultCommandKind`] carried by the result header.
    pub(crate) command_kind: u16,
    /// QEMU-authenticated state digest before the APPLY mutation.
    pub(crate) before_hash: [u8; 32],
    /// QEMU-authenticated state digest after the APPLY mutation.
    pub(crate) after_hash: [u8; 32],
}

/// A production node-adapter sink that mutates live patched-QEMU backends.
pub struct QemuFaultActionSink<'a> {
    nodes: &'a mut QemuNodeSet,
    prepared: Option<PreparedQemuBatch>,
    committed: Vec<(ContentHash, CommittedQemuActionEvidence)>,
    resource_limits: FaultResourceLimits,
}

impl<'a> QemuFaultActionSink<'a> {
    /// Binds a transaction sink to the live node set for one scheduler boundary.
    #[must_use]
    pub const fn new(nodes: &'a mut QemuNodeSet, resource_limits: FaultResourceLimits) -> Self {
        Self {
            nodes,
            prepared: None,
            committed: Vec::new(),
            resource_limits,
        }
    }

    /// Removes APPLY-result identities committed through this transaction sink.
    pub(crate) fn take_committed_evidence(
        &mut self,
    ) -> Vec<(ContentHash, CommittedQemuActionEvidence)> {
        std::mem::take(&mut self.committed)
    }

    fn reject(
        action: Option<&ResolvedBindingAction>,
        error: FaultRuntimeError,
        evidence: ContentHash,
    ) -> Box<RejectedActionBatch> {
        Box::new(RejectedActionBatch {
            error,
            observations: action
                .map(|action| FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectRejected,
                    coordinate: action.coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence,
                })
                .into_iter()
                .collect(),
            rejected_action: action.map(ResolvedBindingAction::id),
        })
    }

    fn prepare_memory_action(
        &mut self,
        action: &ResolvedBindingAction,
    ) -> Result<PreparedMemoryAction, FaultRuntimeError> {
        let prepared = prepare_memory_action_payload(action, self.resource_limits)?;
        let encoded = prepared
            .payload
            .encode_preparation()
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let admitted = self
            .nodes
            .fault_capabilities(&prepared.node)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?
            .iter()
            .any(|row| {
                row.command_kind == FaultCommandKind::MemoryMutation
                    && row.semantic_version == FAULT_COMMAND_SEMANTIC_VERSION
                    && row.supports_phase(FaultBoundaryPhase::NodeBoundary)
                    && usize::try_from(row.maximum_payload_bytes)
                        .is_ok_and(|maximum| encoded.len() <= maximum)
            });
        if !admitted {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        }
        let current = self
            .nodes
            .fault_command_coordinate(&prepared.node)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?
            .retired;
        let coordinate =
            qemu_execution_coordinate(action.coordinate.retired_instructions, current)?;
        Ok(PreparedMemoryAction {
            action: prepared.action,
            node: prepared.node,
            coordinate,
            payload: prepared.payload,
        })
    }

    fn prepare_typed_action(
        &mut self,
        action: &ResolvedBindingAction,
    ) -> Result<PreparedTypedNodeAction, FaultRuntimeError> {
        let provisional = node_payload::encode_node_action(action, [1; 32])
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let node = NodeId {
            name: provisional.node,
        };
        let (capability_hash, maximum_payload_bytes) = {
            let capability = self
                .nodes
                .fault_capabilities(&node)
                .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?
                .iter()
                .find(|row| {
                    row.command_kind == provisional.command_kind
                        && row.semantic_version == FAULT_COMMAND_SEMANTIC_VERSION
                        && row.supports_phase(FaultBoundaryPhase::NodeBoundary)
                })
                .ok_or(FaultRuntimeError::AdapterActionMismatch)?;
            (capability.capability_hash, capability.maximum_payload_bytes)
        };
        let encoded = node_payload::encode_node_action(action, capability_hash)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let payload = encoded
            .payload
            .encode()
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        if !usize::try_from(maximum_payload_bytes).is_ok_and(|maximum| payload.len() <= maximum) {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        }
        let current = self
            .nodes
            .fault_command_coordinate(&node)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?
            .retired;
        let coordinate =
            qemu_execution_coordinate(action.coordinate.retired_instructions, current)?;
        Ok(PreparedTypedNodeAction {
            action: action.clone(),
            node,
            coordinate,
            command_kind: encoded.command_kind,
            payload,
        })
    }
}

fn qemu_execution_coordinate(
    recorded: Option<u64>,
    current: u64,
) -> Result<u64, FaultRuntimeError> {
    match recorded {
        Some(recorded) if recorded != current => Err(FaultRuntimeError::AdapterActionMismatch),
        Some(recorded) => Ok(recorded),
        None => Ok(current),
    }
}

impl FaultActionSink for QemuFaultActionSink<'_> {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        if self.prepared.is_some() {
            return Err(Self::reject(
                None,
                FaultRuntimeError::AdapterTransactionPending,
                ContentHash::from_bytes(b"qemu-transaction-pending"),
            ));
        }
        let mut by_node = BTreeMap::<NodeId, Vec<PreparedMemoryAction>>::new();
        let mut typed_actions = Vec::new();
        for action in actions {
            if matches!(
                action.effect.specification(),
                EffectSpecification::Node(NodeEffectSpecification::MemoryMutation { .. })
            ) {
                let prepared = self.prepare_memory_action(action).map_err(|error| {
                    Self::reject(
                        Some(action),
                        error,
                        ContentHash::from_bytes(b"qemu-memory-prepare-rejection"),
                    )
                })?;
                by_node
                    .entry(prepared.node.clone())
                    .or_default()
                    .push(prepared);
            } else {
                let prepared = self.prepare_typed_action(action).map_err(|error| {
                    Self::reject(
                        Some(action),
                        error,
                        ContentHash::from_bytes(b"qemu-typed-prepare-rejection"),
                    )
                })?;
                typed_actions.push(prepared);
            }
        }
        let mut node_batches = Vec::with_capacity(by_node.len());
        for (node, prepared) in by_node {
            let coordinate = prepared
                .first()
                .map(|action| action.coordinate)
                .ok_or_else(|| {
                    Self::reject(
                        None,
                        FaultRuntimeError::AdapterActionMismatch,
                        ContentHash::from_bytes(b"qemu-empty-memory-batch"),
                    )
                })?;
            if prepared
                .iter()
                .any(|action| action.coordinate != coordinate)
            {
                return Err(Self::reject(
                    prepared.first().map(|action| &action.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    ContentHash::from_bytes(b"qemu-mixed-node-coordinates"),
                ));
            }
            let batch = memory_batch(&prepared, [0; 32]);
            let encoded = batch.encode_preparation().map_err(|_source| {
                Self::reject(
                    prepared.first().map(|action| &action.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    ContentHash::from_bytes(b"qemu-memory-batch-resource-limit"),
                )
            })?;
            let admitted = self
                .nodes
                .fault_capabilities(&node)
                .map_err(|_source| {
                    Self::reject(
                        prepared.first().map(|action| &action.action),
                        FaultRuntimeError::AdapterActionMismatch,
                        ContentHash::from_bytes(b"qemu-memory-batch-capability"),
                    )
                })?
                .iter()
                .any(|row| {
                    usize::try_from(row.maximum_payload_bytes)
                        .is_ok_and(|maximum| encoded.len() <= maximum)
                });
            if !admitted {
                return Err(Self::reject(
                    prepared.first().map(|action| &action.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    ContentHash::from_bytes(b"qemu-memory-batch-capability"),
                ));
            }
            node_batches.push(PreparedQemuNodeBatch {
                node,
                coordinate,
                actions: prepared,
            });
        }
        let mut material = Vec::with_capacity(actions.len() * 32);
        for action in actions {
            material.extend_from_slice(&action.id().bytes);
        }
        let transaction = ContentHash::from_bytes(&material);
        let predictions = actions
            .iter()
            .map(|action| PreparedActionResult {
                action: action.id(),
                precondition: None,
                observation: transaction_observation(
                    action,
                    ContentHash::from_bytes(b"qemu-predicted-evidence"),
                ),
            })
            .collect::<Vec<_>>();
        self.prepared = Some(PreparedQemuBatch {
            transaction,
            results: predictions.clone(),
            nodes: node_batches,
            typed_actions,
        });
        Ok(PreparedActionBatch {
            transaction,
            results: predictions,
        })
    }

    fn abort_batch(&mut self, transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        let prepared = self
            .prepared
            .take()
            .ok_or(FaultRuntimeError::UnknownAdapterTransaction)?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultRuntimeError::UnknownAdapterTransaction);
        }
        Ok(())
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        let prepared = self.prepared.take().ok_or({
            FaultActionCommitError::Fatal(FaultRuntimeError::UnknownAdapterTransaction)
        })?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultActionCommitError::Fatal(
                FaultRuntimeError::UnknownAdapterTransaction,
            ));
        }
        let mut results = prepared.results;
        let typed_actions = prepared.typed_actions;
        let total_actions = prepared
            .nodes
            .iter()
            .map(|node| node.actions.len())
            .sum::<usize>()
            .checked_add(typed_actions.len())
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
        let current = u64::try_from(self.committed.len()).unwrap_or(u64::MAX);
        let requested = u64::try_from(total_actions).unwrap_or(u64::MAX);
        self.resource_limits
            .reserve("event_records", current, requested)
            .map_err(|error| {
                FaultActionCommitError::Fatal(FaultRuntimeError::ResourceLimit(error))
            })?;
        self.committed
            .try_reserve_exact(total_actions)
            .map_err(|_| {
                FaultActionCommitError::Fatal(FaultRuntimeError::ResourceLimit(
                    FaultResourceLimitError::Exceeded {
                        field: "event_records",
                        current,
                        requested,
                        configured: self.resource_limits.event_records,
                        hard: FaultResourceLimits::compiled_maximum().event_records,
                    },
                ))
            })?;
        let mut authorized = Vec::new();
        authorized
            .try_reserve_exact(prepared.nodes.len())
            .map_err(|_| {
                FaultActionCommitError::Fatal(FaultRuntimeError::ResourceLimit(
                    FaultResourceLimitError::Exceeded {
                        field: "event_records",
                        current: 0,
                        requested: u64::try_from(prepared.nodes.len()).unwrap_or(u64::MAX),
                        configured: self.resource_limits.event_records,
                        hard: FaultResourceLimits::compiled_maximum().event_records,
                    },
                ))
            })?;
        for prepared in prepared.nodes {
            let preparation_payload = memory_batch(&prepared.actions, [0; 32])
                .encode_preparation()
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch)
                })?;
            let preparation_sequence = self
                .nodes
                .reserve_fault_command_sequence(&prepared.node)
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::SequenceOverflow(
                        "qemu_fault_command",
                    ))
                })?;
            let preparation_header = memory_command_header(
                prepared
                    .actions
                    .first()
                    .ok_or(FaultActionCommitError::Fatal(
                        FaultRuntimeError::IncompleteAdapterState,
                    ))?,
                &prepared.node,
                prepared.coordinate,
                preparation_sequence,
                FAULT_COMMAND_FLAG_PREPARE_ONLY,
                [0; 32],
                &preparation_payload,
            )?;
            let preparation_result = self
                .nodes
                .apply_fault_command_at_current_boundary(
                    &prepared.node,
                    preparation_header,
                    &preparation_payload,
                )
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterTransactionRollback)
                })?;
            let DequeuedFaultResult::Valid {
                header: preparation_header,
                payload: preparation_evidence,
            } = preparation_result
            else {
                return Err(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ));
            };
            verify_qemu_evidence_hash(&preparation_header, &preparation_evidence)?;
            if preparation_header.status != FaultResultStatus::Prepared {
                let evidence = result_evidence_hash(&preparation_header, &preparation_evidence);
                let rejection = Self::reject(
                    prepared.actions.first().map(|action| &action.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    evidence,
                );
                return Err(FaultActionCommitError::Rejected(rejection));
            }
            let preparation = MemoryMutationBatchEvidenceV1::decode(&preparation_evidence)
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
                })?;
            let before_sha256 = preparation.before_sha256().map_err(|_source| {
                FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
            })?;
            let observed_precondition = ContentHash::from_bytes(&before_sha256);
            if let Some((action, expected)) = prepared.actions.iter().find_map(|prepared| {
                prepared
                    .action
                    .expected_precondition
                    .filter(|expected| *expected != observed_precondition)
                    .map(|expected| (&prepared.action, expected))
            }) {
                return Err(FaultActionCommitError::Rejected(Self::reject(
                    Some(action),
                    FaultRuntimeError::ReplayPreconditionMismatch {
                        action: action.id(),
                        expected,
                        observed: observed_precondition,
                    },
                    result_evidence_hash(&preparation_header, &preparation_evidence),
                )));
            }
            if preparation_header.before_hash != before_sha256
                || !memory_batch_evidence_matches(&preparation, &prepared)
            {
                let evidence = result_evidence_hash(&preparation_header, &preparation_evidence);
                let rejection = Self::reject(
                    prepared.actions.first().map(|action| &action.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    evidence,
                );
                return Err(FaultActionCommitError::Rejected(rejection));
            }
            let mutation_payload = memory_batch(&prepared.actions, preparation.precondition_sha256)
                .encode()
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch)
                })?;
            authorized.push(AuthorizedQemuNodeBatch {
                prepared,
                preparation,
                preparation_evidence_sha256: Sha256::digest(&preparation_evidence).into(),
                preparation_evidence_len: preparation_evidence.len(),
                result_buffer: preparation_evidence,
                mutation_payload,
            });
        }

        let mut authorized_typed = Vec::new();
        authorized_typed
            .try_reserve_exact(typed_actions.len())
            .map_err(|_| {
                FaultActionCommitError::Fatal(FaultRuntimeError::ResourceLimit(
                    FaultResourceLimitError::Exceeded {
                        field: "event_records",
                        current: 0,
                        requested: u64::try_from(typed_actions.len()).unwrap_or(u64::MAX),
                        configured: self.resource_limits.event_records,
                        hard: FaultResourceLimits::compiled_maximum().event_records,
                    },
                ))
            })?;
        for prepared in typed_actions {
            let request = NodeFaultPayloadV1::decode(&prepared.payload).map_err(|_source| {
                FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
            })?;
            let result_buffer =
                reserve_fault_result_storage(self.resource_limits, NODE_FAULT_EVIDENCE_V1_BYTES)?;
            let coordinate = prepared.coordinate;
            let sequence = self
                .nodes
                .reserve_fault_command_sequence(&prepared.node)
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::SequenceOverflow(
                        "qemu_fault_command",
                    ))
                })?;
            let header = typed_command_header(
                &prepared,
                coordinate,
                sequence,
                FAULT_COMMAND_FLAG_PREPARE_ONLY,
                [0; 32],
            )?;
            let result = self
                .nodes
                .apply_fault_command_at_current_boundary_with_result_buffer(
                    &prepared.node,
                    header,
                    &prepared.payload,
                    result_buffer,
                )
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterTransactionRollback)
                })?;
            let (evidence, result_buffer) = validate_typed_node_result_decoded(
                &request,
                &prepared.payload,
                result,
                FaultResultStatus::Prepared,
            )?;
            if evidence.before_sha256 != evidence.after_sha256 {
                return Err(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ));
            }
            let observed_precondition = ContentHash::from_bytes(&evidence.before_sha256);
            if let Some(expected) = prepared.action.expected_precondition
                && expected != observed_precondition
            {
                return Err(FaultActionCommitError::Rejected(Self::reject(
                    Some(&prepared.action),
                    FaultRuntimeError::ReplayPreconditionMismatch {
                        action: prepared.action.id(),
                        expected,
                        observed: observed_precondition,
                    },
                    ContentHash::from_bytes(&evidence.encode().map_err(|_source| {
                        FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
                    })?),
                )));
            }
            authorized_typed.push(AuthorizedTypedNodeAction {
                prepared,
                preparation: evidence,
                request,
                result_buffer,
            });
        }

        let mut applied = false;
        for authorized in authorized {
            let AuthorizedQemuNodeBatch {
                prepared,
                preparation,
                preparation_evidence_sha256,
                preparation_evidence_len,
                result_buffer,
                mutation_payload,
            } = authorized;
            let mutation_sequence = self
                .nodes
                .reserve_fault_command_sequence(&prepared.node)
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::SequenceOverflow(
                        "qemu_fault_command",
                    ))
                })?;
            let mutation_header = memory_command_header(
                prepared
                    .actions
                    .first()
                    .ok_or(FaultActionCommitError::Fatal(
                        FaultRuntimeError::IncompleteAdapterState,
                    ))?,
                &prepared.node,
                prepared.coordinate,
                mutation_sequence,
                FAULT_COMMAND_FLAG_NONE,
                preparation.precondition_sha256,
                &mutation_payload,
            )?;
            let result = self
                .nodes
                .apply_fault_command_at_current_boundary_with_result_buffer(
                    &prepared.node,
                    mutation_header,
                    &mutation_payload,
                    result_buffer,
                )
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterTransactionRollback)
                })?;
            let DequeuedFaultResult::Valid {
                header: result_header,
                payload: mut result_payload,
            } = result
            else {
                return Err(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ));
            };
            verify_qemu_evidence_hash(&result_header, &result_payload)?;
            if result_header.status != FaultResultStatus::Applied {
                if applied {
                    return Err(FaultActionCommitError::Fatal(
                        FaultRuntimeError::AdapterTransactionRollback,
                    ));
                }
                return Err(FaultActionCommitError::Rejected(Self::reject(
                    prepared.actions.first().map(|action| &action.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    result_evidence_hash(&result_header, &result_payload),
                )));
            }
            if result_header.before_hash
                != preparation.before_sha256().map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
                })?
                || result_header.after_hash
                    != preparation.after_sha256().map_err(|_source| {
                        FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
                    })?
                || result_payload.len() != preparation_evidence_len
                || <[u8; 32]>::from(Sha256::digest(&result_payload)) != preparation_evidence_sha256
                || !memory_batch_evidence_matches(&preparation, &prepared)
            {
                return Err(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ));
            }
            let evidence =
                memory_application_evidence_hash(&mut result_payload, preparation.actions.len())?;
            let precondition = ContentHash::from_bytes(&result_header.before_hash);
            let committed_evidence = CommittedQemuActionEvidence {
                command_sequence: mutation_sequence,
                command_kind: FaultCommandKind::MemoryMutation as u16,
                before_hash: result_header.before_hash,
                after_hash: result_header.after_hash,
            };
            applied = true;
            for prepared in prepared.actions {
                let action = prepared.action.id();
                retain_committed_evidence(&mut self.committed, action, committed_evidence)?;
                finalize_staged_result(
                    &mut results,
                    action,
                    precondition,
                    prepared.coordinate,
                    evidence,
                )?;
            }
        }
        for authorized in authorized_typed {
            let AuthorizedTypedNodeAction {
                prepared,
                preparation,
                request,
                result_buffer,
            } = authorized;
            let coordinate = prepared.coordinate;
            let sequence = self
                .nodes
                .reserve_fault_command_sequence(&prepared.node)
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::SequenceOverflow(
                        "qemu_fault_command",
                    ))
                })?;
            let header = typed_command_header(
                &prepared,
                coordinate,
                sequence,
                FAULT_COMMAND_FLAG_NONE,
                preparation.before_sha256,
            )?;
            let result = self
                .nodes
                .apply_fault_command_at_current_boundary_with_result_buffer(
                    &prepared.node,
                    header,
                    &prepared.payload,
                    result_buffer,
                )
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterTransactionRollback)
                })?;
            let (evidence, _result_buffer) = validate_typed_node_result_decoded(
                &request,
                &prepared.payload,
                result,
                FaultResultStatus::Applied,
            )?;
            let evidence_hash = typed_node_application_evidence_hash(&evidence, coordinate);
            let action = prepared.action.id();
            retain_committed_evidence(
                &mut self.committed,
                action,
                CommittedQemuActionEvidence {
                    command_sequence: sequence,
                    command_kind: prepared.command_kind as u16,
                    before_hash: evidence.before_sha256,
                    after_hash: evidence.after_sha256,
                },
            )?;
            finalize_staged_result(
                &mut results,
                action,
                ContentHash::from_bytes(&preparation.before_sha256),
                coordinate,
                evidence_hash,
            )?;
        }
        if results.iter().any(|result| result.precondition.is_none()) {
            return Err(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ));
        }
        Ok(PreparedActionBatch {
            transaction,
            results,
        })
    }
}

// crucible-lint: allow rust-allow -- the command header authenticates each independent memory action field.
#[allow(clippy::too_many_arguments)]
fn memory_command_header(
    prepared: &PreparedMemoryAction,
    node: &NodeId,
    coordinate: u64,
    sequence: u64,
    flags: u16,
    expected_precondition_hash: [u8; 32],
    payload: &[u8],
) -> Result<FaultCommandHeaderV1, FaultActionCommitError> {
    let action = &prepared.action;
    Ok(FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation,
        command_flags: flags,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: sequence,
        target_node_hash: qemu_fault_target_hash(&node.name),
        target_icount: coordinate,
        authorization_ceiling_icount: coordinate,
        binding_hash: ContentHash::from_canonical_material(
            "crucible.fault-binding.v1",
            action.binding.as_str(),
        )
        .bytes,
        opportunity_hash: action.opportunity.map_or([0; 32], |hash| hash.bytes),
        expected_precondition_hash,
        payload_hash: *blake3::hash(payload).as_bytes(),
        payload_offset: 0,
        payload_length: u32::try_from(payload.len()).map_err(|_source| {
            FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch)
        })?,
    })
}

#[cfg(test)]
#[path = "fault_action_sink_tests.rs"]
mod tests;
