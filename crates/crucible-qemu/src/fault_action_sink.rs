//! Production signal-driven node actions backed by live patched QEMU.
//!
//! Preparation performs only closed-schema and admitted-capability validation.
//! Commit publishes exact-boundary commands and derives durable observations
//! from authenticated QEMU results. Any ambiguous visibility is fatal; it is
//! never converted into an unchanged adapter rejection.

use crucible::model::{
    BindingActionKind, ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION,
    FaultActionCommitError, FaultActionSink, FaultObservation, FaultObservationKind, FaultPhase,
    FaultRuntimeError, MemoryAddressSpace, MemoryMutationAtomicity as ModelMemoryMutationAtomicity,
    MemoryMutationKind, NodeEffectSpecification, NodeId, PreparedActionBatch, PreparedActionResult,
    RejectedActionBatch, ResolvedBindingAction, ResolvedFaultTarget,
};
use crucible_shmem::{
    DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_FLAG_NONE,
    FAULT_COMMAND_FLAG_PREPARE_ONLY, FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase,
    FaultCommandHeaderV1, FaultCommandKind, FaultResultStatus, MEMORY_MUTATION_NO_VCPU,
    MemoryMutationAddressSpace, MemoryMutationAtomicity, MemoryMutationBatchActionV1,
    MemoryMutationBatchEvidenceV1, MemoryMutationBatchV1, MemoryMutationEvidenceV1,
    MemoryMutationPayloadV1, MemoryMutationTransformKind, NodeFaultEvidenceV1, NodeFaultPayloadV1,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

use crate::{QemuNodeSet, qemu_fault_target_hash};

#[path = "fault_action_sink/node_payload.rs"]
mod node_payload;

#[derive(Clone)]
struct PreparedMemoryAction {
    action: ResolvedBindingAction,
    node: NodeId,
    payload: MemoryMutationPayloadV1,
}

#[derive(Clone)]
struct PreparedQemuBatch {
    transaction: ContentHash,
    action_order: Vec<ContentHash>,
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
    command_kind: FaultCommandKind,
    payload: Vec<u8>,
}

struct AuthorizedQemuNodeBatch {
    prepared: PreparedQemuNodeBatch,
    preparation: MemoryMutationBatchEvidenceV1,
    mutation_payload: Vec<u8>,
}

/// A production node-adapter sink that mutates live patched-QEMU backends.
pub struct QemuFaultActionSink<'a> {
    nodes: &'a mut QemuNodeSet,
    prepared: Option<PreparedQemuBatch>,
}

impl<'a> QemuFaultActionSink<'a> {
    /// Binds a transaction sink to the live node set for one scheduler boundary.
    #[must_use]
    pub const fn new(nodes: &'a mut QemuNodeSet) -> Self {
        Self {
            nodes,
            prepared: None,
        }
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
        &self,
        action: &ResolvedBindingAction,
    ) -> Result<PreparedMemoryAction, FaultRuntimeError> {
        if action.kind != BindingActionKind::Apply || action.phase != FaultPhase::Boundary {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        }
        let ResolvedFaultTarget::MemoryRange {
            node,
            address_space,
            guest_address,
            vcpu,
            length_bytes,
        } = &action.target
        else {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        };
        let EffectSpecification::Node(NodeEffectSpecification::MemoryMutation {
            address_space: requested_address_space,
            range,
            mutation,
            atomicity,
        }) = action.effect.specification()
        else {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        };
        let target_address_space = match (address_space.as_str(), vcpu) {
            ("gpa", None) => MemoryAddressSpace::GuestPhysical,
            ("gva", Some(_)) => MemoryAddressSpace::GuestVirtual,
            _ => return Err(FaultRuntimeError::AdapterActionMismatch),
        };
        if target_address_space != *requested_address_space
            || *atomicity != ModelMemoryMutationAtomicity::AllOrNothing
            || range.start() != *guest_address
            || range.length() != *length_bytes
        {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        }
        let length = usize::try_from(*length_bytes)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let (transform, mask, values) = match mutation {
            MemoryMutationKind::BitFlip { mask } => {
                let pattern = mask.decode();
                let mask = pattern.iter().copied().cycle().take(length).collect();
                (MemoryMutationTransformKind::BitFlip, mask, Vec::new())
            }
            MemoryMutationKind::Replace { bytes } => (
                MemoryMutationTransformKind::Replace,
                vec![0xff; length],
                bytes.decode(),
            ),
        };
        let (address_space, vcpu_index) = match target_address_space {
            MemoryAddressSpace::GuestPhysical => (
                MemoryMutationAddressSpace::GuestPhysical,
                MEMORY_MUTATION_NO_VCPU,
            ),
            MemoryAddressSpace::GuestVirtual => (
                MemoryMutationAddressSpace::GuestVirtual,
                (*vcpu).ok_or(FaultRuntimeError::AdapterActionMismatch)?,
            ),
        };
        let payload = MemoryMutationPayloadV1 {
            address_space,
            transform,
            atomicity: MemoryMutationAtomicity::AllOrNothing,
            vcpu_index,
            address: *guest_address,
            mask,
            values,
            expected_translation_sha256: [0; 32],
        };
        let encoded = payload
            .encode_preparation()
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let node = NodeId {
            name: node.as_str().to_owned(),
        };
        let admitted = self
            .nodes
            .fault_capabilities(&node)
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
        Ok(PreparedMemoryAction {
            action: action.clone(),
            node,
            payload,
        })
    }

    fn prepare_typed_action(
        &self,
        action: &ResolvedBindingAction,
    ) -> Result<PreparedTypedNodeAction, FaultRuntimeError> {
        let provisional = node_payload::encode_node_action(action, [1; 32])
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let node = NodeId {
            name: provisional.node,
        };
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
        let encoded = node_payload::encode_node_action(action, capability.capability_hash)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let payload = encoded
            .payload
            .encode()
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        if !usize::try_from(capability.maximum_payload_bytes)
            .is_ok_and(|maximum| payload.len() <= maximum)
        {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        }
        Ok(PreparedTypedNodeAction {
            action: action.clone(),
            node,
            command_kind: encoded.command_kind,
            payload,
        })
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
                if prepared.action.coordinate.retired_instructions.is_none() {
                    return Err(Self::reject(
                        Some(action),
                        FaultRuntimeError::AdapterActionMismatch,
                        ContentHash::from_bytes(b"qemu-missing-node-coordinate"),
                    ));
                }
                typed_actions.push(prepared);
            }
        }
        let mut node_batches = Vec::with_capacity(by_node.len());
        for (node, prepared) in by_node {
            let Some(coordinate) = prepared
                .first()
                .and_then(|action| action.action.coordinate.retired_instructions)
            else {
                return Err(Self::reject(
                    prepared.first().map(|action| &action.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    ContentHash::from_bytes(b"qemu-missing-node-coordinate"),
                ));
            };
            if prepared
                .iter()
                .any(|action| action.action.coordinate.retired_instructions != Some(coordinate))
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
                observation: applied_observation(
                    action,
                    ContentHash::from_bytes(b"qemu-predicted-evidence"),
                ),
            })
            .collect();
        self.prepared = Some(PreparedQemuBatch {
            transaction,
            action_order: actions.iter().map(ResolvedBindingAction::id).collect(),
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
        let action_order = prepared.action_order;
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
        let mut authorized = Vec::with_capacity(prepared.nodes.len());
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
                mutation_payload,
            });
        }

        let mut authorized_typed = Vec::with_capacity(typed_actions.len());
        for prepared in typed_actions {
            let coordinate = prepared.action.coordinate.retired_instructions.ok_or(
                FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch),
            )?;
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
                .apply_fault_command_at_current_boundary(&prepared.node, header, &prepared.payload)
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterTransactionRollback)
                })?;
            let evidence = validate_typed_result(&prepared, result, FaultResultStatus::Prepared)?;
            if evidence.before_sha256 != evidence.after_sha256 {
                return Err(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ));
            }
            let observed_precondition = ContentHash::from_bytes(&evidence.before_sha256);
            if let Some(expected) = prepared.action.expected_precondition {
                if expected != observed_precondition {
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
            }
            authorized_typed.push((prepared, evidence));
        }

        let mut results = Vec::with_capacity(total_actions);
        let mut applied = false;
        for authorized in authorized {
            let AuthorizedQemuNodeBatch {
                prepared,
                preparation,
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
                .apply_fault_command_at_current_boundary(
                    &prepared.node,
                    mutation_header,
                    &mutation_payload,
                )
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterTransactionRollback)
                })?;
            let DequeuedFaultResult::Valid {
                header: result_header,
                payload: result_payload,
            } = result
            else {
                return Err(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ));
            };
            verify_qemu_evidence_hash(&result_header, &result_payload)?;
            let mut evidence = result_header.encode().to_vec();
            evidence.extend_from_slice(&result_payload);
            let evidence = ContentHash::from_bytes(&evidence);
            if result_header.status != FaultResultStatus::Applied {
                let rejection = Self::reject(
                    prepared.actions.first().map(|action| &action.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    evidence,
                );
                if applied {
                    return Err(FaultActionCommitError::Fatal(
                        FaultRuntimeError::AdapterTransactionRollback,
                    ));
                }
                return Err(FaultActionCommitError::Rejected(rejection));
            }
            let committed =
                MemoryMutationBatchEvidenceV1::decode(&result_payload).map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
                })?;
            if result_header.before_hash
                != committed.before_sha256().map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
                })?
                || result_header.after_hash
                    != committed.after_sha256().map_err(|_source| {
                        FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
                    })?
                || committed != preparation
                || !memory_batch_evidence_matches(&committed, &prepared)
            {
                return Err(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ));
            }
            let precondition = ContentHash::from_bytes(&result_header.before_hash);
            applied = true;
            results.extend(
                prepared
                    .actions
                    .into_iter()
                    .map(|prepared| PreparedActionResult {
                        action: prepared.action.id(),
                        precondition: Some(precondition),
                        observation: applied_observation(&prepared.action, evidence),
                    }),
            );
        }
        for (prepared, preparation) in authorized_typed {
            let coordinate = prepared.action.coordinate.retired_instructions.ok_or(
                FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch),
            )?;
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
                .apply_fault_command_at_current_boundary(&prepared.node, header, &prepared.payload)
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::AdapterTransactionRollback)
                })?;
            let evidence = validate_typed_result(&prepared, result, FaultResultStatus::Applied)?;
            if evidence.before_sha256 != preparation.before_sha256 {
                return Err(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ));
            }
            let evidence_hash = ContentHash::from_bytes(&evidence.encode().map_err(|_source| {
                FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
            })?);
            results.push(PreparedActionResult {
                action: prepared.action.id(),
                precondition: Some(ContentHash::from_bytes(&preparation.before_sha256)),
                observation: applied_observation(&prepared.action, evidence_hash),
            });
        }
        let mut by_action = results
            .into_iter()
            .map(|result| (result.action, result))
            .collect::<BTreeMap<_, _>>();
        let results = action_order
            .into_iter()
            .map(|action| by_action.remove(&action))
            .collect::<Option<Vec<_>>>()
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
        if !by_action.is_empty() {
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

fn typed_command_header(
    prepared: &PreparedTypedNodeAction,
    coordinate: u64,
    sequence: u64,
    flags: u16,
    expected_precondition_hash: [u8; 32],
) -> Result<FaultCommandHeaderV1, FaultActionCommitError> {
    let payload_length = u32::try_from(prepared.payload.len()).map_err(|_source| {
        FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch)
    })?;
    Ok(FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: prepared.command_kind,
        command_flags: flags,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: sequence,
        target_node_hash: qemu_fault_target_hash(&prepared.node.name),
        target_icount: coordinate,
        authorization_ceiling_icount: coordinate,
        binding_hash: ContentHash::from_canonical_material(
            "crucible.fault-binding.v1",
            prepared.action.binding.as_str(),
        )
        .bytes,
        opportunity_hash: prepared
            .action
            .opportunity
            .map_or([0; 32], |hash| hash.bytes),
        expected_precondition_hash,
        payload_hash: *blake3::hash(&prepared.payload).as_bytes(),
        payload_offset: 0,
        payload_length,
    })
}

fn validate_typed_result(
    prepared: &PreparedTypedNodeAction,
    result: DequeuedFaultResult,
    expected_status: FaultResultStatus,
) -> Result<NodeFaultEvidenceV1, FaultActionCommitError> {
    let DequeuedFaultResult::Valid {
        header,
        payload: evidence_bytes,
    } = result
    else {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ));
    };
    verify_qemu_evidence_hash(&header, &evidence_bytes)?;
    if header.status != expected_status {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::AdapterActionMismatch,
        ));
    }
    let request = NodeFaultPayloadV1::decode(&prepared.payload).map_err(|_source| {
        FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
    })?;
    let evidence = NodeFaultEvidenceV1::decode(&evidence_bytes).map_err(|_source| {
        FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
    })?;
    let request_sha256: [u8; 32] = Sha256::digest(&prepared.payload).into();
    if evidence.command_kind != request.command_kind
        || evidence.operation != request.operation
        || evidence.target_kind != request.target_kind
        || evidence.model_phase != request.model_phase
        || evidence.generation != request.generation
        || evidence.action_hash != request.action_hash
        || evidence.target_hash != request.target_hash
        || evidence.schema_hash != request.schema_hash
        || evidence.request_sha256 != request_sha256
        || header.before_hash != evidence.before_sha256
        || header.after_hash != evidence.after_sha256
    {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ));
    }
    Ok(evidence)
}

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

fn memory_batch(
    actions: &[PreparedMemoryAction],
    expected_precondition_sha256: [u8; 32],
) -> MemoryMutationBatchV1 {
    MemoryMutationBatchV1 {
        actions: actions
            .iter()
            .map(|prepared| MemoryMutationBatchActionV1 {
                action_hash: prepared.action.id().bytes,
                mutation: prepared.payload.clone(),
            })
            .collect(),
        expected_precondition_sha256,
    }
}

fn memory_batch_evidence_matches(
    evidence: &MemoryMutationBatchEvidenceV1,
    prepared: &PreparedQemuNodeBatch,
) -> bool {
    evidence.actions.len() == prepared.actions.len()
        && evidence
            .actions
            .iter()
            .zip(&prepared.actions)
            .all(|(evidence, prepared_action)| {
                evidence.action_hash == prepared_action.action.id().bytes
                    && memory_evidence_matches(
                        &evidence.evidence,
                        &prepared_action.payload,
                        prepared.coordinate,
                        qemu_fault_target_hash(&prepared.node.name),
                    )
            })
}

fn memory_evidence_matches(
    evidence: &MemoryMutationEvidenceV1,
    payload: &MemoryMutationPayloadV1,
    coordinate: u64,
    target_node_hash: [u8; 32],
) -> bool {
    evidence.address_space == payload.address_space
        && evidence.transform == payload.transform
        && evidence.vcpu_index == payload.vcpu_index
        && evidence.address == payload.address
        && usize::try_from(evidence.length) == Ok(payload.mask.len())
        && evidence.observed_icount == coordinate
        && evidence.target_node_hash == target_node_hash
}

fn result_evidence_hash(
    header: &crucible_shmem::FaultResultHeaderV1,
    payload: &[u8],
) -> ContentHash {
    let mut material = header.encode().to_vec();
    material.extend_from_slice(payload);
    ContentHash::from_bytes(&material)
}

fn verify_qemu_evidence_hash(
    header: &crucible_shmem::FaultResultHeaderV1,
    payload: &[u8],
) -> Result<(), FaultActionCommitError> {
    let observed: [u8; 32] = Sha256::digest(payload).into();
    if observed != header.evidence_hash {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ));
    }
    Ok(())
}

fn applied_observation(action: &ResolvedBindingAction, evidence: ContentHash) -> FaultObservation {
    let kind = match action.kind {
        BindingActionKind::UpsertPersistent => FaultObservationKind::BindingActivation,
        BindingActionKind::RemovePersistent => FaultObservationKind::BindingDeactivation,
        BindingActionKind::Apply => FaultObservationKind::EffectApplied,
    };
    FaultObservation {
        semantic_version: FAULT_RUNTIME_STATE_VERSION,
        kind,
        coordinate: action.coordinate,
        binding: Some(action.binding.clone()),
        target: Some(action.target.clone()),
        opportunity: action.opportunity,
        evidence,
    }
}
