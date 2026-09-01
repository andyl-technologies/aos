//! Transactional PREPARE and APPLY orchestration for live QEMU fault actions.

use super::*;

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
            let maximum_evidence = usize::try_from(self.resource_limits.effect_payload_bytes)
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::ResourceLimit(
                        FaultResourceLimitError::Exceeded {
                            field: "effect_payload_bytes",
                            current: 0,
                            requested: self.resource_limits.effect_payload_bytes,
                            configured: self.resource_limits.effect_payload_bytes,
                            hard: FaultResourceLimits::compiled_maximum().effect_payload_bytes,
                        },
                    ))
                })?;
            let event_staging_allowance = self.event_staging_allowance(&prepared.node)?;
            let preparation_result = self
                .nodes
                .apply_fault_preparation_at_current_boundary(
                    &prepared.node,
                    preparation_header,
                    &preparation_payload,
                    maximum_evidence,
                    event_staging_allowance,
                )
                .map_err(map_preparation_result_error)?;
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
                mutation_sequence: None,
                mutation_header: None,
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
            let event_staging_allowance = self.event_staging_allowance(&prepared.node)?;
            let result = self
                .nodes
                .apply_fault_command_at_current_boundary_with_limits(
                    &prepared.node,
                    header,
                    &prepared.payload,
                    result_buffer,
                    event_staging_allowance,
                )
                .map_err(map_preparation_result_error)?;
            if let Some(evidence) = typed_preparation_rejection_evidence(&result)? {
                return Err(FaultActionCommitError::Rejected(Self::reject(
                    Some(&prepared.action),
                    FaultRuntimeError::AdapterActionMismatch,
                    evidence,
                )));
            }
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
                        action: prepared.action_id,
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
                apply_sequence: None,
                apply_header: None,
            });
        }

        stage_apply_commands(self.nodes, &mut authorized, &mut authorized_typed)?;
        let mut applied = false;
        for authorized in authorized {
            let AuthorizedQemuNodeBatch {
                prepared,
                preparation,
                preparation_evidence_sha256,
                preparation_evidence_len,
                result_buffer,
                mutation_payload,
                mutation_sequence,
                mutation_header,
            } = authorized;
            let mutation_sequence = mutation_sequence.ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
            let mutation_header = mutation_header.ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
            let event_staging_allowance = self.event_staging_allowance(&prepared.node)?;
            let result = self
                .nodes
                .apply_fault_command_at_current_boundary_with_limits(
                    &prepared.node,
                    mutation_header,
                    &mutation_payload,
                    result_buffer,
                    event_staging_allowance,
                )
                .map_err(map_preparation_result_error)?;
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
                let action = prepared.action_id;
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
                apply_sequence,
                apply_header,
            } = authorized;
            let coordinate = prepared.coordinate;
            let sequence = apply_sequence.ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
            let header = apply_header.ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
            let event_staging_allowance = self.event_staging_allowance(&prepared.node)?;
            let result = self
                .nodes
                .apply_fault_command_at_current_boundary_with_limits(
                    &prepared.node,
                    header,
                    &prepared.payload,
                    result_buffer,
                    event_staging_allowance,
                )
                .map_err(map_preparation_result_error)?;
            let (evidence, _result_buffer) = validate_typed_node_result_decoded(
                &request,
                &prepared.payload,
                result,
                FaultResultStatus::Applied,
            )?;
            let evidence_hash = typed_node_application_evidence_hash(&evidence, coordinate);
            let action = prepared.action_id;
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
