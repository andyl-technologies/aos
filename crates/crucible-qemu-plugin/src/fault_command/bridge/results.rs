//! Result polling and correlation release.

use super::*;

impl FaultCommandBridge {
    pub(super) fn poll_results(
        &mut self,
        _logical_icount_offset: u64,
    ) -> Result<bool, FaultCommandBridgeError> {
        let payload_capacity = usize::try_from(HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_source| FaultCommandBridgeError::PayloadCapacity)?;
        loop {
            let mut peeked = QemuFaultResult::default();
            let mut peeked_payload_len = 0_usize;
            let status = (self.apis.peek)(&mut peeked, &mut peeked_payload_len);
            if status == 0 {
                return Ok(true);
            }
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuPeek { status });
            }
            if peeked_payload_len > payload_capacity {
                return Err(FaultCommandBridgeError::QemuPayloadLength {
                    length: peeked_payload_len,
                    capacity: payload_capacity,
                });
            }
            let is_capability_query = self.capability_queries.contains(&peeked.command_sequence)
                && peeked.status == FaultResultStatus::Applied as u16;
            let is_register_result = peeked.command_kind
                == FaultCommandKind::CpuRegisterTransform as u16
                && peeked.status == FaultResultStatus::Applied as u16
                && self.register_evidence_identity.is_some();
            let result_payload_len = if is_capability_query {
                self.capability_payload.len()
            } else if is_register_result {
                peeked_payload_len
                    .checked_add(128)
                    .ok_or(FaultCommandBridgeError::PayloadCapacity)?
            } else {
                peeked_payload_len
            };
            if !self.results.can_enqueue(result_payload_len)? {
                return Ok(false);
            }
            let mut payload = vec![0_u8; peeked_payload_len];
            let mut result = QemuFaultResult::default();
            let mut payload_len = 0_usize;
            let payload_pointer = if payload.is_empty() {
                std::ptr::null_mut()
            } else {
                payload.as_mut_ptr()
            };
            let status = (self.apis.poll)(
                &mut result,
                payload_pointer,
                payload.len(),
                &mut payload_len,
            );
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuPoll { status });
            }
            if result.command_sequence != peeked.command_sequence || result != peeked {
                return Err(FaultCommandBridgeError::QemuPeekChanged {
                    expected_sequence: peeked.command_sequence,
                    observed_sequence: result.command_sequence,
                });
            }
            if payload_len != peeked_payload_len {
                return Err(FaultCommandBridgeError::QemuPayloadLengthChanged {
                    expected: peeked_payload_len,
                    observed: payload_len,
                });
            }
            let logical_icount_offset = result
                .emitted_tick
                .checked_sub(result.observed_icount)
                .ok_or(FaultCommandBridgeError::InvalidSimTickObservation {
                    observed_tick: i64::try_from(result.emitted_tick).unwrap_or(i64::MAX),
                    raw_icount: result.observed_icount,
                })?;
            let mut result_payload = &payload[..];
            let translated_register: Vec<u8>;
            let translated_clock: Vec<u8>;
            let register_command = self
                .register_commands
                .get(&result.command_sequence)
                .cloned();
            if is_capability_query {
                self.capability_queries.remove(&result.command_sequence);
                result_payload = &self.capability_payload;
                result.evidence_hash = *blake3::hash(result_payload).as_bytes();
            } else if is_register_result && payload.starts_with(b"CRUCQRW1") {
                let identity = self
                    .register_evidence_identity
                    .as_ref()
                    .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
                translated_register = translate_register_evidence(
                    &payload,
                    RegisterEvidenceObservation {
                        identity,
                        logical_icount_offset,
                        expected_raw_icount: result.applied_icount,
                        expected_model_phase: None,
                        expected_before: result.before_hash,
                        expected_after: result.after_hash,
                    },
                    register_command
                        .as_ref()
                        .and_then(|command| command.mutation.as_ref())
                        .ok_or(FaultCommandBridgeError::RegisterEvidence)?,
                )?;
                result_payload = &translated_register;
                result.evidence_hash = *blake3::hash(result_payload).as_bytes();
            } else if result.command_kind == FaultCommandKind::ClockTransform as u16
                && payload.starts_with(b"CRUCCIM1")
            {
                translated_clock = translate_clock_impulse_evidence(
                    &payload,
                    self.clock_manifest_payload
                        .as_deref()
                        .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                    &result,
                    logical_icount_offset,
                    self.clock_commands
                        .get(&result.command_sequence)
                        .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                )?;
                result_payload = &translated_clock;
                result.evidence_hash = *blake3::hash(result_payload).as_bytes();
            }
            let header = FaultResultHeaderV2 {
                abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
                abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
                command_kind: result.command_kind,
                status: result_status(result.status)?,
                semantic_version: result.semantic_version,
                command_sequence: result.command_sequence,
                observed_icount: result.observed_icount,
                applied_icount: result.applied_icount,
                emitted_tick: result.emitted_tick,
                capability_version: result.capability_version,
                phase: boundary_phase(result.phase)?,
                before_hash: result.before_hash,
                after_hash: result.after_hash,
                evidence_hash: result.evidence_hash,
                result_payload_hash: [0; 32],
                result_offset: 0,
                result_length: 0,
            };
            self.results.enqueue(header, result_payload)?;
            if self.retain_prepared_correlation(&result) {
                continue;
            }
            if result.command_kind == FaultCommandKind::CpuRegisterTransform as u16 {
                let Some(command) = register_command else {
                    return Err(FaultCommandBridgeError::RegisterEvidence);
                };
                if result.status == FaultResultStatus::Applied as u16 {
                    match command.operation {
                        NodeFaultOperationV1::Upsert => {
                            if let Some(prior) = self
                                .active_register_bindings
                                .insert(command.binding_hash, result.command_sequence)
                                && prior != result.command_sequence
                            {
                                self.register_commands.remove(&prior);
                            }
                        }
                        NodeFaultOperationV1::Remove => {
                            if let Some(prior) =
                                self.active_register_bindings.remove(&command.binding_hash)
                            {
                                self.register_commands.remove(&prior);
                            }
                            self.register_commands.remove(&result.command_sequence);
                        }
                        NodeFaultOperationV1::Apply => {}
                    }
                } else {
                    self.register_commands.remove(&result.command_sequence);
                }
            }
            if result.command_kind == FaultCommandKind::CpuInstructionTransform as u16 {
                track_instruction_result(
                    &mut self.instruction_commands,
                    &mut self.active_instruction_bindings,
                    result.command_sequence,
                    result.status,
                )?;
            }
            if result.command_kind == FaultCommandKind::CpuException as u16
                && result.status != FaultResultStatus::Applied as u16
            {
                self.exception_commands.remove(&result.command_sequence);
            }
            if result.command_kind == FaultCommandKind::MemoryEccEvent as u16
                && result.status != FaultResultStatus::Applied as u16
            {
                self.memory_ecc_commands.remove(&result.command_sequence);
            }
            if matches!(
                result.command_kind,
                value if value == FaultCommandKind::ClockTransform as u16
                    || value == FaultCommandKind::ClockSourceState as u16
            ) {
                let command = self
                    .clock_commands
                    .get(&result.command_sequence)
                    .cloned()
                    .ok_or(FaultCommandBridgeError::ClockEvidence)?;
                if result.status == FaultResultStatus::Applied as u16 {
                    match command.operation {
                        NodeFaultOperationV1::Upsert => {
                            let _prior = self
                                .active_clock_bindings
                                .insert(command.binding_hash, result.command_sequence);
                        }
                        NodeFaultOperationV1::Remove => {
                            let _prior = self.active_clock_bindings.remove(&command.binding_hash);
                            self.clock_commands.remove(&result.command_sequence);
                        }
                        NodeFaultOperationV1::Apply => {}
                    }
                } else {
                    self.clock_commands.remove(&result.command_sequence);
                }
            }
            if matches!(
                result.command_kind,
                value if value == FaultCommandKind::AcceleratorLifecycle as u16
                    || value == FaultCommandKind::AcceleratorResultTransform as u16
                    || value == FaultCommandKind::AcceleratorMemoryEvent as u16
                    || value == FaultCommandKind::AcceleratorService as u16
            ) {
                let command = self
                    .accelerator_commands
                    .get(&result.command_sequence)
                    .cloned()
                    .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
                if result.status == FaultResultStatus::Applied as u16 {
                    match command.operation {
                        NodeFaultOperationV1::Upsert => {
                            if let Some(prior) = self
                                .active_accelerator_bindings
                                .insert(command.binding_hash, result.command_sequence)
                                && prior != result.command_sequence
                            {
                                self.accelerator_commands.remove(&prior);
                            }
                        }
                        NodeFaultOperationV1::Remove => {
                            if let Some(prior) = self
                                .active_accelerator_bindings
                                .remove(&command.binding_hash)
                            {
                                self.accelerator_commands.remove(&prior);
                            }
                            self.accelerator_commands.remove(&result.command_sequence);
                        }
                        NodeFaultOperationV1::Apply => {}
                    }
                } else {
                    self.accelerator_commands.remove(&result.command_sequence);
                }
            }
        }
    }
}
