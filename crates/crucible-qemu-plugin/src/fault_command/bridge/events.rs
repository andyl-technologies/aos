//! Event polling and local result publication.

use super::*;

impl FaultCommandBridge {
    pub(super) fn poll_events(
        &mut self,
        _logical_icount_offset: u64,
    ) -> Result<bool, FaultCommandBridgeError> {
        let payload_capacity = node_event_envelope_maximum_bytes()?;
        loop {
            let mut peeked = QemuFaultEvent::default();
            let mut peeked_payload_len = 0_usize;
            let status = (self.apis.event_peek)(&mut peeked, &mut peeked_payload_len);
            if status == 0 {
                return Ok(true);
            }
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuEventPeek { status });
            }
            if peeked_payload_len == 0 || peeked_payload_len > payload_capacity {
                return Err(FaultCommandBridgeError::QemuEventPayloadLength {
                    length: peeked_payload_len,
                    capacity: payload_capacity,
                });
            }
            let evidence_length = usize::try_from(peeked.evidence_length)
                .map_err(|_source| FaultCommandBridgeError::EventEnvelope)?;
            let hard_evidence_limit = usize::try_from(HARD_FAULT_PAYLOAD_BYTES)
                .map_err(|_source| FaultCommandBridgeError::PayloadCapacity)?;
            if evidence_length == 0 || evidence_length > hard_evidence_limit {
                return Err(FaultCommandBridgeError::EventEnvelope);
            }
            let published_payload_len = if matches!(
                peeked.command_kind,
                value if value == FaultCommandKind::CpuRegisterTransform as u16
                    || value == FaultCommandKind::CpuInstructionTransform as u16
            ) {
                evidence_length
                    .checked_add(128)
                    .ok_or(FaultCommandBridgeError::PayloadCapacity)?
            } else {
                evidence_length
            };
            if !self.events.can_enqueue(published_payload_len)? {
                return Ok(false);
            }
            let mut payload = vec![0_u8; peeked_payload_len];
            let mut event = QemuFaultEvent::default();
            let mut payload_len = 0_usize;
            let status = (self.apis.event_poll)(
                &mut event,
                payload.as_mut_ptr(),
                payload.len(),
                &mut payload_len,
            );
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuEventPoll { status });
            }
            if event != peeked {
                return Err(FaultCommandBridgeError::QemuEventPeekChanged {
                    expected_sequence: peeked.event_sequence,
                    observed_sequence: event.event_sequence,
                });
            }
            if payload_len != peeked_payload_len {
                return Err(FaultCommandBridgeError::QemuEventPayloadLengthChanged {
                    expected: peeked_payload_len,
                    observed: payload_len,
                });
            }
            if event.event_sequence == 0 {
                return Err(FaultCommandBridgeError::QemuEventSequenceZero);
            }
            let envelope = decode_node_event_envelope(&payload, &event, self.target_node_hash)?;
            let request_payload = envelope.request;
            let payload = envelope.evidence;
            let logical_icount_offset = event
                .observed_tick
                .checked_sub(
                    event
                        .observed_icount
                        .checked_mul(crucible_shmem::TICKS_PER_INSTRUCTION)
                        .ok_or(FaultCommandBridgeError::CoordinateOverflow)?,
                )
                .ok_or(FaultCommandBridgeError::InvalidSimTickObservation {
                    observed_tick: i64::try_from(event.observed_tick).unwrap_or(i64::MAX),
                    raw_icount: event.observed_icount,
                })?;
            let observed_logical_tick = event.observed_tick;
            let event_command_kind = command_kind(event.command_kind)?;
            let register_command = if event_command_kind == FaultCommandKind::CpuRegisterTransform {
                Some(register_command_expectation(
                    request_payload,
                    event.binding_hash,
                    self.register_evidence_identity
                        .as_ref()
                        .ok_or(FaultCommandBridgeError::RegisterEvidence)?,
                )?)
            } else {
                None
            };
            if register_command
                .as_ref()
                .is_some_and(|command| command.binding_hash != event.binding_hash)
            {
                return Err(FaultCommandBridgeError::RegisterEvidence);
            }
            let instruction_command =
                if event_command_kind == FaultCommandKind::CpuInstructionTransform {
                    Some(instruction_command_expectation(
                        request_payload,
                        event.binding_hash,
                        self.register_evidence_identity
                            .as_ref()
                            .ok_or(FaultCommandBridgeError::InstructionEvidence)?,
                    )?)
                } else {
                    None
                };
            let exception_command = if event_command_kind == FaultCommandKind::CpuException {
                Some(exception_command_expectation(
                    request_payload,
                    event.binding_hash,
                )?)
            } else {
                None
            };
            let memory_ecc_command = if event_command_kind == FaultCommandKind::MemoryEccEvent {
                Some(memory_ecc_command_expectation(
                    request_payload,
                    event.binding_hash,
                )?)
            } else {
                None
            };
            let clock_command = if matches!(
                event_command_kind,
                FaultCommandKind::ClockTransform | FaultCommandKind::ClockSourceState
            ) {
                Some(clock_command_expectation(
                    request_payload,
                    event.binding_hash,
                    event_command_kind,
                )?)
            } else {
                None
            };
            let accelerator_command = if matches!(
                event_command_kind,
                FaultCommandKind::AcceleratorLifecycle
                    | FaultCommandKind::AcceleratorResultTransform
                    | FaultCommandKind::AcceleratorMemoryEvent
                    | FaultCommandKind::AcceleratorService
            ) {
                Some(accelerator_command_expectation(
                    request_payload,
                    event.binding_hash,
                    event_command_kind,
                )?)
            } else {
                None
            };
            if let Some(command) = &instruction_command {
                self.instruction_commands
                    .entry(event.rule_command_sequence)
                    .or_insert_with(|| command.clone());
            }
            let instruction_terminal = event.command_kind
                == FaultCommandKind::CpuInstructionTransform as u16
                && FaultTerminalEvidenceV1::has_magic(payload);
            let published_payload = if matches!(
                event_command_kind,
                FaultCommandKind::NodeLifecycle | FaultCommandKind::NodeHang
            ) && payload.get(..8) == Some(b"CRUCLIF1")
            {
                translate_lifecycle_evidence(payload, &event, logical_icount_offset)?
            } else if event.command_kind == FaultCommandKind::CpuRegisterTransform as u16 {
                let identity = self
                    .register_evidence_identity
                    .as_ref()
                    .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
                translate_register_evidence(
                    payload,
                    RegisterEvidenceObservation {
                        identity,
                        logical_icount_offset,
                        expected_raw_icount: event.observed_icount,
                        expected_model_phase: Some(event.model_phase),
                        expected_before: event.before_hash,
                        expected_after: event.after_hash,
                    },
                    register_command
                        .as_ref()
                        .and_then(|command| command.mutation.as_ref())
                        .ok_or(FaultCommandBridgeError::RegisterEvidence)?,
                )?
            } else if event.command_kind == FaultCommandKind::CpuInstructionTransform as u16 {
                let command = instruction_command
                    .as_ref()
                    .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
                if instruction_terminal {
                    translate_terminal_instruction_evidence(payload, &event, command)?
                } else {
                    translate_instruction_evidence(
                        payload,
                        self.instruction_evidence_identity
                            .as_ref()
                            .ok_or(FaultCommandBridgeError::InstructionEvidence)?,
                        self.register_evidence_identity
                            .as_ref()
                            .ok_or(FaultCommandBridgeError::InstructionEvidence)?,
                        logical_icount_offset,
                        &event,
                        command,
                    )?
                }
            } else if event.command_kind == FaultCommandKind::CpuException as u16 {
                let command = exception_command
                    .as_ref()
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
                if payload.len() == 648 {
                    translate_hardware_exception_evidence(
                        payload,
                        self.hardware_error_manifest_payload
                            .as_deref()
                            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        &event,
                        command,
                    )?
                } else {
                    translate_exception_evidence(
                        payload,
                        self.instruction_evidence_identity
                            .as_ref()
                            .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
                        logical_icount_offset,
                        &event,
                        command,
                    )?
                }
            } else if event.command_kind == FaultCommandKind::MemoryEccEvent as u16 {
                translate_hardware_ecc_evidence(
                    payload,
                    self.hardware_error_manifest_payload
                        .as_deref()
                        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                    &event,
                    memory_ecc_command
                        .as_ref()
                        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                )?
            } else if event.command_kind == FaultCommandKind::ClockTransform as u16
                || event.command_kind == FaultCommandKind::ClockSourceState as u16
            {
                translate_clock_evidence(
                    payload,
                    self.clock_manifest_payload
                        .as_deref()
                        .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                    &event,
                    observed_logical_tick,
                    clock_command
                        .as_ref()
                        .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                )?
            } else if matches!(
                event.command_kind,
                value if value == FaultCommandKind::AcceleratorLifecycle as u16
                    || value == FaultCommandKind::AcceleratorResultTransform as u16
                    || value == FaultCommandKind::AcceleratorMemoryEvent as u16
                    || value == FaultCommandKind::AcceleratorService as u16
            ) {
                translate_accelerator_evidence(
                    payload,
                    &event,
                    self.accelerator_manifest_payload
                        .as_deref()
                        .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?,
                    accelerator_command
                        .as_ref()
                        .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?,
                )?
            } else {
                payload.to_vec()
            };
            if event.command_kind == FaultCommandKind::CpuInstructionTransform as u16 {
                if instruction_terminal {
                    track_terminal_instruction_event(
                        &mut self.instruction_commands,
                        &mut self.active_instruction_bindings,
                        event.rule_command_sequence,
                    )?;
                } else {
                    track_instruction_event(
                        &mut self.instruction_commands,
                        event.rule_command_sequence,
                        &published_payload,
                    )?;
                }
            }
            let header = FaultEventHeaderV1 {
                command_kind: event_command_kind,
                outcome: event_outcome(event.outcome)?,
                event_sequence: event.event_sequence,
                rule_command_sequence: event.rule_command_sequence,
                observed_icount: observed_logical_tick,
                model_phase: event.model_phase,
                target_kind: event.target_kind,
                generation: event.generation,
                binding_hash: event.binding_hash,
                opportunity_hash: event.opportunity_hash,
                action_hash: event.action_hash,
                target_hash: event.target_hash,
                before_hash: event.before_hash,
                after_hash: event.after_hash,
                evidence_hash: [0; 32],
                payload_hash: [0; 32],
                payload_offset: 0,
                payload_length: 0,
            };
            self.events.enqueue(header, &published_payload)?;
            if let Some(command) = register_command
                && command.operation == NodeFaultOperationV1::Apply
            {
                self.register_commands.remove(&event.rule_command_sequence);
            }
            if event.command_kind == FaultCommandKind::CpuException as u16 {
                self.exception_commands.remove(&event.rule_command_sequence);
            }
            if event.command_kind == FaultCommandKind::MemoryEccEvent as u16 {
                self.memory_ecc_commands
                    .remove(&event.rule_command_sequence);
            }
            if clock_command
                .as_ref()
                .is_some_and(|command| command.operation == NodeFaultOperationV1::Apply)
            {
                self.clock_commands.remove(&event.rule_command_sequence);
            }
            if accelerator_command
                .as_ref()
                .is_some_and(|command| command.operation == NodeFaultOperationV1::Apply)
            {
                self.accelerator_commands
                    .remove(&event.rule_command_sequence);
            }
        }
    }

    pub(super) fn publish_local_rejection(
        &mut self,
        command_kind: u16,
        command_sequence: u64,
        phase: FaultBoundaryPhase,
        status: FaultResultStatus,
        logical_icount: u64,
        logical_icount_offset: u64,
    ) -> Result<(), FaultCommandBridgeError> {
        let raw_icount = logical_icount
            .checked_sub(logical_icount_offset)
            .filter(|raw_tick| raw_tick % crucible_shmem::TICKS_PER_INSTRUCTION == 0)
            .map(|raw_tick| raw_tick / crucible_shmem::TICKS_PER_INSTRUCTION)
            .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
        let header = FaultResultHeaderV2 {
            abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
            abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
            command_kind,
            status,
            semantic_version: crucible_shmem::FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence,
            observed_icount: raw_icount,
            applied_icount: 0,
            emitted_tick: logical_icount,
            capability_version: 1,
            phase,
            before_hash: [0; 32],
            after_hash: [0; 32],
            evidence_hash: [0; 32],
            result_payload_hash: [0; 32],
            result_offset: 0,
            result_length: 0,
        };
        self.results.enqueue(header, &[])
    }

    pub(super) fn publish_local_applied(
        &mut self,
        command_kind: u16,
        command_sequence: u64,
        phase: FaultBoundaryPhase,
        logical_icount: u64,
        logical_icount_offset: u64,
        payload: &[u8],
    ) -> Result<(), FaultCommandBridgeError> {
        let raw_icount = logical_icount
            .checked_sub(logical_icount_offset)
            .filter(|raw_tick| raw_tick % crucible_shmem::TICKS_PER_INSTRUCTION == 0)
            .map(|raw_tick| raw_tick / crucible_shmem::TICKS_PER_INSTRUCTION)
            .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
        let header = FaultResultHeaderV2 {
            abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
            abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
            command_kind,
            status: FaultResultStatus::Applied,
            semantic_version: crucible_shmem::FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence,
            observed_icount: raw_icount,
            applied_icount: raw_icount,
            emitted_tick: logical_icount,
            capability_version: 1,
            phase,
            before_hash: [0; 32],
            after_hash: [0; 32],
            evidence_hash: *blake3::hash(payload).as_bytes(),
            result_payload_hash: [0; 32],
            result_offset: 0,
            result_length: 0,
        };
        self.results.enqueue(header, payload)
    }
}
