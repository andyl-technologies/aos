//! Live command/result/event bridge operations.

use super::*;
impl FaultCommandBridge {
    /// Retains correlation until QEMU publishes a terminal command result.
    pub(super) fn retain_prepared_correlation(&mut self, result: &QemuFaultResult) -> bool {
        if result.status != FaultResultStatus::Prepared as u16 {
            self.prepared_commands.remove(&result.command_sequence);
            self.prepare_only_commands.remove(&result.command_sequence);
            return false;
        }

        self.prepared_commands.insert(result.command_sequence);
        true
    }

    /// Releases terminal prepare-only correlations before the next command.
    pub(super) fn release_prepare_only_correlations(&mut self, next_sequence: u64) {
        let completed = self
            .prepare_only_commands
            .range(..next_sequence)
            .copied()
            .filter(|sequence| self.prepared_commands.contains(sequence))
            .collect::<Vec<_>>();
        for sequence in completed {
            self.register_commands.remove(&sequence);
            self.instruction_commands.remove(&sequence);
            self.exception_commands.remove(&sequence);
            self.memory_ecc_commands.remove(&sequence);
            self.clock_commands.remove(&sequence);
            self.accelerator_commands.remove(&sequence);
            self.prepared_commands.remove(&sequence);
            self.prepare_only_commands.remove(&sequence);
        }
    }

    /// Builds the bridge and snapshots the immutable QEMU capability registry.
    pub(crate) fn new(
        apis: QemuFaultCommandApis,
        target_node_hash: [u8; 32],
        region: &mut MappedSetupRegion,
        vm_slot: u32,
    ) -> Result<Self, FaultCommandBridgeError> {
        if target_node_hash == [0; 32] {
            return Err(FaultCommandBridgeError::ZeroTargetNodeHash);
        }
        let commands = StableFaultCommandTransport::new(
            region
                .fault_command_transport_mut(vm_slot)
                .map_err(|source| FaultCommandBridgeError::MappedTransport { source })?,
        )?;
        let results = StableFaultResultTransport::new(
            region
                .fault_result_transport_mut(vm_slot)
                .map_err(|source| FaultCommandBridgeError::MappedTransport { source })?,
        )?;
        let events = StableFaultEventTransport::new(
            region
                .fault_event_transport_mut(vm_slot)
                .map_err(|source| FaultCommandBridgeError::MappedTransport { source })?,
        )?;
        Ok(Self {
            apis,
            target_node_hash,
            commands,
            results,
            events,
            last_sequence: 0,
            capability_payload: Vec::new(),
            capability_queries: BTreeSet::new(),
            register_manifest_payload: None,
            interrupt_manifest_payload: None,
            hardware_error_manifest_payload: None,
            clock_manifest_payload: None,
            accelerator_manifest_payload: None,
            system_manifest_payload: Vec::new(),
            register_evidence_identity: None,
            instruction_evidence_identity: None,
            register_commands: BTreeMap::new(),
            active_register_bindings: BTreeMap::new(),
            instruction_commands: BTreeMap::new(),
            active_instruction_bindings: BTreeMap::new(),
            exception_commands: BTreeMap::new(),
            memory_ecc_commands: BTreeMap::new(),
            clock_commands: BTreeMap::new(),
            active_clock_bindings: BTreeMap::new(),
            accelerator_commands: BTreeMap::new(),
            active_accelerator_bindings: BTreeMap::new(),
            prepared_commands: BTreeSet::new(),
            prepare_only_commands: BTreeSet::new(),
            pending_command: None,
            initialized: false,
        })
    }

    /// Admits the realized QEMU capability and target manifests exactly once.
    ///
    /// QEMU invokes its plugin installer before CPU objects are realized. The
    /// first vCPU-init callback is therefore the earliest boundary at which an
    /// architecture manifest can be both complete and immutable.
    pub(crate) fn initialize(&mut self) -> Result<(), FaultCommandBridgeError> {
        if self.initialized {
            return Ok(());
        }
        let apis = self.apis;
        let mut rows = initialization_stage("capability registry", apis.capability_rows())?;
        let (register_manifest_payload, register_evidence_identity) = if rows.iter().any(|row| {
            row.command_kind == FaultCommandKind::CpuRegisterTransform
                && row.required_feature_bits & FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION != 0
        }) {
            let manifest = initialization_stage("register manifest", apis.register_manifest())?;
            initialization_stage(
                "register manifest binding",
                apis.bind_register_manifest(&manifest),
            )?;
            let payload = manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            let manifest_digest = fault_register_manifest_digest_v1(&manifest)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            let evidence_identity = RegisterEvidenceIdentity {
                architecture: manifest.architecture,
                manifest_digest,
                cpu_model_digest: fault_register_cpu_model_digest_v1(
                    manifest.architecture,
                    &manifest.cpu_model,
                ),
                rows: manifest.rows.clone(),
            };
            let register_row = rows
                .iter_mut()
                .find(|row| row.command_kind == FaultCommandKind::CpuRegisterTransform)
                .ok_or(FaultCommandBridgeError::RegisterCapabilityMissing)?;
            register_row.scope = manifest.architecture;
            register_row.capability_hash =
                register_capability_hash(manifest.architecture, manifest_digest);
            (Some(payload), Some(evidence_identity))
        } else {
            (None, None)
        };
        let (interrupt_manifest_payload, interrupt_manifest_digest) = if rows.iter().any(|row| {
            matches!(
                row.command_kind,
                FaultCommandKind::InterruptDisposition | FaultCommandKind::InterruptStorm
            ) && row.required_feature_bits & FAULT_CAPABILITY_FEATURE_INTERRUPT != 0
        }) {
            let manifest = initialization_stage("interrupt manifest", apis.interrupt_manifest())?;
            initialization_stage(
                "interrupt manifest binding",
                apis.bind_interrupt_manifest(&manifest),
            )?;
            if register_evidence_identity
                .as_ref()
                .is_some_and(|register| register.architecture != manifest.architecture)
            {
                return Err(FaultCommandBridgeError::InterruptManifestRow);
            }
            let payload = manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            (
                Some(payload.clone()),
                Some(*blake3::hash(&payload).as_bytes()),
            )
        } else {
            (None, None)
        };
        let (hardware_error_manifest_payload, hardware_error_manifest_digest) = if rows
            .iter()
            .any(|row| row.required_feature_bits & FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR != 0)
        {
            let manifest =
                initialization_stage("hardware-error manifest", apis.hardware_error_manifest())?;
            initialization_stage(
                "hardware-error manifest binding",
                apis.bind_hardware_error_manifest(&manifest),
            )?;
            if register_evidence_identity
                .as_ref()
                .is_some_and(|register| register.architecture != manifest.architecture)
            {
                return Err(FaultCommandBridgeError::HardwareErrorManifestRow);
            }
            let payload = manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            (
                Some(payload.clone()),
                Some(*blake3::hash(&payload).as_bytes()),
            )
        } else {
            (None, None)
        };
        let (clock_manifest_payload, clock_manifest_digest) = if rows
            .iter()
            .any(|row| row.required_feature_bits & FAULT_CAPABILITY_FEATURE_GUEST_CLOCK != 0)
        {
            let manifest = initialization_stage("clock manifest", apis.clock_manifest())?;
            initialization_stage(
                "clock manifest binding",
                apis.bind_clock_manifest(&manifest),
            )?;
            if register_evidence_identity
                .as_ref()
                .is_some_and(|register| register.architecture != manifest.architecture)
            {
                return Err(FaultCommandBridgeError::ClockManifestRow);
            }
            let payload = manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            (
                Some(payload.clone()),
                Some(*blake3::hash(&payload).as_bytes()),
            )
        } else {
            (None, None)
        };
        let (accelerator_manifest_payload, accelerator_manifest_digest) =
            match initialization_stage("accelerator manifest", apis.accelerator_manifest())? {
                Some(manifest) => {
                    let payload = manifest
                        .encode()
                        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
                    (
                        Some(payload.clone()),
                        Some(*blake3::hash(&payload).as_bytes()),
                    )
                }
                None => (None, None),
            };
        let system_manifest_payload =
            initialization_stage("system manifest", apis.system_manifest())?
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?
                .to_vec();
        if let Some(register) = register_evidence_identity.as_ref() {
            rows.push(target_manifest_capability_row(
                register.architecture,
                register.manifest_digest,
                interrupt_manifest_digest,
                hardware_error_manifest_digest,
                clock_manifest_digest,
                accelerator_manifest_digest,
            ));
            rows.sort_by_key(|row| {
                (
                    row.command_kind as u16,
                    row.semantic_version,
                    row.scope as u16,
                )
            });
            fault_capability_manifest_digest(&rows)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        }
        let instruction_evidence_identity = if rows.iter().any(|row| {
            matches!(
                row.command_kind,
                FaultCommandKind::CpuInstructionTransform | FaultCommandKind::CpuException
            ) && row.required_feature_bits & FAULT_CAPABILITY_FEATURE_INSTRUCTION != 0
        }) {
            let identity = apis.instruction_manifest()?;
            if register_evidence_identity
                .as_ref()
                .is_some_and(|register| register.architecture != identity.architecture)
            {
                return Err(FaultCommandBridgeError::InstructionManifestChanged);
            }
            Some(identity)
        } else {
            None
        };
        let capability_payload = encode_fault_capability_manifest(&rows)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;

        self.capability_payload = capability_payload;
        self.register_manifest_payload = register_manifest_payload;
        self.interrupt_manifest_payload = interrupt_manifest_payload;
        self.hardware_error_manifest_payload = hardware_error_manifest_payload;
        self.clock_manifest_payload = clock_manifest_payload;
        self.accelerator_manifest_payload = accelerator_manifest_payload;
        self.system_manifest_payload = system_manifest_payload;
        self.register_evidence_identity = register_evidence_identity;
        self.instruction_evidence_identity = instruction_evidence_identity;
        self.initialized = true;
        Ok(())
    }

    /// Drains completed results, submits every published command, then drains
    /// synchronous QEMU rejections.
    ///
    /// `logical_icount_offset` is the scheduler logical coordinate minus QEMU's
    /// raw retired count and must be the same offset used by the sim-loop
    /// authorization ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`FaultCommandBridgeError`] for malformed transport framing,
    /// missing/changed capabilities, coordinate overflow, QEMU API failure, or
    /// lossless result-publication failure.
    pub(crate) fn pump(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
    ) -> Result<(), FaultCommandBridgeError> {
        if !self.initialized {
            return Err(FaultCommandBridgeError::NotInitialized);
        }
        let logical_icount = raw_icount
            .checked_add(logical_icount_offset)
            .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
        if !self.poll_results(logical_icount_offset)? {
            return Ok(());
        }
        if !self.poll_events(logical_icount_offset)? {
            return Ok(());
        }
        loop {
            let command = match self.pending_command.take() {
                Some(command) => command,
                None => {
                    let Some(command) = self.commands.dequeue()? else {
                        break;
                    };
                    command
                }
            };
            let required_result_payload = match &command {
                DequeuedFaultCommand::Valid { header, payload }
                    if header.command_kind == FaultCommandKind::QueryTargetManifest =>
                {
                    let query = FaultTargetManifestQueryV1::decode(payload).ok();
                    match query.map(|query| query.kind) {
                        Some(FaultTargetManifestKind::Register) => {
                            self.register_manifest_payload.as_ref().map_or(0, Vec::len)
                        }
                        Some(FaultTargetManifestKind::Interrupt) => {
                            self.interrupt_manifest_payload.as_ref().map_or(0, Vec::len)
                        }
                        Some(FaultTargetManifestKind::HardwareError) => self
                            .hardware_error_manifest_payload
                            .as_ref()
                            .map_or(0, Vec::len),
                        Some(FaultTargetManifestKind::Clock) => {
                            self.clock_manifest_payload.as_ref().map_or(0, Vec::len)
                        }
                        Some(FaultTargetManifestKind::Accelerator) => self
                            .accelerator_manifest_payload
                            .as_ref()
                            .map_or(0, Vec::len),
                        Some(FaultTargetManifestKind::System) => self.system_manifest_payload.len(),
                        None => 0,
                    }
                }
                DequeuedFaultCommand::Valid { .. } | DequeuedFaultCommand::Rejected { .. } => 0,
            };
            if !self.results.can_enqueue(required_result_payload)? {
                self.pending_command = Some(command);
                return Ok(());
            }
            match command {
                DequeuedFaultCommand::Valid { header, payload } => {
                    self.submit(*header, &payload, logical_icount_offset, logical_icount)?;
                }
                DequeuedFaultCommand::Rejected {
                    raw_command_kind,
                    command_sequence,
                    error,
                } => {
                    if command_sequence == 0 {
                        return Err(FaultCommandBridgeError::UncorrelatableMalformedCommand);
                    }
                    self.publish_local_rejection(
                        raw_command_kind,
                        command_sequence,
                        FaultBoundaryPhase::NodeBoundary,
                        rejection_status(error),
                        logical_icount,
                    )?;
                }
            }
            // Preserve the earliest QEMU completion point before a later
            // locally rejected command can publish ahead of it.
            if !self.poll_results(logical_icount_offset)? {
                return Ok(());
            }
            if !self.poll_events(logical_icount_offset)? {
                return Ok(());
            }
        }
        if self.poll_results(logical_icount_offset)? {
            let _drained = self.poll_events(logical_icount_offset)?;
        }
        Ok(())
    }

    fn submit(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        logical_icount_offset: u64,
        logical_icount: u64,
    ) -> Result<(), FaultCommandBridgeError> {
        if header.command_sequence <= self.last_sequence {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::DuplicateSequence,
                logical_icount,
            );
        }
        self.last_sequence = header.command_sequence;
        self.release_prepare_only_correlations(header.command_sequence);
        if header.target_node_hash != self.target_node_hash {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::InvalidTarget,
                logical_icount,
            );
        }
        if header.command_kind == FaultCommandKind::QueryTargetManifest {
            let query = match FaultTargetManifestQueryV1::decode(payload) {
                Ok(query) => query,
                Err(_source) => {
                    return self.publish_local_rejection(
                        header.command_kind as u16,
                        header.command_sequence,
                        header.phase,
                        FaultResultStatus::MalformedCommand,
                        logical_icount,
                    );
                }
            };
            if header.phase != FaultBoundaryPhase::NodeBoundary
                || header.target_icount != 0
                || header.authorization_ceiling_icount != 0
                || logical_icount != 0
            {
                return self.publish_local_rejection(
                    header.command_kind as u16,
                    header.command_sequence,
                    header.phase,
                    FaultResultStatus::InvalidPhase,
                    logical_icount,
                );
            }
            let result_payload = match query.kind {
                FaultTargetManifestKind::Register => self.register_manifest_payload.clone(),
                FaultTargetManifestKind::Interrupt => self.interrupt_manifest_payload.clone(),
                FaultTargetManifestKind::HardwareError => {
                    self.hardware_error_manifest_payload.clone()
                }
                FaultTargetManifestKind::Clock => self.clock_manifest_payload.clone(),
                FaultTargetManifestKind::Accelerator => self.accelerator_manifest_payload.clone(),
                FaultTargetManifestKind::System => Some(self.system_manifest_payload.clone()),
            };
            let Some(result_payload) = result_payload else {
                return self.publish_local_rejection(
                    header.command_kind as u16,
                    header.command_sequence,
                    header.phase,
                    FaultResultStatus::UnsupportedCapability,
                    logical_icount,
                );
            };
            return self.publish_local_applied(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                logical_icount,
                &result_payload,
            );
        }
        let register_expectation = if header.command_kind == FaultCommandKind::CpuRegisterTransform
        {
            let identity = self
                .register_evidence_identity
                .as_ref()
                .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
            Some(register_command_expectation(
                payload,
                header.binding_hash,
                identity,
            )?)
        } else {
            None
        };
        let instruction_expectation =
            if header.command_kind == FaultCommandKind::CpuInstructionTransform {
                let identity = self
                    .register_evidence_identity
                    .as_ref()
                    .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
                Some(instruction_command_expectation(
                    payload,
                    header.binding_hash,
                    identity,
                )?)
            } else {
                None
            };
        let exception_expectation = if header.command_kind == FaultCommandKind::CpuException {
            Some(exception_command_expectation(payload, header.binding_hash)?)
        } else {
            None
        };
        let memory_ecc_expectation = if header.command_kind == FaultCommandKind::MemoryEccEvent {
            Some(memory_ecc_command_expectation(
                payload,
                header.binding_hash,
            )?)
        } else {
            None
        };
        let clock_expectation = if matches!(
            header.command_kind,
            FaultCommandKind::ClockTransform | FaultCommandKind::ClockSourceState
        ) {
            Some(clock_command_expectation(
                payload,
                header.binding_hash,
                header.command_kind,
            )?)
        } else {
            None
        };
        let accelerator_expectation = if matches!(
            header.command_kind,
            FaultCommandKind::AcceleratorLifecycle
                | FaultCommandKind::AcceleratorResultTransform
                | FaultCommandKind::AcceleratorMemoryEvent
                | FaultCommandKind::AcceleratorService
        ) {
            Some(accelerator_command_expectation(
                payload,
                header.binding_hash,
                header.command_kind,
            )?)
        } else {
            None
        };
        let Some(target_icount) = header.target_icount.checked_sub(logical_icount_offset) else {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::PastBoundary,
                logical_icount,
            );
        };
        let Some(authorization_ceiling_icount) = header
            .authorization_ceiling_icount
            .checked_sub(logical_icount_offset)
        else {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::PastBoundary,
                logical_icount,
            );
        };
        if header.command_kind == FaultCommandKind::QueryCapabilities {
            self.capability_queries.insert(header.command_sequence);
        }
        let command = QemuFaultCommand {
            abi_major: header.abi_major,
            abi_minor: header.abi_minor,
            command_kind: header.command_kind as u16,
            command_flags: header.command_flags,
            phase: header.phase as u16,
            reserved: 0,
            semantic_version: header.semantic_version,
            command_sequence: header.command_sequence,
            target_node_hash: header.target_node_hash,
            target_icount,
            authorization_ceiling_icount,
            binding_hash: header.binding_hash,
            opportunity_hash: header.opportunity_hash,
            expected_precondition_hash: header.expected_precondition_hash,
        };
        let payload_pointer = if payload.is_empty() {
            std::ptr::null()
        } else {
            payload.as_ptr()
        };
        if let Some(expectation) = register_expectation {
            self.register_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = instruction_expectation {
            self.instruction_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = exception_expectation {
            self.exception_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = memory_ecc_expectation {
            self.memory_ecc_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = clock_expectation {
            self.clock_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = accelerator_expectation {
            self.accelerator_commands
                .insert(header.command_sequence, expectation);
        }
        if header.command_flags & FAULT_COMMAND_FLAG_PREPARE_ONLY != 0 {
            self.prepare_only_commands.insert(header.command_sequence);
        }
        let status = (self.apis.submit)(&command, payload_pointer, payload.len());
        if status != 0 {
            self.capability_queries.remove(&header.command_sequence);
            self.register_commands.remove(&header.command_sequence);
            self.instruction_commands.remove(&header.command_sequence);
            self.exception_commands.remove(&header.command_sequence);
            self.memory_ecc_commands.remove(&header.command_sequence);
            self.clock_commands.remove(&header.command_sequence);
            self.accelerator_commands.remove(&header.command_sequence);
            self.prepare_only_commands.remove(&header.command_sequence);
            return Err(FaultCommandBridgeError::QemuSubmit { status });
        }
        Ok(())
    }

    fn poll_results(
        &mut self,
        logical_icount_offset: u64,
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
                    identity,
                    logical_icount_offset,
                    result.applied_icount,
                    None,
                    result.before_hash,
                    result.after_hash,
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
            let observed_icount = result
                .observed_icount
                .checked_add(logical_icount_offset)
                .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
            let applied_icount = if result.applied_icount == 0 {
                0
            } else {
                result
                    .applied_icount
                    .checked_add(logical_icount_offset)
                    .ok_or(FaultCommandBridgeError::CoordinateOverflow)?
            };
            let header = FaultResultHeaderV1 {
                abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
                abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
                command_kind: result.command_kind,
                status: result_status(result.status)?,
                semantic_version: result.semantic_version,
                command_sequence: result.command_sequence,
                observed_icount,
                applied_icount,
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
                            {
                                if prior != result.command_sequence {
                                    self.register_commands.remove(&prior);
                                }
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

    fn poll_events(&mut self, logical_icount_offset: u64) -> Result<bool, FaultCommandBridgeError> {
        let payload_capacity = usize::try_from(HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_source| FaultCommandBridgeError::PayloadCapacity)?;
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
            let published_payload_len = if matches!(
                peeked.command_kind,
                value if value == FaultCommandKind::CpuRegisterTransform as u16
                    || value == FaultCommandKind::CpuInstructionTransform as u16
            ) {
                peeked_payload_len
                    .checked_add(128)
                    .ok_or(FaultCommandBridgeError::PayloadCapacity)?
            } else {
                peeked_payload_len
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
            if event.reserved != 0 {
                return Err(FaultCommandBridgeError::QemuEventReserved);
            }
            if event.event_sequence == 0 {
                return Err(FaultCommandBridgeError::QemuEventSequenceZero);
            }
            let observed_icount = event
                .observed_icount
                .checked_add(logical_icount_offset)
                .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
            let register_command = self
                .register_commands
                .get(&event.rule_command_sequence)
                .cloned();
            if register_command
                .as_ref()
                .is_some_and(|command| command.binding_hash != event.binding_hash)
            {
                return Err(FaultCommandBridgeError::RegisterEvidence);
            }
            let instruction_command = self
                .instruction_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let exception_command = self
                .exception_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let memory_ecc_command = self
                .memory_ecc_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let clock_command = self
                .clock_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let accelerator_command = self
                .accelerator_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let instruction_terminal = event.command_kind
                == FaultCommandKind::CpuInstructionTransform as u16
                && FaultTerminalEvidenceV1::has_magic(&payload);
            let published_payload =
                if event.command_kind == FaultCommandKind::CpuRegisterTransform as u16 {
                    let identity = self
                        .register_evidence_identity
                        .as_ref()
                        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
                    translate_register_evidence(
                        &payload,
                        identity,
                        logical_icount_offset,
                        event.observed_icount,
                        Some(event.model_phase),
                        event.before_hash,
                        event.after_hash,
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
                        translate_terminal_instruction_evidence(&payload, &event, command)?
                    } else {
                        translate_instruction_evidence(
                            &payload,
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
                            &payload,
                            self.hardware_error_manifest_payload
                                .as_deref()
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                            &event,
                            command,
                        )?
                    } else {
                        translate_exception_evidence(
                            &payload,
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
                        &payload,
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
                        &payload,
                        self.clock_manifest_payload
                            .as_deref()
                            .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                        &event,
                        observed_icount,
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
                        &payload,
                        &event,
                        self.accelerator_manifest_payload
                            .as_deref()
                            .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?,
                        accelerator_command
                            .as_ref()
                            .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?,
                    )?
                } else {
                    payload
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
                command_kind: command_kind(event.command_kind)?,
                outcome: event_outcome(event.outcome)?,
                event_sequence: event.event_sequence,
                rule_command_sequence: event.rule_command_sequence,
                observed_icount,
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
            if let Some(command) = register_command {
                if command.operation == NodeFaultOperationV1::Apply {
                    self.register_commands.remove(&event.rule_command_sequence);
                }
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

    fn publish_local_rejection(
        &mut self,
        command_kind: u16,
        command_sequence: u64,
        phase: FaultBoundaryPhase,
        status: FaultResultStatus,
        logical_icount: u64,
    ) -> Result<(), FaultCommandBridgeError> {
        let header = FaultResultHeaderV1 {
            abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
            abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
            command_kind,
            status,
            semantic_version: crucible_shmem::FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence,
            observed_icount: logical_icount,
            applied_icount: 0,
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

    fn publish_local_applied(
        &mut self,
        command_kind: u16,
        command_sequence: u64,
        phase: FaultBoundaryPhase,
        logical_icount: u64,
        payload: &[u8],
    ) -> Result<(), FaultCommandBridgeError> {
        let header = FaultResultHeaderV1 {
            abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
            abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
            command_kind,
            status: FaultResultStatus::Applied,
            semantic_version: crucible_shmem::FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence,
            observed_icount: logical_icount,
            applied_icount: logical_icount,
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

fn initialization_stage<T>(
    stage: &'static str,
    result: Result<T, FaultCommandBridgeError>,
) -> Result<T, FaultCommandBridgeError> {
    result.map_err(|source| FaultCommandBridgeError::InitializationStage {
        stage,
        source: Box::new(source),
    })
}
