//! Live command/result/event bridge operations.

use super::*;

mod events;
mod initialization;
mod results;
use initialization::initialization_stage;

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
        let event_envelope_version = (apis.event_envelope_version)();
        if event_envelope_version != NODE_EVENT_ENVELOPE_VERSION {
            return Err(FaultCommandBridgeError::EventEnvelopeVersion {
                observed: event_envelope_version,
            });
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
    /// `logical_icount_offset` is scheduler-logical minus QEMU raw retired count.
    /// The return is true only after every visible result and event crosses shared memory.
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
    ) -> Result<bool, FaultCommandBridgeError> {
        self.pump_inner(raw_icount, None, &|| Ok(logical_icount_offset))
    }

    /// Pumps with a freshly observed raw-to-logical offset after every QEMU mutation.
    pub(crate) fn pump_with_offset_reader(
        &mut self,
        raw_icount: u64,
        offset_reader: &dyn Fn() -> Result<u64, FaultCommandBridgeError>,
    ) -> Result<bool, FaultCommandBridgeError> {
        self.pump_inner(raw_icount, None, offset_reader)
    }

    /// Pumps exactly through the host-bound command producer frontier.
    pub(crate) fn pump_through_frontier(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
        fault_command_frontier: u64,
    ) -> Result<bool, FaultCommandBridgeError> {
        self.pump_inner(raw_icount, Some(fault_command_frontier), &|| {
            Ok(logical_icount_offset)
        })
    }

    /// Pumps a bound frontier while refreshing the offset after QEMU mutations.
    pub(crate) fn pump_through_frontier_with_offset_reader(
        &mut self,
        raw_icount: u64,
        fault_command_frontier: u64,
        offset_reader: &dyn Fn() -> Result<u64, FaultCommandBridgeError>,
    ) -> Result<bool, FaultCommandBridgeError> {
        self.pump_inner(raw_icount, Some(fault_command_frontier), offset_reader)
    }

    fn pump_inner(
        &mut self,
        raw_icount: u64,
        fault_command_frontier: Option<u64>,
        offset_reader: &dyn Fn() -> Result<u64, FaultCommandBridgeError>,
    ) -> Result<bool, FaultCommandBridgeError> {
        if !self.initialized {
            return Err(FaultCommandBridgeError::NotInitialized);
        }
        let mut logical_icount_offset = offset_reader()?;
        if !self.poll_results(logical_icount_offset)? {
            return Ok(false);
        }
        if !self.poll_events(logical_icount_offset)? {
            return Ok(false);
        }
        if fault_command_frontier.is_some_and(|frontier| self.commands.write_index() != frontier) {
            return Ok(false);
        }
        loop {
            logical_icount_offset = offset_reader()?;
            let logical_icount = raw_icount
                .checked_mul(crucible_shmem::TICKS_PER_INSTRUCTION)
                .and_then(|raw_tick| raw_tick.checked_add(logical_icount_offset))
                .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
            let command = match self.pending_command.take() {
                Some(command) => command,
                None => {
                    if let Some(frontier) = fault_command_frontier {
                        if self.commands.write_index() != frontier {
                            return Ok(false);
                        }
                        if self.commands.read_index() == frontier {
                            break;
                        }
                    }
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
                return Ok(false);
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
                        logical_icount_offset,
                    )?;
                }
            }
            logical_icount_offset = offset_reader()?;
            // Preserve the earliest QEMU completion point before a later
            // locally rejected command can publish ahead of it.
            if !self.poll_results(logical_icount_offset)? {
                return Ok(false);
            }
            if !self.poll_events(logical_icount_offset)? {
                return Ok(false);
            }
        }
        logical_icount_offset = offset_reader()?;
        if !self.poll_results(logical_icount_offset)? {
            return Ok(false);
        }
        if !self.poll_events(logical_icount_offset)? {
            return Ok(false);
        }
        Ok(fault_command_frontier.is_none_or(|frontier| {
            self.pending_command.is_none()
                && self.commands.read_index() == frontier
                && self.commands.write_index() == frontier
        }))
    }

    /// Publishes results and events produced by synchronous boundary dispatch.
    pub(crate) fn drain_publications(
        &mut self,
        logical_icount_offset: u64,
    ) -> Result<bool, FaultCommandBridgeError> {
        if !self.poll_results(logical_icount_offset)? {
            return Ok(false);
        }
        self.poll_events(logical_icount_offset)
    }

    /// Returns whether the command consumer remains exactly at the bound frontier.
    pub(crate) fn command_frontier_is_settled(&self, frontier: u64) -> bool {
        self.pending_command.is_none()
            && self.commands.read_index() == frontier
            && self.commands.write_index() == frontier
    }

    /// Commits every QEMU fault due at this exact node boundary.
    pub(crate) fn dispatch_node_boundary(
        &self,
        raw_icount: u64,
    ) -> Result<(), FaultCommandBridgeError> {
        let status = (self.apis.dispatch_node_boundary)(raw_icount);
        if status == 0 {
            Ok(())
        } else {
            Err(FaultCommandBridgeError::NodeBoundaryDispatch { status })
        }
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
                logical_icount_offset,
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
                logical_icount_offset,
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
                        logical_icount_offset,
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
                    logical_icount_offset,
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
                    logical_icount_offset,
                );
            };
            return self.publish_local_applied(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                logical_icount,
                logical_icount_offset,
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
        let Some(target_icount) =
            logical_tick_to_raw_floor(header.target_icount, logical_icount_offset)
        else {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::PastBoundary,
                logical_icount,
                logical_icount_offset,
            );
        };
        let Some(authorization_ceiling_icount) =
            logical_tick_to_raw_floor(header.authorization_ceiling_icount, logical_icount_offset)
        else {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::PastBoundary,
                logical_icount,
                logical_icount_offset,
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
            target_tick: header.target_icount,
            authorization_ceiling_tick: header.authorization_ceiling_icount,
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
}
