//! Host-side QEMU plugin setup handoff.
//!
//! This module consumes the Linux spawn descriptors, initializes the shared
//! memory memfd with the typed Crucible region image, runs the blocking
//! `Hello`/`Setup`/`SetupAck` protocol over a real Unix socket, and retains the
//! descriptors needed by later scheduler/runtime code. It intentionally stops
//! before deterministic guest execution.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycleIoError, ControlLifecycleState,
    ControlLifecycleStream, HostHandshakeConfig, NegotiatedHandshake, SchedulableNodeSetup,
    SetupDescriptorFds,
    app_random_branch_plan::AppRandomBranchPlan,
    plugin_setup_plan::{PluginSetupPlan, PluginSetupPlanError},
    selectable_catalog_plan::{
        SelectableCatalogPlan, SelectableCatalogPlanError, SelectablePlanContinuation,
        SelectablePlanLimits,
    },
};
use crucible_shmem::{
    ABI_VERSION, DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR,
    FAULT_COMMAND_SEMANTIC_VERSION, FaultAbiError, FaultAcceleratorCapabilityManifestV1,
    FaultBoundaryPhase, FaultCapabilityRowV1, FaultClockCapabilityManifestV1, FaultCommandHeaderV1,
    FaultCommandKind, FaultHardwareErrorCapabilityManifestV1, FaultInterruptCapabilityManifestV1,
    FaultRegisterCapabilityManifestV1, FaultResultStatus, FaultSystemCapabilityManifestV1,
    FaultTargetManifestKind, FaultTargetManifestQueryV1, FaultTransportError,
    MappedSetupRegionAccessError, RegionAllocation, RegionConfig, RegionLayoutError,
    RegionSerializationError, RegionSetupValidationError, SetupRegionMapError,
    ValidatedSetupRegion, decode_fault_capability_manifest, dequeue_fault_result,
    enqueue_fault_command, fault_capability_manifest_digest, mmap_setup_region,
    validate_setup_region_header,
};
use thiserror::Error;

use crate::{
    QemuFaultCapabilityRequirement, QemuNodeChannelError, QemuPluginIpcControlChannel,
    QemuSpawnSetupResources, fault_capability::QemuExactFaultManifests,
};

/// Completed host-side setup state for one QEMU plugin node.
#[derive(Debug)]
pub struct QemuHostPluginSetup {
    control: ControlLifecycleStream<UnixStream>,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    negotiated: NegotiatedHandshake,
    setup_ack: SchedulableNodeSetup,
    region: ValidatedSetupRegion,
    next_fault_command_sequence: u64,
    fault_capabilities: Vec<FaultCapabilityRowV1>,
    fault_capability_digest: [u8; 32],
    register_manifest: Option<FaultRegisterCapabilityManifestV1>,
    interrupt_manifest: Option<FaultInterruptCapabilityManifestV1>,
    hardware_error_manifest: Option<FaultHardwareErrorCapabilityManifestV1>,
    clock_manifest: Option<FaultClockCapabilityManifestV1>,
    accelerator_manifest: Option<FaultAcceleratorCapabilityManifestV1>,
    system_manifest: FaultSystemCapabilityManifestV1,
    ready_markers: std::collections::BTreeSet<crucible::model::FaultObjectId>,
}

impl QemuHostPluginSetup {
    /// Returns the host control lifecycle state after setup.
    #[must_use]
    pub fn control_state(&self) -> ControlLifecycleState {
        self.control.state()
    }

    /// Returns the negotiated `Hello`/`HelloAck` values.
    #[must_use]
    pub const fn negotiated_handshake(&self) -> NegotiatedHandshake {
        self.negotiated
    }

    /// Returns the accepted ready setup acknowledgement.
    #[must_use]
    pub const fn setup_ack(&self) -> SchedulableNodeSetup {
        self.setup_ack
    }

    /// Returns the validated shared-memory setup region token.
    #[must_use]
    pub const fn region(&self) -> ValidatedSetupRegion {
        self.region
    }

    /// Returns the first command sequence not consumed by setup admission.
    #[must_use]
    pub const fn next_fault_command_sequence(&self) -> u64 {
        self.next_fault_command_sequence
    }

    /// Returns the immutable QEMU fault capabilities admitted before guest start.
    #[must_use]
    pub fn fault_capabilities(&self) -> &[FaultCapabilityRowV1] {
        &self.fault_capabilities
    }

    /// Returns the admitted exact capability-manifest digest.
    #[must_use]
    pub const fn fault_capability_digest(&self) -> [u8; 32] {
        self.fault_capability_digest
    }

    /// Returns the immutable register targets admitted before guest start.
    #[must_use]
    pub const fn register_manifest(&self) -> Option<&FaultRegisterCapabilityManifestV1> {
        self.register_manifest.as_ref()
    }

    /// Returns the immutable interrupt targets admitted before guest start.
    #[must_use]
    pub const fn interrupt_manifest(&self) -> Option<&FaultInterruptCapabilityManifestV1> {
        self.interrupt_manifest.as_ref()
    }

    /// Returns the immutable hardware-error targets admitted before guest start.
    #[must_use]
    pub const fn hardware_error_manifest(&self) -> Option<&FaultHardwareErrorCapabilityManifestV1> {
        self.hardware_error_manifest.as_ref()
    }

    /// Returns the immutable guest-clock sources admitted before guest start.
    #[must_use]
    pub const fn clock_manifest(&self) -> Option<&FaultClockCapabilityManifestV1> {
        self.clock_manifest.as_ref()
    }

    /// Returns the immutable accelerator targets admitted before guest start.
    #[must_use]
    pub const fn accelerator_manifest(&self) -> Option<&FaultAcceleratorCapabilityManifestV1> {
        self.accelerator_manifest.as_ref()
    }

    /// Returns the live-admitted QEMU build, patch, shared-memory, and VMState identity.
    #[must_use]
    pub const fn system_manifest(&self) -> &FaultSystemCapabilityManifestV1 {
        &self.system_manifest
    }

    /// Clones the complete public target manifests admitted during setup.
    ///
    /// Discovery gates use this snapshot to demand exact admission from a
    /// separately launched process. A missing mandatory manifest is treated as
    /// an incomplete setup rather than silently weakening the comparison.
    pub(crate) fn exact_fault_manifests(&self) -> Option<QemuExactFaultManifests> {
        Some(QemuExactFaultManifests {
            system: self.system_manifest,
            register: self.register_manifest.clone()?,
            interrupt: self.interrupt_manifest.clone()?,
            hardware_error: self.hardware_error_manifest.clone()?,
            clock: self.clock_manifest.clone()?,
            accelerator: self.accelerator_manifest.clone(),
        })
    }

    /// Returns the launch-bound guest markers eligible to complete ready policies.
    #[must_use]
    pub const fn ready_markers(
        &self,
    ) -> &std::collections::BTreeSet<crucible::model::FaultObjectId> {
        &self.ready_markers
    }

    /// Returns the retained host shared-memory descriptor.
    #[must_use]
    pub fn shmem_fd(&self) -> RawFd {
        self.shmem_fd.as_raw_fd()
    }

    /// Borrows the retained host shared-memory descriptor.
    #[must_use]
    pub fn shmem_as_fd(&self) -> BorrowedFd<'_> {
        self.shmem_fd.as_fd()
    }

    /// Returns the retained host wake event descriptor.
    #[must_use]
    pub fn wake_fd(&self) -> RawFd {
        self.wake_fd.as_raw_fd()
    }

    /// Borrows the retained host wake event descriptor.
    ///
    /// A live host-I/O runtime clones this to signal the plugin wake eventfd once
    /// per quantum, which the node's shared-memory `start_quantum` futex wake
    /// alone does not do (it is required to rouse a vCPU parked in its
    /// between-quanta idle wait, exactly as the M1 scheduler does).
    #[must_use]
    pub fn wake_as_fd(&self) -> BorrowedFd<'_> {
        self.wake_fd.as_fd()
    }

    /// Signals QEMU's registered plugin wake eventfd.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the retained eventfd rejects the
    /// exact eight-byte counter write.
    pub fn signal_plugin_wake(&self) -> Result<(), QemuNodeChannelError> {
        let bytes = 1_u64.to_ne_bytes();
        loop {
            // SAFETY: setup retains a live eventfd and `bytes` is the exact
            // eight-byte counter representation required by eventfd writes.
            let result = unsafe {
                libc::write(
                    self.wake_fd(),
                    bytes.as_ptr().cast::<libc::c_void>(),
                    bytes.len(),
                )
            };
            if result == bytes.len() as isize {
                return Ok(());
            }
            if result >= 0 {
                return Err(QemuNodeChannelError::new(
                    "signal plugin wake eventfd",
                    format!("short eventfd write: expected 8 bytes, wrote {result}"),
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(QemuNodeChannelError::new(
                "signal plugin wake eventfd",
                error.to_string(),
            ));
        }
    }

    /// Proves that the plugin sent no unsolicited run-phase control bytes.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when bytes are pending, the plugin has
    /// already closed the control socket, or the nonblocking peek fails.
    pub fn assert_run_control_silent(&self) -> Result<(), QemuNodeChannelError> {
        let mut byte = [0_u8; 1];
        loop {
            // SAFETY: the control stream owns a live Unix socket and `byte` is
            // writable for the single requested peek byte. `MSG_PEEK` leaves
            // lifecycle framing untouched and `MSG_DONTWAIT` changes no fd flag.
            let result = unsafe {
                libc::recv(
                    self.control_socket_fd(),
                    byte.as_mut_ptr().cast::<libc::c_void>(),
                    byte.len(),
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            if result > 0 {
                return Err(QemuNodeChannelError::new(
                    "assert run control silence",
                    "plugin sent an unsolicited run-phase control frame",
                ));
            }
            if result == 0 {
                return Err(QemuNodeChannelError::new(
                    "assert run control silence",
                    "plugin closed the run control socket before Quit",
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(QemuNodeChannelError::new(
                "assert run control silence",
                error.to_string(),
            ));
        }
    }

    fn control_socket_fd(&self) -> RawFd {
        self.control.as_raw_fd()
    }
}

impl QemuPluginIpcControlChannel for QemuHostPluginSetup {
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.control.host_send_quit().map_err(|source| {
            QemuNodeChannelError::new("send plugin control Quit", source.to_string())
        })
    }
}

/// Runs host-side setup over real spawn descriptors and enters shmem run state.
///
/// The function initializes the spawn-created memfd with the region described
/// by `config`, accepts the plugin handshake for `slot_index`, sends the memfd
/// and wake eventfd via `SCM_RIGHTS`, accepts `SetupAck(0)`, and advances the
/// host lifecycle into the shared-memory run phase. It does not execute any
/// guest instructions or assert replay determinism.
///
/// # Errors
///
/// Returns [`QemuHostPluginSetupError`] when region allocation or serialization
/// fails, when the spawn memfd length does not match the computed layout, when
/// memfd initialization fails, or when the control protocol rejects the
/// handshake, descriptor handoff, ready acknowledgement, or run transition.
pub fn complete_qemu_host_plugin_setup(
    resources: QemuSpawnSetupResources,
    config: RegionConfig,
    slot_index: u32,
    required_capabilities: &QemuFaultCapabilityRequirement,
) -> Result<QemuHostPluginSetup, QemuHostPluginSetupError> {
    complete_qemu_host_plugin_setup_with_app_random_branch_plan(
        resources,
        config,
        slot_index,
        required_capabilities,
        &AppRandomBranchPlan::default(),
    )
}

/// Runs host-side setup with one immutable app-random branch replay plan.
///
/// The plan is combined with an empty selectable catalog. After the control
/// handshake, v2 receives the raw app-random body and v3 receives the canonical
/// composite body in the same third sealed descriptor. Setup never relies on
/// optional descriptor counts.
///
/// # Errors
///
/// Returns [`QemuHostPluginSetupError`] for the failures documented by
/// [`complete_qemu_host_plugin_setup`], or when the plan memfd cannot be
/// created, populated, or sealed before descriptor handoff.
pub fn complete_qemu_host_plugin_setup_with_app_random_branch_plan(
    resources: QemuSpawnSetupResources,
    config: RegionConfig,
    slot_index: u32,
    required_capabilities: &QemuFaultCapabilityRequirement,
    app_random_branch_plan: &AppRandomBranchPlan,
) -> Result<QemuHostPluginSetup, QemuHostPluginSetupError> {
    let selectable_catalog_plan = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 1, 1)
            .map_err(|source| QemuHostPluginSetupError::SelectableCatalogPlan { source })?,
        Vec::new(),
        SelectablePlanContinuation::cold(),
    )
    .map_err(|source| QemuHostPluginSetupError::SelectableCatalogPlan { source })?;
    let plugin_setup_plan =
        PluginSetupPlan::new(app_random_branch_plan.clone(), selectable_catalog_plan);
    complete_qemu_host_plugin_setup_with_plugin_setup_plan(
        resources,
        config,
        slot_index,
        required_capabilities,
        &plugin_setup_plan,
    )
}

/// Completes setup with one version-negotiated composite plugin plan.
///
/// Negotiated control-protocol v2 sends only the nested app-random body in the
/// third descriptor. Version 3 and later send the complete composite setup
/// plan, so version fallback never changes the meaning of an existing profile.
///
/// # Errors
///
/// Returns [`QemuHostPluginSetupError`] for the failures documented by
/// [`complete_qemu_host_plugin_setup`], or when the selected canonical plan
/// body cannot be encoded, populated, or sealed before descriptor handoff.
pub fn complete_qemu_host_plugin_setup_with_plugin_setup_plan(
    resources: QemuSpawnSetupResources,
    config: RegionConfig,
    slot_index: u32,
    required_capabilities: &QemuFaultCapabilityRequirement,
    plugin_setup_plan: &PluginSetupPlan,
) -> Result<QemuHostPluginSetup, QemuHostPluginSetupError> {
    let allocation = RegionAllocation::new(config)
        .map_err(|source| QemuHostPluginSetupError::RegionLayout { source })?;
    let layout = allocation.layout();
    if resources.region_len() != layout.region_size {
        return Err(QemuHostPluginSetupError::RegionLengthMismatch {
            spawn_region_len: resources.region_len(),
            layout_region_len: layout.region_size,
        });
    }

    let bytes = allocation
        .setup_region_bytes()
        .map_err(|source| QemuHostPluginSetupError::RegionSerialization { source })?;
    let (control_socket, shmem_fd, wake_fd, region_len, fault_node_hash) = resources.into_parts();
    if required_capabilities
        .target_manifest()
        .is_some_and(|required| required.node_hash() != fault_node_hash)
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetIdentityMismatch);
    }
    write_shmem_setup_region(shmem_fd.as_raw_fd(), &bytes)?;
    let region = validate_setup_region_header(allocation.header().snapshot(), layout.region_size)
        .map_err(|source| QemuHostPluginSetupError::RegionValidation { source })?;

    let mut admission_region = mmap_setup_region(shmem_fd.as_fd(), region_len)
        .map_err(|source| QemuHostPluginSetupError::AdmissionMap { source })?;
    enqueue_capability_query(&mut admission_region, slot_index, fault_node_hash)?;
    if required_capabilities.target_manifest().is_some() {
        enqueue_target_manifest_query(
            &mut admission_region,
            slot_index,
            fault_node_hash,
            FaultTargetManifestKind::Register,
            2,
        )?;
    }
    if required_capabilities.target_manifest().is_some() {
        enqueue_target_manifest_query(
            &mut admission_region,
            slot_index,
            fault_node_hash,
            FaultTargetManifestKind::Interrupt,
            3,
        )?;
    }
    if required_capabilities.target_manifest().is_some() {
        enqueue_target_manifest_query(
            &mut admission_region,
            slot_index,
            fault_node_hash,
            FaultTargetManifestKind::Clock,
            4,
        )?;
        enqueue_target_manifest_query(
            &mut admission_region,
            slot_index,
            fault_node_hash,
            FaultTargetManifestKind::HardwareError,
            5,
        )?;
    }
    enqueue_target_manifest_query(
        &mut admission_region,
        slot_index,
        fault_node_hash,
        FaultTargetManifestKind::System,
        6,
    )?;
    if required_capabilities
        .target_manifest()
        .and_then(crate::QemuTargetManifestRequirement::exact_accelerator_manifest)
        .is_some()
    {
        enqueue_target_manifest_query(
            &mut admission_region,
            slot_index,
            fault_node_hash,
            FaultTargetManifestKind::Accelerator,
            7,
        )?;
    }

    let mut control = ControlLifecycleStream::connected_unix_stream(control_socket)
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;
    let negotiated = control
        .host_accept_handshake(HostHandshakeConfig {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index,
            node_count: layout.node_count,
        })
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;
    if negotiated.proto_version < 3
        && plugin_setup_plan.selectable_catalog_plan() != &SelectableCatalogPlan::default()
    {
        return Err(
            QemuHostPluginSetupError::SelectableCatalogRequiresProtocolV3 {
                negotiated: negotiated.proto_version,
            },
        );
    }
    let setup_plan_bytes = if negotiated.proto_version >= 3 {
        plugin_setup_plan
            .encode()
            .map_err(|source| QemuHostPluginSetupError::PluginSetupPlan { source })?
    } else {
        plugin_setup_plan.app_random_branch_plan().encode()
    };
    let plugin_setup_plan_fd = sealed_plugin_setup_plan_fd(&setup_plan_bytes)?;
    control
        .host_send_setup_with_descriptors(
            region_len,
            SetupDescriptorFds {
                shmem_fd: shmem_fd.as_raw_fd(),
                wake_fd: wake_fd.as_raw_fd(),
                plugin_setup_plan_fd: plugin_setup_plan_fd.as_raw_fd(),
            },
        )
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;
    let setup_ack = control
        .host_accept_setup_ack()
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;
    let fault_capabilities = accept_capability_result(&mut admission_region, slot_index)?;
    let register_manifest = required_capabilities
        .target_manifest()
        .map(|required| accept_register_manifest(&mut admission_region, slot_index, required))
        .transpose()?;
    let interrupt_manifest = required_capabilities
        .target_manifest()
        .map(|required| accept_interrupt_manifest(&mut admission_region, slot_index, required))
        .transpose()?;
    let clock_manifest = required_capabilities
        .target_manifest()
        .map(|_required| {
            accept_clock_manifest(
                &mut admission_region,
                slot_index,
                required_capabilities
                    .target_manifest()
                    .ok_or(QemuHostPluginSetupError::AdmissionTargetIdentity)?,
            )
        })
        .transpose()?;
    let hardware_error_manifest = required_capabilities
        .target_manifest()
        .map(|required| accept_hardware_error_manifest(&mut admission_region, slot_index, required))
        .transpose()?;
    let system_manifest = accept_system_manifest(&mut admission_region, slot_index)?;
    if required_capabilities
        .exact_system_manifest()
        .is_some_and(|required| required != &system_manifest)
    {
        return Err(QemuHostPluginSetupError::AdmissionSystemManifestMismatch);
    }
    let accelerator_manifest = required_capabilities
        .target_manifest()
        .and_then(crate::QemuTargetManifestRequirement::exact_accelerator_manifest)
        .map(|required| accept_accelerator_manifest(&mut admission_region, slot_index, required))
        .transpose()?;
    let next_fault_command_sequence = if accelerator_manifest.is_some() { 8 } else { 7 };
    let expected_capabilities = required_capabilities
        .rows_for_manifests(
            register_manifest.as_ref(),
            interrupt_manifest.as_ref(),
            hardware_error_manifest.as_ref(),
            clock_manifest.as_ref(),
            accelerator_manifest.as_ref(),
        )
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if fault_capabilities != expected_capabilities {
        let observed_digest = fault_capability_manifest_digest(&fault_capabilities)
            .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
        let required_digest = fault_capability_manifest_digest(&expected_capabilities)
            .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
        let first_mismatch_index = expected_capabilities
            .iter()
            .zip(&fault_capabilities)
            .position(|(required, observed)| required != observed)
            .unwrap_or_else(|| expected_capabilities.len().min(fault_capabilities.len()));
        return Err(QemuHostPluginSetupError::AdmissionCapabilityMismatch {
            required_digest,
            observed_digest,
            first_mismatch_index,
            required_row: expected_capabilities
                .get(first_mismatch_index)
                .cloned()
                .map(Box::new),
            observed_row: fault_capabilities
                .get(first_mismatch_index)
                .cloned()
                .map(Box::new),
        });
    }
    let admitted_capability_digest = fault_capability_manifest_digest(&fault_capabilities)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    control
        .enter_run_via_shared_memory()
        .map_err(|source| QemuHostPluginSetupError::Control { source })?;

    Ok(QemuHostPluginSetup {
        control,
        shmem_fd,
        wake_fd,
        negotiated,
        setup_ack,
        region,
        next_fault_command_sequence,
        fault_capabilities,
        fault_capability_digest: admitted_capability_digest,
        register_manifest,
        interrupt_manifest,
        hardware_error_manifest,
        clock_manifest,
        accelerator_manifest,
        system_manifest,
        ready_markers: required_capabilities.ready_markers().clone(),
    })
}

fn sealed_plugin_setup_plan_fd(bytes: &[u8]) -> Result<OwnedFd, QemuHostPluginSetupError> {
    let name = c"crucible-plugin-setup-plan";
    let raw_fd = unsafe {
        // SAFETY: `name` is a live NUL-terminated C string and memfd_create
        // returns a new descriptor or -1 without retaining the pointer.
        libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
    };
    if raw_fd < 0 {
        return Err(setup_io_error(
            "create plugin setup-plan memfd",
            io::Error::last_os_error(),
        ));
    }
    let fd = unsafe {
        // SAFETY: successful memfd_create returned one uniquely owned descriptor.
        OwnedFd::from_raw_fd(raw_fd)
    };
    let length = libc::off_t::try_from(bytes.len()).map_err(|_error| {
        setup_io_error(
            "size plugin setup-plan memfd",
            io::Error::new(io::ErrorKind::InvalidInput, "setup plan is too large"),
        )
    })?;
    let status = unsafe {
        // SAFETY: `fd` is a live memfd and `length` is range-checked.
        libc::ftruncate(fd.as_raw_fd(), length)
    };
    if status != 0 {
        return Err(setup_io_error(
            "size plugin setup-plan memfd",
            io::Error::last_os_error(),
        ));
    }
    write_shmem_setup_region(fd.as_raw_fd(), bytes).map_err(|error| match error {
        QemuHostPluginSetupError::Io { source, .. } => {
            setup_io_error("write plugin setup-plan memfd", source)
        }
        other => other,
    })?;
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    let status = unsafe {
        // SAFETY: `fd` is a live sealable memfd and `seals` is the reviewed
        // immutable-descriptor policy.
        libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals)
    };
    if status != 0 {
        return Err(setup_io_error(
            "seal plugin setup-plan memfd",
            io::Error::last_os_error(),
        ));
    }
    Ok(fd)
}

fn enqueue_target_manifest_query(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    target_node_hash: [u8; 32],
    kind: FaultTargetManifestKind,
    command_sequence: u64,
) -> Result<(), QemuHostPluginSetupError> {
    let payload = FaultTargetManifestQueryV1 { kind }.encode();
    let transport = region
        .fault_command_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let mut binding_hasher = blake3::Hasher::new();
    binding_hasher.update(b"crucible.qemu-fault-target-manifest-admission.v1\0");
    binding_hasher.update(&target_node_hash);
    binding_hasher.update(&payload);
    enqueue_fault_command(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
        FaultCommandHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::QueryTargetManifest,
            command_flags: 0,
            phase: FaultBoundaryPhase::NodeBoundary,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence,
            target_node_hash,
            target_icount: 0,
            authorization_ceiling_icount: 0,
            binding_hash: *binding_hasher.finalize().as_bytes(),
            opportunity_hash: [0; 32],
            expected_precondition_hash: [0; 32],
            payload_hash: [0; 32],
            payload_offset: 0,
            payload_length: 0,
        },
        &payload,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })
}

fn enqueue_capability_query(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    target_node_hash: [u8; 32],
) -> Result<(), QemuHostPluginSetupError> {
    if target_node_hash == [0; 32] {
        return Err(QemuHostPluginSetupError::AdmissionTargetIdentity);
    }
    let transport = region
        .fault_command_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let mut binding_hasher = blake3::Hasher::new();
    binding_hasher.update(b"crucible.qemu-fault-capability-admission.v1\0");
    binding_hasher.update(&target_node_hash);
    let header = FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::QueryCapabilities,
        command_flags: 0,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 1,
        target_node_hash,
        target_icount: 0,
        authorization_ceiling_icount: 0,
        binding_hash: *binding_hasher.finalize().as_bytes(),
        opportunity_hash: [0; 32],
        expected_precondition_hash: [0; 32],
        payload_hash: [0; 32],
        payload_offset: 0,
        payload_length: 0,
    };
    enqueue_fault_command(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
        header,
        &[],
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })
}

fn accept_capability_result(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
) -> Result<Vec<FaultCapabilityRowV1>, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 1
        || header.command_kind != FaultCommandKind::QueryCapabilities as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    decode_fault_capability_manifest(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })
}

fn accept_register_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &crate::QemuTargetManifestRequirement,
) -> Result<FaultRegisterCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 2
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultRegisterCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if manifest.architecture != required.architecture()
        || manifest.cpu_model != required.realized_cpu_type()
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetManifestMismatch {
            required_architecture: required.architecture(),
            observed_architecture: manifest.architecture,
            required_cpu_model: required.realized_cpu_type(),
            observed_cpu_model: manifest.cpu_model.clone(),
        });
    }
    Ok(manifest)
}

fn accept_interrupt_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &crate::QemuTargetManifestRequirement,
) -> Result<FaultInterruptCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 3
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultInterruptCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if manifest.architecture != required.architecture()
        || required
            .exact_interrupt_manifest()
            .is_some_and(|expected| expected != &manifest)
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetManifestMismatch {
            required_architecture: required.architecture(),
            observed_architecture: manifest.architecture,
            required_cpu_model: required.realized_cpu_type(),
            observed_cpu_model: required.realized_cpu_type(),
        });
    }
    Ok(manifest)
}

fn accept_clock_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &crate::QemuTargetManifestRequirement,
) -> Result<FaultClockCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 4
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultClockCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if manifest.architecture != required.architecture()
        || required
            .exact_clock_manifest()
            .is_some_and(|expected| expected != &manifest)
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetManifestMismatch {
            required_architecture: required.architecture(),
            observed_architecture: manifest.architecture,
            required_cpu_model: required.realized_cpu_type(),
            observed_cpu_model: required.realized_cpu_type(),
        });
    }
    Ok(manifest)
}

fn accept_hardware_error_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &crate::QemuTargetManifestRequirement,
) -> Result<FaultHardwareErrorCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 5
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultHardwareErrorCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if manifest.architecture != required.architecture()
        || required
            .exact_hardware_error_manifest()
            .is_some_and(|expected| expected != &manifest)
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetManifestMismatch {
            required_architecture: required.architecture(),
            observed_architecture: manifest.architecture,
            required_cpu_model: required.realized_cpu_type(),
            observed_cpu_model: required.realized_cpu_type(),
        });
    }
    Ok(manifest)
}

fn accept_accelerator_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &FaultAcceleratorCapabilityManifestV1,
) -> Result<FaultAcceleratorCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 7
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultAcceleratorCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if &manifest != required {
        return Err(QemuHostPluginSetupError::AdmissionAcceleratorManifestMismatch);
    }
    Ok(manifest)
}

fn accept_system_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
) -> Result<FaultSystemCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 6
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    FaultSystemCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })
}

fn write_shmem_setup_region(fd: RawFd, bytes: &[u8]) -> Result<(), QemuHostPluginSetupError> {
    let mut written = 0;
    while written < bytes.len() {
        let offset = libc::off_t::try_from(written).map_err(|_error| {
            setup_io_error(
                "compute shmem setup write offset",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "setup region write offset cannot fit off_t",
                ),
            )
        })?;
        let result = unsafe {
            // SAFETY: `fd` is a live memfd retained by setup resources, the
            // source slice is valid for the requested byte count, and `pwrite`
            // does not mutate Rust-managed memory.
            libc::pwrite(
                fd,
                bytes[written..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - written,
                offset,
            )
        };
        if result < 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(setup_io_error("write setup region to shmem memfd", source));
        }
        let count = usize::try_from(result).map_err(|_error| {
            setup_io_error(
                "convert shmem setup write count",
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "setup region pwrite returned an invalid byte count",
                ),
            )
        })?;
        if count == 0 {
            return Err(setup_io_error(
                "write setup region to shmem memfd",
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "setup region pwrite wrote zero bytes",
                ),
            ));
        }
        written += count;
    }
    Ok(())
}

fn setup_io_error(operation: &'static str, source: io::Error) -> QemuHostPluginSetupError {
    QemuHostPluginSetupError::Io { operation, source }
}

/// An error produced while running host-side plugin setup.
#[derive(Debug, Error)]
pub enum QemuHostPluginSetupError {
    /// The requested shared-memory layout could not be allocated.
    #[error("setup shared-memory layout failed")]
    RegionLayout {
        /// Underlying region layout error.
        source: RegionLayoutError,
    },
    /// The spawn-created memfd length did not match the requested layout.
    #[error(
        "spawn shared-memory length {spawn_region_len} does not match setup layout length {layout_region_len}"
    )]
    RegionLengthMismatch {
        /// Byte length used to size the spawn-created memfd.
        spawn_region_len: u64,
        /// Byte length computed from the setup region configuration.
        layout_region_len: u64,
    },
    /// The setup region image could not be serialized.
    #[error("setup shared-memory serialization failed")]
    RegionSerialization {
        /// Underlying serialization error.
        source: RegionSerializationError,
    },
    /// The compatibility wrapper could not build its empty selectable plan.
    #[error("empty selectable catalog plan construction failed: {source}")]
    SelectableCatalogPlan {
        /// Canonical selectable-plan failure.
        source: SelectableCatalogPlanError,
    },
    /// Negotiation selected the legacy profile for a nonempty selectable plan.
    #[error(
        "guest-selectable catalog setup requires control protocol v3, negotiated v{negotiated}"
    )]
    SelectableCatalogRequiresProtocolV3 {
        /// Negotiated legacy control-protocol version.
        negotiated: u32,
    },
    /// The negotiated composite plugin setup plan could not be encoded.
    #[error("composite plugin setup plan encoding failed: {source}")]
    PluginSetupPlan {
        /// Canonical composite-plan failure.
        source: PluginSetupPlanError,
    },
    /// A host-side descriptor or memfd write operation failed.
    #[error("{operation} failed: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The locally initialized setup region failed ABI validation.
    #[error("setup shared-memory validation failed")]
    RegionValidation {
        /// Underlying region validation error.
        source: RegionSetupValidationError,
    },
    /// The host could not map the setup region for pre-start capability admission.
    #[error("fault capability admission mapping failed: {source}")]
    AdmissionMap {
        /// Shared-memory mapping failure.
        source: SetupRegionMapError,
    },
    /// Spawn resources were not bound to a canonical nonzero node identity.
    #[error("fault capability admission target identity is the reserved all-zero hash")]
    AdmissionTargetIdentity,
    /// Spawn resources did not match the launch-bound World node identity.
    #[error("fault capability admission target identity differs from the launch manifest")]
    AdmissionTargetIdentityMismatch,
    /// The mapped region could not expose this VM's dedicated fault transport.
    #[error("fault capability admission transport access failed: {source}")]
    AdmissionAccess {
        /// Typed mapping failure.
        source: MappedSetupRegionAccessError,
    },
    /// The mandatory capability command/result transport failed.
    #[error("fault capability admission transport failed: {source}")]
    AdmissionTransport {
        /// Lossless ring or arena failure.
        source: FaultTransportError,
    },
    /// The plugin acknowledged setup without publishing the mandatory result.
    #[error("fault capability admission result is missing after setup acknowledgement")]
    AdmissionResultMissing,
    /// The plugin published an ABI-invalid capability result.
    #[error("fault capability result sequence {command_sequence} is invalid: {source}")]
    AdmissionResultInvalid {
        /// Result sequence recovered from the invalid envelope.
        command_sequence: u64,
        /// Exact ABI validation failure.
        source: FaultAbiError,
    },
    /// QEMU rejected or miscorrelated the mandatory capability query.
    #[error(
        "fault capability result mismatch: sequence={command_sequence} kind={command_kind} status={status:?} phase={phase:?} capability_version={capability_version} observed_icount={observed_icount} applied_icount={applied_icount} evidence_hash={evidence_hash:02x?}"
    )]
    AdmissionResultRejected {
        /// Returned sequence.
        command_sequence: u64,
        /// Returned raw command kind.
        command_kind: u16,
        /// Returned status.
        status: FaultResultStatus,
        /// Returned boundary phase.
        phase: FaultBoundaryPhase,
        /// Returned capability ABI version.
        capability_version: u32,
        /// Returned setup-time observation coordinate.
        observed_icount: u64,
        /// Returned setup-time application coordinate.
        applied_icount: u64,
        /// Returned evidence digest.
        evidence_hash: [u8; 32],
    },
    /// The returned immutable capability manifest was malformed.
    #[error("fault capability manifest is invalid: {source}")]
    AdmissionManifest {
        /// Exact manifest codec failure.
        source: FaultAbiError,
    },
    /// QEMU advertised a valid manifest other than the launch-bound exact set.
    #[error(
        "fault capability manifest mismatch at row {first_mismatch_index}: required_digest={required_digest:02x?} observed_digest={observed_digest:02x?} required_row={required_row:?} observed_row={observed_row:?}"
    )]
    AdmissionCapabilityMismatch {
        /// Digest of the launch-bound exact manifest.
        required_digest: [u8; 32],
        /// Digest of the manifest returned by live QEMU.
        observed_digest: [u8; 32],
        /// First row index at which the exact manifests differ.
        first_mismatch_index: usize,
        /// Launch-bound row at the first mismatch, or `None` when QEMU has an extra row.
        required_row: Option<Box<FaultCapabilityRowV1>>,
        /// QEMU row at the first mismatch, or `None` when QEMU omitted a row.
        observed_row: Option<Box<FaultCapabilityRowV1>>,
    },
    /// QEMU's immutable build, patch, ABI, or VMState identity changed across replay.
    #[error("fault system manifest differs from the launch-bound exact identity")]
    AdmissionSystemManifestMismatch,
    /// QEMU's target manifest described a different launch identity.
    #[error(
        "fault target manifest mismatch: required architecture={required_architecture:?} cpu_model={required_cpu_model}; observed architecture={observed_architecture:?} cpu_model={observed_cpu_model}"
    )]
    AdmissionTargetManifestMismatch {
        /// Launch-bound architecture.
        required_architecture: crucible_shmem::FaultCapabilityScope,
        /// Architecture returned by live QEMU.
        observed_architecture: crucible_shmem::FaultCapabilityScope,
        /// Launch-bound CPU model.
        required_cpu_model: String,
        /// CPU model returned by live QEMU.
        observed_cpu_model: String,
    },
    /// QEMU's accelerator manifest differed from the exact World declaration.
    #[error("accelerator target manifest differs from the launch-bound World manifest")]
    AdmissionAcceleratorManifestMismatch,
    /// The control-protocol lifecycle failed.
    #[error("setup control lifecycle failed")]
    Control {
        /// Underlying lifecycle error.
        source: ControlLifecycleIoError,
    },
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::error::Error;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::thread;

    use crucible_protocol::{
        CONTROL_PROTOCOL_VERSION, HandshakeError, PluginHandshakeConfig, PluginMsg,
        SETUP_ACK_STATUS_READY, host_negotiate_handshake,
    };
    use crucible_shmem::{ABI_VERSION, RegionLayout, mmap_setup_region};

    use crate::spawn::create_test_spawn_resource_pair;

    const EVENTFD_WAKE_PROBE: u64 = 7;

    #[test]
    fn qemu_host_rejects_a_v1_plugin_against_the_current_region() {
        assert_eq!(ABI_VERSION, 18);
        let config = HostHandshakeConfig {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index: 0,
            node_count: 1,
        };
        assert_eq!(
            host_negotiate_handshake(
                PluginMsg::Hello {
                    proto_version: CONTROL_PROTOCOL_VERSION,
                    abi_version: 1,
                },
                config,
            ),
            Err(HandshakeError::AbiMismatch {
                plugin_abi: 1,
                host_abi: ABI_VERSION,
            })
        );
    }

    #[test]
    fn qemu_host_plugin_setup_wires_real_socket_descriptors_and_memfd() -> Result<(), Box<dyn Error>>
    {
        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
        let plugin_peer = thread::spawn(move || plugin_peer_complete_setup(plugin_socket));

        let mut setup = complete_qemu_host_plugin_setup(
            resources.into_setup_resources(),
            config,
            0,
            &QemuFaultCapabilityRequirement::abi_boundary_v1(),
        )?;

        assert_eq!(
            setup.control_state(),
            ControlLifecycleState::RunningViaSharedMemory
        );
        assert_eq!(
            setup.negotiated_handshake(),
            NegotiatedHandshake {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
                slot_index: 0,
                node_count: layout.node_count,
            }
        );
        assert_eq!(setup.setup_ack().setup_ack_status(), SETUP_ACK_STATUS_READY);
        assert!(setup.setup_ack().can_schedule());
        assert_eq!(
            setup.region(),
            ValidatedSetupRegion {
                region_len: layout.region_size,
                abi_version: ABI_VERSION,
            }
        );
        assert_fd_open(setup.shmem_fd())?;
        assert_fd_open(setup.wake_fd())?;
        assert_eq!(read_eventfd_counter(setup.wake_fd())?, EVENTFD_WAKE_PROBE);
        setup.signal_plugin_wake()?;
        assert_eq!(read_eventfd_counter(setup.wake_fd())?, 1);
        QemuPluginIpcControlChannel::send_quit(&mut setup)?;
        assert_eq!(setup.control_state(), ControlLifecycleState::QuitSent);

        let plugin_region = match plugin_peer.join() {
            Ok(Ok(region)) => region,
            Ok(Err(error)) => return Err(error.into()),
            Err(_panic) => return Err("plugin setup peer panicked".into()),
        };
        assert_eq!(plugin_region, setup.region());

        Ok(())
    }

    #[test]
    fn qemu_host_plugin_setup_preserves_the_raw_v2_third_descriptor() -> Result<(), Box<dyn Error>>
    {
        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
        let plugin_peer =
            thread::spawn(move || plugin_peer_complete_setup_version(plugin_socket, 2));

        let mut setup = complete_qemu_host_plugin_setup(
            resources.into_setup_resources(),
            config,
            0,
            &QemuFaultCapabilityRequirement::abi_boundary_v1(),
        )?;
        assert_eq!(setup.negotiated_handshake().proto_version, 2);
        QemuPluginIpcControlChannel::send_quit(&mut setup)?;
        match plugin_peer.join() {
            Ok(Ok(_region)) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(_panic) => Err("legacy plugin setup peer panicked".into()),
        }
    }

    #[test]
    fn qemu_host_rejects_selectable_catalog_downgrade_to_v2() -> Result<(), Box<dyn Error>> {
        use crucible_protocol::selectable_catalog_plan::{
            SelectablePlanDeclaration, SelectablePlanPresence,
        };

        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
        let plugin_peer =
            thread::spawn(move || plugin_peer_complete_setup_version(plugin_socket, 2));
        let declaration = SelectablePlanDeclaration::new(
            "network.policy",
            vec![1, 2],
            vec![1],
            vec!["recovery".to_owned()],
            SelectablePlanPresence::Required,
        )?;
        let selectable = SelectableCatalogPlan::new(
            SelectablePlanLimits::new(1, 3, 3)?,
            vec![declaration],
            SelectablePlanContinuation::cold(),
        )?;
        let plan = PluginSetupPlan::new(AppRandomBranchPlan::default(), selectable);

        let error = match complete_qemu_host_plugin_setup_with_plugin_setup_plan(
            resources.into_setup_resources(),
            config,
            0,
            &QemuFaultCapabilityRequirement::abi_boundary_v1(),
            &plan,
        ) {
            Ok(_setup) => return Err("v2 discarded a nonempty selectable plan".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            QemuHostPluginSetupError::SelectableCatalogRequiresProtocolV3 { negotiated: 2 }
        ));
        assert!(matches!(plugin_peer.join(), Ok(Err(_))));
        Ok(())
    }

    #[test]
    fn qemu_host_plugin_setup_rejects_spawn_region_length_mismatch_before_protocol()
    -> Result<(), Box<dyn Error>> {
        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, _plugin_socket) =
            create_test_spawn_resource_pair(layout.region_size + 4096)?;

        let error = complete_qemu_host_plugin_setup(
            resources.into_setup_resources(),
            config,
            0,
            &QemuFaultCapabilityRequirement::abi_boundary_v1(),
        )
        .err()
        .ok_or("setup should reject mismatched spawn region length")?;

        assert!(matches!(
            error,
            QemuHostPluginSetupError::RegionLengthMismatch {
                spawn_region_len,
                layout_region_len,
            } if spawn_region_len == layout.region_size + 4096
                && layout_region_len == layout.region_size
        ));

        Ok(())
    }

    #[test]
    fn qemu_host_plugin_setup_rejects_spawn_node_identity_mismatch_before_protocol()
    -> Result<(), Box<dyn Error>> {
        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, _plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
        let required = QemuFaultCapabilityRequirement::live_gate_v1(
            crate::LivePluginGuestArchitecture::X86_64,
            "qemu64",
            "different-node",
            false,
        );

        let error =
            complete_qemu_host_plugin_setup(resources.into_setup_resources(), config, 0, &required)
                .err()
                .ok_or("setup should reject a mismatched launch node")?;

        assert!(matches!(
            error,
            QemuHostPluginSetupError::AdmissionTargetIdentityMismatch
        ));
        Ok(())
    }

    #[test]
    fn qemu_host_plugin_setup_rejects_a_valid_but_inexact_capability_manifest()
    -> Result<(), Box<dyn Error>> {
        let config = RegionConfig::new(1, 4, 0);
        let layout = RegionLayout::for_config(config)?;
        let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
        let required = QemuFaultCapabilityRequirement::abi_boundary_v1();
        let mut observed = required.rows().to_vec();
        let _omitted_boundary = observed
            .pop()
            .ok_or("baseline manifest must not be empty")?;
        let plugin_peer =
            thread::spawn(move || plugin_peer_complete_setup_with_rows(plugin_socket, &observed));

        let error =
            complete_qemu_host_plugin_setup(resources.into_setup_resources(), config, 0, &required)
                .err()
                .ok_or("setup should reject an inexact manifest")?;
        assert!(matches!(
            error,
            QemuHostPluginSetupError::AdmissionCapabilityMismatch {
                required_digest,
                observed_digest,
                ..
            } if required_digest == required.digest() && observed_digest != required_digest
        ));
        let _peer_result = plugin_peer
            .join()
            .map_err(|_panic| "plugin setup peer panicked")?;
        Ok(())
    }

    fn plugin_peer_complete_setup(
        plugin_socket: UnixStream,
    ) -> Result<ValidatedSetupRegion, String> {
        plugin_peer_complete_setup_version(plugin_socket, CONTROL_PROTOCOL_VERSION)
    }

    fn plugin_peer_complete_setup_version(
        plugin_socket: UnixStream,
        protocol_version: u32,
    ) -> Result<ValidatedSetupRegion, String> {
        let requirement = QemuFaultCapabilityRequirement::abi_boundary_v1();
        plugin_peer_complete_setup_with_rows_and_version(
            plugin_socket,
            requirement.rows(),
            protocol_version,
        )
    }

    fn plugin_peer_complete_setup_with_rows(
        plugin_socket: UnixStream,
        rows: &[FaultCapabilityRowV1],
    ) -> Result<ValidatedSetupRegion, String> {
        plugin_peer_complete_setup_with_rows_and_version(
            plugin_socket,
            rows,
            CONTROL_PROTOCOL_VERSION,
        )
    }

    fn plugin_peer_complete_setup_with_rows_and_version(
        plugin_socket: UnixStream,
        rows: &[FaultCapabilityRowV1],
        protocol_version: u32,
    ) -> Result<ValidatedSetupRegion, String> {
        let mut plugin = ControlLifecycleStream::connected_unix_stream(plugin_socket)
            .map_err(|error| error.to_string())?;
        let negotiated = plugin
            .plugin_start_handshake(PluginHandshakeConfig {
                proto_version: protocol_version,
                abi_version: ABI_VERSION,
            })
            .map_err(|error| error.to_string())?;
        if negotiated.slot_index != 0 {
            return Err(format!(
                "expected slot 0 from host handshake, got {}",
                negotiated.slot_index
            ));
        }

        let setup = plugin
            .plugin_recv_setup_with_descriptors()
            .map_err(|error| error.to_string())?;
        let mut mapped = mmap_setup_region(setup.descriptors.shmem_fd.as_fd(), setup.region_len)
            .map_err(|error| error.to_string())?;
        let validated = mapped
            .validate_header()
            .map_err(|error| error.to_string())?;
        assert_fd_open(setup.descriptors.wake_fd.as_raw_fd()).map_err(|error| error.to_string())?;
        write_eventfd_counter(setup.descriptors.wake_fd.as_raw_fd(), EVENTFD_WAKE_PROBE)
            .map_err(|error| error.to_string())?;
        let mut setup_plan_bytes = Vec::new();
        File::from(setup.descriptors.plugin_setup_plan_fd)
            .read_to_end(&mut setup_plan_bytes)
            .map_err(|error| error.to_string())?;
        if negotiated.proto_version >= 3 {
            PluginSetupPlan::decode(&setup_plan_bytes).map_err(|error| error.to_string())?;
        } else {
            AppRandomBranchPlan::decode(&setup_plan_bytes).map_err(|error| error.to_string())?;
        }

        publish_capability_result(&mut mapped, rows).map_err(|error| error.to_string())?;
        publish_system_manifest_result(&mut mapped).map_err(|error| error.to_string())?;

        plugin
            .plugin_send_ready_setup_ack()
            .map_err(|error| error.to_string())?;
        plugin
            .enter_run_via_shared_memory()
            .map_err(|error| error.to_string())?;
        plugin
            .plugin_read_run_control_frame()
            .map_err(|error| error.to_string())?;

        Ok(validated)
    }

    pub(crate) fn publish_test_admission_results(
        mapped: &mut crucible_shmem::MappedSetupRegion,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let rows = QemuFaultCapabilityRequirement::abi_boundary_v1();
        publish_capability_result(mapped, rows.rows())?;
        publish_system_manifest_result(mapped)
    }

    fn publish_capability_result(
        mapped: &mut crucible_shmem::MappedSetupRegion,
        rows: &[FaultCapabilityRowV1],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let command_transport = mapped.fault_command_transport_mut(0)?;
        let command = crucible_shmem::dequeue_fault_command(
            command_transport.ring,
            command_transport.slots,
            command_transport.arena_header,
            command_transport.arena,
            command_transport.arena_region_offset,
        )?
        .ok_or("capability query was not published before descriptor handoff")?;
        let header = match command {
            crucible_shmem::DequeuedFaultCommand::Valid { header, payload } => {
                if !payload.is_empty() {
                    return Err("capability query payload must be empty".into());
                }
                header
            }
            crucible_shmem::DequeuedFaultCommand::Rejected { error, .. } => {
                return Err(format!("capability query was invalid: {error}").into());
            }
        };
        if header.command_kind != FaultCommandKind::QueryCapabilities
            || header.command_sequence != 1
        {
            return Err("unexpected setup-time fault command".into());
        }
        let payload = crucible_shmem::encode_fault_capability_manifest(rows)?;
        let result_transport = mapped.fault_result_transport_mut(0)?;
        crucible_shmem::enqueue_fault_result(
            result_transport.ring,
            result_transport.slots,
            result_transport.arena_header,
            result_transport.arena,
            result_transport.arena_region_offset,
            crucible_shmem::FaultResultHeaderV1 {
                abi_major: FAULT_COMMAND_ABI_MAJOR,
                abi_minor: FAULT_COMMAND_ABI_MINOR,
                command_kind: FaultCommandKind::QueryCapabilities as u16,
                status: FaultResultStatus::Applied,
                semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
                command_sequence: 1,
                observed_icount: 0,
                applied_icount: 0,
                capability_version: 1,
                phase: FaultBoundaryPhase::NodeBoundary,
                before_hash: [0; 32],
                after_hash: [0; 32],
                evidence_hash: *blake3::hash(&payload).as_bytes(),
                result_payload_hash: [0; 32],
                result_offset: 0,
                result_length: 0,
            },
            &payload,
        )?;
        Ok(())
    }

    fn publish_system_manifest_result(
        mapped: &mut crucible_shmem::MappedSetupRegion,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let command_transport = mapped.fault_command_transport_mut(0)?;
        let command = crucible_shmem::dequeue_fault_command(
            command_transport.ring,
            command_transport.slots,
            command_transport.arena_header,
            command_transport.arena,
            command_transport.arena_region_offset,
        )?
        .ok_or("system-manifest query was not published before descriptor handoff")?;
        let (header, query_payload) = match command {
            crucible_shmem::DequeuedFaultCommand::Valid { header, payload } => (header, payload),
            crucible_shmem::DequeuedFaultCommand::Rejected { error, .. } => {
                return Err(format!("system-manifest query was invalid: {error}").into());
            }
        };
        let query = FaultTargetManifestQueryV1::decode(&query_payload)?;
        if header.command_kind != FaultCommandKind::QueryTargetManifest
            || header.command_sequence != 6
            || query.kind != FaultTargetManifestKind::System
        {
            return Err("unexpected setup-time system-manifest command".into());
        }

        let payload = FaultSystemCapabilityManifestV1 {
            semantic_version: 1,
            vmstate_format_version: 1,
            vmstate_section_count: 9,
            vmstate_sections_sha256: [1; 32],
            emulator_build_id: [2; 32],
            emulator_patch_series_hash: [3; 32],
            shmem_header_hash: [4; 32],
        }
        .encode()?;
        let result_transport = mapped.fault_result_transport_mut(0)?;
        crucible_shmem::enqueue_fault_result(
            result_transport.ring,
            result_transport.slots,
            result_transport.arena_header,
            result_transport.arena,
            result_transport.arena_region_offset,
            crucible_shmem::FaultResultHeaderV1 {
                abi_major: FAULT_COMMAND_ABI_MAJOR,
                abi_minor: FAULT_COMMAND_ABI_MINOR,
                command_kind: FaultCommandKind::QueryTargetManifest as u16,
                status: FaultResultStatus::Applied,
                semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
                command_sequence: 6,
                observed_icount: 0,
                applied_icount: 0,
                capability_version: 1,
                phase: FaultBoundaryPhase::NodeBoundary,
                before_hash: [0; 32],
                after_hash: [0; 32],
                evidence_hash: *blake3::hash(&payload).as_bytes(),
                result_payload_hash: [0; 32],
                result_offset: 0,
                result_length: 0,
            },
            &payload,
        )?;
        Ok(())
    }

    fn assert_fd_open(fd: RawFd) -> Result<(), io::Error> {
        let result = unsafe {
            // SAFETY: `fcntl` validates the descriptor number and reads flags only.
            libc::fcntl(fd, libc::F_GETFD)
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn write_eventfd_counter(fd: RawFd, value: u64) -> Result<(), io::Error> {
        let bytes = value.to_ne_bytes();
        let result = unsafe {
            // SAFETY: `fd` is expected to be a live eventfd, and `bytes` points
            // at the required eight-byte eventfd counter value.
            libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len())
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result != bytes.len() as libc::ssize_t {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "eventfd counter write was short",
            ));
        }
        Ok(())
    }

    fn read_eventfd_counter(fd: RawFd) -> Result<u64, io::Error> {
        let mut bytes = [0; 8];
        let result = unsafe {
            // SAFETY: `fd` is expected to be a live eventfd, and `bytes` points
            // at eight writable bytes for the eventfd counter value.
            libc::read(fd, bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len())
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result != bytes.len() as libc::ssize_t {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eventfd counter read was short",
            ));
        }
        Ok(u64::from_ne_bytes(bytes))
    }
}
