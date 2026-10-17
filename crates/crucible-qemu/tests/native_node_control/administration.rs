//! Actual original socket/reader enrollment through the isolated GPL actor.

use super::*;
use crucible_qemu::native_node_control::NativeAdministrationTransport;

#[test]
#[ignore = "requires matching source-built QEMU and GPL plugin"]
// crucible-lint: allow clippy-disallowed-method -- Operational deadlines in these administration tests bound native supervision and never enter modeled state.
#[allow(clippy::disallowed_methods)] // External-child watchdog only, never simulated time.
fn actual_native_administration_binds_original_reader_and_endpoint() -> Result<(), Box<dyn Error>> {
    let qemu = artifact("CRUCIBLE_NATIVE_PROBE_QEMU")?;
    let plugin = artifact("CRUCIBLE_NATIVE_PROBE_PLUGIN")?;
    let mut firmware = tempfile::NamedTempFile::new()?;
    let mut rom = vec![0x90u8; 65_536];
    rom[0xfff0..0xfff5].copy_from_slice(&[0xea, 0, 0, 0, 0xf0]);
    firmware.write_all(&rom)?;
    let bios = firmware.path();
    let initialization = Some(
        crucible_protocol::node_control::NativeInitializationPreparation {
            preparation: NativePreparation {
                scope: original(1, 0, 350).scope,
                boundary: position(0),
                maximum_commands: U64::new(8),
            },
            realize_operation: id("mechanical/realize"),
            realize_request_digest: [11; 32],
            policy_digest: [12; 32],
            class_mask: 7,
            maximum_callbacks: 64,
        },
    );
    let phase_preparation = Some(crucible_protocol::node_control::NativePhasePreparation {
        initialization: initialization
            .as_ref()
            .ok_or("initialization absent")?
            .clone(),
        policy_digest: [13; 32],
        mapping: crucible_protocol::node_control::NativePhaseMapping::InstructionReaction,
        maximum_microstep: U64::new(1024),
    });
    let (mut native, endpoint) = NativeAdministrationTransport::prepare(
        phase_preparation.as_ref().ok_or("phase absent")?.clone(),
        [14; 32],
        9,
    )?;
    let administrative = native.preparation().clone();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let digest = hex(endpoint.scope_digest());
    let edition = endpoint.edition();
    let native_socket = endpoint.into_socket();
    let (host_stream, plugin_stream) = UnixStream::pair()?;
    host_stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    host_stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let allocation = RegionAllocation::new(RegionConfig::new(1, 8))?;
    let region_bytes = allocation.setup_region_bytes()?;
    let shared = memfd(&region_bytes, false)?;
    let base = QemuLaunchPluginConfig::new(plugin.to_string_lossy(), PROBE_VM_SLOT);
    let mut mapped = mmap_setup_region(shared.as_fd(), region_bytes.len() as u64)?;
    let transport = mapped.fault_command_transport_mut(PROBE_VM_SLOT)?;
    enqueue_fault_command(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
        FaultCommandHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::QueryCapabilities,
            command_flags: 0,
            phase: FaultBoundaryPhase::NodeBoundary,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 1,
            target_node_hash: base.fault_node_hash(),
            target_icount: 0,
            authorization_ceiling_icount: 0,
            binding_hash: [1; 32],
            opportunity_hash: [0; 32],
            expected_precondition_hash: [0; 32],
            payload_hash: [0; 32],
            payload_offset: 0,
            payload_length: 0,
        },
        &[],
    )?;
    // SAFETY: eventfd creates a fresh descriptor with no pointer arguments.
    let raw_wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if raw_wake < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: This new eventfd has no other descriptor owner.
    let wake = unsafe { OwnedFd::from_raw_fd(raw_wake) };
    let pins = [
        pin_descriptor(plugin_stream.as_raw_fd())?,
        pin_descriptor(shared.as_raw_fd())?,
        pin_descriptor(wake.as_raw_fd())?,
        pin_descriptor(native_socket.as_raw_fd())?,
    ];
    let mappings = [
        (pins[0].as_raw_fd(), 3),
        (pins[1].as_raw_fd(), 4),
        (pins[2].as_raw_fd(), 5),
        (pins[3].as_raw_fd(), 9),
    ];
    let mut plugin_args = format!(
        "{},{},node_control_fd=9,node_control_scope_hash={digest},node_control_version={}",
        plugin.display(),
        base.plugin_args_raw(),
        edition.version()
    );
    if let Some(initialization) = &initialization {
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        plugin_args.push_str(&format!(",node_initialization_commitment={},node_initialization_realize_digest={},node_initialization_policy_digest={},node_initialization_class_mask={},node_initialization_max_callbacks={}",
            hex(&initialization.identity_digest()?), hex(&initialization.realize_request_digest), hex(&initialization.policy_digest), initialization.class_mask, initialization.maximum_callbacks));
    }
    if let Some(phase) = &phase_preparation {
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        plugin_args.push_str(&format!(",node_phase_commitment={},node_phase_policy_digest={},node_phase_mapping=1,node_phase_max_microsteps={}",
            hex(&phase.identity_digest()?),hex(&phase.policy_digest),phase.maximum_microstep.get()));
    }
    plugin_args.push_str(&format!(
        ",node_administration_commitment={},node_administration_policy_digest={}",
        hex(&administrative.identity_digest()?),
        hex(&administrative.policy_digest)
    ));
    let mut command = Command::new(qemu);
    command
        .arg("-crucible-node-administration")
        .arg(administrative.early_launch_argument()?);
    if let Some(phase) = &phase_preparation {
        command
            .arg("-crucible-node-phase")
            .arg(phase.early_launch_argument()?);
    }
    if let Some(initialization) = &initialization {
        command
            .arg("-crucible-node-initialization")
            .arg(initialization.early_launch_argument()?);
    }
    command
        .args([
            "-machine",
            "pc,hpet=off",
            "-accel",
            "sim",
            "-icount",
            "shift=0,align=off,sleep=off",
            "-m",
            "32",
            "-nodefaults",
            "-display",
            "none",
            "-serial",
            "none",
            "-monitor",
            "none",
            "-bios",
        ])
        .arg(bios)
        .arg("-plugin")
        .arg(plugin_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    // SAFETY: The child closure uses only async-signal-safe dup2/close syscalls
    // over prevalidated disjoint scalar mappings. Pins remain live through exec.
    unsafe {
        command.pre_exec(move || {
            for (source, target) in mappings {
                if libc::dup2(source, target) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for (source, _) in mappings {
                libc::close(source);
            }
            Ok(())
        });
    }
    let mut child = ChildCustody(command.spawn()?);
    native.bind_process(child.0.id())?;
    drop(pins);
    drop(plugin_stream);
    drop(native_socket);

    let selectable = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 1, 1)?,
        Vec::new(),
        SelectablePlanContinuation::cold(),
    )?;
    let plan = memfd(
        &PluginSetupPlan::new(AppRandomBranchPlan::default(), selectable).encode()?,
        true,
    )?;
    let mut legacy = ControlLifecycleStream::connected_unix_stream(host_stream)?;
    legacy.host_accept_handshake(HostHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
        slot_index: PROBE_VM_SLOT,
        node_count: allocation.layout().node_count,
    })?;
    legacy.host_send_setup_with_descriptors(
        region_bytes.len() as u64,
        SetupDescriptorFds {
            shmem_fd: shared.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
            plugin_setup_plan_fd: plan.as_raw_fd(),
        },
    )?;
    if let Err(error) = legacy.host_accept_setup_ack() {
        // Let the child flush its install refusal before owned cleanup kills it.
        std::thread::sleep(Duration::from_millis(100));
        return Err(error.into());
    }
    legacy.enter_run_via_shared_memory()?;
    // Release only the legacy install barrier. The registered native controller
    // still withholds every modeled transition until its original command.
    mapped.node_slot(PROBE_VM_SLOT)?.publish_scheduler_advance(
        authorize_advance_ceiling(0, 1, None)?,
        AdvanceStopCondition::Ceiling,
    )?;

    let mut first = None;
    for _ in 0..2 {
        assert!(native.request_original()?);
        let deadline = Instant::now() + Duration::from_secs(5);
        let recovered = loop {
            if let Some(facts) = native.receive_original()? {
                break facts.clone();
            }
            if child.0.try_wait()?.is_some() {
                return Err("native child exited before original enrollment reply".into());
            }
            if Instant::now() >= deadline {
                return Err("native original enrollment watchdog expired".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(recovered.process_id.get(), u64::from(child.0.id()));
        assert_ne!(recovered.thread_id.get(), recovered.process_id.get());
        assert_eq!(recovered.registration_id.get(), 1);
        recovered.validate_against(&administrative)?;
        assert_eq!(
            u32::from_be_bytes(recovered.encode()?[12..16].try_into()?),
            7
        );
        if let Some(original) = &first {
            assert_eq!(&recovered, original);
        } else {
            first = Some(recovered);
        }
    }
    drop(child);
    Ok(())
}
