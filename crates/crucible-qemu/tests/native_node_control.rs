//! Actual QEMU/GPL plugin boundary probes, without provider qualification claims.

#![cfg(target_os = "linux")]
// crucible-lint: allow panic-shortcut -- These native node control tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use std::{
    error::Error,
    fs::File,
    io::{self, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use crucible_node_contract::{HashRef, Id, Phase, Position, U64};
use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycleStream, HostHandshakeConfig, SetupDescriptorFds,
    app_random_branch_plan::AppRandomBranchPlan,
    node_control::{
        BoundaryPolicy, ExecutionCommand, ExecutionKind, NativeControlEdition, NativeFrame,
        NativePreparation, NativeStopFacts, NativeStopKind, NativeTimerObservation,
        NativeWriterObservation, OwnerScope,
    },
    plugin_setup_plan::PluginSetupPlan,
    selectable_catalog_plan::{
        SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanLimits,
    },
};
use crucible_qemu::{QemuLaunchPluginConfig, native_node_control::NativeQemuControlTransport};
use crucible_shmem::{
    ABI_VERSION, AdvanceStopCondition, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR,
    FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase, FaultCommandHeaderV1, FaultCommandKind,
    RegionAllocation, RegionConfig, authorize_advance_ceiling, enqueue_fault_command,
    mmap_setup_region,
};

const PROBE_VM_SLOT: u32 = 0;

struct ChildCustody(Child);

impl Drop for ChildCustody {
    fn drop(&mut self) {
        // The test owns this exact Child; every failure contains and reaps it.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn position(time: u64) -> Position {
    Position {
        time_ps: U64::new(time),
        microstep: U64::new(0),
        phase: Phase::BoundaryControl,
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn hash(domain: &str) -> HashRef {
    HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    }
}

fn original(sequence: u64, start: u64, limit: u64) -> ExecutionCommand {
    ExecutionCommand {
        sequence: U64::new(sequence),
        scope: OwnerScope {
            session: id("mechanical/session"),
            incarnation: id("mechanical/incarnation"),
            activation: id("mechanical/activation"),
            node: id("mechanical/node"),
            owner: id("mechanical/owner"),
            world_generation: U64::new(1),
            owner_generation: U64::new(1),
            world_binding: hash("cnp.world-binding.v1"),
            owner_binding: hash("cnp.owner-binding.v1"),
        },
        operation: id(&format!("mechanical/operation/{sequence}")),
        grant: id(&format!("mechanical/grant/{sequence}")),
        input_epoch: id("mechanical/input-epoch"),
        input_batch: id("mechanical/input-batch"),
        input_batch_hash: hash("cnp.input-batch.v1"),
        closed_input_prefix: position(limit),
        authorization_digest: [7; 32],
        kind: ExecutionKind::ExactRun {
            start: position(start),
            limit: position(limit),
            boundary_policy: BoundaryPolicy::HorizonPark,
        },
    }
}

fn memfd(bytes: &[u8], sealed: bool) -> io::Result<File> {
    // SAFETY: The static name is NUL terminated; successful creation returns
    // a uniquely owned descriptor, immediately retained by File below.
    let descriptor = unsafe {
        libc::memfd_create(
            c"crucible-native-probe".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: A successful memfd_create returns this new unique descriptor.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(bytes)?;
    // Writable shared mappings still require a fixed-size backing object;
    // immutable setup plans additionally reject writes before SCM transfer.
    let seals = libc::F_SEAL_GROW
        | libc::F_SEAL_SHRINK
        | libc::F_SEAL_SEAL
        | if sealed { libc::F_SEAL_WRITE } else { 0 };
    // SAFETY: The owned descriptor is live; the command takes scalar flags.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn pin_descriptor(descriptor: i32) -> io::Result<OwnedFd> {
    // Keep all sources beyond fixed target numbers before fork; dup2 cannot
    // overwrite another captured source, even when the parent assigned fd3.
    // SAFETY: fcntl duplicates a live descriptor without consuming its owner.
    let pinned = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 64) };
    if pinned < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The duplicate is uniquely owned by this result.
    Ok(unsafe { OwnedFd::from_raw_fd(pinned) })
}

fn artifact(variable: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = PathBuf::from(
        std::env::var_os(variable)
            .ok_or_else(|| io::Error::other(format!("set {variable} to the built artifact")))?,
    );
    if !path.is_file() {
        return Err(
            io::Error::other(format!("missing {variable} artifact: {}", path.display())).into(),
        );
    }
    Ok(path)
}

// Wall time bounds this external-process test watchdog; it is never a modeled clock.
// crucible-lint: allow clippy-disallowed-method -- Operational deadlines in these native node control tests bound native supervision and never enter modeled state.
#[allow(clippy::disallowed_methods)]
fn next_any_frame(
    control: &mut NativeQemuControlTransport,
    child: &mut Child,
) -> Result<NativeFrame, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(frame) = control.poll_original()? {
            return Ok(frame);
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!("native QEMU exited early: {status}")).into());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native original receipt unavailable",
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn next_frame(
    control: &mut NativeQemuControlTransport,
    child: &mut Child,
) -> Result<NativeFrame, Box<dyn Error>> {
    loop {
        let frame = next_any_frame(control, child)?;
        if !matches!(
            frame,
            NativeFrame::CpuPark(_)
                | NativeFrame::WriterChunk(_)
                | NativeFrame::PhaseTimerChunk(_)
                | NativeFrame::InitializationCut(_)
                | NativeFrame::InitializationStopped(_)
                | NativeFrame::InitializationAcknowledged(_)
        ) {
            return Ok(frame);
        }
    }
}

fn read_timers(
    native: &mut NativeQemuControlTransport,
    child: &mut Child,
    sequence: U64,
) -> Result<NativeTimerObservation, Box<dyn Error>> {
    loop {
        assert!(native.request_timer_observation(sequence)?);
        let NativeFrame::TimerChunk(_) = next_frame(native, child)? else {
            panic!("original native timer slice");
        };
        if let Some(observation) = native.timer_observation(sequence) {
            return Ok(observation.clone());
        }
    }
}

fn run_windows(
    limits: &[u64],
    require_cpu_park: bool,
    pit_timer: bool,
    writer_custody: bool,
) -> Result<Vec<NativeStopFacts>, Box<dyn Error>> {
    run_probe(limits, require_cpu_park, pit_timer, writer_custody, false)
}

fn run_probe(
    limits: &[u64],
    require_cpu_park: bool,
    pit_timer: bool,
    writer_custody: bool,
    expect_source_fault: bool,
) -> Result<Vec<NativeStopFacts>, Box<dyn Error>> {
    run_initialized_probe(
        limits,
        require_cpu_park,
        pit_timer,
        writer_custody,
        expect_source_fault,
        false,
        ProjectionProbe::Disabled,
    )
}

enum ProjectionProbe {
    Disabled,
    Phase,
    Successor,
}

fn run_initialized_probe(
    limits: &[u64],
    require_cpu_park: bool,
    pit_timer: bool,
    writer_custody: bool,
    expect_source_fault: bool,
    initialize: bool,
    projection: ProjectionProbe,
) -> Result<Vec<NativeStopFacts>, Box<dyn Error>> {
    let phase_projection = !matches!(projection, ProjectionProbe::Disabled);
    let successor_recovery = matches!(projection, ProjectionProbe::Successor);
    let qemu = artifact("CRUCIBLE_NATIVE_PROBE_QEMU")?;
    let plugin = artifact("CRUCIBLE_NATIVE_PROBE_PLUGIN")?;
    let mut pit_firmware = None;
    let bios = if pit_timer || writer_custody {
        let mut rom = vec![0x90u8; 65_536];
        let pit_program = [
            0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0xb0, 0x30, 0xe6, 0x43, 0xb0, 0x04, 0xe6, 0x40, 0x30,
            0xc0, 0xe6, 0x40, 0xeb, 0xfe,
        ];
        let loop_program = [0x90, 0xeb, 0xfd];
        let phase_program = [
            0xb0, 0x30, 0xe6, 0x43, 0xb0, 0x04, 0xe6, 0x40, 0xb0, 0, 0xe6, 0x40, 0x90, 0xeb, 0xfd,
        ];
        let program: &[u8] = if phase_projection {
            &phase_program
        } else if pit_timer {
            &pit_program
        } else {
            &loop_program
        };
        rom[..program.len()].copy_from_slice(program);
        rom[0xfff0..0xfff5].copy_from_slice(&[0xea, 0, 0, 0, 0xf0]);
        let mut firmware = tempfile::NamedTempFile::new()?;
        firmware.write_all(&rom)?;
        let path = firmware.path().to_path_buf();
        pit_firmware = Some(firmware);
        path
    } else {
        artifact("CRUCIBLE_NATIVE_PROBE_BIOS")?
    };
    let edition = if successor_recovery {
        NativeControlEdition::PreparationSuccessor
    } else if phase_projection {
        NativeControlEdition::PhaseProjection
    } else if writer_custody {
        NativeControlEdition::OwnedCustody
    } else {
        NativeControlEdition::Original
    };
    let preparation = NativePreparation {
        scope: original(1, 0, limits[0]).scope,
        boundary: position(0),
        maximum_commands: U64::new(8),
    };
    let initialization =
        initialize.then(
            || crucible_protocol::node_control::NativeInitializationPreparation {
                preparation: preparation.clone(),
                realize_operation: id("mechanical/realize"),
                realize_request_digest: [11; 32],
                policy_digest: [12; 32],
                class_mask: 7,
                maximum_callbacks: 64,
            },
        );
    let phase_preparation =
        initialization
            .as_ref()
            .filter(|_| phase_projection)
            .map(
                |initialization| crucible_protocol::node_control::NativePhasePreparation {
                    initialization: initialization.clone(),
                    policy_digest: [13; 32],
                    mapping:
                        crucible_protocol::node_control::NativePhaseMapping::InstructionReaction,
                    maximum_microstep: U64::new(1024),
                },
            );
    let (mut native, endpoint) = if let Some(phase) = &phase_preparation {
        if successor_recovery {
            NativeQemuControlTransport::prepare_successor(phase.clone())?
        } else {
            NativeQemuControlTransport::prepare_phase(phase.clone())?
        }
    } else if let Some(initialization) = &initialization {
        NativeQemuControlTransport::prepare_initialization(initialization.clone())?
    } else {
        NativeQemuControlTransport::prepare_for_edition(preparation, edition)?
    };
    let digest = endpoint
        .scope_digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
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
    let mut command = Command::new(qemu);
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
            if pit_timer { "pc,hpet=off" } else { "pc" },
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

    if expect_source_fault {
        let mut diagnostic = None;
        while diagnostic.is_none() {
            match next_any_frame(&mut native, &mut child.0)? {
                NativeFrame::SourceFault(facts) => diagnostic = Some(facts),
                NativeFrame::CpuPark(_) | NativeFrame::WriterChunk(_) => {}
                frame => panic!("source fault is not a native completion: {frame:?}"),
            }
        }
        let diagnostic = diagnostic.ok_or("original fault diagnostic absent")?;
        assert_eq!(diagnostic.code, 3);
        assert_eq!(diagnostic.flags, 7);
        assert_eq!(diagnostic.fault_id.get(), 1);
        assert_eq!(diagnostic.command_sequence.get(), 0);
        assert_eq!(diagnostic.command_digest, [0; 32]);
        assert_eq!(diagnostic.ingress_id.get(), 0);
        assert!(matches!(diagnostic.ingress_kind, 1 | 2));
        assert_eq!(native.source_fault(), Some(diagnostic.as_ref()));
        assert!(native.transmit_original(original(1, 0, limits[0])).is_err());
        assert!(native.transmit_acknowledgement(U64::new(1)).is_err());
        assert!(native.original_facts(U64::new(1)).is_none());
        assert_eq!(
            next_any_frame(&mut native, &mut child.0)?,
            NativeFrame::SourceFault(diagnostic)
        );
        let retained = mapped.fault_command_transport_mut(PROBE_VM_SLOT)?;
        assert_eq!(retained.ring.read_index(), 0);
        assert_eq!(retained.ring.write_index(), 1);

        // A diagnostic does not prove suspension. Containment uses this exact
        // uniquely owned Child and an actual kernel kill/wait, independently.
        child.0.kill()?;
        let status = child.0.wait()?;
        assert!(!status.success());
        assert_eq!(child.0.try_wait()?, Some(status));
        return Ok(Vec::new());
    }

    let original_initialization_cut = if let Some(preparation) = &initialization {
        loop {
            native.request_initialization_cut()?;
            match next_any_frame(&mut native, &mut child.0)? {
                NativeFrame::InitializationCut(cut) => {
                    cut.validate_against(preparation)?;
                    break Some(*cut);
                }
                NativeFrame::CpuPark(_) | NativeFrame::WriterChunk(_) => {}
                frame => panic!("original construction cut: {frame:?}"),
            }
        }
    } else {
        None
    };
    let original_cpu_park = if require_cpu_park {
        assert!(native.request_cpu_park()?);
        let facts = loop {
            match next_any_frame(&mut native, &mut child.0)? {
                NativeFrame::CpuPark(facts) => break facts,
                NativeFrame::InitializationCut(_) | NativeFrame::WriterChunk(_) => {}
                frame => panic!("actual source CPU-only initial park observation: {frame:?}"),
            }
        };
        assert_eq!(facts.cpu_count, 1);
        assert_eq!(facts.coverage, 1);
        assert_eq!(facts.current_ps.get(), 0);
        assert_eq!(facts.retired_count.get(), 0);
        assert_eq!(native.prepared_cpu_park(), Some(&facts));
        Some(facts)
    } else {
        None
    };
    let original_writers = if writer_custody {
        let initial = read_writers(&mut native, &mut child.0, U64::new(0))?;
        Some(initial)
    } else {
        None
    };
    // Startup callbacks may settle before the authentic initial HOLD. Their
    // actual original cut determines refusal; a fixed startup count is not an
    // authored preparation epoch and cannot establish deterministic readiness.
    let pending_unknown_writers = !initialize
        && original_writers.as_ref().is_some_and(|initial| {
            !initial.work.is_empty()
                || initial
                    .aio
                    .iter()
                    .any(|context| context.pending_bhs != 0 || context.queued_coroutines != 0)
        });
    if let Some(cut) = &original_initialization_cut {
        use crucible_protocol::node_control::{
            NativeInitializationClass, NativeInitializationCommand, NativeInitializationStatus,
        };
        // This actual PC fixture enrolls its original dispatcher and two IDE
        // restart callbacks before construction; an empty cut would not prove
        // the HOME cleanup path this test is intended to exercise.
        if !phase_projection {
            assert_eq!(cut.rows.len(), 3);
            assert_eq!(
                cut.rows
                    .iter()
                    .filter(|row| row.class == NativeInitializationClass::QmpDispatcherStartup)
                    .count(),
                1
            );
            assert_eq!(
                cut.rows
                    .iter()
                    .filter(|row| row.class == NativeInitializationClass::IdeZeroErrorRestart)
                    .count(),
                2
            );
        }
        let writers = original_writers
            .as_ref()
            .ok_or("original writer cut absent")?;
        assert_eq!(writers.current_ps.get(), 0);
        assert_eq!(writers.retired_count.get(), 0);
        assert_eq!(writers.gate_generation, cut.hold_generation);
        for row in &cut.rows {
            assert!(
                writers
                    .bottom_halves
                    .iter()
                    .any(|bh| bh.bh_id == row.callback_id
                        && bh.context_id == row.context_id
                        && bh.active_callbacks == 0)
            );
        }
        let preparation = initialization
            .as_ref()
            .ok_or("original initialization absent")?;
        let original = NativeInitializationCommand {
            sequence: U64::new(1),
            class_mask: preparation.class_mask,
            maximum_callbacks: preparation.maximum_callbacks,
            prepared_scope_hash: cut.prepared_scope_hash,
            initialization_commitment: cut.initialization_commitment,
            realize_request_digest: preparation.realize_request_digest,
            policy_digest: preparation.policy_digest,
            original_cut_digest: cut.original_cut_digest,
        };
        assert!(
            native
                .transmit_original(self::original(1, 0, limits[0]))
                .is_err()
        );
        assert!(native.transmit_initialization(original.clone())?.1);
        let receipt = loop {
            match next_any_frame(&mut native, &mut child.0)? {
                NativeFrame::InitializationStopped(receipt) => break *receipt,
                NativeFrame::InitializationCut(_)
                | NativeFrame::CpuPark(_)
                | NativeFrame::WriterChunk(_) => {}
                frame => panic!("original initialization completion: {frame:?}"),
            }
        };
        assert_eq!(receipt.status, NativeInitializationStatus::Applied);
        assert_eq!(receipt.applied_callbacks as usize, cut.rows.len());
        assert_eq!(receipt.hold_generation, cut.hold_generation);
        assert_eq!(native.initialization_cut(), Some(cut));
        assert!(!native.initialization_acknowledged());
        if successor_recovery {
            assert!(native.request_preparation_successor().is_err());
        }
        assert!(
            native
                .transmit_original(self::original(1, 0, limits[0]))
                .is_err()
        );
        native.transmit_initialization(original.clone())?;
        loop {
            match next_any_frame(&mut native, &mut child.0)? {
                NativeFrame::InitializationStopped(retry) => {
                    assert_eq!(*retry, receipt);
                    break;
                }
                NativeFrame::InitializationCut(_)
                | NativeFrame::CpuPark(_)
                | NativeFrame::WriterChunk(_) => {}
                frame => panic!("same original result: {frame:?}"),
            }
        }
        assert!(native.transmit_initialization_acknowledgement()?);
        assert!(!native.initialization_acknowledged());
        assert!(native.transmit_initialization_acknowledgement()?);
        loop {
            match next_any_frame(&mut native, &mut child.0)? {
                NativeFrame::InitializationAcknowledged(_) => break,
                NativeFrame::InitializationCut(_)
                | NativeFrame::InitializationStopped(_)
                | NativeFrame::CpuPark(_)
                | NativeFrame::WriterChunk(_) => {}
                frame => panic!("original construction ACK: {frame:?}"),
            }
        }
        assert!(native.initialization_acknowledged());
        assert_eq!(native.initialization_receipt(), Some(&receipt));
        if successor_recovery {
            let successor = read_successor(&mut native, &mut child.0)?;
            assert_eq!(successor.initialization, receipt);
            assert_eq!(successor.facts.original_cut_digest, cut.original_cut_digest);
            assert_eq!(successor.facts.hold_generation, cut.hold_generation);
            assert!(
                successor
                    .writers
                    .aio
                    .iter()
                    .all(|context| context.pending_bhs == 0 && context.queued_coroutines == 0)
            );
            assert_eq!(
                native.writer_observation(U64::new(0)),
                original_writers.as_ref()
            );
        }
        let retained = mapped.fault_command_transport_mut(PROBE_VM_SLOT)?;
        assert_eq!(retained.ring.read_index(), 0);
        assert_eq!(retained.ring.write_index(), 1);
    }
    let mut start = 0;
    let retained_successor = native.preparation_successor().cloned();
    let mut outcomes = Vec::new();
    let mut windows = limits.to_vec();
    let mut index = 0;
    let mut pit_arm = None;
    while index < windows.len() {
        let limit = windows[index];
        let original = original(index as u64 + 1, start, limit);
        assert!(native.transmit_original(original.clone())?.1);
        let NativeFrame::Stopped(facts) = next_frame(&mut native, &mut child.0)? else {
            panic!("original native stop");
        };
        let expected_kind = if pending_unknown_writers {
            NativeStopKind::Unsupported
        } else {
            NativeStopKind::HorizonPark
        };
        assert_eq!(facts.kind, expected_kind);
        assert_eq!(facts.pending_classes, u32::MAX);
        assert_eq!(
            facts.reached,
            position(if pending_unknown_writers {
                start
            } else {
                limit
            })
        );
        assert_eq!(facts.command_digest, original.identity_digest()?);
        if let Some(initial) = &original_writers {
            let cut = read_writers(&mut native, &mut child.0, facts.sequence)?;
            assert_eq!(cut.sequence, facts.sequence);
            assert_eq!(cut.command_digest, facts.command_digest);
            assert_eq!(cut.current_ps, facts.reached.time_ps);
            assert_eq!(cut.retired_count, facts.retired_count);
            assert_eq!(cut.gate_generation, initial.gate_generation);
            assert_eq!(cut.roster_sha256, initial.roster_sha256);
            assert_eq!(cut.coverage, 7);
            assert_eq!(cut.flags, 15);
            if initialize {
                assert!(
                    cut.aio
                        .iter()
                        .all(|context| context.pending_bhs == 0 && context.queued_coroutines == 0)
                );
            } else {
                assert_eq!(cut.bottom_halves, initial.bottom_halves);
            }
            assert_eq!(cut.work, initial.work);
        }
        native.transmit_original(original)?;
        assert_eq!(
            next_frame(&mut native, &mut child.0)?,
            NativeFrame::Stopped(facts.clone())
        );
        if pit_timer && !phase_projection {
            let sequence = U64::new(index as u64 + 1);
            let observation = read_timers(&mut native, &mut child.0, sequence)?;
            assert_eq!(observation.sequence, sequence);
            assert_eq!(observation.current_ps, facts.reached.time_ps);
            assert_eq!(observation.command_digest, facts.command_digest);
            // Recovery after assembly returns the exact same canonical object.
            assert!(native.request_timer_observation(sequence)?);
            assert!(matches!(
                next_frame(&mut native, &mut child.0)?,
                NativeFrame::TimerChunk(_)
            ));
            assert_eq!(native.timer_observation(sequence), Some(&observation));
            if index == 0 {
                let deadline = facts
                    .next_native_deadline_ps
                    .ok_or("actual pending PIT deadline")?;
                let arm = observation
                    .timers
                    .iter()
                    .find(|arm| arm.expiry_ps == deadline)
                    .cloned()
                    .ok_or("authentic original pending timer arm")?;
                assert!(deadline.get() > limit);
                windows.push(deadline.get());
                windows.push(
                    deadline
                        .get()
                        .checked_add(50)
                        .ok_or("PIT deadline overflow")?,
                );
                pit_arm = Some(arm);
            } else {
                let original_arm = pit_arm.as_ref().ok_or("original PIT arm retained")?;
                if index == 1 {
                    assert!(
                        observation.timers.contains(original_arm),
                        "exclusive horizon retains same original arm"
                    );
                } else {
                    assert!(
                        !observation.timers.contains(original_arm),
                        "next native window consumes original PIT arm"
                    );
                }
            }
        }
        if phase_projection {
            let sequence = facts.sequence;
            let births = read_phase_timers(&mut native, &mut child.0, sequence)?;
            eprintln!(
                "actual original phase stop seq={} clock={} retired={} births={:?}",
                sequence.get(),
                facts.reached.time_ps.get(),
                facts.retired_count.get(),
                births.timers
            );
            if facts.reached.time_ps.get() == 350 {
                assert_eq!(facts.retired_count.get(), 6);
                assert!(births.timers.iter().all(|timer| {
                    timer
                        .birth
                        .position()
                        .is_none_or(|position| position.time_ps.get() < 350)
                }));
            }
            if facts.reached.time_ps.get() == 351 {
                assert_eq!(facts.retired_count.get(), 7);
                assert!(births.timers.iter().any(|timer| matches!(&timer.birth,
                    crucible_protocol::node_control::NativeTimerBirth::Reaction { position, sequence:birth_sequence, command_digest, .. }
                    if position.time_ps.get()==350 && position.microstep.get()==0 && position.phase==Phase::Reaction
                        && *birth_sequence==sequence && *command_digest==facts.command_digest)));
            }
            assert!(native.request_phase_timer_observation(sequence)?);
            loop {
                if matches!(
                    next_any_frame(&mut native, &mut child.0)?,
                    NativeFrame::PhaseTimerChunk(_)
                ) {
                    break;
                }
            }
            assert_eq!(native.phase_timer_observation(sequence), Some(&births));
        }
        assert!(native.transmit_acknowledgement(U64::new(index as u64 + 1))?);
        assert!(matches!(
            next_frame(&mut native, &mut child.0)?,
            NativeFrame::Acknowledged(_)
        ));
        if successor_recovery {
            assert_eq!(
                Some(read_successor(&mut native, &mut child.0)?),
                retained_successor
            );
            assert_eq!(
                native.writer_observation(U64::new(0)),
                original_writers.as_ref()
            );
        }
        start = facts.reached.time_ps.get();
        outcomes.push(facts);
        index += 1;
    }
    if let Some(initial) = original_writers {
        assert_eq!(
            read_writers(&mut native, &mut child.0, U64::new(0))?,
            initial
        );
    }
    if let Some(original) = original_cpu_park {
        assert!(native.request_cpu_park()?);
        let mut recovered = next_any_frame(&mut native, &mut child.0)?;
        while matches!(
            recovered,
            NativeFrame::WriterChunk(_)
                | NativeFrame::InitializationCut(_)
                | NativeFrame::InitializationStopped(_)
                | NativeFrame::InitializationAcknowledged(_)
        ) {
            recovered = next_any_frame(&mut native, &mut child.0)?;
        }
        assert_eq!(recovered, NativeFrame::CpuPark(original.clone()));
        // Recovery returns historical bytes, not invented current readiness.
        assert!(original.current_ps.get() < limits[limits.len() - 1]);
    }
    // Even a well-formed legacy FIFO entry is not a native staged input cut.
    // Setup and every native grant preserve the same original unread entry.
    let retained = mapped.fault_command_transport_mut(PROBE_VM_SLOT)?;
    assert_eq!(retained.ring.read_index(), 0);
    assert_eq!(retained.ring.write_index(), 1);
    drop(pit_firmware);
    Ok(outcomes)
}

#[test]
#[ignore = "requires built strict-native QEMU, GPL plugin and BIOS artifact environment"]
fn actual_native_channel_preserves_exclusive_retirement_and_partitioned_service_credit()
-> Result<(), Box<dyn Error>> {
    let loose = run_windows(&[200], false, false, false)?;
    let split = run_windows(&[110, 200], false, false, false)?;
    let credit = run_windows(&[110, 151], false, false, false)?;
    let equal = run_windows(&[100, 101], false, false, false)?;

    assert_eq!(loose[0].retired_count.get(), 3);
    assert_eq!(split[0].retired_count.get(), 2);
    assert_eq!(split[0].next_service_deadline_ps, Some(U64::new(150)));
    assert_eq!(split[1].retired_count, loose[0].retired_count);
    assert_eq!(
        split[1].next_service_deadline_ps,
        loose[0].next_service_deadline_ps
    );
    assert_eq!(credit[1].retired_count.get(), 3);
    assert_eq!(equal[0].retired_count.get(), 1);
    assert_eq!(equal[1].retired_count.get(), 2);
    Ok(())
}

#[test]
#[ignore = "requires built CPU-park source query, matched GPL plugin and BIOS artifacts"]
fn actual_native_cpu_park_preserves_original_scoped_history_without_readiness_claim()
-> Result<(), Box<dyn Error>> {
    let observations = run_windows(&[200], true, false, false)?;
    assert_eq!(observations[0].retired_count.get(), 3);
    Ok(())
}

#[test]
#[ignore = "requires native timer inventory, matched GPL plugin and QEMU artifacts"]
fn actual_native_pit_inventory_retains_original_arm_at_horizon_and_across_slice_retry()
-> Result<(), Box<dyn Error>> {
    let observations = run_windows(&[10_000], true, true, false)?;
    assert_eq!(observations.len(), 3);
    Ok(())
}

// Wall time bounds this external-process test watchdog; it is never a modeled clock.
// crucible-lint: allow clippy-disallowed-method -- Operational deadlines in these native node control tests bound native supervision and never enter modeled state.
#[allow(clippy::disallowed_methods)]
fn read_writers(
    native: &mut NativeQemuControlTransport,
    child: &mut Child,
    sequence: U64,
) -> Result<NativeWriterObservation, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // The initial CPU-only fact can precede completion of the actual HOLD.
        // Retry this original offset; the reader never resamples source queues.
        assert!(native.request_writer_observation(sequence)?);
        while native.poll_original()?.is_some() {}
        if let Some(cut) = native.writer_observation(sequence) {
            return Ok(cut.clone());
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!("native QEMU exited early: {status}")).into());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original writer object unavailable",
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
#[ignore = "requires source-held writer cut, edition-two GPL plugin and QEMU artifacts"]
fn actual_native_writer_hold_preserves_original_cuts_and_legacy_fifo() -> Result<(), Box<dyn Error>>
{
    let observations = run_windows(&[110, 200], true, false, true)?;
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].kind, observations[1].kind);
    match observations[0].kind {
        NativeStopKind::Unsupported => {
            assert_eq!(observations[0].retired_count.get(), 0);
            assert_eq!(observations[1].retired_count.get(), 0);
        }
        NativeStopKind::HorizonPark => {
            assert_eq!(observations[0].retired_count.get(), 2);
            assert_eq!(observations[1].retired_count.get(), 3);
        }
        kind => panic!("unexpected actual native writer stop: {kind:?}"),
    }
    Ok(())
}

#[test]
#[ignore = "requires genuine GPL native IRQ/work-fault injection launcher and matching plugin"]
fn actual_native_source_fault_requires_independent_child_containment() -> Result<(), Box<dyn Error>>
{
    assert!(run_probe(&[110], false, false, true, true)?.is_empty());
    Ok(())
}

#[test]
#[ignore = "requires source-built native initialization QEMU and matching GPL plugin"]
fn original_construction_epoch_applies_finite_home_cut_and_retains_ack_custody()
-> Result<(), Box<dyn Error>> {
    let outcomes = run_initialized_probe(
        &[110, 200],
        true,
        false,
        true,
        false,
        true,
        ProjectionProbe::Disabled,
    )?;
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].kind, NativeStopKind::HorizonPark);
    assert_eq!(outcomes[0].retired_count.get(), 2);
    assert_eq!(outcomes[1].retired_count.get(), 3);
    Ok(())
}

// Wall time bounds this external-process test watchdog; it is never a modeled clock.
// crucible-lint: allow clippy-disallowed-method -- Operational deadlines in these native node control tests bound native supervision and never enter modeled state.
#[allow(clippy::disallowed_methods)]
fn read_phase_timers(
    native: &mut NativeQemuControlTransport,
    child: &mut Child,
    sequence: U64,
) -> Result<crucible_protocol::node_control::NativePhaseTimerObservation, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(native.request_phase_timer_observation(sequence)?);
        while native.poll_original()?.is_some() {}
        if let Some(observation) = native.phase_timer_observation(sequence) {
            return Ok(observation.clone());
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!("native QEMU exited: {status}")).into());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native phase original slice unavailable",
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
#[ignore = "requires genuine V6 source phase policy, matched GPL plugin and original construction pin"]
fn actual_native_pit_instruction_birth_is_excluded_at350_and_mapped_at351()
-> Result<(), Box<dyn Error>> {
    let stops = run_initialized_probe(
        &[350, 351],
        true,
        true,
        true,
        false,
        true,
        ProjectionProbe::Phase,
    )?;
    assert_eq!(stops.len(), 2);
    assert_eq!(stops[0].retired_count.get(), 6);
    assert_eq!(stops[1].retired_count.get(), 7);
    Ok(())
}

// Wall time bounds only the native child watchdog; no modeled clock uses it.
// crucible-lint: allow clippy-disallowed-method -- Operational deadlines in these native node control tests bound native supervision and never enter modeled state.
#[allow(clippy::disallowed_methods)]
fn read_successor(
    native: &mut NativeQemuControlTransport,
    child: &mut Child,
) -> Result<crucible_protocol::node_control::NativePreparationSuccessorObservation, Box<dyn Error>>
{
    let deadline = Instant::now() + Duration::from_secs(10);
    assert!(native.request_preparation_successor()?);
    let mut received = false;
    loop {
        while let Some(frame) = native.poll_original()? {
            if matches!(frame, NativeFrame::PreparationSuccessorChunk(_)) {
                received = true;
            }
        }
        if received {
            if let Some(original) = native.preparation_successor() {
                return Ok(original.clone());
            }
            assert!(native.request_preparation_successor()?);
            received = false;
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!("native QEMU exited: {status}")).into());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original preparation successor unavailable",
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
#[ignore = "requires actual source successor API and explicitly negotiated edition-four GPL plugin"]
fn actual_native_successor_keeps_pre_home_evidence_and_original_ack_distinct()
-> Result<(), Box<dyn Error>> {
    let stops = run_initialized_probe(
        &[350, 351],
        true,
        true,
        true,
        false,
        true,
        ProjectionProbe::Successor,
    )?;
    assert_eq!(stops.len(), 2);
    assert_eq!(stops[0].retired_count.get(), 6);
    assert_eq!(stops[1].retired_count.get(), 7);
    Ok(())
}

#[path = "native_node_control/administration.rs"]
mod administration;
