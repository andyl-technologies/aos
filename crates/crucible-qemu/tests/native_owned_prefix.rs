//! Genuine original host-driver custody over the native quiet prefix endpoint.
//!
//! Constructor and absolute supervisor mechanics come from the frozen component
//! fixture. This distinct scenario drives Compute/ACK/Continue through the owning
//! archive/transport driver; it grants no timer/output/retirement/common readiness.

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
        BoundaryPolicy, ExecutionCommand, ExecutionKind, NativeFrame, NativePreparation, OwnerScope,
    },
    plugin_setup_plan::PluginSetupPlan,
    selectable_catalog_plan::{
        SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanLimits,
    },
};
use crucible_qemu::{
    QemuLaunchPluginConfig,
    native_node_control::{NativeAdministrationTransport, NativeQemuControlTransport},
};
use crucible_shmem::{
    ABI_VERSION, AdvanceStopCondition, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR,
    FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase, FaultCommandHeaderV1, FaultCommandKind,
    RegionAllocation, RegionConfig, authorize_advance_ceiling, enqueue_fault_command,
    mmap_setup_region,
};

#[path = "native_node_control/watchdog.rs"]
mod watchdog;

use watchdog::{OriginalDeadline, check_child};

const PROBE_VM_SLOT: u32 = 0;

struct ChildCustody(Option<Child>);

impl ChildCustody {
    fn process(&mut self) -> Result<&mut Child, Box<dyn Error>> {
        self.0
            .as_mut()
            .ok_or_else(|| "original child already transferred".into())
    }

    fn take_child(&mut self) -> Result<Child, Box<dyn Error>> {
        self.0
            .take()
            .ok_or_else(|| "original child already transferred".into())
    }
}

impl Drop for ChildCustody {
    fn drop(&mut self) {
        // The test owns this exact Child; every failure contains and reaps it.
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
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

use crucible_qemu::native_node_control::owned_operation::{
    Archive, ArchiveBudget, NativeOwnedPrefixOperation, OriginalOperationProgress, TurnoverState,
};

#[test]
#[ignore = "requires exact native quiet prefix source and GPL runtime"]
fn actual_native_library_owner_preserves_original_child_and_quiet_custody()
-> Result<(), Box<dyn Error>> {
    run_original_native_owner_scenario(false)
}

#[test]
#[ignore = "requires exact native initial contract and GPL runtime"]
fn actual_native_session_consumes_original_initial_custody_into_quiet_operation()
-> Result<(), Box<dyn Error>> {
    run_original_native_owner_scenario(true)
}

#[path = "native_owned_prefix/initial_session.rs"]
mod initial_session;

fn run_original_native_owner_scenario(initial_contract: bool) -> Result<(), Box<dyn Error>> {
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
    let (mut native, endpoint) = {
        use sha2::{Digest, Sha256};
        let parameters = crucible_qemu::native_node_control::NativeFixedMicrovmParameters {
            policy_digest: [15; 32],
            firmware_sha256: Sha256::digest(&rom).into(),
            firmware_length: U64::new(rom.len() as u64),
            ram_length: U64::new(32 * 1024 * 1024),
            seed: U64::new(8254),
            maximum_service_span: U64::new(64),
            mapping:
                crucible_protocol::node_control::NativeFixedMicrovmMapping::InstructionThenTimers,
            maximum_callbacks: 64,
        };
        {
            NativeAdministrationTransport::prepare_prefix(
                phase_preparation.as_ref().ok_or("phase absent")?.clone(),
                [14; 32],
                9,
                parameters,
                crucible_qemu::native_node_control::NativePrefixParameters {
                    effect_policy_digest: [16; 32],
                    maximum_callbacks: 64,
                    maximum_service_span: U64::new(4),
                    prefix_policy_digest: [17; 32],
                    maximum_prefixes: 2,
                },
            )?
        }
    };
    let administrative = native.preparation().clone();
    // Full root preparation is separately pinned in both native launch and the
    // immutable controller-nine bootstrap. Source policy enrollment still provides
    // no epoch or finite effect permission; old compute frames remain refused.
    let fixed_root = native.fixed_microvm_preparation().cloned();
    let effect_preparation = native.effect_preparation().cloned();
    let prefix_preparation = native
        .prefix_preparation()
        .cloned()
        .ok_or("prefix preparation absent")?;
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
    {
        plugin_args.push_str(",node_root_epoch_version=1");
    }
    {
        plugin_args.push_str(",node_endpoint_owner_version=1");
    }
    if let Some(effect) = &effect_preparation {
        plugin_args.push_str(&format!(
            ",node_effect_commitment={}",
            hex(&effect.identity_digest()?)
        ));
    }
    plugin_args.push_str(&format!(
        ",node_prefix_commitment={}",
        hex(&prefix_preparation.identity_digest()?)
    ));
    {
        plugin_args.push_str(",node_bounded_teardown_version=1");
    }
    if initial_contract {
        plugin_args.push_str(",node_prefix_preparation_contract_version=1");
    }
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
    if let Some(root) = &fixed_root {
        plugin_args.push_str(&format!(
            ",node_fixed_microvm_commitment={},node_fixed_microvm_policy_digest={}",
            hex(&root.identity_digest()?),
            hex(&root.policy_digest)
        ));
    }
    let mut command = Command::new(qemu);
    if let Some(effect) = &effect_preparation {
        command
            .arg("-crucible-node-effect")
            .arg(effect.early_launch_argument()?);
    }
    command
        .arg("-crucible-node-prefix")
        .arg(prefix_preparation.early_launch_argument()?);
    if let Some(root) = &fixed_root {
        command
            .arg("-crucible-node-root")
            .arg(root.early_launch_argument()?);
    }
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
            "microvm,acpi=off,rtc=off,pcie=off,usb=off,isa-serial=off,ioapic2=off,pit=on,pic=on",
            "-smp",
            "1",
            "-cpu",
            "qemu64",
            "-seed",
            "8254",
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
    {
        // Diagnostic-only source artifacts retain the exact original argv;
        // these launch bytes are correlation, never native effect authority.
        eprintln!("original-controller-nine-command={command:?}");
    }

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
    let mut child = ChildCustody(Some(command.spawn()?));
    native.bind_process(child.process()?.id())?;
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
    let original_handshake = legacy.host_accept_handshake(HostHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
        slot_index: PROBE_VM_SLOT,
        node_count: allocation.layout().node_count,
    });

    original_handshake?;
    legacy.host_send_setup_with_descriptors(
        region_bytes.len() as u64,
        SetupDescriptorFds {
            shmem_fd: shared.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
            plugin_setup_plan_fd: plan.as_raw_fd(),
        },
    )?;
    legacy.host_accept_setup_ack()?;
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
        let NativeFrame::AdministrationFacts(recovered) =
            OriginalDeadline::after(Duration::from_secs(5)).next_matching(
                || {
                    Ok(native
                        .receive_original()?
                        .cloned()
                        .map(|facts| NativeFrame::AdministrationFacts(Box::new(facts))))
                },
                || check_child(child.process()?),
                |_| true,
            )?
        else {
            return Err("foreign original enrollment response".into());
        };
        assert_eq!(recovered.process_id.get(), u64::from(child.process()?.id()));
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
    let original_preparation = administrative.phase.initialization.clone();
    let query = NativeFrame::QueryInitialization(
        crucible_protocol::node_control::NativeInitializationQuery {
            prepared_scope_hash: original_preparation.preparation.scope.identity_digest()?,
            initialization_commitment: original_preparation.identity_digest()?,
        },
    );
    assert!(native.send_construction(&query)?);
    let NativeFrame::InitializationCut(cut) =
        next_construction_reply(&mut native, child.process()?, Duration::from_secs(5))?
    else {
        return Err("foreign original construction response".into());
    };
    cut.validate_against(&original_preparation)?;
    assert!(
        !cut.rows.is_empty(),
        "original early enrolled callbacks must survive to HOME"
    );
    let initialize = crucible_protocol::node_control::NativeInitializationCommand {
        sequence: U64::new(1),
        class_mask: original_preparation.class_mask,
        maximum_callbacks: original_preparation.maximum_callbacks,
        prepared_scope_hash: query_scope(&query)?,
        initialization_commitment: original_preparation.identity_digest()?,
        realize_request_digest: original_preparation.realize_request_digest,
        policy_digest: original_preparation.policy_digest,
        original_cut_digest: cut.original_cut_digest,
    };
    initialize.validate_against(&original_preparation, &cut)?;
    let request = NativeFrame::Initialize(Box::new(initialize.clone()));
    assert!(native.send_construction(&request)?);

    let NativeFrame::InitializationStopped(receipt) =
        next_construction_reply(&mut native, child.process()?, Duration::from_secs(5))?
    else {
        return Err("foreign original HOME response".into());
    };
    receipt.validate_against(&initialize, &cut)?;
    assert_eq!(
        receipt.status,
        crucible_protocol::node_control::NativeInitializationStatus::Applied
    );
    assert_eq!(receipt.applied_callbacks as usize, cut.rows.len());
    let acknowledgement = crucible_protocol::node_control::NativeInitializationAcknowledgement {
        prepared_scope_hash: initialize.prepared_scope_hash,
        initialization_commitment: initialize.initialization_commitment,
        sequence: initialize.sequence,
        command_digest: initialize.identity_digest()?,
    };
    let ack_request = NativeFrame::AcknowledgeInitialization(acknowledgement.clone());
    for _ in 0..2 {
        assert!(native.send_construction(&ack_request)?);
        let NativeFrame::InitializationAcknowledged(ack) =
            next_construction_reply(&mut native, child.process()?, Duration::from_secs(5))?
        else {
            return Err("foreign original ACK response".into());
        };
        assert_eq!(ack, acknowledgement);
    }
    assert!(native.send_construction(&request)?);
    let NativeFrame::InitializationStopped(recovered) =
        next_construction_reply(&mut native, child.process()?, Duration::from_secs(5))?
    else {
        return Err("changed original construction response".into());
    };
    assert_eq!(recovered, receipt);
    let mut original_bytes = Vec::new();
    let mut original_facts = None;
    loop {
        let query = crucible_protocol::node_control::NativePreparationSuccessorQuery {
            prepared_scope_hash: initialize.prepared_scope_hash,
            initialization_sequence: initialize.sequence,
            original_cut_digest: cut.original_cut_digest,
            offset: U64::new(original_bytes.len() as u64),
        };
        assert!(native.send_construction(&NativeFrame::QueryPreparationSuccessor(query.clone()))?);
        let NativeFrame::PreparationSuccessorChunk(chunk) =
            next_construction_reply(&mut native, child.process()?, Duration::from_secs(5))?
        else {
            return Err("foreign original successor response".into());
        };
        assert_eq!(chunk.offset, query.offset);
        if let Some(facts) = &original_facts {
            assert_eq!(facts, &chunk.facts);
        } else {
            original_facts = Some(chunk.facts.clone());
        }
        original_bytes.extend_from_slice(&chunk.bytes);
        if original_bytes.len() as u64 == chunk.facts.content_length.get() {
            break;
        }
    }
    let facts = original_facts.ok_or("original successor missing")?;
    let successor = crucible_protocol::node_control::NativePreparationSuccessorObservation::decode(
        facts,
        &original_bytes,
    )?;
    assert_eq!(successor.cpu_park.current_ps.get(), 0);
    assert_eq!(successor.cpu_park.retired_count.get(), 0);
    assert_eq!(successor.cpu_park.next_service_deadline_ps, None);
    assert_eq!(successor.cpu_park.pending_service_credit_ps.get(), 0);
    assert_eq!(successor.initialization, *receipt);
    assert_eq!(successor.writers.cpus.len(), 1);
    assert!(successor.writers.work.is_empty());
    assert!(
        native
            .send_construction(&NativeFrame::Command(Box::new(original(1, 0, 350))))
            .is_err()
    );
    let mut command = original(1, 0, 350);
    let empty = crucible_node_contract::InputBatch {
        schema_version: 1,
        execution_owner_id: command.scope.owner.clone(),
        input_epoch: command.input_epoch.clone(),
        batch_id: command.input_batch.clone(),
        batch_sequence: U64::new(1),
        events: Vec::new(),
        extensions: Default::default(),
    };
    command.input_batch_hash = empty.identity()?;
    let compute = crucible_protocol::node_control::NativeEffectCompute {
        command,
        effect_preparation: prefix_preparation.identity_digest()?,
        maximum_callbacks: 64,
        maximum_service_span: U64::new(4),
        input_batch_sequence: U64::new(1),
    };
    let archive_directory = tempfile::tempdir()?;
    let archive_path = archive_directory.path().join("original-command.archive");
    let archive = Archive::create(
        &archive_path,
        compute.command.scope.identity_digest()?,
        compute.effect_preparation,
        ArchiveBudget {
            lifetime_bytes: 65_536 + 136,
            lifetime_commands: 1,
            maximum_prefixes: 2,
        },
    )?;
    let original_pid = child.process()?.id();
    let mut driver = if initial_contract {
        initial_session::prepare_and_consume(
            child.take_child()?,
            native,
            archive,
            &archive_directory.path().join("original-initial.evidence"),
            (*receipt).clone(),
            compute.clone(),
        )?
    } else {
        NativeOwnedPrefixOperation::retain(child.take_child()?, native, archive, compute.clone())
    };
    let initial_bytes = initial_session::retained_bytes(&driver, initial_contract)?;
    assert_eq!(driver.process_id(), original_pid);
    assert!(!driver.reaped());
    assert!(driver.supervision_refusal().is_none());
    assert_eq!(
        driver.archive_state(),
        TurnoverState::CommandReserved { sequence: 1 }
    );
    let original_durable_bytes = std::fs::read(&archive_path)?;

    next_driver_progress(&mut driver, OriginalOperationProgress::ResultRetained)?;
    let NativeFrame::EffectProgress(first) = driver
        .journal()
        .and_then(|journal| journal.retained_frame(0))
        .ok_or("driver original result missing")?
    else {
        return Err("foreign driver initial body".into());
    };
    first.validate_against(&compute)?;
    assert_eq!(first.raw_before.get(), 0);
    assert_eq!(first.raw_after.get(), 1);
    assert_eq!(first.returned_service_count.get(), 1);
    assert_eq!(first.end_result, 0);
    assert!(driver.request_continuation().is_err());
    next_driver_progress(
        &mut driver,
        OriginalOperationProgress::AcknowledgementConsumed,
    )?;

    driver.request_continuation()?;
    next_driver_progress(&mut driver, OriginalOperationProgress::ResultRetained)?;
    let NativeFrame::PrefixProgress(prefix) = driver
        .journal()
        .and_then(|journal| journal.retained_frame(1))
        .ok_or("driver original continuation missing")?
    else {
        return Err("foreign driver typed body".into());
    };
    prefix.validate_after_initial(&compute, &first)?;
    assert_eq!(prefix.raw_before.get(), 1);
    assert_eq!(prefix.raw_after.get(), 4);
    assert_eq!(prefix.cpu_retirements.get(), 3);
    assert_eq!(prefix.cumulative_cpu_retirements.get(), 4);
    assert_eq!(prefix.timer_callbacks.get(), 0);
    assert_eq!(prefix.end_result, 0);
    assert_eq!(
        prefix.status,
        crucible_protocol::node_control::NativeEffectProgressStatus::PartialPrefix
    );
    next_driver_progress(
        &mut driver,
        OriginalOperationProgress::AcknowledgementConsumed,
    )?;

    assert_eq!(
        driver.journal().map(|journal| journal.retained_prefixes()),
        Some(2)
    );
    assert!(driver.request_continuation().is_err());
    assert!(driver.operation_failure().is_none());
    assert_eq!(driver.original(), &compute);
    assert_eq!(
        driver.archive_state(),
        TurnoverState::CommandReserved { sequence: 1 }
    );
    assert_eq!(std::fs::read(&archive_path)?, original_durable_bytes);
    assert!(!driver.reaped());
    driver.dispose(Duration::from_secs(5))?;
    assert!(driver.reaped());
    assert!(driver.poll().is_err());
    assert_eq!(driver.original(), &compute);
    assert_eq!(std::fs::read(&archive_path)?, original_durable_bytes);
    assert_eq!(
        initial_session::retained_bytes(&driver, initial_contract)?,
        initial_bytes
    );
    drop(child);
    Ok(())
}

fn next_driver_progress(
    driver: &mut NativeOwnedPrefixOperation,
    expected: OriginalOperationProgress,
) -> Result<(), Box<dyn Error>> {
    // Preserve the component's original ten-second result and five-second ACK
    // waits. Every iteration checks the same absolute deadline on both sides.
    let deadline = match expected {
        OriginalOperationProgress::AcknowledgementConsumed => {
            OriginalDeadline::after(Duration::from_secs(5))
        }
        _ => OriginalDeadline::native(),
    };
    loop {
        deadline.check()?;
        let progress = driver.poll()?;
        deadline.check()?;
        if progress == expected {
            return Ok(());
        }
        deadline.wait_pending()?;
    }
}

fn query_scope(query: &NativeFrame) -> Result<[u8; 32], Box<dyn Error>> {
    match query {
        NativeFrame::QueryInitialization(query) => Ok(query.prepared_scope_hash),
        _ => Err("not original query".into()),
    }
}

/// Receives one original response under the existing finite child supervisor.
///
/// # Errors
/// Propagates receive errors, actual child death, or the unchanged absolute
/// deadline. It neither replaces a packet nor resets a partially elapsed wait.
fn next_construction_reply(
    native: &mut NativeAdministrationTransport,
    child: &mut Child,
    duration: Duration,
) -> Result<NativeFrame, Box<dyn Error>> {
    OriginalDeadline::after(duration).next_matching(
        || Ok(native.receive_construction()?),
        || check_child(child),
        |_| true,
    )
}
