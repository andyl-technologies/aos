//! Actual original socket/reader enrollment through the isolated GPL actor.

use super::*;
use crucible_qemu::native_node_control::NativeAdministrationTransport;

#[test]
#[ignore = "requires matching source-built QEMU and GPL plugin"]
// crucible-lint: allow clippy-disallowed-method -- Absolute external-child watchdogs measure process responsiveness, never guest time.
#[allow(clippy::disallowed_methods)]
fn actual_microvm_original_construction_acks_without_guest_execution() -> Result<(), Box<dyn Error>>
{
    run_original_construction(false, None, false)
}

#[test]
#[ignore = "requires source-built fixed-microvm constructor and GPL factory fixture"]
// crucible-lint: allow clippy-disallowed-method -- Absolute external-child watchdogs measure process responsiveness, never guest time.
#[allow(clippy::disallowed_methods)]
fn actual_fixed_microvm_constructor_seals_original_source_objects_without_effect_permission()
-> Result<(), Box<dyn Error>> {
    run_original_construction(true, None, false)
}

#[test]
#[ignore = "requires source-built dormant V9 registrar and matching GPL plugin"]
// crucible-lint: allow clippy-disallowed-method -- Absolute external-child watchdogs measure process responsiveness, never guest time.
#[allow(clippy::disallowed_methods)]
fn actual_fixed_microvm_dormant_epoch_registration_has_no_effect_permission()
-> Result<(), Box<dyn Error>> {
    run_original_construction(true, None, true)
}

// crucible-lint: allow clippy-disallowed-method -- Absolute external-child watchdogs measure process responsiveness, never guest time.
#[allow(clippy::disallowed_methods)]
fn run_original_construction(
    pin_fixed_root: bool,
    containment: Option<(&str, &str, &str)>,
    dormant_epoch: bool,
) -> Result<(), Box<dyn Error>> {
    let containment_log = containment
        .map(|_| {
            std::env::var_os("CRUCIBLE_NATIVE_PROBE_CONTAINMENT_LOG")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    io::Error::other(
                        "set CRUCIBLE_NATIVE_PROBE_CONTAINMENT_LOG to the source fixture log",
                    )
                })
        })
        .transpose()?;
    let log_offset = containment_log
        .as_ref()
        .map(|path| {
            std::fs::metadata(path)
                .map(|metadata| metadata.len())
                .or_else(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        Ok(0)
                    } else {
                        Err(error)
                    }
                })
        })
        .transpose()?;
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
    let (mut native, endpoint) = if pin_fixed_root {
        use sha2::{Digest, Sha256};
        NativeAdministrationTransport::prepare_fixed_microvm(
            phase_preparation.as_ref().ok_or("phase absent")?.clone(), [14;32], 9,
            crucible_qemu::native_node_control::NativeFixedMicrovmParameters {
                policy_digest: [15;32], firmware_sha256: Sha256::digest(&rom).into(),
                firmware_length: U64::new(rom.len() as u64), ram_length: U64::new(32*1024*1024),
                seed: U64::new(8254), maximum_service_span: U64::new(64),
                mapping: crucible_protocol::node_control::NativeFixedMicrovmMapping::InstructionThenTimers,
                maximum_callbacks: 64,
            },
        )?
    } else {
        NativeAdministrationTransport::prepare_construction(
            phase_preparation.as_ref().ok_or("phase absent")?.clone(),
            [14; 32],
            9,
        )?
    };
    let administrative = native.preparation().clone();
    // Full root preparation is separately pinned in both native launch and the
    // immutable edition-seven bootstrap. Source policy enrollment still provides
    // no epoch or finite effect permission; old compute frames remain refused.
    let fixed_root = native.fixed_microvm_preparation().cloned();
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
    if dormant_epoch {
        plugin_args.push_str(",node_root_epoch_version=1");
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
    let original_handshake = legacy.host_accept_handshake(HostHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
        slot_index: PROBE_VM_SLOT,
        node_count: allocation.layout().node_count,
    });
    if let Some(("foreign-thread-delivery", diagnostic, original_seam)) = containment {
        // This real producer runs during source registration, before an Init
        // cut or command can exist. Preserve the full original preparation and
        // transport without minting an unissued operation or Applied receipt.
        let original_preparation = native.fixed_microvm_preparation().cloned();
        let original_administration = administrative.encode()?;
        assert!(original_handshake.is_err());

        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err("pre-Init original child containment watchdog".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(status.code(), Some(125));
        assert_eq!(child.0.wait()?, status, "original child was reaped");
        assert_eq!(
            native.fixed_microvm_preparation(),
            original_preparation.as_ref()
        );
        assert_eq!(administrative.encode()?, original_administration);
        assert_original_containment_log(
            containment_log
                .as_ref()
                .ok_or("containment diagnostic path absent")?,
            log_offset.ok_or("log offset absent")?,
            "foreign-thread-delivery",
            diagnostic,
            original_seam,
        )?;
        return Ok(());
    }
    original_handshake?;
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

    if let Some(("foreign-thread-post-install", diagnostic, original_seam)) = containment {
        // The successor fixture waits for genuine post-install RR custody before
        // relinquishing BQL. No host Init query, command or ACK has been sent.
        let original_preparation = native.fixed_microvm_preparation().cloned();
        let original_administration = administrative.encode()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err("post-install pre-Init child containment watchdog".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        };

        assert_eq!(status.code(), Some(125));
        assert_eq!(child.0.wait()?, status, "original child was reaped");
        assert_eq!(
            native.fixed_microvm_preparation(),
            original_preparation.as_ref()
        );
        assert_eq!(administrative.encode()?, original_administration);
        let path = containment_log
            .as_ref()
            .ok_or("containment diagnostic path absent")?;
        let offset = log_offset.ok_or("log offset absent")?;
        assert_original_containment_log(
            path,
            offset,
            "foreign-thread-delivery",
            diagnostic,
            original_seam,
        )?;
        assert_original_containment_log(
            path,
            offset,
            "foreign-thread-delivery",
            diagnostic,
            "same-original-process=1 actual-BQL=held before-native-seal=1 effect-permission=absent",
        )?;
        return Ok(());
    }

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
    let original_preparation = administrative.phase.initialization.clone();
    let query = NativeFrame::QueryInitialization(
        crucible_protocol::node_control::NativeInitializationQuery {
            prepared_scope_hash: original_preparation.preparation.scope.identity_digest()?,
            initialization_commitment: original_preparation.identity_digest()?,
        },
    );
    assert!(native.send_construction(&query)?);
    let deadline = Instant::now() + Duration::from_secs(5);
    let cut = loop {
        match native.receive_construction()? {
            Some(NativeFrame::InitializationCut(cut)) => break cut,
            Some(_) => return Err("foreign original construction response".into()),
            None => {}
        }
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("original cut watchdog".into());
        }
        std::thread::sleep(Duration::from_millis(1));
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
    if let Some((mode, diagnostic, original_seam)) = containment {
        // The original request, host endpoint and complete preparation stay
        // owned while the supervisor awaits this exact child. A missing receipt
        // or watchdog expiry cannot qualify a containment result.
        let original_request =
            crucible_protocol::node_control::encode_frame_for_edition(edition, &request)?;
        let original_preparation = native.fixed_microvm_preparation().cloned();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut historical_applied = None;
        let status = loop {
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            match native.receive_construction()? {
                Some(NativeFrame::InitializationStopped(receipt)) => {
                    // Applied describes the preceding original construction
                    // cleanup. The reader can send this retained historical
                    // body while the source fixture is still checking roots;
                    // it supplies no evidence about the subsequent mutation
                    // or current physical state.
                    receipt.validate_against(&initialize, &cut)?;
                    assert_eq!(
                        receipt.status,
                        crucible_protocol::node_control::NativeInitializationStatus::Applied
                    );
                    if let Some(original) = &historical_applied {
                        assert_eq!(original, &receipt);
                    } else {
                        historical_applied = Some(receipt);
                    }
                }
                Some(frame) => {
                    return Err(format!("foreign lifetime containment response: {frame:?}").into());
                }
                None => {}
            }
            if Instant::now() >= deadline {
                return Err("actual lifetime child did not exit before watchdog".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(
            status.code(),
            Some(125),
            "actual source fail-stop disposition"
        );
        assert_eq!(child.0.wait()?, status, "original child was reaped");
        assert_eq!(
            crucible_protocol::node_control::encode_frame_for_edition(edition, &request)?,
            original_request
        );
        assert_eq!(
            native.fixed_microvm_preparation(),
            original_preparation.as_ref()
        );
        assert_original_containment_log(
            containment_log
                .as_ref()
                .ok_or("containment diagnostic path absent")?,
            log_offset.ok_or("log offset absent")?,
            mode,
            diagnostic,
            original_seam,
        )?;
        // The optional historical Applied body stays owned beside the exact
        // original request and endpoint. It supplies no NoEffects, current
        // physical-stop, ACK, lifetime or readiness attestation.
        drop(historical_applied);
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let receipt = loop {
        match native.receive_construction()? {
            Some(NativeFrame::InitializationStopped(receipt)) => break receipt,
            Some(_) => return Err("foreign original HOME response".into()),
            None => {}
        }
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("original HOME watchdog".into());
        }
        std::thread::sleep(Duration::from_millis(1));
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
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match native.receive_construction()? {
                Some(NativeFrame::InitializationAcknowledged(ack)) => {
                    assert_eq!(ack, acknowledgement);
                    break;
                }
                Some(_) => return Err("foreign original ACK response".into()),
                None => {}
            }
            if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
                return Err("original ACK watchdog".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert!(native.send_construction(&request)?);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match native.receive_construction()? {
            Some(NativeFrame::InitializationStopped(recovered)) => {
                assert_eq!(recovered, receipt);
                break;
            }
            Some(_) => return Err("changed original construction retry response".into()),
            None => {}
        }
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("original retry watchdog".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
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
        let deadline = Instant::now() + Duration::from_secs(5);
        let chunk = loop {
            match native.receive_construction()? {
                Some(NativeFrame::PreparationSuccessorChunk(chunk)) => break chunk,
                Some(_) => return Err("foreign original successor response".into()),
                None => {}
            }
            if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
                return Err("original successor watchdog".into());
            }
            std::thread::sleep(Duration::from_millis(1));
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
    assert!(child.0.try_wait()?.is_none());
    drop(child);
    Ok(())
}

fn query_scope(query: &NativeFrame) -> Result<[u8; 32], Box<dyn Error>> {
    match query {
        NativeFrame::QueryInitialization(query) => Ok(query.prepared_scope_hash),
        _ => Err("not original query".into()),
    }
}

fn assert_original_containment_log(
    path: &std::path::Path,
    offset: u64,
    mode: &str,
    diagnostic: &str,
    original_seam: &str,
) -> Result<(), Box<dyn Error>> {
    let mut file = std::fs::File::open(path)?;
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset))?;
    let mut bytes = String::new();
    std::io::Read::read_to_string(&mut file, &mut bytes)?;

    assert!(
        bytes.contains(&format!("ATTEMPT mode={mode}")),
        "no original source attempt: {bytes}"
    );
    assert!(
        bytes.contains(original_seam),
        "no genuine source seam: {bytes}"
    );
    assert!(
        bytes.contains(diagnostic),
        "missing native lifetime refusal: {bytes}"
    );
    Ok(())
}

#[path = "construction_containment.rs"]
mod containment;
