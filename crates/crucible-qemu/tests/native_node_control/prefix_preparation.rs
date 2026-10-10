//! Genuine pre-command initial observation and source-consumed preparation ACK.
//!
//! The explicitly selected contract gates Compute; original initial bytes remain
//! historical after the first CPU effect. No common Ready or capture is claimed.

use super::*;

#[test]
#[ignore = "requires matching native ACK6 source and explicit initial-contract GPL runtime"]
fn actual_initial_preparation_contract_precedes_compute_and_preserves_original_history()
-> Result<(), Box<dyn Error>> {
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
                    maximum_service_span: U64::new(1),
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
    plugin_args.push_str(",node_prefix_preparation_contract_version=1");
    plugin_args.push_str(&format!(
        ",node_prefix_commitment={}",
        hex(&prefix_preparation.identity_digest()?)
    ));
    {
        plugin_args.push_str(",node_bounded_teardown_version=1");
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
                || check_child(&mut child.0),
                |_| true,
            )?
        else {
            return Err("foreign original enrollment response".into());
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
    let NativeFrame::InitializationCut(cut) =
        next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
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
        next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
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
            next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
        else {
            return Err("foreign original ACK response".into());
        };
        assert_eq!(ack, acknowledgement);
    }
    assert!(native.send_construction(&request)?);
    let NativeFrame::InitializationStopped(recovered) =
        next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
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
            next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
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
    let initial_query = NativeFrame::QueryPrefixPreparation {
        scope: prefix_preparation
            .original_effect
            .original_root
            .administration
            .phase
            .initialization
            .preparation
            .scope
            .identity_digest()?,
        prefix_preparation: prefix_preparation.identity_digest()?,
    };
    let mut original_initial = None;
    for _ in 0..2 {
        assert!(native.send_construction(&initial_query)?);
        let NativeFrame::PrefixPreparationFacts(facts) =
            next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
        else {
            return Err("foreign initial preparation facts response".into());
        };
        let observation = facts.observe_original(&prefix_preparation, &receipt)?;
        assert_eq!(observation.initial, position(0));
        assert_eq!(observation.next_cpu_deadline_ps.get(), 50);
        assert!(observation.epoch_incarnation.get() > 0);
        assert!(observation.cpu_incarnation.get() > 0);
        assert_eq!(&facts.canonical_bytes()[560..568], &[0; 8]);
        if let Some((original_facts, original_observation)) = &original_initial {
            assert_eq!(&facts, original_facts);
            assert_eq!(&observation, original_observation);
        } else {
            original_initial = Some((facts, observation));
        }
    }
    let (original_initial_facts, original_initial_observation) =
        original_initial.ok_or("original initial facts missing")?;
    let offered_initial =
        crucible_protocol::node_control::NativePrefixPreparationAcknowledgement::from_original(
            &original_initial_observation,
        )?;
    let initial_ack = NativeFrame::AcknowledgePrefixPreparation(offered_initial.clone());
    for _ in 0..2 {
        assert!(native.send_construction(&initial_ack)?);
        let NativeFrame::PrefixPreparationAcknowledged(consumed) =
            next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
        else {
            return Err("native consumed initial ACK missing".into());
        };
        assert_eq!(consumed, offered_initial);
    }
    {
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
            maximum_service_span: U64::new(1),
            input_batch_sequence: U64::new(1),
        };
        let request = NativeFrame::EffectCompute(Box::new(compute.clone()));
        assert!(native.send_construction(&request)?);
        let NativeFrame::EffectProgress(result) =
            next_construction_reply(&mut native, &mut child.0, Duration::from_secs(10))?
        else {
            return Err("foreign effect response".into());
        };
        result.validate_against(&compute)?;
        assert_eq!(
            result.status,
            crucible_protocol::node_control::NativeEffectProgressStatus::PartialPrefix
        );
        assert_eq!(result.raw_before.get(), 0);
        assert_eq!(result.raw_after.get(), 1);
        assert_eq!(result.returned_service_count.get(), 1);
        assert_eq!(result.end_result, 0);
        assert!(native.send_construction(&request)?);
        let NativeFrame::EffectProgress(cached_result) =
            next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
        else {
            return Err("changed original effect response".into());
        };
        assert_eq!(cached_result, result);
        let offered =
            crucible_protocol::node_control::NativePrefixAcknowledgement::from_initial(&result)?;
        let request = NativeFrame::AcknowledgePrefix(offered.clone());
        let mut consumed = None;
        for _ in 0..2 {
            assert!(native.send_construction(&request)?);
            let NativeFrame::PrefixAcknowledged(ack) =
                next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
            else {
                return Err("foreign original prefix ACK response".into());
            };
            ack.validate_initial(&result)?;
            assert_eq!(ack, offered);
            if let Some(original) = &consumed {
                assert_eq!(original, &ack);
            } else {
                consumed = Some(ack);
            }
        }
    }

    assert!(native.send_construction(&initial_query)?);
    let NativeFrame::PrefixPreparationFacts(historical) =
        next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
    else {
        return Err("original pre-command facts history missing".into());
    };
    assert_eq!(historical, original_initial_facts);
    assert_eq!(
        historical.observe_original(&prefix_preparation, &receipt)?,
        original_initial_observation
    );
    assert!(native.send_construction(&initial_ack)?);
    let NativeFrame::PrefixPreparationAcknowledged(historical) =
        next_construction_reply(&mut native, &mut child.0, Duration::from_secs(5))?
    else {
        return Err("original consumed preparation ACK history missing".into());
    };
    assert_eq!(historical, offered_initial);
    assert!(child.0.try_wait()?.is_none());
    drop(child);
    Ok(())
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
