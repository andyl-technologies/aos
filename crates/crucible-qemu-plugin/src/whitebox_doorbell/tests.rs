//! White-box doorbell unit tests and deterministic decision-source fixtures.

use super::*;

fn collision_free_setup(trap: WhiteboxDoorbellTrap) -> WhiteboxDoorbellSetupValidation {
    WhiteboxDoorbellSetupValidation::validate(
        trap,
        WhiteboxDoorbellSetupResources::from_observed_resources(&[], &[]),
    )
}

#[test]
fn whitebox_registration_off_mode_installs_no_trap_and_preserves_black_box() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::Off,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );

    let plan = match doorbell.registration_plan(
        WhiteboxDoorbellCapabilities::none(),
        WhiteboxDoorbellSetupValidation::unchecked(doorbell.trap()),
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("off-mode should not require capabilities: {error}"),
    };

    assert_eq!(plan, WhiteboxDoorbellRegistrationPlan::Disabled);
    assert!(!plan.installs_trap());
    assert!(plan.black_box_remains_functional());
}

#[test]
fn whitebox_registration_off_mode_bypasses_whitebox_payload_validation() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::Off,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        0,
    );

    assert_eq!(
        doorbell.registration_plan(
            WhiteboxDoorbellCapabilities::none(),
            WhiteboxDoorbellSetupValidation::unchecked(doorbell.trap()),
        ),
        Ok(WhiteboxDoorbellRegistrationPlan::Disabled)
    );
}

#[test]
fn whitebox_registration_on_mode_requires_trap_and_memory_read_capabilities() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let setup_validation = collision_free_setup(doorbell.trap());

    assert_eq!(
        doorbell.registration_plan(WhiteboxDoorbellCapabilities::none(), setup_validation),
        Err(WhiteboxDoorbellError::CapabilityUnavailable {
            symbol: QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL,
        })
    );
    assert_eq!(
        doorbell.registration_plan(
            WhiteboxDoorbellCapabilities {
                register_doorbell_trap: true,
                guest_memory_read: false,
                guest_memory_write: false,
            },
            setup_validation,
        ),
        Err(WhiteboxDoorbellError::CapabilityUnavailable {
            symbol: QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL,
        })
    );

    let plan = match doorbell.registration_plan(
        WhiteboxDoorbellCapabilities::guest_to_host(),
        setup_validation,
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("on-mode capabilities should produce install plan: {error}"),
    };
    assert_eq!(
        plan,
        WhiteboxDoorbellRegistrationPlan::Install {
            trap: WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            callback_kind: PluginDeviceCallbackKind::WhiteboxDoorbell,
            max_payload_len: 128,
        }
    );
    assert!(plan.installs_trap());
    assert!(!plan.black_box_remains_functional());
}

#[test]
fn whitebox_registration_on_mode_requires_setup_collision_validation() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );

    assert_eq!(
        doorbell.registration_plan(
            WhiteboxDoorbellCapabilities::guest_to_host(),
            WhiteboxDoorbellSetupValidation::unchecked(doorbell.trap()),
        ),
        Err(WhiteboxDoorbellError::SetupCollisionUnchecked {
            trap: doorbell.trap(),
        })
    );
    assert_eq!(
        doorbell.registration_plan(
            WhiteboxDoorbellCapabilities::guest_to_host(),
            WhiteboxDoorbellSetupValidation::validate(
                doorbell.trap(),
                WhiteboxDoorbellSetupResources::from_observed_resources(&[0xe7], &[]),
            ),
        ),
        Err(WhiteboxDoorbellError::SetupCollision {
            trap: doorbell.trap(),
            collision: WhiteboxDoorbellCollision::X86PortMapped { port: 0xe7 },
        })
    );
    assert_eq!(
        doorbell.registration_plan(
            WhiteboxDoorbellCapabilities::guest_to_host(),
            collision_free_setup(WhiteboxDoorbellTrap::Aarch64Hlt { immediate: 0x4c1 }),
        ),
        Err(WhiteboxDoorbellError::SetupValidationTrapMismatch {
            configured: doorbell.trap(),
            validated: WhiteboxDoorbellTrap::Aarch64Hlt { immediate: 0x4c1 },
        })
    );

    let aarch64 = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::Aarch64Hlt { immediate: 0x4c1 },
        128,
    );
    assert_eq!(
        aarch64.registration_plan(
            WhiteboxDoorbellCapabilities::guest_to_host(),
            WhiteboxDoorbellSetupValidation::validate(
                aarch64.trap(),
                WhiteboxDoorbellSetupResources::from_observed_resources(&[], &[0x4c1]),
            ),
        ),
        Err(WhiteboxDoorbellError::SetupCollision {
            trap: aarch64.trap(),
            collision: WhiteboxDoorbellCollision::Aarch64ReservedImmediateInUse {
                immediate: 0x4c1,
            },
        })
    );
}

#[test]
fn whitebox_doorbell_abi_vectors_cover_x86_64_and_aarch64() {
    assert_eq!(WHITEBOX_DOORBELL_ABIS.len(), 2);
    assert_eq!(
        WHITEBOX_DOORBELL_ABIS
            .iter()
            .map(|abi| abi.vector_name())
            .collect::<Vec<_>>(),
        vec!["x86_64-out-dx-eax-port-e7", "aarch64-hlt-imm-04c1"]
    );
    assert_eq!(
        WHITEBOX_DOORBELL_ABIS
            .iter()
            .map(|abi| abi.version())
            .collect::<Vec<_>>(),
        vec![
            WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
            WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
        ]
    );
    assert_eq!(
        whitebox_doorbell_abi_for_architecture(WhiteboxDoorbellArchitecture::X86_64),
        WHITEBOX_DOORBELL_X86_64_ABI
    );
    assert_eq!(
        whitebox_doorbell_abi_for_architecture(WhiteboxDoorbellArchitecture::Aarch64),
        WHITEBOX_DOORBELL_AARCH64_ABI
    );
}

#[test]
fn whitebox_doorbell_x86_64_golden_vector_freezes_out_dx_eax() {
    let abi = WHITEBOX_DOORBELL_X86_64_ABI;

    assert_eq!(abi.architecture().as_str(), "x86_64");
    assert_eq!(abi.instruction(), WhiteboxDoorbellInstruction::X86OutDxEax);
    assert_eq!(abi.instruction().as_str(), "out-dx-eax");
    assert_eq!(
        abi.trap(),
        WhiteboxDoorbellTrapAbi::X86PortIo {
            port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
        }
    );
    assert_eq!(
        WhiteboxDoorbellTrap::from_abi(abi.trap()),
        WhiteboxDoorbellTrap::X86PortIo {
            port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
        }
    );
    assert_eq!(abi.payload_pointer_register(), "rax");
    assert_eq!(abi.payload_length_register(), "rcx");
    assert_eq!(abi.assembly(), "out dx, eax");
    assert_eq!(
        encode_x86_64_out_dx_eax_instruction(),
        WHITEBOX_DOORBELL_X86_64_OUT_DX_EAX_BYTES
    );
    assert_eq!(abi.instruction_bytes(), &[0xef]);
}

#[test]
fn whitebox_doorbell_aarch64_golden_vector_freezes_hlt_immediate() {
    let abi = WHITEBOX_DOORBELL_AARCH64_ABI;

    assert_eq!(abi.architecture().as_str(), "aarch64");
    assert_eq!(abi.instruction(), WhiteboxDoorbellInstruction::Aarch64Hlt);
    assert_eq!(abi.instruction().as_str(), "hlt-imm16");
    assert_eq!(
        abi.trap(),
        WhiteboxDoorbellTrapAbi::Aarch64Hlt {
            immediate: WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE,
        }
    );
    assert_eq!(
        WhiteboxDoorbellTrap::from_abi(abi.trap()),
        WhiteboxDoorbellTrap::Aarch64Hlt {
            immediate: WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE,
        }
    );
    assert_eq!(abi.payload_pointer_register(), "x0");
    assert_eq!(abi.payload_length_register(), "x1");
    assert_eq!(abi.assembly(), "hlt #0x04c1");
    assert_eq!(
        encode_aarch64_hlt_instruction(WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE),
        WHITEBOX_DOORBELL_AARCH64_HLT_BYTES
    );
    assert_eq!(abi.instruction_bytes(), &[0x20, 0x98, 0x40, 0xd4]);
}

#[test]
fn whitebox_doorbell_registration_uses_single_source_abi_trap() {
    for abi in WHITEBOX_DOORBELL_ABIS {
        let doorbell = PluginWhiteboxDoorbell::from_abi(PluginSwitch::On, *abi, 128);
        let setup_validation = collision_free_setup(doorbell.trap());
        let plan = match doorbell.registration_plan(
            WhiteboxDoorbellCapabilities::guest_to_host(),
            setup_validation,
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("ABI-derived doorbell should validate: {error}"),
        };

        assert_eq!(doorbell.trap(), WhiteboxDoorbellTrap::from_abi(abi.trap()));
        assert_eq!(
            plan,
            WhiteboxDoorbellRegistrationPlan::Install {
                trap: WhiteboxDoorbellTrap::from_abi(abi.trap()),
                callback_kind: PluginDeviceCallbackKind::WhiteboxDoorbell,
                max_payload_len: 128,
            }
        );
    }
}

#[test]
fn whitebox_doorbell_reads_guest_memory_via_api_and_stamps_current_icount() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let frame = coverage_marker_frame("mark");
    let expected_body = coverage_marker_body("mark");
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, frame.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 777, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(frame);
    let mut sink = RecordingMarkerSink::default();

    let marker = match handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event) {
        Ok(marker) => marker,
        Err(error) => panic!("doorbell should be serviced: {error}"),
    };

    assert_eq!(reader.calls, vec![(2, 777, range)]);
    assert_eq!(marker.marker_icount(), 777);
    assert_eq!(marker.vcpu_index(), 2);
    assert_eq!(marker.payload_range(), range);
    assert_eq!(marker.kind(), 4);
    assert_eq!(marker.payload(), expected_body);
    assert_eq!(
        marker.decoded_payload(),
        &WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
            point: String::from("mark"),
        })
    );
    assert_eq!(sink.markers, vec![marker]);
}

#[test]
fn whitebox_doorbell_records_decoded_marker_into_engine_event_log_sink() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        256,
    );
    let payload = WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
        flavor: WhiteboxAssertionMarkerFlavor::Reachable,
        condition: true,
        must_hit: true,
        id: String::from("guest.ready"),
        message: String::from("guest reported ready"),
        location: String::from("guest.rs:7"),
        details: vec![WhiteboxMarkerDetail::new("phase", "setup")],
    });
    let frame = encode_whitebox_marker_frame(&payload)
        .unwrap_or_else(|error| panic!("test marker frame should encode: {error}"));
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, frame.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 888, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(frame);
    let mut sink = EngineEventLogMarkerSink::new("db-0");

    let marker = match handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event) {
        Ok(marker) => marker,
        Err(error) => panic!("doorbell should append marker to engine event log: {error}"),
    };

    assert_eq!(marker.marker_icount(), 888);
    assert_eq!(marker.decoded_payload(), &payload);
    assert_eq!(sink.entries.len(), 1);
    let entry = &sink.entries[0];
    assert_eq!(entry.class(), crucible::EventClass::Observational);
    assert_eq!(
        entry.time().icount,
        crucible::EventLogIcountStamp {
            node: Some(crucible_node("db-0")),
            icount: crucible::Icount { retired: 888 },
        }
    );
    assert_eq!(
        entry.source(),
        &crucible::EventSource::Guest {
            node: crucible_node("db-0"),
        }
    );
    assert_eq!(entry.event_payload().kind(), "guest_marker");
    assert_eq!(
        entry.event_payload().string("assertion"),
        Some("guest.ready")
    );
    assert!(crucible::event_log_causal_projection(&sink.entries).is_empty());
}

#[test]
fn whitebox_channel_safety_reads_payload_snapshot_at_exact_trap_icount() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        256,
    );
    let trap_snapshot = coverage_marker_frame("trap-snapshot");
    let later_guest_memory = coverage_marker_frame("late-mutation");
    let range = GuestMemoryRange::new(
        GuestMemoryAddressSpace::Physical,
        0x1000,
        trap_snapshot.len(),
    );
    let event = WhiteboxDoorbellTrapEvent::from_shared_page(3, 1234, range);
    let mut reader =
        MutatingSnapshotGuestMemoryReader::new(trap_snapshot, later_guest_memory.clone());
    let mut sink = RecordingMarkerSink::default();

    let marker = match handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event) {
        Ok(marker) => marker,
        Err(error) => panic!("trap-icount snapshot should decode as a marker: {error}"),
    };

    assert_eq!(reader.calls, vec![(3, 1234, range)]);
    assert_eq!(reader.memory_after_read, later_guest_memory);
    assert_eq!(marker.marker_icount(), 1234);
    assert_eq!(marker.vcpu_index(), 3);
    assert_eq!(marker.payload_range(), range);
    assert!(matches!(
        marker.decoded_payload(),
        WhiteboxMarkerPayload::Coverage(body) if body.point == "trap-snapshot"
    ));
    assert_eq!(sink.markers, vec![marker]);
}

#[test]
fn whitebox_doorbell_rejects_malformed_frame_without_marker() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 4);
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 777, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(b"mark".to_vec());
    let mut sink = RecordingMarkerSink::default();

    assert_eq!(
        handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
        Err(WhiteboxDoorbellError::DoorbellFrameDecode {
            marker_icount: 777,
            source: WhiteboxDoorbellFrameDecodeError::TruncatedFrame {
                len: 4,
                minimum_len: WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
            },
        })
    );
    assert_eq!(reader.calls, vec![(2, 777, range)]);
    assert!(sink.markers.is_empty());
    assert_eq!(
        sink.diagnostics,
        vec![WhiteboxDoorbellDecodeDiagnostic::frame_decode(
            event,
            WhiteboxDoorbellFrameDecodeError::TruncatedFrame {
                len: 4,
                minimum_len: WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
            },
        )]
    );
}

#[test]
fn whitebox_doorbell_rejects_random_request_on_observational_marker_path() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let frame = random_request_frame(1, 4, "rng");
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, frame.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 777, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(frame);
    let mut sink = RecordingMarkerSink::default();

    assert_eq!(
        handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
        Err(WhiteboxDoorbellError::NonObservationalMarkerKind {
            marker_icount: 777,
            kind: WhiteboxDoorbellMarkerKind::RandomRequest,
        })
    );
    assert_eq!(reader.calls, vec![(2, 777, range)]);
    assert!(sink.markers.is_empty());
    assert_eq!(
        sink.diagnostics,
        vec![WhiteboxDoorbellDecodeDiagnostic::non_observational_kind(
            event,
            WhiteboxDoorbellMarkerKind::RandomRequest,
        )]
    );
}

#[test]
fn whitebox_doorbell_records_unknown_kind_decode_diagnostic_without_marker() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let frame = doorbell_frame(0xffff, &[]);
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, frame.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 778, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(frame);
    let mut sink = RecordingMarkerSink::default();

    assert_eq!(
        handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
        Err(WhiteboxDoorbellError::DoorbellMarkerDecode {
            marker_icount: 778,
            source: WhiteboxMarkerPayloadDecodeError::UnknownKind { kind: 0xffff },
        })
    );
    assert_eq!(reader.calls, vec![(2, 778, range)]);
    assert!(sink.markers.is_empty());
    assert_eq!(
        sink.diagnostics,
        vec![WhiteboxDoorbellDecodeDiagnostic::marker_decode(
            event,
            WhiteboxMarkerPayloadDecodeError::UnknownKind { kind: 0xffff },
        )]
    );
}

#[test]
fn whitebox_doorbell_payload_source_is_shared_page_or_register_pointer_length() {
    let shared_range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 8);
    let register_range = GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x2000, 16);

    let shared = WhiteboxDoorbellTrapEvent::from_shared_page(0, 12, shared_range);
    let register = WhiteboxDoorbellTrapEvent::from_register_pointer_length(1, 34, register_range);

    assert_eq!(
        shared.payload_source(),
        WhiteboxDoorbellPayloadSource::SharedPage {
            range: shared_range,
        }
    );
    assert_eq!(shared.payload_range(), shared_range);
    assert_eq!(
        register.payload_source(),
        WhiteboxDoorbellPayloadSource::RegisterPointerLength {
            range: register_range,
        }
    );
    assert_eq!(register.payload_range(), register_range);
}

#[test]
fn whitebox_guest_memory_addressing_uses_supplied_s5_virtual_pointer_length_evidence() {
    let s5_pass = phase0_s5_pass_resolution();

    assert_eq!(s5_pass.check, WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK);
    assert_eq!(
        s5_pass.default_payload_addressing_mode(),
        WhiteboxPayloadAddressingMode::VirtualPointerLength
    );
    assert!(s5_pass.virtual_pointer_length_is_sound());
    assert!(!s5_pass.physical_pinned_fallback_adopted);

    let source = s5_pass.default_payload_source(0x2000, 0x1000, 64);
    assert_eq!(
        source,
        WhiteboxDoorbellPayloadSource::RegisterPointerLength {
            range: GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x2000, 64),
        }
    );
    let event = WhiteboxDoorbellTrapEvent::from_default_payload_addressing(
        1, 99, s5_pass, 0x2000, 0x1000, 64,
    );
    assert_eq!(event.payload_source(), source);
    assert_eq!(
        event.payload_range().address_space(),
        GuestMemoryAddressSpace::Virtual
    );
}

#[test]
fn whitebox_guest_memory_addressing_unresolved_default_is_physical_shared_page() {
    let unresolved = WHITEBOX_GUEST_MEMORY_ADDRESSING_UNRESOLVED;

    assert_eq!(unresolved.check, WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK);
    assert_eq!(
        unresolved.default_payload_addressing_mode(),
        WhiteboxPayloadAddressingMode::PhysicalSharedPage
    );
    assert!(!unresolved.virtual_pointer_length_is_sound());
    let event = WhiteboxDoorbellTrapEvent::from_default_payload_addressing(
        1, 99, unresolved, 0x2000, 0x1000, 64,
    );
    assert_eq!(
        event.payload_source(),
        WhiteboxDoorbellPayloadSource::SharedPage {
            range: GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 64),
        }
    );
    assert_eq!(
        event.payload_range().address_space(),
        GuestMemoryAddressSpace::Physical
    );
}

#[test]
fn whitebox_guest_memory_addressing_rejects_non_s5_evidence() {
    let mut non_s5_pass = phase0_s5_pass_resolution();
    non_s5_pass.check = "checks.crucible.phase0.other";

    assert!(!non_s5_pass.virtual_pointer_length_is_sound());
    assert_eq!(
        non_s5_pass.default_payload_addressing_mode(),
        WhiteboxPayloadAddressingMode::PhysicalSharedPage
    );
    assert_eq!(
        non_s5_pass.default_payload_source(0x2000, 0x1000, 64),
        WhiteboxDoorbellPayloadSource::SharedPage {
            range: GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 64),
        }
    );
}

#[test]
fn whitebox_guest_memory_addressing_app_random_reply_range_tracks_payload_resolution() {
    let virtual_event = WhiteboxDoorbellTrapEvent::from_default_payload_addressing(
        0,
        50,
        phase0_s5_pass_resolution(),
        0x2000,
        0x1000,
        random_request_frame(5, 2, "rng").len(),
    );
    let physical_event = WhiteboxDoorbellTrapEvent::from_default_payload_addressing(
        0,
        50,
        WHITEBOX_GUEST_MEMORY_ADDRESSING_UNRESOLVED,
        0x2000,
        0x1000,
        random_request_frame(5, 2, "rng").len(),
    );
    let frame = match WhiteboxDoorbellFrame::decode(&random_request_frame(5, 2, "rng")) {
        Ok(frame) => frame,
        Err(error) => panic!("random-request frame should decode: {error:?}"),
    };
    let virtual_request =
        match AppRandomDoorbellRequest::from_frame("node-a", virtual_event, frame.clone()) {
            Ok(request) => request,
            Err(error) => panic!("virtual random request should decode: {error:?}"),
        };
    let physical_request =
        match AppRandomDoorbellRequest::from_frame("node-a", physical_event, frame) {
            Ok(request) => request,
            Err(error) => panic!("physical random request should decode: {error:?}"),
        };

    assert_eq!(
        virtual_request.reply_range(),
        GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x2000, 2)
    );
    assert_eq!(
        physical_request.reply_range(),
        GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 2)
    );
}

#[test]
fn whitebox_doorbell_rejects_oversized_payload_before_guest_memory_read() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        3,
    );
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 4);
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(b"mark".to_vec());
    let mut sink = RecordingMarkerSink::default();

    assert_eq!(
        handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
        Err(WhiteboxDoorbellError::PayloadTooLarge {
            len: 4,
            max_payload_len: 3,
        })
    );
    assert!(reader.calls.is_empty());
    assert!(sink.markers.is_empty());
}

#[test]
fn whitebox_doorbell_read_failure_records_no_marker() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::Aarch64Hlt { immediate: 0x4c1 },
        128,
    );
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x2000, 4);
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(1, 44, range);
    let mut reader = RecordingGuestMemoryReader::failing("translation failed");
    let mut sink = RecordingMarkerSink::default();

    assert_eq!(
        handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
        Err(WhiteboxDoorbellError::GuestMemoryRead {
            range,
            source: GuestMemoryReadError::new("translation failed"),
        })
    );
    assert_eq!(reader.calls, vec![(1, 44, range)]);
    assert!(sink.markers.is_empty());
}

#[test]
fn whitebox_doorbell_trap_while_disabled_is_loud() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::Off,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 4);
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(b"mark".to_vec());
    let mut sink = RecordingMarkerSink::default();

    assert_eq!(
        handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
        Err(WhiteboxDoorbellError::TrapWhileDisabled)
    );
    assert!(reader.calls.is_empty());
    assert!(sink.markers.is_empty());
}

#[test]
fn whitebox_guest_input_is_not_visible_before_delivery_icount() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let input = input_at(50, b"ack");
    let mut writer = RecordingGuestInputWriter::default();

    assert_eq!(
        handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 49, &input),
        Ok(WhiteboxGuestInputOutcome::NotReady {
            delivery_icount: 50,
        })
    );
    assert!(writer.writes.is_empty());
}

#[test]
fn whitebox_guest_input_writes_at_exact_delivery_icount_only() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let input = input_at(50, b"ack");
    let mut writer = RecordingGuestInputWriter::default();

    let outcome =
        match handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 50, &input)
        {
            Ok(outcome) => outcome,
            Err(error) => panic!("input should deliver exactly at icount: {error}"),
        };

    assert_eq!(
        outcome,
        WhiteboxGuestInputOutcome::Delivered(WhiteboxGuestInputInjection {
            delivery_icount: 50,
            payload_range: input.payload_range(),
            payload_len: 3,
        })
    );
    assert_eq!(
        writer.writes,
        vec![(50, input.payload_range(), b"ack".to_vec())]
    );
}

#[test]
fn whitebox_guest_input_rejects_oversized_payload_before_guest_memory_write() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        3,
    );
    let capability = guest_input_capability(&doorbell);
    let input = input_at(50, b"toolong");
    let mut writer = RecordingGuestInputWriter::default();

    assert_eq!(
        handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 50, &input),
        Err(WhiteboxDoorbellError::PayloadTooLarge {
            len: 7,
            max_payload_len: 3,
        })
    );
    assert!(writer.writes.is_empty());
}

#[test]
fn whitebox_guest_input_rejects_late_delivery() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let input = input_at(50, b"ack");
    let mut writer = RecordingGuestInputWriter::default();

    assert_eq!(
        handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 51, &input),
        Err(WhiteboxDoorbellError::InputDeliveryAlreadyPassed {
            delivery_icount: 50,
            current_icount: 51,
        })
    );
    assert!(writer.writes.is_empty());
}

#[test]
fn whitebox_channel_safety_injects_host_to_guest_only_at_delivery_icount() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let input = input_at(88, b"reply");
    let mut writer = RecordingGuestInputWriter::default();

    assert_eq!(
        handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 87, &input),
        Ok(WhiteboxGuestInputOutcome::NotReady {
            delivery_icount: 88,
        })
    );
    assert!(writer.writes.is_empty());

    assert_eq!(
        handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 88, &input),
        Ok(WhiteboxGuestInputOutcome::Delivered(
            WhiteboxGuestInputInjection {
                delivery_icount: 88,
                payload_range: input.payload_range(),
                payload_len: 5,
            }
        ))
    );
    assert_eq!(
        writer.writes,
        vec![(88, input.payload_range(), b"reply".to_vec())]
    );

    assert_eq!(
        handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 89, &input),
        Err(WhiteboxDoorbellError::InputDeliveryAlreadyPassed {
            delivery_icount: 88,
            current_icount: 89,
        })
    );
    assert_eq!(writer.writes.len(), 1);
}

#[test]
fn whitebox_channel_safety_ignores_producer_timing_before_delivery_icount() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let input = input_at(88, b"reply");

    let mut eager_writer = RecordingGuestInputWriter::default();
    for current_icount in [81, 82, 87] {
        assert_eq!(
            handle_whitebox_guest_input_callback(
                &doorbell,
                &capability,
                &mut eager_writer,
                current_icount,
                &input,
            ),
            Ok(WhiteboxGuestInputOutcome::NotReady {
                delivery_icount: 88,
            })
        );
    }
    assert!(eager_writer.writes.is_empty());
    assert_eq!(
        handle_whitebox_guest_input_callback(&doorbell, &capability, &mut eager_writer, 88, &input,),
        Ok(WhiteboxGuestInputOutcome::Delivered(
            WhiteboxGuestInputInjection {
                delivery_icount: 88,
                payload_range: input.payload_range(),
                payload_len: 5,
            }
        ))
    );

    let mut just_in_time_writer = RecordingGuestInputWriter::default();
    assert_eq!(
        handle_whitebox_guest_input_callback(
            &doorbell,
            &capability,
            &mut just_in_time_writer,
            88,
            &input,
        ),
        Ok(WhiteboxGuestInputOutcome::Delivered(
            WhiteboxGuestInputInjection {
                delivery_icount: 88,
                payload_range: input.payload_range(),
                payload_len: 5,
            }
        ))
    );
    assert_eq!(eager_writer.writes, just_in_time_writer.writes);
}

#[test]
fn whitebox_guest_input_while_disabled_is_loud() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::Off,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );

    assert_eq!(
        doorbell.require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional()),
        Err(WhiteboxDoorbellError::InputWhileDisabled)
    );
}

#[test]
fn whitebox_guest_input_requires_qemu_guest_memory_write_capability() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );

    assert_eq!(
        doorbell.require_guest_input_capability(WhiteboxDoorbellCapabilities::guest_to_host()),
        Err(WhiteboxDoorbellError::CapabilityUnavailable {
            symbol: QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL,
        })
    );
    assert!(
        doorbell
            .require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())
            .is_ok()
    );
}

#[test]
fn whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let payload = random_request_frame(7, 2, "workload");
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(1, 99, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(payload);
    let record = AppRandomDecisionRecord::new("node-a", "workload", 7, 16, 0xbeef);
    let mut decisions = RecordingAppRandomSource::with_record(record.clone());
    let mut writer = RecordingGuestInputWriter::default();

    let outcome = match handle_whitebox_app_random_callback(
        &doorbell,
        &capability,
        &mut reader,
        &mut decisions,
        &mut writer,
        "node-a",
        event,
    ) {
        Ok(outcome) => outcome,
        Err(error) => panic!("app-random request should be served: {error}"),
    };

    let service = match outcome {
        AppRandomDoorbellOutcome::Served(service) => service,
        AppRandomDoorbellOutcome::Dropped { diagnostic } => {
            panic!("valid app-random request should not drop: {diagnostic:?}")
        }
    };
    assert_eq!(reader.calls, vec![(1, 99, range)]);
    assert_eq!(decisions.requests.len(), 1);
    assert_eq!(decisions.requests[0].node_name(), "node-a");
    assert_eq!(decisions.requests[0].guest_request_id(), 7);
    assert_eq!(decisions.requests[0].trap_icount(), 99);
    assert_eq!(decisions.requests[0].width_bytes(), 2);
    assert_eq!(decisions.requests[0].width_bits(), 16);
    assert_eq!(decisions.requests[0].stream_tag(), "workload");
    assert_eq!(service.request(), &decisions.requests[0]);
    assert_eq!(service.decision(), &record);
    assert_eq!(service.injection().delivery_icount(), 99);
    assert_eq!(service.injection().payload_len(), 2);
    assert_eq!(
        writer.writes,
        vec![(
            99,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, 2),
            vec![0xef, 0xbe],
        )]
    );
}

#[test]
fn whitebox_app_random_decision_source_uses_engine_seeded_node_stream_name_hash() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let payload = random_request_frame(0x0bad_f00d, 3, "workload");
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 321, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(payload);
    let mut decisions =
        EngineAppRandomDecisionSource::from_seed(crucible::Seed::from_u64(0x0010_0016));
    let mut writer = RecordingGuestInputWriter::default();

    let outcome = match handle_whitebox_app_random_callback(
        &doorbell,
        &capability,
        &mut reader,
        &mut decisions,
        &mut writer,
        "node-a",
        event,
    ) {
        Ok(outcome) => outcome,
        Err(error) => panic!("engine-backed app-random request should be served: {error}"),
    };

    let service = match outcome {
        AppRandomDoorbellOutcome::Served(service) => service,
        AppRandomDoorbellOutcome::Dropped { diagnostic } => {
            panic!("valid engine-backed app-random request should not drop: {diagnostic:?}")
        }
    };
    let stream = EngineAppRandomDecisionSource::stream_id("node-a", "workload");
    let recorded = decisions.decisions();
    assert_eq!(recorded.len(), 2);
    let raw_value = match &recorded[0] {
        crucible::Decision::RngDraw(crucible::RngDecision {
            stream: recorded_stream,
            value,
        }) if recorded_stream == &stream => *value,
        decision => panic!("first engine app-random decision should be RNG draw: {decision:?}"),
    };
    let app_random = match &recorded[1] {
        crucible::Decision::AppRandom(decision) => decision,
        decision => {
            panic!("second engine app-random decision should be Decision::AppRandom: {decision:?}")
        }
    };
    assert_eq!(reader.calls, vec![(2, 321, range)]);
    assert_eq!(app_random.node.name.as_str(), "node-a");
    assert_eq!(&app_random.stream, &stream);
    assert_eq!(app_random.request_id, 0x0bad_f00d);
    assert_eq!(app_random.width, 24);
    assert_eq!(app_random.value, raw_value & ((1_u64 << 24) - 1));
    assert_eq!(service.request().stream_tag(), "workload");
    assert_eq!(service.decision().stream_tag(), "workload");
    assert_eq!(service.decision().request_id(), 0x0bad_f00d);
    assert_eq!(service.decision().width_bits(), 24);
    assert_eq!(service.decision().value(), app_random.value);
    assert_eq!(service.injection().delivery_icount(), 321);

    let reply = app_random.value.to_le_bytes();
    assert_eq!(
        writer.writes,
        vec![(
            321,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, 3),
            vec![reply[0], reply[1], reply[2]],
        )]
    );
}

#[test]
fn whitebox_app_random_decision_source_isolates_same_tag_by_node() {
    let seed = crucible::Seed::from_u64(0x0010_0016);
    let node_a_stream = EngineAppRandomDecisionSource::stream_id("node-a", "shared");
    let node_b_stream = EngineAppRandomDecisionSource::stream_id("node-b", "shared");
    let request_a1 = app_random_request("node-a", 1, 4, "shared");
    let request_b = app_random_request("node-b", 1, 4, "shared");
    let request_a2 = app_random_request("node-a", 2, 4, "shared");
    let mut mixed = EngineAppRandomDecisionSource::from_seed(seed);

    let mixed_a1 = match mixed.serve_app_random(&request_a1) {
        Ok(record) => record,
        Err(error) => panic!("node-a first request should record: {error}"),
    };
    let mixed_b = match mixed.serve_app_random(&request_b) {
        Ok(record) => record,
        Err(error) => panic!("node-b request should record: {error}"),
    };
    let mixed_a2 = match mixed.serve_app_random(&request_a2) {
        Ok(record) => record,
        Err(error) => panic!("node-a second request should record: {error}"),
    };

    let mut node_a_only = EngineAppRandomDecisionSource::from_seed(seed);
    let expected_a1 = match node_a_only.serve_app_random(&request_a1) {
        Ok(record) => record,
        Err(error) => panic!("node-a baseline first request should record: {error}"),
    };
    let expected_a2 = match node_a_only.serve_app_random(&request_a2) {
        Ok(record) => record,
        Err(error) => panic!("node-a baseline second request should record: {error}"),
    };

    assert_ne!(node_a_stream, node_b_stream);
    assert_eq!(mixed_a1.value(), expected_a1.value());
    assert_eq!(mixed_a2.value(), expected_a2.value());
    assert_eq!(mixed_a1.stream_tag(), "shared");
    assert_eq!(mixed_b.stream_tag(), "shared");
    assert_eq!(mixed_a2.stream_tag(), "shared");
    assert_eq!(
        engine_rng_draw_streams(mixed.decisions()),
        vec![node_a_stream.clone(), node_b_stream, node_a_stream]
    );
}

#[test]
fn whitebox_app_random_drops_malformed_request_without_decision_or_reply() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let payload = random_request_frame(1, 9, "wide");
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(payload);
    let mut decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
        "node-a", "wide", 0, 72, 0,
    ));
    let mut writer = RecordingGuestInputWriter::default();

    let outcome = match handle_whitebox_app_random_callback(
        &doorbell,
        &capability,
        &mut reader,
        &mut decisions,
        &mut writer,
        "node-a",
        event,
    ) {
        Ok(outcome) => outcome,
        Err(error) => panic!("malformed app-random request should drop, not fail: {error}"),
    };

    assert_eq!(
        outcome,
        AppRandomDoorbellOutcome::Dropped {
            diagnostic: AppRandomDecodeDiagnostic::new(
                AppRandomDecodeDiagnosticKind::InvalidRandomWidth {
                    width_bytes: 9,
                    max_width_bytes: WHITEBOX_APP_RANDOM_MAX_WIDTH_BYTES,
                },
            ),
        }
    );
    assert_eq!(reader.calls, vec![(0, 10, range)]);
    assert!(decisions.requests.is_empty());
    assert!(writer.writes.is_empty());
}

#[test]
fn whitebox_app_random_decoder_rejects_bad_magic_version_kind_and_utf8() {
    assert_eq!(
        WhiteboxDoorbellFrame::decode(&[1, 2, 3]),
        Err(WhiteboxDoorbellFrameDecodeError::TruncatedFrame {
            len: 3,
            minimum_len: WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
        })
    );

    let bad_magic = doorbell_frame_with_header(0, WHITEBOX_DOORBELL_PROTOCOL_VERSION, 5, &[]);
    assert_eq!(
        WhiteboxDoorbellFrame::decode(&bad_magic),
        Err(WhiteboxDoorbellFrameDecodeError::BadMagic {
            expected: WHITEBOX_DOORBELL_FRAME_MAGIC,
            actual: 0,
        })
    );

    let bad_version = doorbell_frame_with_header(WHITEBOX_DOORBELL_FRAME_MAGIC, 1, 5, &[]);
    assert_eq!(
        WhiteboxDoorbellFrame::decode(&bad_version),
        Err(WhiteboxDoorbellFrameDecodeError::UnsupportedVersion {
            expected: WHITEBOX_DOORBELL_PROTOCOL_VERSION,
            actual: 1,
        })
    );

    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(
        0,
        10,
        GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, 32),
    );
    let wrong_kind = match WhiteboxDoorbellFrame::decode(&doorbell_frame(4, &[])) {
        Ok(frame) => frame,
        Err(error) => panic!("wrong-kind frame header should decode: {error:?}"),
    };
    assert_eq!(
        AppRandomDoorbellRequest::from_frame("node-a", event, wrong_kind),
        Err(AppRandomDecodeDiagnostic::new(
            AppRandomDecodeDiagnosticKind::UnexpectedKind {
                expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                actual: 4,
            },
        ))
    );

    let mut invalid_utf8_body = Vec::new();
    invalid_utf8_body.extend_from_slice(&1_u32.to_le_bytes());
    invalid_utf8_body.push(1);
    invalid_utf8_body.extend_from_slice(&1_u16.to_le_bytes());
    invalid_utf8_body.push(0xff);
    let invalid_utf8 = match WhiteboxDoorbellFrame::decode(&doorbell_frame(5, &invalid_utf8_body)) {
        Ok(frame) => frame,
        Err(error) => panic!("invalid-utf8 frame header should decode: {error:?}"),
    };
    assert_eq!(
        AppRandomDoorbellRequest::from_frame("node-a", event, invalid_utf8),
        Err(AppRandomDecodeDiagnostic::new(
            AppRandomDecodeDiagnosticKind::InvalidUtf8StreamTag,
        ))
    );
}

#[test]
fn whitebox_app_random_drops_bad_magic_version_len_and_kind_without_side_effects() {
    let cases = [
        (
            "bad magic",
            doorbell_frame_with_header(0, WHITEBOX_DOORBELL_PROTOCOL_VERSION, 5, &[]),
            AppRandomDecodeDiagnosticKind::BadMagic {
                expected: WHITEBOX_DOORBELL_FRAME_MAGIC,
                actual: 0,
            },
        ),
        (
            "bad version",
            doorbell_frame_with_header(WHITEBOX_DOORBELL_FRAME_MAGIC, 1, 5, &[]),
            AppRandomDecodeDiagnosticKind::UnsupportedVersion {
                expected: WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                actual: 1,
            },
        ),
        (
            "declared length exceeds bound",
            doorbell_frame_with_declared_len(
                WHITEBOX_DOORBELL_FRAME_MAGIC,
                WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                5,
                129,
                &[],
            ),
            AppRandomDecodeDiagnosticKind::PayloadLengthExceedsBound {
                declared_len: 129,
                max_payload_len: 128,
            },
        ),
        (
            "declared length mismatch",
            doorbell_frame_with_declared_len(
                WHITEBOX_DOORBELL_FRAME_MAGIC,
                WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                5,
                4,
                &[0xa5],
            ),
            AppRandomDecodeDiagnosticKind::PayloadLengthMismatch {
                declared_len: 4,
                actual_len: 1,
            },
        ),
        (
            "wrong kind",
            doorbell_frame(4, &[]),
            AppRandomDecodeDiagnosticKind::UnexpectedKind {
                expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                actual: 4,
            },
        ),
    ];

    for (name, payload, expected_kind) in cases {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let capability = guest_input_capability(&doorbell);
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(payload);
        let mut decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
            "node-a", name, 0, 8, 0,
        ));
        let mut writer = RecordingGuestInputWriter::default();

        let outcome = match handle_whitebox_app_random_callback(
            &doorbell,
            &capability,
            &mut reader,
            &mut decisions,
            &mut writer,
            "node-a",
            event,
        ) {
            Ok(outcome) => outcome,
            Err(error) => panic!("malformed app-random case `{name}` should drop: {error}"),
        };

        assert_eq!(
            outcome,
            AppRandomDoorbellOutcome::Dropped {
                diagnostic: AppRandomDecodeDiagnostic::new(expected_kind),
            },
            "malformed app-random case `{name}` produced the wrong diagnostic"
        );
        assert_eq!(reader.calls, vec![(0, 10, range)]);
        assert!(
            decisions.requests.is_empty(),
            "malformed app-random case `{name}` must not draw a decision"
        );
        assert!(
            writer.writes.is_empty(),
            "malformed app-random case `{name}` must not write a reply"
        );
    }
}

#[test]
fn whitebox_app_random_rejects_unmasked_decision_value_without_reply() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let payload = random_request_frame(3, 1, "byte");
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(payload);
    let mut decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
        "node-a", "byte", 3, 8, 0x1ff,
    ));
    let mut writer = RecordingGuestInputWriter::default();

    assert_eq!(
        handle_whitebox_app_random_callback(
            &doorbell,
            &capability,
            &mut reader,
            &mut decisions,
            &mut writer,
            "node-a",
            event,
        ),
        Err(AppRandomDoorbellError::DecisionValueOutOfRange {
            width_bits: 8,
            value: 0x1ff,
        })
    );
    assert_eq!(decisions.requests.len(), 1);
    assert!(writer.writes.is_empty());
}

#[test]
fn whitebox_app_random_rejects_request_id_mismatch_without_reply() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let capability = guest_input_capability(&doorbell);
    let payload = random_request_frame(11, 1, "byte");
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
    let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
    let mut reader = RecordingGuestMemoryReader::with_payload(payload);
    let mut decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
        "node-a", "byte", 12, 8, 0xff,
    ));
    let mut writer = RecordingGuestInputWriter::default();

    assert_eq!(
        handle_whitebox_app_random_callback(
            &doorbell,
            &capability,
            &mut reader,
            &mut decisions,
            &mut writer,
            "node-a",
            event,
        ),
        Err(AppRandomDoorbellError::DecisionRequestIdMismatch {
            expected: 11,
            actual: 12,
        })
    );
    assert_eq!(decisions.requests.len(), 1);
    assert!(writer.writes.is_empty());
}

#[test]
fn whitebox_app_random_zero_requests_leave_no_decisions_or_replies() {
    let doorbell = PluginWhiteboxDoorbell::new(
        PluginSwitch::Off,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );
    let plan = match doorbell.registration_plan(
        WhiteboxDoorbellCapabilities::none(),
        WhiteboxDoorbellSetupValidation::validate(
            doorbell.trap(),
            WhiteboxDoorbellSetupResources::from_observed_resources(&[0xe7], &[]),
        ),
    ) {
        Ok(plan) => plan,
        Err(error) => panic!("zero-request black-box plan should validate: {error}"),
    };
    let decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
        "node-a", "unused", 0, 8, 7,
    ));
    let writer = RecordingGuestInputWriter::default();

    assert!(plan.black_box_remains_functional());
    assert!(decisions.requests.is_empty());
    assert!(writer.writes.is_empty());
}

struct EngineAppRandomDecisionSource {
    recorder: crucible::DecisionRecorder,
}

impl EngineAppRandomDecisionSource {
    fn from_seed(seed: crucible::Seed) -> Self {
        let scenario = crucible::ScenarioDef::from_canonical_material_with_seed(
            "crucible.test.whitebox-app-random",
            "scenario=app-random-doorbell",
            seed,
        );
        Self {
            recorder: crucible::DecisionRecorder::new(crucible::Configuration::genesis(scenario)),
        }
    }

    fn decisions(&self) -> &[crucible::Decision] {
        self.recorder.schedule().decisions()
    }

    fn stream_id(node_name: &str, stream_tag: &str) -> crucible::RngStreamId {
        crucible::RngStreamId::from_name(Self::stream_name(node_name, stream_tag))
    }

    fn stream_name(node_name: &str, stream_tag: &str) -> String {
        format!(
            "app-random/node:{}:{}/stream:{}:{}",
            node_name.len(),
            node_name,
            stream_tag.len(),
            stream_tag
        )
    }
}

impl AppRandomDecisionSource for EngineAppRandomDecisionSource {
    fn serve_app_random(
        &mut self,
        request: &AppRandomDoorbellRequest,
    ) -> Result<AppRandomDecisionRecord, AppRandomDecisionError> {
        let node = crucible::NodeId {
            name: request.node_name().to_owned(),
        };
        let stream = Self::stream_id(request.node_name(), request.stream_tag());
        self.recorder
            .serve_app_random_request(
                node,
                stream,
                u64::from(request.guest_request_id()),
                request.width_bits(),
            )
            .map_err(|error| AppRandomDecisionError::new(error.to_string()))?;

        let app_random = match self.recorder.schedule().decisions().last() {
            Some(crucible::Decision::AppRandom(decision)) => decision,
            Some(decision) => {
                return Err(AppRandomDecisionError::new(format!(
                    "last engine decision was not app-random: {decision:?}"
                )));
            }
            None => {
                return Err(AppRandomDecisionError::new(
                    "engine did not record an app-random decision",
                ));
            }
        };

        Ok(AppRandomDecisionRecord::new(
            app_random.node.name.clone(),
            request.stream_tag().to_owned(),
            app_random.request_id,
            app_random.width,
            app_random.value,
        ))
    }
}

fn app_random_request(
    node_name: &str,
    request_id: u32,
    width_bytes: u8,
    stream_tag: &str,
) -> AppRandomDoorbellRequest {
    let frame = match WhiteboxDoorbellFrame::decode(&random_request_frame(
        request_id,
        width_bytes,
        stream_tag,
    )) {
        Ok(frame) => frame,
        Err(error) => panic!("test random-request frame should decode: {error:?}"),
    };
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, 32);
    let event =
        WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, u64::from(request_id), range);
    match AppRandomDoorbellRequest::from_frame(node_name, event, frame) {
        Ok(request) => request,
        Err(error) => panic!("test random-request should parse: {error:?}"),
    }
}

fn engine_rng_draw_streams(decisions: &[crucible::Decision]) -> Vec<crucible::RngStreamId> {
    decisions
        .iter()
        .filter_map(|decision| match decision {
            crucible::Decision::RngDraw(draw) => Some(draw.stream.clone()),
            _ => None,
        })
        .collect()
}

fn input_at(delivery_icount: u64, payload: &[u8]) -> WhiteboxGuestInput {
    WhiteboxGuestInput::new(
        delivery_icount,
        GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x3000, payload.len()),
        payload.to_vec(),
    )
}

fn phase0_s5_pass_resolution() -> WhiteboxGuestMemoryAddressingResolution {
    WhiteboxGuestMemoryAddressingResolution {
        check: WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK,
        qemu_plugin_read_memory_vaddr_available: true,
        virtual_address_read_result: true,
        resident_read: true,
        page_spanning_read: true,
        paged_mmap_read: true,
        marker_icounts_reproducible: true,
        read_bytes_match_expected: true,
        read_hashes_reproducible: true,
        side_effect_free_fingerprint_match: true,
        physical_pinned_fallback_adopted: false,
    }
}

fn guest_input_capability(doorbell: &PluginWhiteboxDoorbell) -> WhiteboxGuestInputCapability {
    match doorbell.require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional()) {
        Ok(capability) => capability,
        Err(error) => panic!("bidirectional capability should be available: {error}"),
    }
}

fn random_request_frame(guest_request_id: u32, width_bytes: u8, stream_tag: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&guest_request_id.to_le_bytes());
    body.push(width_bytes);
    body.extend_from_slice(&(stream_tag.len() as u16).to_le_bytes());
    body.extend_from_slice(stream_tag.as_bytes());
    doorbell_frame(WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST, &body)
}

fn doorbell_frame(kind: u16, body: &[u8]) -> Vec<u8> {
    match encode_whitebox_doorbell_frame(kind, body) {
        Ok(frame) => frame,
        Err(error) => panic!("test doorbell frame should encode: {error}"),
    }
}

fn coverage_marker_body(point: &str) -> Vec<u8> {
    let payload = WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
        point: String::from(point),
    });
    match crucible_protocol::encode_whitebox_marker_payload_body(&payload) {
        Ok(body) => body,
        Err(error) => panic!("test coverage marker body should encode: {error}"),
    }
}

fn coverage_marker_frame(point: &str) -> Vec<u8> {
    let payload = WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
        point: String::from(point),
    });
    match encode_whitebox_marker_frame(&payload) {
        Ok(frame) => frame,
        Err(error) => panic!("test coverage marker frame should encode: {error}"),
    }
}

fn doorbell_frame_with_header(magic: u32, version: u16, kind: u16, body: &[u8]) -> Vec<u8> {
    doorbell_frame_with_declared_len(magic, version, kind, body.len() as u32, body)
}

fn doorbell_frame_with_declared_len(
    magic: u32,
    version: u16,
    kind: u16,
    declared_len: u32,
    body: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&magic.to_le_bytes());
    frame.extend_from_slice(&version.to_le_bytes());
    frame.extend_from_slice(&kind.to_le_bytes());
    frame.extend_from_slice(&declared_len.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

struct RecordingGuestMemoryReader {
    calls: Vec<(u32, u64, GuestMemoryRange)>,
    result: Result<Vec<u8>, GuestMemoryReadError>,
}

impl RecordingGuestMemoryReader {
    fn with_payload(payload: Vec<u8>) -> Self {
        Self {
            calls: Vec::new(),
            result: Ok(payload),
        }
    }

    fn failing(message: impl Into<String>) -> Self {
        Self {
            calls: Vec::new(),
            result: Err(GuestMemoryReadError::new(message)),
        }
    }
}

impl GuestMemoryReader for RecordingGuestMemoryReader {
    fn read_guest_memory(
        &mut self,
        vcpu_index: u32,
        current_icount: u64,
        range: GuestMemoryRange,
    ) -> Result<Vec<u8>, GuestMemoryReadError> {
        self.calls.push((vcpu_index, current_icount, range));
        self.result.clone()
    }
}

struct MutatingSnapshotGuestMemoryReader {
    calls: Vec<(u32, u64, GuestMemoryRange)>,
    memory_after_read: Vec<u8>,
    later_guest_memory: Vec<u8>,
}

impl MutatingSnapshotGuestMemoryReader {
    fn new(trap_snapshot: Vec<u8>, later_guest_memory: Vec<u8>) -> Self {
        Self {
            calls: Vec::new(),
            memory_after_read: trap_snapshot,
            later_guest_memory,
        }
    }
}

impl GuestMemoryReader for MutatingSnapshotGuestMemoryReader {
    fn read_guest_memory(
        &mut self,
        vcpu_index: u32,
        current_icount: u64,
        range: GuestMemoryRange,
    ) -> Result<Vec<u8>, GuestMemoryReadError> {
        self.calls.push((vcpu_index, current_icount, range));
        let snapshot = self.memory_after_read.clone();
        self.memory_after_read = self.later_guest_memory.clone();
        Ok(snapshot)
    }
}

#[derive(Default)]
struct RecordingMarkerSink {
    markers: Vec<WhiteboxMarker>,
    diagnostics: Vec<WhiteboxDoorbellDecodeDiagnostic>,
}

impl WhiteboxMarkerSink for RecordingMarkerSink {
    fn record_whitebox_marker(
        &mut self,
        marker: &WhiteboxMarker,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        self.markers.push(marker.clone());
        Ok(())
    }

    fn record_whitebox_decode_diagnostic(
        &mut self,
        diagnostic: &WhiteboxDoorbellDecodeDiagnostic,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        self.diagnostics.push(diagnostic.clone());
        Ok(())
    }
}

struct EngineEventLogMarkerSink {
    node: crucible::NodeId,
    event_log: crucible::EventLog,
    entries: Vec<crucible::SchedulerEventLogEntry>,
}

impl EngineEventLogMarkerSink {
    fn new(node_name: &str) -> Self {
        Self {
            node: crucible_node(node_name),
            event_log: crucible::EventLog::new(),
            entries: Vec::new(),
        }
    }
}

impl WhiteboxMarkerSink for EngineEventLogMarkerSink {
    fn record_whitebox_marker(
        &mut self,
        marker: &WhiteboxMarker,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        let event = crucible::observable_event_from_whitebox_marker_payload(
            crucible::Icount {
                retired: marker.marker_icount(),
            },
            self.node.clone(),
            marker.decoded_payload(),
        )
        .ok_or_else(|| {
            WhiteboxMarkerSinkError::new("non-observational marker reached event-log sink")
        })?;
        let sequence = self
            .event_log
            .next_sequence(0)
            .map_err(|error| WhiteboxMarkerSinkError::new(format!("{error:?}")))?;
        let entry = crucible::test_support::condition_observation_entry_for_test(sequence, &event);
        let append = self
            .event_log
            .append_entries(vec![entry])
            .map_err(|error| WhiteboxMarkerSinkError::new(format!("{error:?}")))?;
        self.entries.extend(append.entries);
        Ok(())
    }

    fn record_whitebox_decode_diagnostic(
        &mut self,
        diagnostic: &WhiteboxDoorbellDecodeDiagnostic,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        let event = crucible::ObservableEvent::guest_marker(
            crucible::Icount {
                retired: diagnostic.marker_icount(),
            },
            self.node.clone(),
            crucible::MarkerId::from_name(format!(
                "decode_diagnostic.{}",
                diagnostic.kind().semantic_label()
            )),
        );
        let sequence = self
            .event_log
            .next_sequence(0)
            .map_err(|error| WhiteboxMarkerSinkError::new(format!("{error:?}")))?;
        let entry = crucible::test_support::condition_observation_entry_for_test(sequence, &event);
        let append = self
            .event_log
            .append_entries(vec![entry])
            .map_err(|error| WhiteboxMarkerSinkError::new(format!("{error:?}")))?;
        self.entries.extend(append.entries);
        Ok(())
    }
}

fn crucible_node(name: &str) -> crucible::NodeId {
    crucible::NodeId {
        name: name.to_owned(),
    }
}

#[derive(Default)]
struct RecordingGuestInputWriter {
    writes: Vec<(u64, GuestMemoryRange, Vec<u8>)>,
}

impl WhiteboxGuestInputWriter for RecordingGuestInputWriter {
    fn write_whitebox_input(
        &mut self,
        delivery_icount: u64,
        range: GuestMemoryRange,
        payload: &[u8],
    ) -> Result<(), WhiteboxGuestInputWriteError> {
        self.writes.push((delivery_icount, range, payload.to_vec()));
        Ok(())
    }
}

struct RecordingAppRandomSource {
    requests: Vec<AppRandomDoorbellRequest>,
    result: Result<AppRandomDecisionRecord, AppRandomDecisionError>,
}

impl RecordingAppRandomSource {
    fn with_record(record: AppRandomDecisionRecord) -> Self {
        Self {
            requests: Vec::new(),
            result: Ok(record),
        }
    }
}

impl AppRandomDecisionSource for RecordingAppRandomSource {
    fn serve_app_random(
        &mut self,
        request: &AppRandomDoorbellRequest,
    ) -> Result<AppRandomDecisionRecord, AppRandomDecisionError> {
        self.requests.push(request.clone());
        self.result.clone()
    }
}
