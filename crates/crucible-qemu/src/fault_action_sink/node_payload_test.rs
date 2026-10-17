//! Tests extracted from the adjacent production module.

use super::*;
use crucible::model::{
    BindingActionCause, ByteRange, EffectLifetime, EffectRequest, FaultCoordinate,
    FaultResourceLimitError, FaultResourceLimits, FaultRuntimeError, MemoryAccessClasses,
    MemoryAccessMutation, NodeBootPolicy, NodeOccurrencePolicy, ResolvedMappingOutput,
};
use serde_json::json;
use std::sync::Arc;

fn object_id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test object ID must be valid: {error}"))
}

#[test]
fn atomic_selectors_export_actual_typed_payloads() -> Result<(), Box<dyn std::error::Error>> {
    let mutations = [
        (
            "read-corrupt",
            false,
            true,
            json!({"kind":"read_corrupt","parameters":{"mask":"01"}}),
        ),
        (
            "read-corrupt-gva",
            false,
            true,
            json!({"kind":"read_corrupt","parameters":{"mask":"01"}}),
        ),
        (
            "stuck-read-write",
            true,
            true,
            json!({"kind":"stuck","parameters":{"mask":"0f","value":"05"}}),
        ),
        (
            "stuck-write",
            true,
            false,
            json!({"kind":"stuck","parameters":{"mask":"0f","value":"05"}}),
        ),
        ("lost-write", true, false, json!({"kind":"lost_write"})),
        (
            "torn-write",
            true,
            false,
            json!({"kind":"torn_write","parameters":{"selector":"0f"}}),
        ),
        (
            "torn-write-atomic",
            true,
            false,
            json!({"kind":"torn_write","parameters":{"selector":"0f"}}),
        ),
    ];
    let output = std::env::var_os("AOS_ATOMIC_SELECTOR_OUTPUT").map(std::path::PathBuf::from);
    if let Some(directory) = &output {
        std::fs::create_dir_all(directory)?;
        std::fs::write(
            directory.join("node.hash"),
            crate::qemu_fault_target_hash("node-a"),
        )?;
    }
    for (name, write, read, mutation) in mutations {
        let effect: NodeEffectSpecification = serde_json::from_value(json!({
            "kind": "memory_access_transform",
            "parameters": {
                "range": {"start": 4096, "length": 16},
                "accesses": {"fetch":false,"cpu_load":read,"cpu_store":write,
                             "dma_read":false,"dma_write":false,"page_table_walk":false},
                "violate_atomicity": name == "torn-write-atomic",
                "mutation": mutation,
                "occurrence": {"kind":"every"}
            }
        }))?;
        effect.validate()?;
        let specification = EffectSpecification::Node(effect);
        let descriptor = specification.kind().descriptor();
        let action = ResolvedBindingAction {
            kind: BindingActionKind::UpsertPersistent,
            binding: object_id(name),
            target: ResolvedFaultTarget::MemoryRange {
                node: object_id("node-a"),
                address_space: object_id(if name.ends_with("-gva") { "gva" } else { "gpa" }),
                guest_address: 4096,
                vcpu: name.ends_with("-gva").then_some(0),
                length_bytes: 16,
            },
            phase: descriptor.phases[0],
            effect: Arc::new(EffectRequest::new(
                descriptor.semantic_version,
                EffectLifetime::Persistent,
                specification,
            )?),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash { bytes: [1; 32] },
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_ticks: 1,
                retired_instructions: Some(1),
            },
            cause: BindingActionCause::Signal,
            expected_precondition: None,
        };
        let encoded = encode_node_action(&action, [3; 32])?;
        let bytes = encoded.payload.encode()?;
        assert_eq!(NodeFaultPayloadV1::decode(&bytes), Ok(encoded.payload));
        if let Some(directory) = &output {
            std::fs::write(directory.join(format!("{name}.bin")), bytes)?;
            let binding = ContentHash::from_canonical_material(
                "crucible.fault-binding.v1",
                action.binding.as_str(),
            );
            std::fs::write(directory.join(format!("{name}.binding")), binding.bytes)?;
        }
    }

    let invalid: NodeEffectSpecification = serde_json::from_value(json!({
        "kind":"memory_access_transform", "parameters": {
            "range":{"start":4096,"length":16},
            "accesses":{"fetch":false,"cpu_load":false,"cpu_store":true,
                        "dma_read":false,"dma_write":false,"page_table_walk":false},
            "violate_atomicity":false,
            "mutation":{"kind":"read_corrupt","parameters":{"mask":"01"}},
            "occurrence":{"kind":"every"}
        }
    }))?;
    assert!(invalid.validate().is_err());
    Ok(())
}

fn lifecycle() -> EffectSpecification {
    EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
        transition: NodeLifecycleTransition::Reset,
        downtime_nanos: 1,
        boot_policy: NodeBootPolicy::Immediate,
        volatile_state_policy: NodeStatePolicy::Clear,
        device_state_policy: NodeStatePolicy::DeviceReset,
    })
}

#[test]
fn shared_object_id_hash_matches_the_model_contract() {
    let id = object_id("node-a-register-rip");

    assert_eq!(
        fault_object_id_hash_v1(id.as_str()),
        ContentHash::from_canonical_material("crucible.fault-object.v1", id.as_str()).bytes,
    );
}

#[test]
fn clock_phase_tags_match_the_closed_model_phase_registry() {
    assert_eq!(phase_tag(FaultPhase::ClockRead), 28);
    assert_eq!(phase_tag(FaultPhase::Arm), 29);
    assert_eq!(phase_tag(FaultPhase::Fire), 30);
    assert_eq!(phase_tag(FaultPhase::Synchronize), 31);
    assert_eq!(phase_tag(FaultPhase::SourceSwitch), 32);
    assert_eq!(phase_tag(FaultPhase::Submit), 33);
}

#[test]
fn remove_payload_discards_all_target_fields() {
    let mut target = vec![NodeFaultFieldV1::u32(node_fault_field::T1, 7)];
    assert_eq!(
        payload_fields(
            NodeFaultOperationV1::Remove,
            &lifecycle(),
            &BindingActionCause::Signal,
            &mut target,
        ),
        Ok(Vec::new())
    );
}

#[test]
fn effect_target_pairing_rejects_wrong_category() {
    let target = ResolvedFaultTarget::Vcpu {
        node: object_id("node-a"),
        vcpu: 0,
    };
    assert!(!effect_matches_target(&lifecycle(), &target));
}

#[test]
fn effect_target_pairing_rejects_conflicting_memory_range() {
    let range = ByteRange::new(0x1000, 64)
        .unwrap_or_else(|error| panic!("test range must be valid: {error}"));
    let effect = EffectSpecification::Node(NodeEffectSpecification::MemoryAccessTransform {
        range,
        accesses: MemoryAccessClasses {
            fetch: false,
            cpu_load: false,
            cpu_store: true,
            dma_read: false,
            dma_write: false,
            page_table_walk: false,
        },
        dma_device: None,
        violate_atomicity: false,
        mutation: MemoryAccessMutation::LostWrite,
        occurrence: NodeOccurrencePolicy::Every,
    });
    let target = ResolvedFaultTarget::MemoryRange {
        node: object_id("node-a"),
        address_space: object_id("gpa"),
        guest_address: 0x2000,
        vcpu: None,
        length_bytes: 64,
    };
    assert!(!effect_matches_target(&effect, &target));
}

#[test]
fn page_table_walk_rejects_a_virtual_memory_target() {
    let range = ByteRange::new(0x1000, 8)
        .unwrap_or_else(|error| panic!("test range must be valid: {error}"));
    let effect = EffectSpecification::Node(NodeEffectSpecification::MemoryAccessTransform {
        range,
        accesses: MemoryAccessClasses {
            fetch: false,
            cpu_load: false,
            cpu_store: false,
            dma_read: false,
            dma_write: false,
            page_table_walk: true,
        },
        dma_device: None,
        violate_atomicity: false,
        mutation: MemoryAccessMutation::ReadCorrupt {
            mask: crucible::model::HexBytes::parse("01", 1)
                .unwrap_or_else(|error| panic!("test mask must be valid: {error}")),
        },
        occurrence: NodeOccurrencePolicy::Every,
    });
    let target = ResolvedFaultTarget::MemoryRange {
        node: object_id("node-a"),
        address_space: object_id("gva"),
        guest_address: 0x1000,
        vcpu: Some(0),
        length_bytes: 8,
    };

    assert!(!effect_matches_target(&effect, &target));
}

#[test]
fn dma_device_identity_matches_the_qemu_wire_contract() {
    assert_eq!(
        qemu_virtio_dma_identity(&object_id("virtio-net0")),
        [
            0x73, 0x0e, 0x68, 0xf0, 0x8a, 0xfe, 0x82, 0xa7, 0x98, 0x02, 0xa9, 0xfd, 0x7c, 0xd2,
            0xb0, 0xbf, 0x32, 0x8c, 0x96, 0x5c, 0xeb, 0x4c, 0x76, 0x5f, 0xc5, 0xdb, 0x6f, 0x73,
            0x84, 0xab, 0x07, 0xe6,
        ]
    );
}

#[test]
fn every_typed_node_effect_translates_to_its_closed_wire_schema() {
    let effects = [
        json!({"kind":"lifecycle","parameters":{"transition":"reset","downtime_nanos":10,"boot_policy":{"kind":"immediate"},"volatile_state_policy":"clear","device_state_policy":"device_reset"}}),
        json!({"kind":"hang","parameters":{"scope":{"kind":"node"},"recovery_event":"recover","watchdog_policy":{"kind":"disabled"}}}),
        json!({"kind":"cpu_service","parameters":{"vcpus":[0],"capacity":{"numerator":1,"denominator":2},"quantum_instructions":100,"service_rule":"strict_cap"}}),
        json!({"kind":"vcpu_state","parameters":{"state":"offline","recovery_event":"recover"}}),
        json!({"kind":"register_transform","parameters":{"register":"rax","first_bit":0,"bit_count":8,"mutation":{"kind":"bit_flip","parameters":{"mask":"01"}},"occurrence":{"kind":"every"}}}),
        json!({"kind":"instruction_transform","parameters":{"selector":{"pc_start":4096,"pc_length":4,"instruction_bytes":"90909090","opcode_class":null,"input_state_sha256":null,"occurrence":{"kind":"every"}},"mutation":{"kind":"result_corrupt","parameters":{"transform":{"destination":"rax","mutation":{"kind":"replace","parameters":{"value":"01"}}}}}}}),
        json!({"kind":"cpu_exception","parameters":{"exception":{"architecture":"x86_64","vector":18,"syndrome":0,"fault_address":null,"before_instruction":true,"maskable":false,"record":{"kind":"architecture_default"}}}}),
        json!({"kind":"interrupt_disposition","parameters":{"mutation":{"kind":"delay","parameters":{"delay_nanos":10}}}}),
        json!({"kind":"interrupt_storm","parameters":{"source":"timer","vector":32,"period_nanos":100,"burst":2,"count":4,"routing":{"target_vcpus":[0],"priority":0,"retain_pending":true}}}),
        json!({"kind":"memory_mutation","parameters":{"address_space":"guest_physical","range":{"start":4096,"length":8},"mutation":{"kind":"bit_flip","parameters":{"mask":"01"}},"atomicity":"all_or_nothing"}}),
        json!({"kind":"memory_access_transform","parameters":{"range":{"start":4096,"length":64},"accesses":{"fetch":false,"cpu_load":false,"cpu_store":true,"dma_read":false,"dma_write":false,"page_table_walk":false},"violate_atomicity":true,"mutation":{"kind":"torn_write","parameters":{"selector":"0f"}},"occurrence":{"kind":"every"}}}),
        json!({"kind":"memory_ecc_event","parameters":{"target_vcpu":0,"kind":"corrected","address":4096,"syndrome":1,"bank":"bank-0","channel":"channel-0","rank":"rank-0","guest_visibility":{"kind":"telemetry_only"}}}),
        json!({"kind":"memory_region_state","parameters":{"range":{"start":4096,"length":64},"kind":"retention","process":{"kind":"retention","parameters":{"interval_nanos":100,"decay_mask":"01"}}}}),
        json!({"kind":"memory_service","parameters":{"latency_picoseconds":8,"bandwidth_bytes_per_second":null,"operations_per_second":null,"sharing_scope":{"kind":"range"}}}),
        json!({"kind":"clock_transform","parameters":{"source":"clock-main","mutation":{"kind":"freeze","parameters":{"value_nanos":1000,"release":"resume_from_frozen"}},"monotonicity":"clamp_monotonic","overdue_timer_policy":"fire_at_boundary"}}),
        json!({"kind":"clock_source_state","parameters":{"sources":["clock-main"],"transition":{"kind":"failed","parameters":{"behavior":"read_error"}},"synchronization_policy":{"kind":"step"}}}),
        json!({"kind":"accelerator_lifecycle","parameters":{"device":"accelerator-0","transition":"reset","queue_policy":"clear","memory_policy":"device_reset"}}),
        json!({"kind":"accelerator_result_transform","parameters":{"job_selector":{"job_kind":"matrix-multiply","queue":null,"occurrence":{"kind":"every"}},"transform":{"offset":0,"mask":"01","value":"01"}}}),
        json!({"kind":"accelerator_memory_event","parameters":{"range":{"start":0,"length":1},"ecc":null,"syndrome":null,"transform":"01"}}),
        json!({"kind":"accelerator_service","parameters":{"capacity":{"numerator":1,"denominator":2},"memory_bytes_per_second":null,"jobs_per_second":null,"thermal_power":{"temperature_millikelvin":300000,"power_milliwatts":1000}}}),
    ];
    assert_eq!(effects.len(), 20);
    for encoded_effect in effects {
        let effect: NodeEffectSpecification = serde_json::from_value(encoded_effect)
            .unwrap_or_else(|error| panic!("closed node effect JSON must decode: {error}"));
        effect
            .validate()
            .unwrap_or_else(|error| panic!("closed node effect must validate: {error}"));
        let specification = EffectSpecification::Node(effect);
        let kind = specification.kind();
        let descriptor = kind.descriptor();
        let rule_backed_kind = matches!(
            kind,
            crucible::model::EffectKind::CpuService
                | crucible::model::EffectKind::CpuVcpuState
                | crucible::model::EffectKind::InterruptStorm
                | crucible::model::EffectKind::MemoryRegionState
                | crucible::model::EffectKind::MemoryService
                | crucible::model::EffectKind::ClockSourceState
                | crucible::model::EffectKind::AcceleratorLifecycle
                | crucible::model::EffectKind::AcceleratorService
        );
        let lifetime =
            if rule_backed_kind && descriptor.lifetimes.contains(&EffectLifetime::StateMachine) {
                EffectLifetime::StateMachine
            } else {
                descriptor.lifetimes[0]
            };
        let mut action = ResolvedBindingAction {
            kind: if lifetime == EffectLifetime::Persistent {
                BindingActionKind::UpsertPersistent
            } else {
                BindingActionKind::Apply
            },
            binding: object_id("binding-a"),
            target: test_target(kind),
            phase: descriptor.phases[0],
            effect: Arc::new(
                EffectRequest::new(descriptor.semantic_version, lifetime, specification)
                    .unwrap_or_else(|error| panic!("{kind:?} request must validate: {error}")),
            ),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash { bytes: [1; 32] },
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_ticks: 1,
                retired_instructions: Some(1),
            },
            cause: BindingActionCause::Signal,
            expected_precondition: None,
        };
        if kind == crucible::model::EffectKind::AcceleratorResultTransform {
            let identity = ContentHash::from_bytes(b"accelerator-job");
            action.opportunity = Some(identity);
            action.cause = BindingActionCause::Opportunity {
                identity,
                payload: OpportunityPayload::AcceleratorJob {
                    job_sequence: 2,
                    job_digest: ContentHash::from_bytes(b"accelerator-job-fields"),
                },
            };
        }
        if kind == crucible::model::EffectKind::MemoryService {
            action.phase = FaultPhase::Load;
        }
        if kind == crucible::model::EffectKind::MemoryMutation {
            let prepared = super::super::prepare_memory_action_payload(
                &action,
                FaultResourceLimits::default(),
            )
            .unwrap_or_else(|error| panic!("{kind:?} must prepare atomically: {error}"));
            let bytes = prepared
                .payload
                .encode_preparation()
                .unwrap_or_else(|error| panic!("{kind:?} preparation schema must encode: {error}"));
            assert_eq!(
                crucible_shmem::MemoryMutationPayloadV1::decode_preparation(&bytes),
                Ok(prepared.payload),
            );
            continue;
        }
        let encoded = encode_node_action(&action, [3; 32])
            .unwrap_or_else(|error| panic!("{kind:?} must translate: {error}"));
        let rule_backed_state_machine =
            rule_backed_kind && lifetime == EffectLifetime::StateMachine;
        let expected_operation = match action.kind {
            BindingActionKind::UpsertPersistent => NodeFaultOperationV1::Upsert,
            BindingActionKind::RemovePersistent => NodeFaultOperationV1::Remove,
            BindingActionKind::Apply if rule_backed_state_machine => NodeFaultOperationV1::Upsert,
            BindingActionKind::Apply => NodeFaultOperationV1::Apply,
        };
        assert_eq!(
            encoded.payload.operation, expected_operation,
            "{kind:?} must use the operation implemented by its QEMU handler",
        );
        if kind == crucible::model::EffectKind::CpuInstructionTransform {
            assert_eq!(encoded.payload.operation, NodeFaultOperationV1::Apply);
        }
        if kind == crucible::model::EffectKind::MemoryService {
            assert_eq!(encoded.payload.fields[0], NodeFaultFieldV1::u64(1, 8));
        }
        let bytes = encoded
            .payload
            .encode()
            .unwrap_or_else(|error| panic!("{kind:?} wire schema must encode: {error}"));
        assert_eq!(NodeFaultPayloadV1::decode(&bytes), Ok(encoded.payload));
    }
}

#[test]
fn memory_service_rejects_the_nanosecond_field() {
    let old = json!({
        "kind": "memory_service",
        "parameters": {
            "latency_nanos": 8,
            "bandwidth_bytes_per_second": null,
            "operations_per_second": null,
            "sharing_scope": {"kind": "range"}
        }
    });

    assert!(serde_json::from_value::<NodeEffectSpecification>(old).is_err());
}

#[test]
fn memory_service_rejects_latency_beyond_the_sim_tick_limit() {
    let effect = serde_json::from_value::<NodeEffectSpecification>(json!({
        "kind": "memory_service",
        "parameters": {
            "latency_picoseconds": u64::MAX,
            "bandwidth_bytes_per_second": null,
            "operations_per_second": null,
            "sharing_scope": {"kind": "range"}
        }
    }))
    .unwrap_or_else(|error| panic!("typed service effect must decode: {error}"));

    assert!(effect.validate().is_err());
}

fn mapped_memory_service_action(value: SignalValue) -> ResolvedBindingAction {
    ResolvedBindingAction {
        kind: BindingActionKind::UpsertPersistent,
        binding: object_id("mapped-memory-latency"),
        target: test_target(EffectKind::MemoryService),
        phase: FaultPhase::Load,
        effect: Arc::new(
            EffectRequest::new(
                crucible::model::EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Persistent,
                EffectSpecification::Node(NodeEffectSpecification::MemoryService {
                    latency_picoseconds: 8,
                    bandwidth_bytes_per_second: None,
                    operations_per_second: None,
                    sharing_scope: crucible::model::MemoryServiceScope::Range,
                }),
            )
            .unwrap_or_else(|error| panic!("concrete native service template: {error}")),
        ),
        mapping_output: Arc::new(ResolvedMappingOutput::Parameter {
            parameter: MappedEffectParameter::DurationNanos,
            value,
        }),
        mapped_digest: ContentHash { bytes: [1; 32] },
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_ticks: 1,
            retired_instructions: Some(1),
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn shared_memory_action(kind: EffectKind, space: &str, vcpu: Option<u32>) -> ResolvedBindingAction {
    let value = match kind {
        EffectKind::MemoryAccessTransform => json!({"kind":"memory_access_transform","parameters":{
            "range":{"start":4096,"length":64},
            "accesses":{"fetch":false,"cpu_load":true,"cpu_store":false,
                        "dma_read":false,"dma_write":false,"page_table_walk":false},
            "violate_atomicity":false,
            "mutation":{"kind":"read_corrupt","parameters":{"mask":"01"}},
            "occurrence":{"kind":"every"}
        }}),
        EffectKind::MemoryRegionState => json!({"kind":"memory_region_state","parameters":{
            "range":{"start":4096,"length":64},"kind":"retention",
            "process":{"kind":"retention","parameters":{"interval_nanos":100,"decay_mask":"01"}}
        }}),
        EffectKind::MemoryEccEvent => json!({"kind":"memory_ecc_event","parameters":{
            "target_vcpu":2,"kind":"corrected","address":4096,"syndrome":1,
            "bank":"bank-0","channel":"channel-0","rank":"rank-0",
            "guest_visibility":{"kind":"telemetry_only"}
        }}),
        _ => panic!("shared memory fixture kind"),
    };
    let specification = EffectSpecification::Node(serde_json::from_value(value).expect("effect"));
    let descriptor = specification.kind().descriptor();
    let lifetime = descriptor.lifetimes[0];
    let mut action = mapped_memory_service_action(SignalValue::DurationNanos(4));
    action.kind = if lifetime == EffectLifetime::Persistent {
        BindingActionKind::UpsertPersistent
    } else {
        BindingActionKind::Apply
    };
    action.phase = descriptor.phases[0];
    action.effect = Arc::new(
        EffectRequest::new(descriptor.semantic_version, lifetime, specification)
            .expect("shared effect request"),
    );
    action.target = ResolvedFaultTarget::MemoryRange {
        node: object_id("node-a"),
        address_space: object_id(space),
        guest_address: 4096,
        vcpu,
        length_bytes: 64,
    };
    action.mapping_output = Arc::new(ResolvedMappingOutput::Activation { active: true });
    action
}

#[test]
fn shared_memory_target_matches_the_production_node_header()
-> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::var_os("AOS_SHARED_MEMORY_TARGET_OUTPUT").map(std::path::PathBuf::from);
    if let Some(directory) = &output {
        std::fs::create_dir_all(directory)?;
    }
    for (name, kind, space, vcpu) in [
        ("access-gpa", EffectKind::MemoryAccessTransform, "gpa", None),
        (
            "access-gva",
            EffectKind::MemoryAccessTransform,
            "gva",
            Some(0),
        ),
        ("region-gpa", EffectKind::MemoryRegionState, "gpa", None),
        ("region-gva", EffectKind::MemoryRegionState, "gva", Some(0)),
        ("ecc-gpa", EffectKind::MemoryEccEvent, "gpa", None),
    ] {
        let action = shared_memory_action(kind, space, vcpu);
        let encoded = encode_node_action(&action, [3; 32])?;
        let bytes = encoded.payload.encode()?;
        let prepared = super::super::PreparedTypedNodeAction {
            action: action.clone(),
            action_id: action.id(),
            node: crucible::model::NodeId {
                name: encoded.node.clone(),
            },
            coordinate: 1,
            command_kind: encoded.command_kind,
            payload: bytes.clone(),
        };
        let header = super::super::evidence::typed_command_header(&prepared, 1, 1, 0, [0; 32])?;
        for expected in [
            NodeFaultFieldV1::hash(node_fault_field::T1, header.target_node_hash),
            NodeFaultFieldV1::boolean(node_fault_field::T3, vcpu.is_some()),
            NodeFaultFieldV1::u32(node_fault_field::T4, vcpu.unwrap_or(0)),
        ] {
            assert!(encoded.payload.fields.contains(&expected));
        }
        assert_eq!(encoded.payload.action_hash, action.id().bytes);
        assert_eq!(NodeFaultPayloadV1::decode(&bytes)?, encoded.payload);
        if kind == EffectKind::MemoryEccEvent {
            // The ECC receiver is independent of physical target coordinates.
            assert!(
                encoded
                    .payload
                    .fields
                    .contains(&NodeFaultFieldV1::u32(node_fault_field::P8, 2))
            );
        }
        if let Some(directory) = &output {
            std::fs::write(directory.join(format!("{name}.bin")), &bytes)?;
            std::fs::write(directory.join(format!("{name}.header")), header.encode())?;
            let mut old_target = encoded.payload;
            *old_target
                .fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::T1)
                .expect("memory target") = id_field(node_fault_field::T1, &object_id(space));
            std::fs::write(
                directory.join(format!("{name}-old-t1.bin")),
                old_target.encode()?,
            )?;
        }
    }
    Ok(())
}

#[test]
fn shared_memory_target_refuses_ambiguous_coordinates_and_preserves_removal() {
    for kind in [
        EffectKind::MemoryAccessTransform,
        EffectKind::MemoryRegionState,
        EffectKind::MemoryEccEvent,
    ] {
        for (space, vcpu) in [("gpa", Some(0)), ("gva", None), ("unknown", None)] {
            let mut action = shared_memory_action(kind, space, vcpu);
            assert!(matches!(
                encode_node_action(&action, [3; 32]),
                Err(NodeFaultPayloadError::TargetValue)
            ));
            if kind != EffectKind::MemoryEccEvent {
                action.kind = BindingActionKind::RemovePersistent;
                assert!(
                    encode_node_action(&action, [3; 32])
                        .expect("removal")
                        .payload
                        .fields
                        .is_empty()
                );
            }
        }
    }
    assert!(matches!(
        encode_node_action(
            &shared_memory_action(EffectKind::MemoryEccEvent, "gva", Some(0)),
            [3; 32]
        ),
        Err(NodeFaultPayloadError::TargetValue)
    ));
}

#[test]
fn shared_memory_coordinate_refusal_follows_existing_materialization_errors() {
    let mut action = mapped_memory_service_action(SignalValue::I64(1));
    let ResolvedFaultTarget::MemoryRange {
        address_space,
        vcpu,
        ..
    } = &mut action.target
    else {
        panic!("memory target")
    };
    *address_space = object_id("gpa");
    *vcpu = Some(0);
    assert!(matches!(
        encode_node_action(&action, [3; 32]),
        Err(NodeFaultPayloadError::FieldValue { tag: 1 })
    ));
}

#[test]
fn memory_service_actor_follows_the_authenticated_phase_and_target()
-> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::var_os("AOS_MEMORY_SERVICE_ACTOR_OUTPUT").map(std::path::PathBuf::from);
    if let Some(directory) = &output {
        std::fs::create_dir_all(directory)?;
    }
    for (name, phase, vcpu, space, actor) in [
        (
            "cpu-load-gva",
            FaultPhase::Load,
            Some(0),
            "gva",
            json!({"kind":"cpu_single_access","parameters":{"access":"load"}}),
        ),
        (
            "cpu-store-gva",
            FaultPhase::Store,
            Some(0),
            "gva",
            json!({"kind":"cpu_single_access","parameters":{"access":"store"}}),
        ),
        (
            "fwcfg-read",
            FaultPhase::DmaRead,
            None,
            "gpa",
            json!({"kind":"fw_cfg_payload","parameters":{"direction":"read"}}),
        ),
        (
            "fwcfg-write",
            FaultPhase::DmaWrite,
            None,
            "gpa",
            json!({"kind":"fw_cfg_payload","parameters":{"direction":"write"}}),
        ),
    ] {
        let mut action = mapped_memory_service_action(SignalValue::DurationNanos(4));
        action.phase = phase;
        let ResolvedFaultTarget::MemoryRange {
            address_space,
            vcpu: target_vcpu,
            ..
        } = &mut action.target
        else {
            panic!("memory target")
        };
        *address_space = object_id(space);
        *target_vcpu = vcpu;

        let encoded = encode_node_action(&action, [3; 32])?;
        assert_eq!(encoded.payload.action_hash, action.id().bytes);
        assert_eq!(
            encoded
                .payload
                .fields
                .iter()
                .find(|field| field.tag == node_fault_field::P7),
            Some(&json_field(node_fault_field::P7, &actor)?),
        );
        let bytes = encoded.payload.encode()?;
        assert_eq!(NodeFaultPayloadV1::decode(&bytes)?, encoded.payload);
        let prepared = super::super::PreparedTypedNodeAction {
            action: action.clone(),
            action_id: action.id(),
            node: crucible::model::NodeId {
                name: encoded.node.clone(),
            },
            coordinate: 1,
            command_kind: encoded.command_kind,
            payload: bytes.clone(),
        };
        let header = super::super::evidence::typed_command_header(&prepared, 1, 1, 0, [0; 32])?;
        assert_eq!(
            encoded
                .payload
                .fields
                .iter()
                .find(|field| field.tag == node_fault_field::T1),
            Some(&NodeFaultFieldV1::hash(
                node_fault_field::T1,
                header.target_node_hash
            )),
        );
        let mut without_actor = encoded.payload.clone();
        without_actor
            .fields
            .retain(|field| field.tag != node_fault_field::P7);
        assert!(
            without_actor.encode().is_err(),
            "actor is a required wire field"
        );

        if let Some(directory) = &output {
            std::fs::write(directory.join(format!("{name}.bin")), &bytes)?;
            std::fs::write(directory.join(format!("{name}.header")), header.encode())?;
            let mut old_target = encoded.payload;
            *old_target
                .fields
                .iter_mut()
                .find(|field| field.tag == node_fault_field::T1)
                .expect("memory target") = id_field(node_fault_field::T1, &object_id(space));
            std::fs::write(
                directory.join(format!("{name}-old-t1.bin")),
                old_target.encode()?,
            )?;
        }
    }
    Ok(())
}

#[test]
fn memory_service_actor_refuses_ambiguous_or_unsupported_targets() {
    for (phase, vcpu, space, length) in [
        (FaultPhase::Load, None, "gpa", 1),
        (FaultPhase::Store, None, "gpa", 1),
        (FaultPhase::Load, Some(0), "gpa", 1),
        (FaultPhase::Store, Some(0), "gpa", 1),
        (FaultPhase::Load, Some(0), "gva", 2),
        (FaultPhase::Load, Some(0), "unknown", 1),
        (FaultPhase::Fetch, Some(0), "gpa", 1),
        (FaultPhase::PageTableWalk, Some(0), "gpa", 1),
        (FaultPhase::Queue, Some(0), "gpa", 1),
        (FaultPhase::DmaRead, Some(0), "gpa", 1),
        (FaultPhase::DmaWrite, None, "gva", 1),
        (FaultPhase::DmaRead, None, "gpa", 0),
    ] {
        let mut action = mapped_memory_service_action(SignalValue::DurationNanos(4));
        action.phase = phase;
        let ResolvedFaultTarget::MemoryRange {
            address_space,
            vcpu: target_vcpu,
            length_bytes,
            ..
        } = &mut action.target
        else {
            panic!("memory target")
        };
        *address_space = object_id(space);
        *target_vcpu = vcpu;
        *length_bytes = length;
        assert!(matches!(
            encode_node_action(&action, [3; 32]),
            Err(NodeFaultPayloadError::TargetValue)
        ));
    }
    for (scope, byte_rate, operation_rate, latency) in [
        (crucible::model::MemoryServiceScope::Node, None, None, 1),
        (crucible::model::MemoryServiceScope::Range, Some(1), None, 1),
        (crucible::model::MemoryServiceScope::Range, None, Some(1), 1),
        (crucible::model::MemoryServiceScope::Range, Some(1), None, 0),
    ] {
        let mut action = mapped_memory_service_action(SignalValue::DurationNanos(4));
        action.phase = FaultPhase::DmaRead;
        let ResolvedFaultTarget::MemoryRange {
            address_space,
            vcpu,
            ..
        } = &mut action.target
        else {
            panic!("memory target")
        };
        *address_space = object_id("gpa");
        *vcpu = None;
        action.mapping_output = Arc::new(ResolvedMappingOutput::Activation { active: true });
        action.effect = Arc::new(
            EffectRequest::new(
                crucible::model::EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Persistent,
                EffectSpecification::Node(NodeEffectSpecification::MemoryService {
                    latency_picoseconds: latency,
                    bandwidth_bytes_per_second: byte_rate.map(|rate| {
                        crucible::model::PositiveU64::new("byte rate", rate)
                            .expect("positive byte rate")
                    }),
                    operations_per_second: operation_rate.map(|rate| {
                        crucible::model::PositiveU64::new("operation rate", rate)
                            .expect("positive operation rate")
                    }),
                    sharing_scope: scope,
                }),
            )
            .expect("valid effect; unsupported native actor"),
        );
        assert!(matches!(
            encode_node_action(&action, [3; 32]),
            Err(NodeFaultPayloadError::TargetValue)
        ));
    }

    let mut zero = mapped_memory_service_action(SignalValue::DurationNanos(0));
    zero.phase = FaultPhase::DmaRead;
    let ResolvedFaultTarget::MemoryRange {
        address_space,
        vcpu,
        ..
    } = &mut zero.target
    else {
        panic!("memory target")
    };
    *address_space = object_id("gpa");
    *vcpu = None;
    assert!(matches!(
        encode_node_action(&zero, [3; 32]),
        Err(NodeFaultPayloadError::FieldValue { tag: 1 })
    ));

    zero.kind = BindingActionKind::RemovePersistent;
    zero.phase = FaultPhase::Fetch;
    assert!(
        encode_node_action(&zero, [3; 32])
            .expect("removal has no actor")
            .payload
            .fields
            .is_empty()
    );
}

#[test]
fn mapped_memory_latency_executes_the_resolved_value_and_retains_its_identity() {
    for nanoseconds in [1, 4, i64::MAX as u64 / crucible::SIM_TICKS_PER_NS] {
        let action = mapped_memory_service_action(SignalValue::DurationNanos(nanoseconds));
        let encoded = encode_node_action(&action, [3; 32])
            .unwrap_or_else(|error| panic!("checked mapped service payload: {error}"));
        assert_eq!(encoded.payload.action_hash, action.id().bytes);
        assert_eq!(
            encoded.payload.fields[0],
            NodeFaultFieldV1::u64(1, nanoseconds * crucible::SIM_TICKS_PER_NS)
        );
        let bytes = encoded
            .payload
            .encode()
            .unwrap_or_else(|error| panic!("canonical portable service payload: {error}"));
        assert_eq!(NodeFaultPayloadV1::decode(&bytes), Ok(encoded.payload));
    }
}

#[test]
fn mapped_memory_latency_refuses_invalid_units_and_sim_time_overflow_before_encoding() {
    for value in [
        SignalValue::I64(1),
        SignalValue::DurationNanos(0),
        SignalValue::DurationNanos(i64::MAX as u64 / crucible::SIM_TICKS_PER_NS + 1),
        SignalValue::DurationNanos(u64::MAX),
    ] {
        let action = mapped_memory_service_action(value);
        assert!(matches!(
            encode_node_action(&action, [3; 32]),
            Err(NodeFaultPayloadError::FieldValue { tag: 1 })
        ));
    }
    let mut removal = mapped_memory_service_action(SignalValue::DurationNanos(u64::MAX));
    removal.kind = BindingActionKind::RemovePersistent;
    let encoded = encode_node_action(&removal, [3; 32])
        .unwrap_or_else(|error| panic!("removal has no latency effect: {error}"));
    assert!(encoded.payload.fields.is_empty());
}

#[test]
fn memory_bit_flip_rejects_authored_length_before_expanding_mask() {
    let limits = FaultResourceLimits::default();
    let requested = limits.memory_mutation_bytes_per_effect + 1;
    let specification = EffectSpecification::Node(
        serde_json::from_value(json!({
            "kind": "memory_mutation",
            "parameters": {
                "address_space": "guest_physical",
                "range": {"start": 4096, "length": requested},
                "mutation": {"kind": "bit_flip", "parameters": {"mask": "01"}},
                "atomicity": "all_or_nothing"
            }
        }))
        .unwrap_or_else(|error| panic!("large memory effect must decode: {error}")),
    );
    let descriptor = specification.kind().descriptor();
    let action = ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: object_id("binding-large-memory-bit-flip"),
        target: ResolvedFaultTarget::MemoryRange {
            node: object_id("node-a"),
            address_space: object_id("gpa"),
            guest_address: 4096,
            vcpu: None,
            length_bytes: requested,
        },
        phase: FaultPhase::Boundary,
        effect: Arc::new(
            EffectRequest::new(
                descriptor.semantic_version,
                descriptor.lifetimes[0],
                specification,
            )
            .unwrap_or_else(|error| panic!("large memory request must validate: {error}")),
        ),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash { bytes: [1; 32] },
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_ticks: 1,
            retired_instructions: Some(1),
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    };

    assert!(matches!(
        super::super::prepare_memory_action_payload(&action, limits),
        Err(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "memory_mutation_bytes_per_effect",
                current: 0,
                requested: observed,
                configured,
                hard,
            }
        )) if observed == requested
            && configured == limits.memory_mutation_bytes_per_effect
            && hard == FaultResourceLimits::compiled_maximum().memory_mutation_bytes_per_effect
    ));
}

fn test_target(kind: crucible::model::EffectKind) -> ResolvedFaultTarget {
    use crucible::model::EffectKind;
    let node = || object_id("node-a");
    match kind {
        EffectKind::NodeLifecycle | EffectKind::NodeHang | EffectKind::CpuService => {
            ResolvedFaultTarget::Node { node: node() }
        }
        EffectKind::CpuVcpuState
        | EffectKind::CpuInstructionTransform
        | EffectKind::CpuException => ResolvedFaultTarget::Vcpu {
            node: node(),
            vcpu: 0,
        },
        EffectKind::CpuRegisterTransform => ResolvedFaultTarget::Register {
            node: node(),
            vcpu: 0,
            architecture: object_id("x86-64"),
            register: object_id("rax"),
            first_bit: 0,
            bit_count: 8,
        },
        EffectKind::InterruptDisposition | EffectKind::InterruptStorm => {
            ResolvedFaultTarget::Interrupt {
                node: node(),
                controller: object_id("apic"),
                source: object_id("timer"),
                target_vcpu: 0,
                vector: 32,
            }
        }
        EffectKind::MemoryMutation => ResolvedFaultTarget::MemoryRange {
            node: node(),
            address_space: object_id("gpa"),
            guest_address: 4096,
            vcpu: None,
            length_bytes: 8,
        },
        EffectKind::MemoryAccessTransform
        | EffectKind::MemoryEccEvent
        | EffectKind::MemoryRegionState => ResolvedFaultTarget::MemoryRange {
            node: node(),
            address_space: object_id("gpa"),
            guest_address: 4096,
            vcpu: None,
            length_bytes: 64,
        },
        EffectKind::MemoryService => ResolvedFaultTarget::MemoryRange {
            node: node(),
            address_space: object_id("gva"),
            guest_address: 4096,
            vcpu: Some(0),
            length_bytes: 1,
        },
        EffectKind::ClockTransform | EffectKind::ClockSourceState => {
            ResolvedFaultTarget::ClockSource {
                node: node(),
                source: object_id("clock-main"),
            }
        }
        EffectKind::AcceleratorLifecycle
        | EffectKind::AcceleratorResultTransform
        | EffectKind::AcceleratorMemoryEvent
        | EffectKind::AcceleratorService => ResolvedFaultTarget::Accelerator {
            node: node(),
            device: object_id("accelerator-0"),
        },
        _ => panic!("unexpected typed node effect {kind:?}"),
    }
}
