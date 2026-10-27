//! Independent staged grammar, geometry and complete-byte correlation controls.

// crucible-lint: allow panic-shortcut -- Conformance controls panic on failed invariants.
#![allow(clippy::unwrap_used)]

use super::body::*;
use super::*;
use crate::whole_control::{
    WholeControlProfile,
    inventory::{WholeQueueRecord, WholeQueueRole},
    put_u64,
};

fn queue_plan() -> Vec<u8> {
    use super::queue_plan::QueueRole;

    let mut roles = Vec::new();
    for (role, index, header, entries) in [
        (WholeQueueRole::PacketDelivery, 4, 128, 4096),
        (WholeQueueRole::PacketPublication, 5, 256, 9216),
    ] {
        let role = QueueRole {
            role,
            ring_index: index,
            source_slot: 1,
            target_slot: 2,
            capacity: 1,
            generation: 7,
            header_offset: header,
            entries_offset: entries,
            transport_epoch: 0,
            producer_frontier: 9,
            node: "node/1",
            port: "packet",
            lane: "rx",
        };
        let mut body = vec![0; 80 + role.node.len() + role.port.len() + role.lane.len()];
        role.encode_into(&mut body).unwrap();
        roles.extend_from_slice(&body);
    }
    let mut body = vec![0; 128 + roles.len()];
    body[..8].copy_from_slice(b"CWHLQUE\0");
    put_u32(&mut body, 8, 2);
    let extent = body.len() as u32;
    put_u32(&mut body, 12, extent);
    body[16..48].fill(1);
    for (offset, value) in [
        (48, 7),
        (56, 8),
        (64, 9),
        (72, 16384),
        (88, 3),
        (96, 200),
        (104, 50),
    ] {
        put_u64(&mut body, offset, value);
    }
    put_u32(&mut body, 80, 2);
    put_u32(&mut body, 112, 50);
    put_u32(&mut body, 116, 1);
    body[128..].copy_from_slice(&roles);
    body
}

#[test]
fn queue_plan_matches_same_profile_and_refuses_foreign_overlapping_regions() {
    use super::{plan_ack::QueuePlanAcknowledgement, queue_plan::QueuePlan};

    let body = queue_plan();
    let plan = QueuePlan::decode(&body).unwrap();
    assert_eq!(plan.native_raw, 3);
    assert_eq!(plan.semantic_ps, 200);
    assert_eq!(plan.logical_offset_ps, 50);
    assert_eq!(plan.roles().count(), 2);
    let ack = QueuePlanAcknowledgement::for_plan(&plan, &profile()).unwrap();
    ack.validate_against(&plan, &profile()).unwrap();
    assert_eq!(
        QueuePlanAcknowledgement::decode(&ack.encode().unwrap()).unwrap(),
        ack
    );
    let mut changed_profile = profile();
    changed_profile.input_stage_limit += 1;
    assert!(ack.validate_against(&plan, &changed_profile).is_err());

    for extent in 0..body.len() {
        assert!(QueuePlan::decode(&body[..extent]).is_err());
    }
    for offset in [0, 8, 12, 84, 112, 116, 120, 128 + 6, 128 + 62] {
        let mut changed = body.clone();
        changed[offset] ^= 1;
        assert!(QueuePlan::decode(&changed).is_err());
    }
    let first_extent = read_u32(&body, 128) as usize;
    let mut changed = body.clone();
    put_u64(&mut changed, 128 + first_extent + 40, 4096);
    assert!(QueuePlan::decode(&changed).is_err());
    changed = body.clone();
    put_u64(&mut changed, 128 + 32, u64::MAX);
    assert!(QueuePlan::decode(&changed).is_err());
    changed = body;
    put_u64(&mut changed, 104, 49);
    assert!(QueuePlan::decode(&changed).is_err());
}

pub(crate) fn profile() -> StagedControlProfile {
    StagedControlProfile {
        compute: WholeControlProfile {
            scope: [1; 32],
            operation_capacity: 4,
            body_byte_limit: 65536,
            native_history_byte_limit: 4 * 1024 * 1024,
            provider_history_byte_limit: 4 * 1024 * 1024,
            administrative_read_attempt_limit: 128,
            administrative_read_byte_limit: 4 * 1024 * 1024,
            administrative_write_attempt_limit: 128,
            administrative_write_byte_limit: 4 * 1024 * 1024,
            deadline_monotonic_ns: 1,
            cpu_retirement_limit: 4,
            event_step_limit: 4,
            input_byte_limit: 3,
            input_record_limit: 1,
            output_byte_limit: 0,
            output_record_limit: 0,
        },
        input_stage_limit: 9,
        stage_body_byte_limit: 1024,
    }
}

pub(crate) fn launch_body(architecture: super::launch::LaunchArchitecture) -> Vec<u8> {
    use super::launch::{LaunchArchitecture, LaunchAsset, LaunchSelectionParts};

    let firmware_present = architecture == LaunchArchitecture::X86_64;
    let assets = [
        LaunchAsset {
            role: 1,
            present: true,
            inherited_fd: 7,
            byte_length: 8,
            sha256: [1; 32],
        },
        LaunchAsset {
            role: 2,
            present: false,
            inherited_fd: u32::MAX,
            byte_length: 0,
            sha256: [0; 32],
        },
        LaunchAsset {
            role: 3,
            present: firmware_present,
            inherited_fd: if firmware_present { 8 } else { u32::MAX },
            byte_length: if firmware_present { 8 } else { 0 },
            sha256: if firmware_present { [3; 32] } else { [0; 32] },
        },
    ];
    let (machine, cpu) = match architecture {
        LaunchArchitecture::X86_64 => ("microvm", "qemu64"),
        LaunchArchitecture::Arm64 => ("virt", "cortex-a72"),
    };
    let parts = LaunchSelectionParts {
        architecture,
        kernel_command_line: "console=ttyS0",
        ram_byte_length: 512 * 1024 * 1024,
        ram_backing_kind: 2,
        ram_inherited_fd: u32::MAX,
        ram_backing_offset: 0,
        assets,
    };
    let mut body =
        vec![0; 128 + machine.len() + cpu.len() + parts.kernel_command_line.len() + 3 * 64];
    parts.encode_into(&mut body).unwrap();
    body
}

fn input_inventory() -> Vec<u8> {
    let record = WholeQueueRecord {
        role: WholeQueueRole::PacketDelivery,
        ring_index: 0,
        source_slot: 1,
        target_slot: 2,
        frame_sequence: 3,
        ring_generation: 4,
        read_index: 5,
        write_index: 5,
        transport_epoch: 0,
        native_id: 0,
        time_ps: 50,
        microstep: 0,
        phase: 2,
        delivery_state: 0,
        ring_offset: 128,
        entries_offset: 256,
        capacity: 8,
        delivery_attempts: 0,
        last_attempt_icount: 0,
        frame_delivery_icount: 7,
        node: "node",
        port: "packet",
        lane: "rx",
        media_type: "application/octet-stream",
        common_envelope: b"complete-common-delivery",
        payload: b"abc",
    };
    let extent = 216
        + record.node.len()
        + record.port.len()
        + record.lane.len()
        + record.media_type.len()
        + record.common_envelope.len()
        + record.payload.len();
    let mut body = vec![0; 8 + extent];
    put_u32(&mut body, 0, 1);
    record.encode_into(&mut body[8..]).unwrap();
    body
}

fn stage(inventory: &[u8]) -> Vec<u8> {
    let parts = StageInventoryParts {
        scope: [1; 32],
        native_epoch: 7,
        stage_sequence: 2,
        stage_operation: "stage-2",
        batch: "batch-2",
        node: "node",
        cutoff_ps: 50,
        cutoff_microstep: 3,
        common_inventory_digest: [4; 32],
        common_batch: b"full-canonical-batch-and-original-evidence",
        queue_inventory: inventory,
    };
    let mut body = vec![
        0;
        128 + parts.stage_operation.len()
            + parts.batch.len()
            + parts.node.len()
            + parts.common_batch.len()
            + inventory.len()
    ];
    parts.encode_into(&mut body).unwrap();
    body
}

fn receipt(stage: &StageInventory<'_>) -> StageReceipt {
    StageReceipt {
        scope: stage.scope,
        native_epoch: stage.native_epoch,
        stage_sequence: stage.stage_sequence,
        stage_body_digest: stage.digest(),
        common_inventory_digest: stage.common_inventory_digest,
        queue_plan_digest: [5; 32],
        accepted_records: u64::from(stage.queue_inventory.record_count()),
        accepted_payload_bytes: stage.payload_byte_count().unwrap(),
        cutoff_ps: stage.cutoff_ps,
        cutoff_microstep: stage.cutoff_microstep,
        reservation_digest: [6; 32],
        stage_cut: stage.stage_sequence,
    }
}

#[test]
fn stages_and_compute_have_distinct_nonrenewing_constructor_geometry() {
    let profile = profile();
    let encoded = profile.encode().unwrap();
    assert_eq!(&encoded[8..12], &2u32.to_be_bytes());
    assert_eq!(&encoded[48..52], &4u32.to_be_bytes());
    assert_eq!(&encoded[160..164], &9u32.to_be_bytes());
    assert_eq!(&encoded[164..168], &1024u32.to_be_bytes());
    assert_eq!(StagedControlProfile::decode(&encoded).unwrap(), profile);
    assert!(WholeControlProfile::decode(&encoded).is_err());
    assert!(StagedControlProfile::decode(&profile.compute.encode().unwrap()).is_err());

    let minimum = profile.minimum_wire_history_bytes().unwrap();
    let mut refused = profile.clone();
    refused.compute.native_history_byte_limit = minimum - 1;
    assert_eq!(refused.validate(), Err(WholeControlError::Budget));
    refused = profile;
    refused.input_stage_limit = 0;
    assert_eq!(refused.validate(), Err(WholeControlError::Budget));
}

#[test]
fn constructor_selection_retains_all_bytes_and_refuses_changed_role_names() {
    use super::launch::{LaunchArchitecture, LaunchSelection};
    use super::selection::{LogicalQueueRole, WholeConstructorSelection};

    let roles = [LogicalQueueRole {
        role: WholeQueueRole::PacketDelivery,
        node: "node/1",
        port: "packet",
        lane: "rx",
    }];
    let launch_body = launch_body(LaunchArchitecture::X86_64);
    let launch = LaunchSelection::decode(&launch_body).unwrap();
    let roles_offset = 200 + launch_body.len();
    let selected = WholeConstructorSelection::new(profile(), &launch, &roles).unwrap();
    assert_eq!(selected.roles().collect::<Vec<_>>(), roles);
    assert_eq!(
        WholeConstructorSelection::from_body(selected.body().into()).unwrap(),
        selected
    );
    assert!(
        WholeConstructorSelection::new(profile(), &launch, &[roles[0].clone(), roles[0].clone()])
            .is_err()
    );
    assert!(WholeConstructorSelection::new(profile(), &launch, &[]).is_err());
    for extent in 0..selected.body().len() {
        assert!(WholeConstructorSelection::from_body(selected.body()[..extent].into()).is_err());
    }
    for offset in [
        0,
        8,
        12,
        188,
        192,
        196,
        roles_offset + 2,
        roles_offset + 10,
        roles_offset + 12,
    ] {
        let mut body = selected.body().to_vec();
        body[offset] = 0xff;
        assert!(WholeConstructorSelection::from_body(body.into_boxed_slice()).is_err());
    }
}

#[test]
fn both_explicit_linux_launch_profiles_retain_full_provenance_and_refuse_changes() {
    use super::launch::{LaunchArchitecture, LaunchSelection};

    // These declared provenance fixtures test portable grammar only. Actual
    // source enrollment authenticates the retained original image/RAM owners.
    for architecture in [LaunchArchitecture::X86_64, LaunchArchitecture::Arm64] {
        let body = launch_body(architecture);
        let launch = LaunchSelection::decode(&body).unwrap();
        assert_eq!(launch.architecture, architecture);
        assert_eq!(launch.ram_byte_length, 512 * 1024 * 1024);
        assert_eq!(launch.kernel_command_line, "console=ttyS0");
        assert_eq!(launch.assets[0].inherited_fd, 7);
        for extent in 0..body.len() {
            assert!(LaunchSelection::decode(&body[..extent]).is_err());
        }
        for offset in [0, 8, 12, 20, 24, 28, 48, 52, 64, 68, 72, 120] {
            let mut changed = body.clone();
            changed[offset] ^= 1;
            assert!(LaunchSelection::decode(&changed).is_err());
        }
        let mut changed = body.clone();
        put_u64(&mut changed, 40, 3 * 1024 * 1024 * 1024 + 4096);
        assert!(LaunchSelection::decode(&changed).is_err());
        changed = body;
        put_u32(&mut changed, 104, 1);
        put_u32(&mut changed, 108, 7);
        assert!(LaunchSelection::decode(&changed).is_err());
    }
}

#[test]
fn microvm_launch_requires_immutable_complete_kernel_command_line() {
    use super::launch::{LaunchArchitecture, LaunchSelection};

    let body = launch_body(LaunchArchitecture::X86_64);
    assert_eq!(u32::from_be_bytes(body[28..32].try_into().unwrap()), 33);
    assert!(LaunchSelection::decode(&body).is_ok());

    // microvm otherwise appends device arguments during reset after the
    // sealed command-line commitment has been authenticated.
    let mut automatic_command_line = body;
    put_u32(&mut automatic_command_line, 28, 1);
    assert!(LaunchSelection::decode(&automatic_command_line).is_err());
}

#[test]
fn staged_grammar_refuses_legacy_reserved_unknown_and_oversized_frames() {
    let profile = profile();
    let header = encode_frame_header(StagedFrameKind::StageInventory, 512, &profile).unwrap();
    assert_eq!(
        decode_frame_header(&header, &profile).unwrap(),
        (StagedFrameKind::StageInventory, 512)
    );
    assert!(encode_frame_header(StagedFrameKind::StageInventory, 1025, &profile).is_err());
    assert!(encode_frame_header(StagedFrameKind::StageReceipt, 255, &profile).is_err());
    for offset in [0, 8, 12, 20] {
        let mut changed = header;
        changed[offset] ^= 0xff;
        assert!(decode_frame_header(&changed, &profile).is_err());
    }
}

#[test]
fn staged_constructor_reserves_a_complete_empty_result_inventory() {
    let mut profile = profile();
    profile.compute.body_byte_limit = 343;
    assert!(profile.validate().is_err());

    profile.compute.body_byte_limit = 344;
    assert!(profile.validate().is_ok());

    // The original independently selected edition-one validator is preserved.
    profile.compute.body_byte_limit = 337;
    assert!(profile.compute.validate().is_ok());
}

#[test]
fn complete_stage_preserves_original_evidence_and_actual_payload_counts() {
    let inventory = input_inventory();
    let body = stage(&inventory);
    let original = StageInventory::decode(&body).unwrap();
    assert_eq!(original.body(), body);
    assert_eq!(original.queue_inventory.record_count(), 1);
    assert_eq!(original.payload_byte_count().unwrap(), 3);
    assert!(original.body().len() as u64 > original.payload_byte_count().unwrap());

    for extent in 0..body.len() {
        assert!(StageInventory::decode(&body[..extent]).is_err());
    }
    for offset in [0, 4, 62, 80, 82, 84] {
        let mut changed = body.clone();
        changed[offset] ^= 1;
        assert!(StageInventory::decode(&changed).is_err());
    }
    let mut changed = body;
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        StageInventory::decode(&changed).err(),
        Some(WholeControlError::Correlation)
    );
}

#[test]
fn receipt_and_commit_correlate_complete_original_stage_and_native_cut() {
    let body = stage(&input_inventory());
    let original = StageInventory::decode(&body).unwrap();
    let receipt = receipt(&original);
    let encoded = receipt.encode().unwrap();
    assert_eq!(StageReceipt::decode(&encoded).unwrap(), receipt);
    let commit = StageCommit::for_receipt(&original, &receipt, [5; 32]).unwrap();
    assert_eq!(
        StageCommit::decode(&commit.encode().unwrap()).unwrap(),
        commit
    );

    let mut wrong = receipt.clone();
    wrong.accepted_payload_bytes = body.len() as u64;
    assert_eq!(
        wrong.validate_against(&original, [5; 32]),
        Err(WholeControlError::Correlation)
    );
    wrong = receipt.clone();
    wrong.reservation_digest = [0; 32];
    assert!(StageCommit::for_receipt(&original, &wrong, [5; 32]).is_err());
    assert!(StageCommit::for_receipt(&original, &receipt, [8; 32]).is_err());

    for offset in [0, 4, 184, 188, 232, 255] {
        let mut changed = encoded;
        changed[offset] ^= 1;
        assert!(StageReceipt::decode(&changed).is_err());
    }
}

#[test]
fn committed_reference_ranges_refuse_overflow_without_copying_payload() {
    let mut body = [0; 72];
    put_u32(&mut body, 0, 1);
    put_u64(&mut body, 8, 2);
    put_u64(&mut body, 16, 2);
    body[24..56].fill(3);
    put_u32(&mut body, 56, 4);
    put_u32(&mut body, 60, 5);
    let reference = StageReferences::decode(&body)
        .unwrap()
        .records()
        .next()
        .unwrap();
    assert_eq!(reference.first_record, 4);
    assert_eq!(reference.record_count, 5);

    put_u32(&mut body, 56, u32::MAX);
    assert!(StageReferences::decode(&body).is_err());
    put_u32(&mut body, 56, 4);
    body[64] = 1;
    assert!(StageReferences::decode(&body).is_err());
    body[64] = 0;
    put_u32(&mut body, 0, u32::MAX);
    assert!(StageReferences::decode(&body).is_err());
    assert!(StageReferences::decode(&[0; 8]).is_ok());
}

#[test]
fn staged_compute_does_not_inherit_legacy_encoded_input_record_ceiling() {
    use crate::whole_control::{
        body::{WholeAcknowledgement, WholeRequest, WholeResult, whole_staged_request_digest},
        domain_digest,
    };

    let original_request = include_bytes!("../testdata/native-zero-request.bin");
    let original_result = include_bytes!("../testdata/native-zero-result.bin");
    let mut references = [0; 72];
    put_u32(&mut references, 0, 1);
    put_u64(&mut references, 8, 2);
    put_u64(&mut references, 16, 2);
    references[24..56].fill(3);
    put_u32(&mut references, 60, 100);
    let mut request = WholeRequest::decode(original_request).unwrap();
    request.input_inventory = &references;
    request.quota.input_records = 100;
    let mut request_body = [0; 256 + 72];
    request.encode_staged_into(&mut request_body).unwrap();
    assert_eq!(WholeRequest::decode_staged(&request_body).unwrap(), request);
    assert!(WholeRequest::decode(&request_body).is_err());

    let mut result = WholeResult::decode(original_result).unwrap();
    result.request_digest = whole_staged_request_digest(&request_body).unwrap();
    result.input_inventory_digest =
        domain_digest(b"crucible.qemu.whole.input-inventory.v1\0", &references);
    let mut result_body = [0; 344];
    result.encode_into(&mut result_body).unwrap();
    let ack = WholeAcknowledgement::for_complete_staged(&request_body, &result_body).unwrap();
    ack.validate_against_staged(&request_body, &result_body)
        .unwrap();
    assert!(WholeAcknowledgement::for_complete(&request_body, &result_body).is_err());

    let mut changed = request_body;
    changed[320] = 1;
    assert!(WholeRequest::decode_staged(&changed).is_err());
    assert!(ack.validate_against_staged(&changed, &result_body).is_err());
}

#[test]
fn actual_native_stage_plan_receipt_commit_and_references_match_complete_bytes() {
    use super::queue_plan::QueuePlan;

    // Actual production C codecs emitted these complete vectors. Physical
    // native/producer owners and common authority were explicitly modeled in
    // the component control; these fixtures confer no installed source Ready.
    let plan_body = include_bytes!("../testdata/native-queue-plan.bin");
    let stage_body = include_bytes!("../testdata/native-stage.bin");
    let receipt_body = include_bytes!("../testdata/native-stage-receipt.bin");
    let commit_body = include_bytes!("../testdata/native-stage-commit.bin");
    let consumed_body = include_bytes!("../testdata/native-stage-consumed-commit.bin");
    let reference_body = include_bytes!("../testdata/native-stage-references.bin");
    let host_digest = include_bytes!("../testdata/host-stage-record-cnp-digest.bin");
    let plan = QueuePlan::decode(plan_body).unwrap();
    let stage = StageInventory::decode(stage_body).unwrap();
    let inventory_extent = read_u32(stage_body, 120) as usize;
    let inventory_body = &stage_body[stage_body.len() - inventory_extent..];
    let receipt = StageReceipt::decode(receipt_body).unwrap();
    receipt.validate_against(&stage, plan.digest()).unwrap();
    assert_eq!(receipt.accepted_records, 1);
    assert_eq!(receipt.accepted_payload_bytes, 8);
    assert_eq!(
        stage.queue_inventory.records().next().unwrap().payload,
        b"pppppppp"
    );
    assert_eq!(&inventory_body[8 + 128..8 + 160], host_digest);
    assert_eq!(&receipt.encode().unwrap(), receipt_body);
    let commit = StageCommit::for_receipt(&stage, &receipt, plan.digest()).unwrap();
    assert_eq!(&commit.encode().unwrap(), commit_body);
    assert_eq!(commit_body, consumed_body);
    assert_eq!(StageCommit::decode(consumed_body).unwrap(), commit);
    let reference = StageReferences::decode(reference_body)
        .unwrap()
        .records()
        .next()
        .unwrap();
    assert_eq!(reference.stage_body_digest, stage.digest());
    assert_eq!(reference.stage_sequence, stage.stage_sequence);
    assert_eq!(reference.stage_cut, receipt.stage_cut);

    let parts = StageInventoryParts {
        scope: stage.scope,
        native_epoch: stage.native_epoch,
        stage_sequence: stage.stage_sequence,
        stage_operation: stage.stage_operation,
        batch: stage.batch,
        node: stage.node,
        cutoff_ps: stage.cutoff_ps,
        cutoff_microstep: stage.cutoff_microstep,
        common_inventory_digest: stage.common_inventory_digest,
        common_batch: stage.common_batch,
        queue_inventory: inventory_body,
    };
    let mut encoded = vec![0; stage_body.len()];
    parts.encode_into(&mut encoded).unwrap();
    assert_eq!(&encoded, stage_body);
}

#[test]
fn native_launch2_bytes_match_portable_encoder_and_complete_public_setup() {
    use super::launch2::{LaunchSelection2, LaunchSelection2Parts};
    use crate::plugin_setup_plan::PluginSetupPlan;

    let native = include_bytes!("../testdata/native-launch2.bin");
    let launch = LaunchSelection2::decode(native).unwrap();
    let parts = LaunchSelection2Parts {
        architecture: launch.architecture,
        kernel_command_line: launch.kernel_command_line,
        ram_byte_length: launch.ram_byte_length,
        ram_backing_kind: launch.ram_backing_kind,
        ram_inherited_fd: launch.ram_inherited_fd,
        ram_backing_offset: launch.ram_backing_offset,
        run_seed: launch.run_seed,
        rr_switch_quantum: launch.rr_switch_quantum,
        assets: launch.assets,
    };
    let mut encoded = vec![0; parts.encoded_len().unwrap()];
    parts.encode_into(&mut encoded).unwrap();
    assert_eq!(encoded, native);

    // The independent native emitter's initial model omitted nested public
    // headers. The actual host-typed complete composite preserves those bytes.
    assert!(
        PluginSetupPlan::decode(include_bytes!(
            "../testdata/native-setup-launch2-partial.bin"
        ))
        .is_err()
    );
    let complete = include_bytes!("../testdata/host-setup-launch2-complete.bin");
    let setup = PluginSetupPlan::decode(complete).unwrap();
    assert_eq!(setup.encode().unwrap(), complete);
    let (_, _, selection) = setup.into_parts();
    let selection = selection.unwrap();
    assert_eq!(selection.launch_version(), 2);
    assert_eq!(selection.launch2().unwrap().body(), native);
    assert!(selection.launch().is_err());
}

#[test]
fn explicit_launch2_refuses_changed_arguments_and_unreserved_ready_credit() {
    use super::launch2::LaunchSelection2;
    use crate::plugin_setup_plan::PluginSetupPlan;

    let original = include_bytes!("../testdata/native-launch2.bin");
    for offset in [
        28, 68, 104, 120, 136, 144, 148, 152, 156, 160, 164, 168, 184, 188, 192, 200, 204, 255,
    ] {
        let mut changed = original.to_vec();
        changed[offset] ^= 0x80;
        assert!(
            LaunchSelection2::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
    let mut changed = original.to_vec();
    put_u64(&mut changed, 136, 0);
    assert!(LaunchSelection2::decode(&changed).is_err());

    let setup = PluginSetupPlan::decode(include_bytes!(
        "../testdata/host-setup-launch2-complete.bin"
    ))
    .unwrap();
    let (_, _, selection) = setup.into_parts();
    let selection = selection.unwrap();
    let mut profile = selection.profile().clone();
    profile.compute.administrative_read_attempt_limit = 2
        * (2 * u64::from(profile.compute.operation_capacity)
            + 2 * u64::from(profile.input_stage_limit)
            + 1)
        + 4;
    assert!(profile.validate().is_ok());
    assert_eq!(
        profile.validate_ready_exchange_capacity(),
        Err(WholeControlError::Budget)
    );
}
