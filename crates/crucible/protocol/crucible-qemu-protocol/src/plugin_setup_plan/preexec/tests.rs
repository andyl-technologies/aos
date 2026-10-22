//! Checks selected framing and original relations without granting any purpose.

use super::*;

mod family;
mod publisher;
mod quantum;

use crate::selectable_catalog_plan::{SelectablePlanContinuation, SelectablePlanLimits};

fn selected() -> Vec<u8> {
    let app = AppRandomBranchPlan::default().encode();
    let selectable = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 1, 1).unwrap(),
        Vec::new(),
        SelectablePlanContinuation::cold(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let startup = StartupOperation::new(StartupOperationFields {
        cap_id: [7; 32],
        operation_id: 2,
        original_start_ns: 10,
        absolute_end_ns: 20,
        poll_ns: 1,
        process_generation: 3,
        cancellation_device: 1,
        cancellation_inode: 2,
        cancellation_event_id: 3,
        cancellation_descriptor: 10,
        original_total_metadata_bytes: 4096,
    })
    .unwrap()
    .encode();
    let mut purpose = [0; PURPOSE];
    purpose[..8].copy_from_slice(b"CRUCPUR8");
    purpose[8..12].copy_from_slice(&8_u32.to_be_bytes());
    purpose[12..16].copy_from_slice(&(PURPOSE as u32).to_be_bytes());
    purpose[16..24].copy_from_slice(&4096_u64.to_be_bytes());
    purpose[96..104].copy_from_slice(&3_u64.to_be_bytes());
    purpose[184..216].copy_from_slice(&[7; 32]);
    for (offset, value) in [
        (512, 1_u64),
        (520, 2),
        (528, 100_000),
        (536, 100_000),
        (544, 64),
        (552, 3001),
        (560, 3001),
    ] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    for (offset, value) in [
        (24, 2048_u64),
        (72, 512),
        (80, 1),
        (88, 9),
        (104, 1024),
        (112, 256),
        (120, 1),
        (128, 32),
        (136, 1),
        (472, 1024),
        (480, 2),
    ] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    purpose[744..1000].copy_from_slice(&family::FROZEN_FAMILY);
    // Fixed syntax-only standing observation; no kernel owner is issued.
    for (offset, value) in [(1000, 1_u64), (1008, 29), (1016, 1504)] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    let mut standing = [0_u8; 1496];
    standing[..8].copy_from_slice(b"CRUCSRV4");
    standing[8..12].copy_from_slice(&4_u32.to_be_bytes());
    standing[12..16].copy_from_slice(&1496_u32.to_be_bytes());
    standing[16..48].copy_from_slice(&purpose[184..216]);
    standing[88..120].copy_from_slice(&purpose[184..216]);
    standing[120..152].copy_from_slice(&purpose[816..848]);
    standing[200..232].copy_from_slice(&purpose[144..176]);
    standing[72..80].copy_from_slice(&purpose[88..96]);
    standing[80..88].copy_from_slice(&purpose[96..104]);
    for (offset, value) in [(48, 1_u64), (160, 1), (168, 2), (176, 1)] {
        standing[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    // Independently authored schema11 literal roster: fourteen 1ns polls,
    // absent progress and 500us total bounds, with canonical zero padding.
    standing[192..196].copy_from_slice(&256_u32.to_be_bytes());
    standing[196..200].copy_from_slice(&1_u32.to_be_bytes());
    standing[232..236].copy_from_slice(&11_u32.to_be_bytes());
    for index in 0..14 {
        let offset = 236 + index * 18;
        standing[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
        standing[offset + 9] = 1;
        standing[offset + 10..offset + 18].copy_from_slice(&500_000_u64.to_be_bytes());
    }
    purpose[1024..2520].copy_from_slice(&standing);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CRUCSUP8");
    for field in [
        8,
        HEADER as u32,
        (HEADER + app.len() + selectable.len() + startup.len() + purpose.len()) as u32,
        app.len() as u32,
        selectable.len() as u32,
        0,
        STARTUP_OPERATION_BYTES as u32,
        PURPOSE as u32,
    ] {
        bytes.extend_from_slice(&field.to_be_bytes());
    }
    bytes.extend_from_slice(&app);
    bytes.extend_from_slice(&selectable);
    bytes.extend_from_slice(&startup);
    bytes.extend_from_slice(&purpose);
    bytes
}

#[test]
fn selected_parts_decode_only_matching_outer8_with_original_binding() {
    let bytes = selected();
    let (app, selectable) = decode_parts(&bytes).unwrap();
    assert_eq!(app, AppRandomBranchPlan::default());
    assert_eq!(
        selectable.encode().unwrap().len(),
        read_u32(&bytes, 24).unwrap() as usize
    );
    assert!(PluginSetupPlan::decode(&bytes).is_err());
}

#[test]
fn selected_rejects_superseded_edition_and_changed_purpose_extent() {
    for (magic, version, header) in [(b"CRUCSUP3", 3_u32, 36_u32), (b"CRUCSUP7", 7, 40)] {
        let mut bytes = selected();
        bytes[..8].copy_from_slice(magic);
        bytes[8..12].copy_from_slice(&version.to_be_bytes());
        bytes[12..16].copy_from_slice(&header.to_be_bytes());
        assert!(decode_parts(&bytes).is_err());
    }
    let mut bytes = selected();
    bytes[36..40].copy_from_slice(&496_u32.to_be_bytes());
    assert!(decode_parts(&bytes).is_err());
}

#[test]
fn selected_refuses_wrong_original_total_generation_and_capability() {
    for offset in [16, 96, 184] {
        let mut bytes = selected();
        let purpose = bytes.len() - PURPOSE;
        bytes[purpose + offset] ^= 1;
        assert!(decode_parts(&bytes).is_err());
    }
}

#[test]
fn selected_rejects_overflowing_lengths_and_trailing_data() {
    let mut bytes = selected();
    bytes[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_parts(&bytes).is_err());
    let mut bytes = selected();
    bytes.push(0);
    let len = bytes.len() as u32;
    bytes[16..20].copy_from_slice(&len.to_be_bytes());
    assert!(decode_parts(&bytes).is_err());
}

fn issued_fixture_plan() -> (PluginSetupPlan, [u8; PURPOSE]) {
    let bytes = selected();
    let (app, catalog) = decode_parts(&bytes).unwrap();
    let purpose_start = bytes.len() - PURPOSE;
    let startup =
        StartupOperation::decode(&bytes[purpose_start - STARTUP_OPERATION_BYTES..purpose_start])
            .unwrap();
    let purpose = bytes[purpose_start..].try_into().unwrap();
    (
        PluginSetupPlan::new(app, catalog).with_startup_operation(startup),
        purpose,
    )
}

#[test]
fn current_encoder_matches_independently_constructed_framing() {
    let expected = selected();
    let (plan, purpose) = issued_fixture_plan();
    let encoded = plan.encode_preexec(&purpose, None).unwrap();

    assert_eq!(encoded, expected);
    assert_eq!(read_u32(&encoded, 12).unwrap(), 40);
    assert_eq!(
        read_u32(&encoded, 36).unwrap(),
        PROCESS_PURPOSE_BYTES as u32
    );
    assert_eq!(decode_parts(&encoded).unwrap(), plan.into_parts());
}

#[test]
fn current_encoder_refuses_mismatched_material_before_emitting_a_carrier() {
    let (plan, purpose) = issued_fixture_plan();
    for offset in [8, 12, 16, 96, 184, 536] {
        let mut changed = purpose;
        changed[offset] ^= 1;
        assert!(plan.encode_preexec(&changed, None).is_err());
    }
    let (app, catalog) = plan.into_parts();
    assert!(
        PluginSetupPlan::new(app, catalog)
            .encode_preexec(&purpose, None)
            .is_err()
    );
}

#[test]
fn current_workspace_codec_rejects_the_superseded_record_and_changed_binding() {
    let (plan, purpose) = issued_fixture_plan();
    let mut workspace = [0; DEVICE_DIGEST_PURPOSE_BYTES];
    workspace[..8].copy_from_slice(b"CRUCWSP2");
    workspace[8..12].copy_from_slice(&2_u32.to_be_bytes());
    workspace[12..16].copy_from_slice(&1_u32.to_be_bytes());
    workspace[16..48].copy_from_slice(&purpose[184..216]);
    workspace[48..56].copy_from_slice(&purpose[16..24]);
    workspace[64..72].copy_from_slice(&crate::DEVICE_DIGEST_WORKSPACE_BYTES.to_be_bytes());
    workspace[72..80].copy_from_slice(&purpose[96..104]);
    workspace[80..88].copy_from_slice(&purpose[88..96]);
    workspace[120..128].copy_from_slice(&crate::DEVICE_DIGEST_WORKSPACE_BYTES.to_be_bytes());
    let encoded = plan.encode_preexec(&purpose, Some(&workspace)).unwrap();
    assert_eq!(read_u32(&encoded, 28).unwrap(), 128);
    assert_eq!(decode_parts(&encoded).unwrap(), plan.clone().into_parts());

    for offset in [8, 16, 48, 64, 72, 80, 112, 120] {
        let mut changed = workspace;
        changed[offset] ^= 1;
        assert!(plan.encode_preexec(&purpose, Some(&changed)).is_err());
    }
    workspace[..8].copy_from_slice(b"CRUCWSP1");
    workspace[8..12].copy_from_slice(&1_u32.to_be_bytes());
    assert!(plan.encode_preexec(&purpose, Some(&workspace)).is_err());
}

#[test]
fn current_carrier_requires_issued_family_parent_and_aggregate_envelope() {
    let (plan, purpose) = issued_fixture_plan();
    for offset in [520, 528, 544, 552, 560] {
        let mut changed = purpose;
        changed[offset..offset + 8].fill(0);
        assert!(plan.encode_preexec(&changed, None).is_err());
    }
    let mut previous = selected();
    let purpose_start = previous.len() - PURPOSE;
    previous[purpose_start..purpose_start + 8].copy_from_slice(b"CRUCPUR3");
    previous[purpose_start + 8..purpose_start + 12].copy_from_slice(&3_u32.to_be_bytes());
    assert!(decode_parts(&previous).is_err());
}

#[test]
fn current_carrier_refuses_out_of_range_assigned_credentials() {
    let (plan, purpose) = issued_fixture_plan();
    for offset in [552, 560] {
        let mut changed = purpose;
        changed[offset..offset + 8].copy_from_slice(&(u64::from(u32::MAX) + 1).to_be_bytes());
        assert!(plan.encode_preexec(&changed, None).is_err());
    }
    let mut short = selected();
    short.truncate(short.len() - 16);
    let total = short.len() as u32;
    short[16..20].copy_from_slice(&total.to_be_bytes());
    short[36..40].copy_from_slice(&552_u32.to_be_bytes());
    assert!(decode_parts(&short).is_err());
}

fn present_ram_endpoint(purpose: &mut [u8; PURPOSE]) {
    // These fixture bytes exercise syntax only; they have no physical issuer.
    purpose[576..584].copy_from_slice(&11_u64.to_be_bytes());
    purpose[584..592].copy_from_slice(&13_u64.to_be_bytes());
    purpose[592..624].fill(17);
    purpose[624..656].fill(19);
    purpose[656..688].fill(23);
    purpose[688..720].fill(29);
    purpose[720..728].copy_from_slice(&3_u64.to_be_bytes());
    purpose[728..736].copy_from_slice(&31_u64.to_be_bytes());
}

#[test]
fn current_carrier_supports_absent_ram_and_complete_endpoint_binding() {
    let (plan, mut purpose) = issued_fixture_plan();
    assert_eq!(&purpose[568..744], &[0; 176]);
    let resident = plan.encode_preexec(&purpose, None).unwrap();
    assert_eq!(decode_parts(&resident).unwrap(), plan.clone().into_parts());

    present_ram_endpoint(&mut purpose);
    for retained_template in [0, 1] {
        purpose[736] = retained_template;
        let encoded = plan.encode_preexec(&purpose, None).unwrap();
        assert_eq!(decode_parts(&encoded).unwrap(), plan.clone().into_parts());
        let purpose_start = encoded.len() - PURPOSE;
        assert_eq!(
            &encoded[purpose_start + 568..purpose_start + 744],
            &purpose[568..744]
        );
    }
}

#[test]
fn current_carrier_refuses_partial_endpoint_binding_and_changed_owner_generation() {
    let (plan, mut purpose) = issued_fixture_plan();
    purpose[568] = 1;
    assert!(plan.encode_preexec(&purpose, None).is_err());

    present_ram_endpoint(&mut purpose);
    for (start, end) in [
        (576, 584),
        (584, 592),
        (592, 624),
        (624, 656),
        (656, 688),
        (688, 720),
        (720, 728),
        (728, 736),
    ] {
        let mut changed = purpose;
        changed[start..end].fill(0);
        assert!(plan.encode_preexec(&changed, None).is_err());
    }
    let mut changed = purpose;
    changed[720..728].copy_from_slice(&4_u64.to_be_bytes());
    assert!(plan.encode_preexec(&changed, None).is_err());
    for (offset, value) in [(736, 2), (737, 1), (743, 1)] {
        let mut changed = purpose;
        changed[offset] = value;
        assert!(plan.encode_preexec(&changed, None).is_err());
    }
}

#[test]
fn current_carrier_rejects_prior_purpose_before_decoding_plans() {
    let mut previous = selected();
    let purpose_start = previous.len() - PURPOSE;
    previous.truncate(purpose_start + 568);
    previous[purpose_start..purpose_start + 8].copy_from_slice(b"CRUCPUR4");
    previous[purpose_start + 8..purpose_start + 12].copy_from_slice(&4_u32.to_be_bytes());
    previous[purpose_start + 12..purpose_start + 16].copy_from_slice(&568_u32.to_be_bytes());
    previous[36..40].copy_from_slice(&568_u32.to_be_bytes());
    let total = previous.len() as u32;
    previous[16..20].copy_from_slice(&total.to_be_bytes());

    assert!(decode_parts(&previous).is_err());
}
