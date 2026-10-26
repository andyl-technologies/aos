//! Checks retained failed activation DATA, never a genuine Source/claim issuer.
//!
//! This deliberately unreserved partial has no source/controller association.
//! Its independently allocated fields are real; it cannot become signable from
//! capacity facts or flags. Native evidence children have separate SDK controls.

use super::*;
use crate::node_scheduling::InputPayload;

fn partial() -> OriginalSourceRestorationActivationAttempt {
    OriginalSourceRestorationActivationAttempt {
        process: std::process::id(),
        thread: std::thread::current().id(),
        source: std::ptr::null(),
        controller: std::ptr::null(),
        binding: blake3::hash(b"failed data only"),
        reserved: false,
        order: ActivationOrder {
            started: [true, false],
            verified: [false; PHASES],
            failed: true,
        },
        phases: std::array::from_fn(|_| ActivationPhase {
            banks: std::array::from_fn(|_| Vec::with_capacity(113)),
            values: std::array::from_fn(|_| None),
            native_record: None,
            underlying: None,
        }),
        uploads: std::array::from_fn(|_| ActivationPhase {
            banks: std::array::from_fn(|_| Vec::with_capacity(127)),
            values: std::array::from_fn(|_| None),
            native_record: None,
            underlying: None,
        }),
        world_bodies: None,
        upload_order: upload::UploadOrder::new(),
    }
}

#[test]
fn restoration_capacity_activation_keeps_four_bank_groups_world_payloads_and_failed_json() {
    let mut owner = partial();
    let mut text = String::with_capacity(137);
    text.push_str("failed activation body");
    owner.phases[0].values[2] = Some(serde_json::Value::String(text));
    let reference = canonical::content_ref(b"world bytes", "application/json").unwrap();
    owner.world_bodies = Some(world_content::WorldUploadBodies {
        coordinator: InputPayload {
            reference: reference.clone(),
            bytes: Vec::with_capacity(149),
        },
        manifest: InputPayload {
            reference,
            bytes: Vec::with_capacity(157),
        },
    });
    let old_banks = owner
        .allocated_bank_bytes_with_error::<RuntimeError>()
        .unwrap();
    let mut independent = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    let world = owner.world_bodies.as_ref().unwrap();
    independent.observe(&world.coordinator).unwrap();
    independent.observe(&world.manifest).unwrap();
    let world_facts = independent.finish();

    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    owner.record_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(
        facts.vector_capacity_bytes,
        old_banks + world_facts.vector_capacity_bytes - 149 - 157
    );
    assert_eq!(facts.vector_banks, 16 + world_facts.vector_banks);
    assert_eq!(
        facts.string_capacity_bytes,
        137 + world_facts.string_capacity_bytes
    );
    assert_eq!(facts.capacity_records, 17 + world_facts.capacity_records);
    assert!(owner.order.failed && !owner.reserved);
    assert!(
        owner
            .order
            .authenticate_verified(PacketRestorationActivationPhase::Arm)
            .is_err()
    );
    assert!(owner.source.is_null() && owner.controller.is_null());
}

#[test]
fn restoration_capacity_activation_foreign_origin_precedes_rows_and_short_census_keeps_prefix() {
    let mut owner = partial();
    owner.process = owner.process.wrapping_add(1);
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    assert_eq!(
        owner.record_capacity_data(&mut census),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(census.finish().capacity_records, 0);
    owner.process = std::process::id();
    let prefix = String::with_capacity(167);
    let mut census = OriginalOwnerCapacityMetadataData::new(3, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        owner.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 3);
    assert_eq!(
        facts.vector_capacity_bytes,
        owner.phases[0].banks[..2]
            .iter()
            .map(Vec::capacity)
            .sum::<usize>()
    );
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
}
