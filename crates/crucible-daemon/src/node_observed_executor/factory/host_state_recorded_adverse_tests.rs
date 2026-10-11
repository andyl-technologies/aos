//! Checks production continuation refusals against genuine captured originals.
//!
//! Altered native/coordinator values are inert data-only counterfactuals. The
//! missing and corrupt archive cases exercise the real persistent authority;
//! they never issue replacement captures or import caller-signed populations.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Exact refusal assertions deliberately fail this captured-original fixture.
// crucible-lint: allow rust-allow -- Assertions inspect genuine captured originals and intentionally panic on changed custody or refusal predicates.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible::node_adapters::{HostModelResources, validate_host_continuation};
use crucible::node_contract::RuntimeSnapshot;
use crucible_node_contract::ContentRef;
use std::io::{Read, Seek, SeekFrom, Write};

pub(super) fn verify_original_data_refusals(
    record: &HostArchiveRecord,
    source: &RuntimeSnapshot,
    graph: &AdmittedGraph,
    factory: &InstalledHostStateFactory,
    limits: crucible::node_state::StateLimits,
) {
    let owner = &record.manifest().owners[0];
    let native = record
        .content_bytes(owner.state_ref.as_ref().unwrap(), 16 * 1024 * 1024)
        .unwrap();
    let original: serde_json::Value = serde_json::from_slice(&native).unwrap();
    let descriptor = graph.descriptor(&id("disk")).unwrap();
    let binding = graph.binding(&id("disk")).unwrap();
    let inspect = |bytes: &[u8]| {
        validate_host_continuation(
            bytes,
            source,
            descriptor,
            binding,
            HostModelResources::default(),
        )
    };
    let inventory = inspect(&native).unwrap();
    assert_eq!(original["schema_version"], 5);
    assert_eq!(inventory.recorded_input.as_ref().unwrap().1, U64::new(1));
    assert!(inspect(b"{malformed original").is_err());

    for edition in [1, 2, 3, 4, 6] {
        let mut changed = original.clone();
        changed["schema_version"] = serde_json::json!(edition);
        assert!(
            inspect(&serde_json::to_vec(&changed).unwrap())
                .err()
                .unwrap()
                .reason
                .contains("edition")
        );
    }
    let mut foreign_format = binding.clone();
    for format in &mut foreign_format.compatibility.implementation.formats {
        if format.id.as_str() == "host/native-recorded-block-v1" {
            format.id = id("host/native-continuation-v1");
        }
    }
    assert!(
        validate_host_continuation(
            &native,
            source,
            descriptor,
            &foreign_format,
            HostModelResources::default(),
        )
        .err()
        .unwrap()
        .reason
        .contains("edition")
    );
    for edition in [1, 3, 4, 6] {
        let mut foreign_runtime = source.clone();
        foreign_runtime.schema_version = edition;
        assert!(
            validate_host_continuation(
                &native,
                &foreign_runtime,
                descriptor,
                binding,
                HostModelResources::default(),
            )
            .err()
            .unwrap()
            .reason
            .contains("edition")
        );
    }

    // Reopen the real signed closure and call the installed, allocation-free
    // native source reader. A different native model cannot borrow its cursor.
    let verified = record
        .admit(graph, requirements(), factory, limits)
        .unwrap();
    let mut wrong_model = original.clone();
    wrong_model["native"] =
        serde_json::json!(host_clock_initial_bytes(source.capture_cut.time_ps.get()));
    assert!(
        factory
            .authenticate_source(
                graph,
                &id("disk"),
                &serde_json::to_vec(&wrong_model).unwrap(),
                source,
                verified.content(),
            )
            .is_err()
    );
    assert!(
        factory
            .authenticate_source(graph, &id("disk"), &native, source, verified.content())
            .is_ok()
    );

    for (name, pointer, changed, reason) in [
        (
            "cursor",
            "/recorded_ingress/consumed",
            serde_json::json!("0"),
            "activation history",
        ),
        (
            "owner",
            "/recorded_ingress/histories/0/activation/owners/0/owner",
            serde_json::json!("foreign-owner"),
            "activation history",
        ),
        (
            "generation",
            "/recorded_ingress/histories/0/activation/generation",
            serde_json::json!("77"),
            "activation history",
        ),
        (
            "edition",
            "/schema_version",
            serde_json::json!(1),
            "edition",
        ),
        (
            "explicit-null",
            "/recorded_ingress",
            serde_json::Value::Null,
            "null",
        ),
    ] {
        let mut altered = original.clone();
        *altered.pointer_mut(pointer).unwrap() = changed;
        let bytes = serde_json::to_vec(&altered).unwrap();
        let failure = inspect(&bytes).err().unwrap();
        assert!(
            failure.reason.contains(reason),
            "{name}: {}",
            failure.reason
        );
    }
    let mut missing = original.clone();
    missing["recorded_ingress"]["definition"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(
        inspect(&serde_json::to_vec(&missing).unwrap())
            .err()
            .unwrap()
            .reason
            .contains("complete source inventory")
    );
    let mut changed_proof = original.clone();
    changed_proof["recorded_ingress"]["histories"][0]["proofs"][0]["bytes"] =
        serde_json::json!([0]);
    assert!(
        inspect(&serde_json::to_vec(&changed_proof).unwrap())
            .err()
            .unwrap()
            .reason
            .contains("original proof body")
    );

    let coordinator = record
        .content_bytes(&record.manifest().coordinator_state_ref, 16 * 1024 * 1024)
        .unwrap();
    let coordinator: serde_json::Value = serde_json::from_slice(&coordinator).unwrap();
    assert_eq!(coordinator["schema_version"], 5);
    let scheduling: SchedulingSnapshot =
        serde_json::from_value(coordinator["scheduler"].clone()).unwrap();
    factory
        .authenticate_recorded_coordinator(graph, source, &scheduling)
        .unwrap();
    // Preserve each authentic event ID while replacing one original field.
    // These exercise the complete pending-arrival predicate directly.
    for field in ["native", "source", "delivery", "payload", "producer"] {
        let mut changed = scheduling.clone();
        let delivery = changed.pending_deliveries.first_mut().unwrap();
        match field {
            "native" => delivery.native_sequence = U64::new(999),
            "source" => delivery.source_sequence = U64::new(999),
            "delivery" => delivery.delivery.time_ps = U64::new(50_001),
            "payload" => delivery.payload.media_type = "application/foreign".into(),
            "producer" => delivery.producer = id("foreign-owner"),
            _ => unreachable!(),
        }
        assert!(
            factory
                .authenticate_recorded_coordinator(graph, source, &changed)
                .unwrap_err()
                .reason
                .contains("original complete arrival")
        );
    }
    // Staged-only rows cannot bypass the full original field checks.
    let mut staged_only = scheduling.clone();
    staged_only.pending_deliveries.clear();
    let mut changed_staged = source.clone();
    changed_staged.inputs[0].deliveries[0].producer = id("foreign-owner");
    assert!(
        factory
            .authenticate_recorded_coordinator(graph, &changed_staged, &staged_only)
            .unwrap_err()
            .reason
            .contains("original complete arrival")
    );
    // Remove the authentic unconsumed event from both represented locations.
    // Staging retains the same original arrival in both authentic custody locations.
    let mut forgotten = scheduling.clone();
    forgotten.pending_deliveries.clear();
    let mut forgotten_runtime = source.clone();
    forgotten_runtime.inputs.retain(|input| {
        !input
            .deliveries
            .iter()
            .any(|delivery| delivery.publication_id == id("original/input/1"))
    });
    let failure = factory
        .authenticate_recorded_coordinator(graph, &forgotten_runtime, &forgotten)
        .unwrap_err();
    assert!(failure.reason.contains("omitted or replaced"));
    let mut foreign_closure = scheduling.clone();
    foreign_closure.external_closed_prefixes[0]
        .closed_before
        .time_ps = U64::new(200_001);
    assert!(
        factory
            .authenticate_recorded_coordinator(graph, source, &foreign_closure)
            .unwrap_err()
            .reason
            .contains("external closure")
    );
    assert!(inspect(&native).is_ok());
    factory
        .authenticate_recorded_coordinator(graph, source, &scheduling)
        .unwrap();
}

pub(super) fn verify_archive_availability(
    archive: &HostArchive,
    path: &std::path::Path,
    artifact: &ContentRef,
) {
    let original = path.join(format!("{}.host-world-v1.json", artifact.hash.digest));
    let retained = path.join("temporarily-unavailable-original");
    std::fs::rename(&original, &retained).unwrap();
    assert!(archive.load(artifact).is_err());
    std::fs::rename(&retained, &original).unwrap();

    // Keep the exact original file and alter only its MAC digit. No new body or
    // capture authority is created, and recovery restores the original byte.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&original)
        .unwrap();
    let length = file.metadata().unwrap().len();
    let tail_start = length.saturating_sub(256);
    file.seek(SeekFrom::Start(tail_start)).unwrap();
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).unwrap();
    let marker = b"\"authentication\":[";
    let offset = tail
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap()
        + marker.len();
    let original_byte = tail[offset];
    let changed = if original_byte == b'0' { b'1' } else { b'0' };
    file.seek(SeekFrom::Start(tail_start + offset as u64))
        .unwrap();
    file.write_all(&[changed]).unwrap();
    file.sync_all().unwrap();
    assert!(archive.load(artifact).is_err());
    file.seek(SeekFrom::Start(tail_start + offset as u64))
        .unwrap();
    file.write_all(&[original_byte]).unwrap();
    file.sync_all().unwrap();
    assert!(archive.load(artifact).is_ok());
}

/// Reads the exact actual native owner body from its authenticated capture.
pub(super) fn native_body(record: &HostArchiveRecord) -> serde_json::Value {
    let reference = record.manifest().owners[0].state_ref.as_ref().unwrap();
    let bytes = record.content_bytes(reference, 16 * 1024 * 1024).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
