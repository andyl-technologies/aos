//! Real selected companion windows; fixture batches do not qualify public sources.

// crucible-lint: allow panic-shortcut -- Native original custody changes invalidate this component witness.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::{Endpoint, Event, EventStage, Extensions, Phase, Position};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use super::*;

struct Root(std::path::PathBuf);

impl Root {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lineage-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn grant(quantum: u64) -> DeviceGrant {
    DeviceGrant {
        owner_id: Id::new("source-owner").unwrap(),
        incarnation_id: Id::new("source-incarnation").unwrap(),
        generation: U64::new(1),
        window_id: Id::new(format!("original-window-{quantum}")).unwrap(),
        input_batch_id: Id::new(format!("original-batch-{quantum}")).unwrap(),
        quantum: U64::new(quantum),
        start: Position::new(U64::new(quantum * 10), U64::new(0), Phase::BoundaryControl),
        publication: Position::new(
            U64::new((quantum + 1) * 10),
            U64::new(0),
            Phase::Publication,
        ),
        host_budget_ns: U64::new(1_000_000_000),
    }
}

fn input(grant: &DeviceGrant, payloads: &[&[u8]]) -> InputBatch {
    InputBatch {
        schema_version: 1,
        execution_owner_id: grant.owner_id.clone(),
        input_epoch: Id::new("original-input-epoch").unwrap(),
        batch_id: grant.input_batch_id.clone(),
        batch_sequence: grant.quantum,
        events: payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| Event {
                schema_version: 1,
                id: Id::new("checksum-1").unwrap(),
                source: Endpoint {
                    node_id: Id::new(format!("producer-{index}")).unwrap(),
                    port_id: Id::new("data").unwrap(),
                    lane_id: Id::new("output").unwrap(),
                },
                destination: Endpoint {
                    node_id: Id::new("consumer").unwrap(),
                    port_id: Id::new("data").unwrap(),
                    lane_id: Id::new("input").unwrap(),
                },
                position: Position::new(U64::new(2), U64::new(0), Phase::Delivery),
                stage: EventStage::Delivery,
                publication_position: Position::new(U64::new(1), U64::new(0), Phase::Publication),
                delivery_position: Some(Position::new(U64::new(2), U64::new(0), Phase::Delivery)),
                source_sequence: U64::new(1),
                causal_parent_ids: vec![],
                payload: canonical::content_ref(payload, "application/octet-stream").unwrap(),
                provenance_ref: canonical::content_ref(
                    format!("fixture-{index}").as_bytes(),
                    "text/plain",
                )
                .unwrap(),
                extensions: Extensions::new(),
            })
            .collect(),
        extensions: Extensions::new(),
    }
}

#[test]
#[ignore = "requires the AOS source-built lineage companion; component evidence only"]
fn source_bridge_retains_actual_ordered_close_prior_ack_and_original_typed_rows() {
    let executable = std::env::var_os("CRUCIBLE_REFERENCE_LINEAGE_DEVICE").unwrap();
    let root = Root::new();
    let first = grant(0);
    let mut child = ReferenceChild::spawn(
        Path::new(&executable),
        &root.0,
        first.owner_id.clone(),
        first.incarnation_id.clone(),
        first.generation,
        Duration::from_secs(3),
        true,
    )
    .unwrap();

    child
        .stage(first.clone(), &input(&first, &[]), &[])
        .unwrap();
    child.activate(&first).unwrap();
    let initial = child.close(&first).unwrap();
    child.validate_receipt(&initial).unwrap();
    let preceding = child
        .relation(&first)
        .unwrap()
        .unwrap()
        .evidence()
        .iter()
        .find(|object| {
            object.reference().media_type
                == "application/vnd.crucible.reference-lineage-native-receipt+json"
        })
        .unwrap()
        .reference()
        .clone();
    child.acknowledge_publication(&first).unwrap();

    let second = grant(1);
    let original = input(&second, &[b"same", b"", b"same"]);
    child.stage(second.clone(), &original, b"samesame").unwrap();
    let ReferenceChild::Lineage(peer) = &child else {
        panic!("selected companion differs")
    };
    let commands = peer.native.commands().len();
    child.stage(second.clone(), &original, b"samesame").unwrap();
    let mut changed = original.clone();
    changed.events.swap(0, 2);
    assert!(child.stage(second.clone(), &changed, b"samesame").is_err());
    let ReferenceChild::Lineage(peer) = &child else {
        panic!("selected companion differs")
    };
    assert_eq!(peer.native.commands().len(), commands);
    assert_eq!(peer.accepted.len(), 2);

    child.activate(&second).unwrap();
    let receipt = child.close(&second).unwrap();
    child.validate_receipt(&receipt).unwrap();
    assert_eq!(receipt.output.bytes_processed.get(), 8);
    assert!(receipt.measured_host_ns.get() > 0);
    let relation = child.relation(&second).unwrap().unwrap();
    let root = relation
        .evidence()
        .iter()
        .find(|body| body.reference() == relation.reference())
        .unwrap();
    assert!(root.dependencies().contains(&preceding));
    let batch = canonical::content_ref(
        &canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap(),
        "application/json",
    )
    .unwrap();
    assert!(root.dependencies().contains(&batch));
    assert_eq!(child.evidence(&batch).unwrap().dependencies().len(), 3);
    for event in &original.events {
        let event_ref = canonical::content_ref(
            &canonical::canonical_json(&serde_json::to_value(event).unwrap()).unwrap(),
            "application/json",
        )
        .unwrap();
        assert_eq!(
            child.evidence(&event_ref).unwrap().dependencies(),
            &[event.payload.clone(), event.provenance_ref.clone()]
        );
    }
    assert!(child.evidence(&preceding).is_some());
    child.acknowledge_publication(&second).unwrap();
    let deadline =
        crate::reference_lineage::transport::ExchangeBudget::after(Duration::from_secs(3)).unwrap();
    while !child.quarantine().unwrap() {
        assert!(!deadline.is_expired());
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(child.status(), DeviceStatus::Reaped);
    assert!(child.evidence(&preceding).is_some());
}
