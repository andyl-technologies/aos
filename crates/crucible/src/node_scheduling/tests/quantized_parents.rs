//! Original quantized input provenance, independently of evaluation timing.

use super::*;
use crate::node_scheduling::event::Delivery;
use crate::node_scheduling::{InputIdentity, NativeInputProgress, NativePublication};

fn copy_receipt(receipt: &SchedulingReceipt) -> SchedulingReceipt {
    SchedulingReceipt::new(
        receipt.activation.clone(),
        receipt.node.clone(),
        receipt.operation.clone(),
        receipt.progress.clone(),
        receipt.retained_outputs.clone(),
        receipt.observation.clone(),
    )
}

#[test]
fn quantum_publication_accepts_only_original_consumed_input_parents() {
    let mut scheduler = fixture(quantum(), 100, None);
    let endpoint = Endpoint {
        node_id: id("A"),
        port_id: id("data"),
        lane_id: id("output"),
    };
    scheduler
        .output_endpoints
        .insert(endpoint.clone(), U64::new(4096));
    let input = crucible_node_contract::canonical::content_ref(
        b"original input",
        "application/octet-stream",
    )
    .unwrap();
    let original_parent = position(0, 0, Phase::Delivery);
    let delivery = Delivery {
        connection_id: None,
        connection_policy_ref: None,
        external_root: None,
        provenance_ref: reference(),
        publication_id: id("original-source-output"),
        producer: id("Z"),
        consumer: id("A"),
        producer_endpoint: Endpoint {
            node_id: id("Z"),
            port_id: id("data"),
            lane_id: id("output"),
        },
        consumer_endpoint: Endpoint {
            node_id: id("A"),
            port_id: id("data"),
            lane_id: id("input"),
        },
        source_sequence: U64::new(0),
        native_sequence: U64::new(1),
        evaluation: None,
        causal_parents: Vec::new(),
        publication: position(0, 0, Phase::Publication),
        delivery: original_parent,
        payload: input.clone(),
    };
    scheduler.pending.insert(delivery.key(), delivery);
    scheduler.payloads.insert(input, b"original input".to_vec());
    stage_empty_quantum(&mut scheduler, "batch/original");
    let grant = scheduler
        .admit_quantum(
            &id("A"),
            id("run/original"),
            id("window/original"),
            id("batch/original"),
        )
        .unwrap();
    let mut observation = empty_quantum_observation(
        &scheduler,
        "batch/original",
        position(100, 0, Phase::BoundaryControl),
    );
    observation.input_progress = Some(NativeInputProgress {
        batch: id("batch/original"),
        consumed: vec![InputIdentity {
            producer: id("Z"),
            source_sequence: U64::new(0),
        }],
        proof_ref: reference(),
    });
    observation.publications = vec![NativePublication {
        publication_id: id("derived-output"),
        endpoint,
        native_sequence: U64::new(1),
        publication: grant.limit(),
        evaluation: None,
        causal_parents: vec![original_parent],
        payload: crucible_node_contract::canonical::content_ref(
            b"derived",
            "application/octet-stream",
        )
        .unwrap(),
        payload_bytes: b"derived".to_vec(),
    }];
    let receipt = SchedulingReceipt::new(
        scheduler.activation.clone(),
        id("A"),
        id("run/original"),
        ProgressEvidence::Quantized {
            window: id("window/original"),
            publication: grant.limit(),
            physical: PhysicalState::Unknown,
            closure: Box::new(QuantumClosureEvidence {
                input_batch: id("batch/original"),
                close_receipt: reference(),
                output_inventory: reference(),
                pending_inventory: reference(),
                clock_evidence: reference(),
            }),
        },
        vec![id("derived-output")],
        Some(observation),
    );

    for changed in [
        vec![position(1, 0, Phase::Delivery)],
        vec![original_parent, original_parent],
    ] {
        let mut changed_receipt = copy_receipt(&receipt);
        changed_receipt.observation.as_mut().unwrap().publications[0].causal_parents = changed;
        assert!(matches!(
            scheduler.accept_receipt(changed_receipt),
            Err(SchedulingError::InvalidPublication)
        ));
        assert_eq!(scheduler.pending.len(), 1);
        assert!(scheduler.operations.contains_key(&id("run/original")));
        assert_eq!(scheduler.position(&id("A")).unwrap(), grant.start());
    }
    let mut foreign_prefix = copy_receipt(&receipt);
    foreign_prefix
        .observation
        .as_mut()
        .unwrap()
        .input_progress
        .as_mut()
        .unwrap()
        .consumed[0]
        .producer = id("foreign-producer");
    assert!(matches!(
        scheduler.accept_receipt(foreign_prefix),
        Err(SchedulingError::InvalidReceipt)
    ));
    assert_eq!(scheduler.pending.len(), 1);

    scheduler.accept_receipt(receipt).unwrap();
    assert!(scheduler.pending.is_empty());
    assert_eq!(scheduler.position(&id("A")).unwrap().time_ps, U64::new(100));
}
