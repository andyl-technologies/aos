//! Copy-prefix evidence from actual staging transitions and durable receipt bytes.

use super::*;

#[tokio::test]
async fn copy_progress_requires_the_exact_positive_original_receipt() {
    let fixture = Fixture::new(2).await;
    let (head, proof) = fixture.destination();
    let intent = fixture.copy_intent(&proof, 1);
    let operation_id = intent.operation_id.clone();
    let (head, turn) = fixture
        .begin(&head, intent, Some(proof.clone()), None)
        .unwrap();
    let (head, receipt) = fixture.terminal(
        &head,
        turn,
        Outcome::Copied {
            part: fixture.part(1),
            etag: "\"provider-acknowledged-original\"".into(),
        },
    );
    let persisted = serde_json::to_vec(&receipt).unwrap();
    let retained: Receipt = serde_json::from_slice(&persisted).unwrap();
    let source = protocol::digest(&proof.verified).unwrap();

    let acknowledged = retained
        .copied_part_for(
            &fixture.context,
            &operation_id,
            &source,
            "destination-upload",
            1,
        )
        .unwrap();

    assert_eq!(acknowledged.part, fixture.part(1));
    assert_eq!(acknowledged.etag, "\"provider-acknowledged-original\"");
    assert_eq!(head.stage.as_ref().unwrap().frozen_parts, 1);
    for (operation, source, upload, number) in [
        (
            "another-operation",
            source.as_str(),
            "destination-upload",
            1,
        ),
        (
            operation_id.as_str(),
            "another-source",
            "destination-upload",
            1,
        ),
        (operation_id.as_str(), source.as_str(), "another-upload", 1),
        (
            operation_id.as_str(),
            source.as_str(),
            "destination-upload",
            2,
        ),
    ] {
        assert!(retained
            .copied_part_for(&fixture.context, operation, source, upload, number)
            .is_err());
    }

    let mut changed = retained.clone();
    let Outcome::Copied { part, .. } = &mut changed.outcome else {
        panic!("fixture must retain a copy acknowledgement");
    };
    part.offset = WireInteger::new(1);
    assert!(changed
        .copied_part_for(
            &fixture.context,
            &operation_id,
            &source,
            "destination-upload",
            1
        )
        .is_err());

    let mut other = fixture.context.clone();
    other.intent.expected_sha256 = "0".repeat(64);
    assert!(retained
        .copied_part_for(&other, &operation_id, &source, "destination-upload", 1)
        .is_err());
}
