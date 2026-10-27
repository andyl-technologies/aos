//! Reproduction payload segments: publication order, ownership, and lengths.

use super::*;
use crate::{ReproductionPayload, ReproductionPayloadSegment};
use crucible_store::content_store::ObjectKind;

fn trace_segment(bytes: &[u8]) -> ReproductionPayloadSegment {
    ReproductionPayloadSegment::new(
        ContentId::for_bytes(ObjectKind::Trace, 1, bytes),
        bytes.len() as u64,
    )
    .expect("payload segment")
}

fn static_payload(segments: Vec<ReproductionPayloadSegment>) -> ReproductionPayload {
    ReproductionPayload::new(5, b"static reproduction part".to_vec(), segments)
        .expect("reproduction payload")
}

#[test]
fn reproduction_names_stored_payload_segments_and_owns_their_reads() {
    let (repository, lineage, policy) = fixture();
    let (_, _, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "reproduction-segments");
    let publish = |payload| {
        repository.publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            CampaignHash::derive("test-finding", b"segmented reproduction"),
            payload,
        )
    };
    let first_bytes = b"first schedule segment".as_slice();
    let second_bytes = b"second schedule segment".as_slice();
    let first = trace_segment(first_bytes);
    let second = trace_segment(second_bytes);

    // A record cannot name a segment that is not stored yet.
    repository
        .publish_reproduction_payload_segment(first, first_bytes)
        .expect("publish first segment");
    assert!(publish(static_payload(vec![first, second])).is_err());

    repository
        .publish_reproduction_payload_segment(second, second_bytes)
        .expect("publish second segment");
    let reproduction =
        publish(static_payload(vec![first, second])).expect("publish segmented reproduction");
    assert_eq!(
        repository
            .read_reproduction_payload_segment(reproduction, second.content())
            .expect("read owned segment"),
        second_bytes
    );

    // Bytes must derive the declared segment, and reads are scoped to the
    // segments the record names.
    assert!(
        repository
            .publish_reproduction_payload_segment(first, second_bytes)
            .is_err()
    );
    let unrelated = trace_segment(b"unrelated segment");
    repository
        .publish_reproduction_payload_segment(unrelated, b"unrelated segment")
        .expect("publish unrelated segment");
    assert!(
        repository
            .read_reproduction_payload_segment(reproduction, unrelated.content())
            .is_err()
    );

    // A declared length that disagrees with the stored leaf is refused.
    let mislabeled = ReproductionPayloadSegment::new(first.content(), first.bytes() + 1)
        .expect("mislabeled segment");
    assert!(publish(static_payload(vec![mislabeled])).is_err());
}
