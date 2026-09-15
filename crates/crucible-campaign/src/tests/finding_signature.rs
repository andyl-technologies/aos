//! Finding signature and membership rejection regression.

use super::*;

#[test]
fn finding_signature_and_membership_invariants_fail_closed() {
    assert!(matches!(
        FindingSignature::new(
            FindingKind::PropertyViolation,
            hash("missing-property"),
            None,
            "guest.assertion".to_owned(),
            None,
            BTreeSet::new(),
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding property identity disagrees with failure kind"
        })
    ));

    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        1,
        b"omitted-observation",
    ))
    .expect("observation id");
    assert!(matches!(
        FindingOccurrenceSet::new(
            ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"empty occurrences"),
            0,
            observation,
        ),
        Err(CampaignCodecError::LimitExceeded {
            limit: "finding-occurrence-count"
        })
    ));
    assert!(matches!(
        FindingOccurrenceSet::new(
            ContentId::for_bytes(ObjectKind::Trace, 1, b"not a merkle root"),
            1,
            observation,
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding occurrence root is not a Merkle node"
        })
    ));
}
