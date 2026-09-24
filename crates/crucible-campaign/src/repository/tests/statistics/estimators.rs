//! Event-estimator denominator regression.

use super::*;

#[test]
fn ordinary_and_self_normalized_event_estimates_keep_distinct_denominators() {
    let observation_in =
        ObservationId::from_content_id(content_id(ObjectKind::Observation, 13, "event-in"))
            .expect("event-in observation ID");
    let observation_out =
        ObservationId::from_content_id(content_id(ObjectKind::Observation, 13, "event-out"))
            .expect("event-out observation ID");
    let endpoint = |coordinate, observation, weight| {
        crate::StatisticalEndpointEstimate::new(
            coordinate,
            ProposalId::from_content_id(content_id(
                ObjectKind::CampaignFact,
                3,
                &format!("proposal-{coordinate}"),
            ))
            .expect("proposal ID"),
            AttemptId::from_content_id(content_id(
                ObjectKind::CampaignFact,
                9,
                &format!("attempt-{coordinate}"),
            ))
            .expect("attempt ID"),
            observation,
            BranchPathId::from_content_id(content_id(
                ObjectKind::CampaignFact,
                2,
                &format!("path-{coordinate}"),
            ))
            .expect("path ID"),
            weight,
            crate::StatisticalRational::new(1, 1).expect("proposal probability"),
            weight,
        )
    };
    let report = crate::StatisticalEstimateReport::new(
        CampaignSnapshotId::from_content_id(content_id(
            ObjectKind::CampaignSnapshot,
            3,
            "snapshot",
        ))
        .expect("snapshot ID"),
        CampaignPolicyId::from_content_id(content_id(ObjectKind::Policy, 5, "policy"))
            .expect("policy ID"),
        vec![
            endpoint(
                0,
                observation_in,
                crate::StatisticalRational::new(2, 1).expect("weight two"),
            ),
            endpoint(
                1,
                observation_out,
                crate::StatisticalRational::new(1, 1).expect("weight one"),
            ),
        ],
        crate::StatisticalWeightDiagnostics::new(
            crate::StatisticalRational::new(2, 3).expect("concentration"),
            crate::StatisticalRational::new(9, 5).expect("ESS"),
        ),
    );
    let event = BTreeSet::from([observation_in]);

    assert_eq!(
        report.estimate_event(&event).expect("ordinary estimate"),
        crate::StatisticalRational::new(1, 1).expect("ordinary expected")
    );
    assert_eq!(
        report
            .estimate_event_self_normalized(&event)
            .expect("self-normalized estimate"),
        crate::StatisticalRational::new(2, 3).expect("self-normalized expected")
    );
}
