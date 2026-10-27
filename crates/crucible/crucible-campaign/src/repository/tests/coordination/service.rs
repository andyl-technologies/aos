//! Repository service replay and exact snapshot-bound operational status.

use super::*;

#[test]
fn direct_campaign_service_uses_repository_owner_and_exact_replay() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("service", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let principal = crate::CampaignPrincipal::new("operator:alice").expect("principal");
    let campaign = crate::CampaignName::new("service").expect("campaign name");
    let service = crate::RepositoryCampaignService::new(&repository, PermitAlice);
    let client = crate::CampaignClient::new(service);

    let current = client
        .get_campaign(
            &crate::GetCampaignRequest::new(principal.clone(), campaign.clone())
                .expect("get request"),
        )
        .expect("get campaign");
    assert_eq!(current.snapshot(), genesis.snapshot_id());
    assert_eq!(current.state(), CampaignState::Created);
    assert_eq!(
        current.state(),
        repository
            .state_at_snapshot(current.snapshot())
            .expect("state at returned snapshot")
    );

    let request = crate::ApplyCampaignCommandRequest::new(
        principal.clone(),
        campaign.clone(),
        command(
            "service-resume",
            genesis.snapshot_id(),
            CampaignControlAction::Resume,
        ),
    )
    .expect("apply request");
    let accepted = client
        .apply_campaign_command(&request)
        .expect("apply command");
    assert!(!accepted.replayed());
    let replayed = client
        .apply_campaign_command(&request)
        .expect("replay command");
    assert!(replayed.replayed());
    assert_eq!(replayed.prior_snapshot(), accepted.prior_snapshot());
    assert_eq!(replayed.new_snapshot(), accepted.new_snapshot());

    let pin = crate::PinCampaignRequest::new(
        principal,
        campaign,
        crate::PinRequest {
            command: crate::CampaignCommandId::from_hash(CampaignHash::derive(
                "test",
                b"service-pin",
            )),
            expected_snapshot: accepted.new_snapshot(),
            change: crate::PinChange::new(
                lineage.genesis(),
                Some(crate::PinRetention::Thin),
                "retain semantic replay",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request");
    let pinned = client.pin_campaign(&pin).expect("pin campaign");
    assert!(!pinned.replayed());
    let replayed_pin = client.pin_campaign(&pin).expect("replay pin command");
    assert!(replayed_pin.replayed());
    assert_eq!(replayed_pin.prior_snapshot(), pinned.prior_snapshot());
    assert_eq!(replayed_pin.new_snapshot(), pinned.new_snapshot());
}

#[test]
fn campaign_status_is_exactly_snapshot_bound_and_separates_operational_evidence() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("service-status", &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let principal = crate::CampaignPrincipal::new("operator:alice").expect("principal");
    let campaign = crate::CampaignName::new("service-status").expect("campaign name");
    let client = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ));
    let request = crate::GetCampaignStatusRequest::new(
        principal.clone(),
        campaign.clone(),
        genesis.snapshot_id(),
    )
    .expect("status request");

    let response = client
        .get_campaign_status(&request)
        .expect("campaign status");
    let semantic = response.status().semantic();
    assert_eq!(response.snapshot(), genesis.snapshot_id());
    assert_eq!(
        semantic.continuations(),
        crate::CampaignContinuationStatus::default()
    );
    assert_eq!(semantic.admitted_attempts(), 0);
    assert_eq!(semantic.stored_graph_nodes(), 1);
    assert_eq!(semantic.continuation_records_scanned(), 0);
    assert_eq!(semantic.continuation_bytes_scanned(), 0);
    assert_eq!(
        response.status().operational(),
        crate::CampaignOperationalStatus::Unavailable
    );

    let advanced = repository
        .apply_control(
            campaign.as_str(),
            &command(
                "service-status-resume",
                genesis.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("advance campaign");
    assert!(matches!(
        client.get_campaign_status(&request),
        Err(crate::CampaignClientError::Service(
            crate::CampaignServiceFailure::Stale { expected, current }
        )) if expected == genesis.snapshot_id() && current == advanced.new_snapshot
    ));
}

struct AdvancingOperationalStatus<'a> {
    repository: &'a CampaignRepository,
}

impl crate::CampaignOperationalStatusProvider for AdvancingOperationalStatus<'_> {
    fn operational_status(
        &self,
        campaign: &crate::CampaignName,
        snapshot: crate::CampaignSnapshotId,
    ) -> crate::CampaignOperationalStatus {
        self.repository
            .apply_control(
                campaign.as_str(),
                &command(
                    "advance-during-status",
                    snapshot,
                    CampaignControlAction::Resume,
                ),
            )
            .expect("advance campaign during operational projection");
        crate::CampaignOperationalStatus::Unavailable
    }
}

#[test]
fn campaign_status_rejects_a_head_change_during_operational_projection() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("status-race", &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let provider = AdvancingOperationalStatus {
        repository: &repository,
    };
    let service = crate::RepositoryCampaignService::new(&repository, PermitAlice)
        .with_operational_status(&provider);
    let client = crate::CampaignClient::new(service);
    let request = crate::GetCampaignStatusRequest::new(
        crate::CampaignPrincipal::new("operator:alice").expect("principal"),
        crate::CampaignName::new("status-race").expect("campaign name"),
        genesis.snapshot_id(),
    )
    .expect("status request");

    assert!(matches!(
        client.get_campaign_status(&request),
        Err(crate::CampaignClientError::Service(
            crate::CampaignServiceFailure::Stale { expected, current }
        )) if expected == genesis.snapshot_id() && current != expected
    ));
}
