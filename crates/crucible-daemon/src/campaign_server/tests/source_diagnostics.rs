//! Original repository causes through real authenticated Unix listener requests.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::Shutdown;
use std::sync::Barrier;

use crucible_campaign::{
    BranchBudget, BranchPointId, BranchRequest, BranchRequestCause, CampaignCommandId,
    CampaignLineage, CampaignMode, CampaignPolicy, CampaignSeed, CampaignServiceFailureCategory,
    CandidateSource, ChoiceDomainId, ChoiceOpportunityId, ChoiceValue, ConfigurationArtifactId,
    CreateCampaignRequest, ExplorerPolicy, FairnessPolicy, RepositoryCampaignService,
    RetentionPolicy, StopCondition, SubmitCampaignBranchRequest,
};
use crucible_cas::content_store::{
    BlobStoreAdmin, ContentId, MutableRefBackend, ObjectKind, RefName,
};

use super::*;
use crate::CrucibleCampaignArtifactStore;

fn branch(
    name: &str,
    snapshot: crucible_campaign::CampaignSnapshotId,
) -> SubmitCampaignBranchRequest {
    let id = |label| CampaignHash::derive("source-diagnostic-branch", label);
    let request = BranchRequest::new(
        BranchRequest::identity(
            BranchPointId::from_hash(id(b"point")),
            ConfigurationArtifactId::parse(&format!(
                "crucible.campaign.configuration-artifact@{}",
                ContentId::for_bytes(ObjectKind::Configuration, 1, b"parent").encode(),
            ))
            .expect("parent identity"),
            ChoiceOpportunityId::parse(&format!(
                "crucible.campaign.choice-opportunity@{}",
                ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"opportunity").encode(),
            ))
            .expect("opportunity identity"),
            ChoiceDomainId::parse(&format!(
                "crucible.campaign.choice-domain@{}",
                ContentId::for_bytes(ObjectKind::CampaignFact, 2, b"domain").encode(),
            ))
            .expect("domain identity"),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(id(name.as_bytes()))),
        BranchBudget::new(1, 1).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("canonical branch request");
    SubmitCampaignBranchRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new(name).expect("campaign"),
        snapshot,
        request,
    )
    .expect("authenticated branch envelope")
}

#[test]
fn original_missing_head_is_bound_to_its_request_and_preserves_refs() {
    let blobs = Arc::new(MemoryBlobBackend::new("source-diagnostic", u64::MAX));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let artifacts = CrucibleCampaignArtifactStore::new(repository.clone());
    let scenario = crucible::happy_path_scenario().expect("scenario").scenario;
    let scenario_id = artifacts
        .import_scenario(&scenario)
        .expect("import scenario");
    let configuration_id = artifacts
        .import_configuration(&scenario, &crucible::Schedule::empty())
        .expect("import configuration");
    let stored_scenario = repository
        .load_scenario_artifact(scenario_id)
        .expect("scenario artifact");
    let stored_configuration = repository
        .load_configuration_artifact(configuration_id)
        .expect("configuration artifact");
    let lineage = CampaignLineage::new(
        stored_scenario.scenario(),
        scenario_id,
        stored_configuration.configuration(),
        configuration_id,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        stored_scenario.payload_schema(),
        stored_configuration.payload_schema(),
    )
    .expect("lineage");
    let policy = |seed| {
        CampaignPolicy::new(
            CampaignPolicy::identity(
                lineage.scenario(),
                CampaignSeed::from_bytes([seed; 32]),
                CampaignMode::Strict,
                ExplorerPolicy::Exhaustive {
                    maximum_cardinality: 4,
                },
            ),
            CampaignPolicy::rules(
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                FairnessPolicy::new(0, 0).expect("fairness"),
                RetentionPolicy::new(true, 1, true, true),
                false,
            ),
        )
        .expect("policy")
    };
    let direct = CampaignClient::new(RepositoryCampaignService::new(
        repository.as_ref(),
        AllowAll,
    ));
    let create = |name| {
        CreateCampaignRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new(name).expect("campaign"),
            lineage.clone(),
            policy(if name == "missing-head" { 7 } else { 8 }),
        )
        .expect("create request")
    };
    let created = direct
        .create_campaign(&create("missing-head"))
        .expect("create missing-head campaign");
    let unrelated = direct
        .create_campaign(&create("unrelated-owner"))
        .expect("create unrelated campaign");
    assert_ne!(created.snapshot(), unrelated.snapshot());
    let missing_ref = RefName::new("campaigns/missing-head").expect("missing ref name");
    let unrelated_ref = RefName::new("campaigns/unrelated-owner").expect("unrelated ref name");
    let before = refs.read_ref(&missing_ref).expect("original ref");
    let unrelated_before = refs.read_ref(&unrelated_ref).expect("unrelated ref");

    // Remove only the authenticated head object; retain both original refs.
    blobs
        .acquire_inventory_fence()
        .expect("inventory owner")
        .delete_candidate(created.snapshot().content_id())
        .expect("remove head object");
    let object_count = blobs.object_count().expect("remaining objects");
    let missing = branch("missing-head", created.snapshot());
    let absent = branch("absent-campaign", created.snapshot());
    let missing_digest = missing.request_digest();
    let absent_digest = absent.request_digest();
    let (_directory, listener, socket) = listener();
    let (observed, _observed_rx) = mpsc::channel();
    let diagnostics = Arc::new(RecordingDiagnostics::default());
    let server = CampaignLoopbackServer::new(
        listener,
        repository.clone(),
        Arc::new(RecordingResolver { observed }),
        Arc::new(AllowAll),
        CampaignLoopbackServerConfig::default(),
    )
    .expect("listener")
    .with_diagnostic_sink(diagnostics.clone());
    let shutdown = server.shutdown_handle();
    let server_thread = thread::spawn(move || server.serve().expect("serve listener"));
    let barrier = Arc::new(Barrier::new(2));
    let submit = |request: SubmitCampaignBranchRequest| {
        let barrier = barrier.clone();
        let socket = socket.clone();
        thread::spawn(move || {
            let client = CampaignClient::new(
                LoopbackCampaignService::new(UnixStream::connect(socket).expect("connect"))
                    .expect("loopback"),
            );
            barrier.wait();
            client.submit_branch_request(&request)
        })
    };

    let missing_request = submit(missing);
    let absent_request = submit(absent);
    assert!(matches!(
        missing_request.join().expect("missing request"),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unavailable
        ))
    ));
    assert!(matches!(
        absent_request.join().expect("absent request"),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::NotFound
        ))
    ));
    wait_for_no_active_connections(&shutdown);
    let mut malformed = UnixStream::connect(&socket).expect("connect malformed peer");
    malformed.write_all(&[0; 32]).expect("malformed frame");
    malformed
        .shutdown(Shutdown::Write)
        .expect("close malformed write");
    let closed = malformed.read_to_end(&mut Vec::new());
    assert!(
        closed.is_ok()
            || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    drop(malformed);
    wait_for_no_active_connections(&shutdown);
    shutdown.shutdown();
    let report = server_thread.join().expect("listener joined");

    let records = diagnostics.records();
    assert!(
        records.contains(&CampaignServiceDiagnostic::RequestFailure {
            operation: CampaignServiceOperation::SubmitBranchRequest,
            request_digest: missing_digest,
            failure: CampaignServiceFailure::Unavailable,
        })
    );
    assert!(
        records.contains(&CampaignServiceDiagnostic::RequestFailure {
            operation: CampaignServiceOperation::SubmitBranchRequest,
            request_digest: absent_digest,
            failure: CampaignServiceFailure::NotFound,
        })
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(
                record,
                CampaignServiceDiagnostic::RequestFailureSource { .. }
            ))
            .copied()
            .collect::<Vec<_>>(),
        vec![CampaignServiceDiagnostic::RequestFailureSource {
            operation: CampaignServiceOperation::SubmitBranchRequest,
            request_digest: missing_digest,
            category: CampaignServiceFailureCategory::Missing,
        }]
    );
    assert!(
        records.contains(&CampaignServiceDiagnostic::ConnectionFailure(
            CampaignConnectionDiagnostic::ProtocolFailed
        ))
    );
    assert_eq!(refs.read_ref(&missing_ref).expect("retained ref"), before);
    assert_eq!(
        refs.read_ref(&unrelated_ref)
            .expect("retained unrelated ref"),
        unrelated_before
    );
    let reopened = CampaignRepository::new(blobs.clone(), refs.clone());
    assert_eq!(
        reopened
            .head("unrelated-owner")
            .expect("unrelated owner")
            .snapshot_id(),
        unrelated.snapshot()
    );
    assert_eq!(
        blobs.object_count().expect("objects after refusal"),
        object_count
    );
    assert_eq!(report.completed_connections(), 2);
    assert_eq!(report.protocol_failures(), 1);
}
