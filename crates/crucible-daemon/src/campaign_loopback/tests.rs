#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, mpsc};
use std::thread;

use crucible_campaign::{
    ApplyCampaignCommandRequest, ApplyCampaignCommandResponse, BranchBudget, BranchPointId,
    BranchRequest, BranchRequestCause, BranchRequestResult, CampaignClient, CampaignCommandId,
    CampaignCommandResult, CampaignControlAction, CampaignHash, CampaignLineageId, CampaignName,
    CampaignPolicyId, CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository,
    CampaignService, CampaignServiceOperation, CampaignSnapshotId, CampaignState, CandidateSource,
    ChoiceDomainId, ChoiceOpportunityId, ChoiceValue, ConfigurationArtifactId, ControlRequest,
    GetCampaignRequest, GetCampaignResponse, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES,
    RepositoryCampaignService, RepositoryCampaignServiceError, StopCondition,
    SubmitCampaignBranchRequest, SubmitCampaignBranchResponse,
};
use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

use super::*;

#[derive(Clone, Copy)]
struct FixedCampaignService;

impl CampaignService for FixedCampaignService {
    type Error = Infallible;

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        Ok(GetCampaignResponse::new(
            request,
            snapshot("current"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        )
        .expect("get response"))
    }

    fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        Ok(ApplyCampaignCommandResponse::new(
            request,
            CampaignCommandResult {
                prior_snapshot: request.command().expected_snapshot,
                new_snapshot: snapshot("command-next"),
                replayed: false,
            },
        )
        .expect("command response"))
    }

    fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        Ok(SubmitCampaignBranchResponse::new(
            request,
            BranchRequestResult {
                prior_snapshot: request.expected_snapshot(),
                new_snapshot: snapshot("branch-next"),
                request: request.request().id().expect("branch request id"),
                replayed: false,
            },
        )
        .expect("branch response"))
    }
}

#[test]
fn direct_and_loopback_campaign_services_are_identical() {
    let get = get_request("network-recovery");
    let apply = apply_request("network-recovery");
    let branch = branch_submission("network-recovery");
    let direct = CampaignClient::new(FixedCampaignService);
    let expected_get = direct.get_campaign(&get).expect("direct get");
    let expected_apply = direct.apply_campaign_command(&apply).expect("direct apply");
    let expected_branch = direct
        .submit_branch_request(&branch)
        .expect("direct branch");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        for _ in 0..3 {
            serve_loopback_campaign_once(&mut server_stream, &FixedCampaignService)
                .expect("serve campaign request");
        }
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert_eq!(
        client.get_campaign(&get).expect("loopback get"),
        expected_get
    );
    assert_eq!(
        client
            .apply_campaign_command(&apply)
            .expect("loopback apply"),
        expected_apply
    );
    assert_eq!(
        client
            .submit_branch_request(&branch)
            .expect("loopback branch"),
        expected_branch
    );
    server.join().expect("server thread");
}

#[test]
fn campaign_loopback_rejects_partial_frames_with_a_finite_deadline() {
    let (mut client, mut server) = UnixStream::pair().expect("stream pair");
    let timeouts = LoopbackCampaignTimeouts::new(
        std::time::Duration::from_millis(20),
        std::time::Duration::from_millis(20),
    )
    .expect("timeouts");
    let server_thread = thread::spawn(move || {
        assert!(matches!(
            serve_loopback_campaign_once_with_timeouts(
                &mut server,
                &FixedCampaignService,
                timeouts,
            ),
            Err(LoopbackCampaignServerError::Protocol(
                LoopbackCampaignProtocolError::Io(_)
            ))
        ));
    });
    client.write_all(b"CRUC").expect("partial frame");
    server_thread.join().expect("server thread");
}

#[test]
fn campaign_loopback_frame_header_is_frozen_and_malformed_headers_close() {
    let (mut writer, mut reader) = UnixStream::pair().expect("stream pair");
    write_frame(
        &mut writer,
        GET_CAMPAIGN_REQUEST_KIND,
        b"abc",
        std::time::Duration::from_secs(1),
    )
    .expect("write frame");
    let mut bytes = [0_u8; 19];
    reader.read_exact(&mut bytes).expect("read frame");
    assert_eq!(&bytes, b"CRUCCS01\x01\0\0\0\0\0\0\x03abc");

    for (kind, reserved, length, reason) in [
        (
            GET_CAMPAIGN_REQUEST_KIND,
            [1, 0, 0],
            0,
            "nonzero-reserved-bits",
        ),
        (0xff, [0, 0, 0], 0, "unknown-campaign-service-request-kind"),
        (
            GET_CAMPAIGN_REQUEST_KIND,
            [0, 0, 0],
            u32::try_from(MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES + 1).expect("oversized length"),
            "component-message-too-large",
        ),
    ] {
        let (mut client, mut server) = UnixStream::pair().expect("stream pair");
        let server_thread = thread::spawn(move || {
            assert!(matches!(
                serve_loopback_campaign_once(&mut server, &FixedCampaignService),
                Err(LoopbackCampaignServerError::Protocol(
                    LoopbackCampaignProtocolError::InvalidFrame { reason: actual }
                )) if actual == reason
            ));
        });
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        header[..FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
        header[8] = kind;
        header[9..12].copy_from_slice(&reserved);
        header[12..].copy_from_slice(&length.to_be_bytes());
        client.write_all(&header).expect("malformed header");
        server_thread.join().expect("server thread");
    }
}

#[test]
fn campaign_loopback_rejects_concurrent_exchange_without_waiting() {
    let first_request = get_request("first");
    let first_response = GetCampaignResponse::new(
        &first_request,
        snapshot("current"),
        lineage("lineage"),
        policy("policy"),
        CampaignState::Running,
    )
    .expect("first response");
    let (client_stream, mut peer) = UnixStream::pair().expect("stream pair");
    let service = Arc::new(LoopbackCampaignService::new(client_stream).expect("loopback service"));
    let (request_seen_tx, request_seen_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let peer_thread = thread::spawn(move || {
        read_frame(
            &mut peer,
            GET_CAMPAIGN_REQUEST_KIND,
            std::time::Duration::from_secs(1),
        )
        .expect("first request");
        request_seen_tx.send(()).expect("request seen");
        release_rx.recv().expect("release response");
        write_frame(
            &mut peer,
            GET_CAMPAIGN_RESPONSE_KIND,
            &first_response.canonical_bytes(),
            std::time::Duration::from_secs(1),
        )
        .expect("first response");
    });
    let first_service = Arc::clone(&service);
    let first_thread = thread::spawn(move || first_service.get_campaign(&first_request));
    request_seen_rx.recv().expect("first request observed");

    let second_service = Arc::clone(&service);
    let (second_tx, second_rx) = mpsc::channel();
    let second_thread =
        thread::spawn(move || second_tx.send(second_service.get_campaign(&get_request("second"))));
    assert!(matches!(
        second_rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .expect("bounded busy response"),
        Err(LoopbackCampaignProtocolError::ConnectionBusy)
    ));
    second_thread
        .join()
        .expect("second caller")
        .expect("second result receiver");

    release_tx.send(()).expect("release first response");
    first_thread
        .join()
        .expect("first caller")
        .expect("first response");
    peer_thread.join().expect("peer thread");
}

struct WrongGetService {
    response: GetCampaignResponse,
}

impl CampaignService for WrongGetService {
    type Error = Infallible;

    fn get_campaign(
        &self,
        _request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        Ok(self.response.clone())
    }

    fn apply_campaign_command(
        &self,
        _request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn submit_branch_request(
        &self,
        _request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }
}

#[test]
fn campaign_loopback_server_rejects_cross_request_responses() {
    let served = get_request("served");
    let other = get_request("other");
    let service = WrongGetService {
        response: GetCampaignResponse::new(
            &other,
            snapshot("current"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        )
        .expect("wrong response"),
    };
    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        assert!(matches!(
            serve_loopback_campaign_once(&mut server_stream, &service),
            Err(LoopbackCampaignServerError::Protocol(
                LoopbackCampaignProtocolError::Codec(_)
            ))
        ));
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert!(client.get_campaign(&served).is_err());
    server.join().expect("server thread");
}

#[test]
fn campaign_loopback_client_closes_after_a_cross_request_response() {
    let served = get_request("served");
    let other = get_request("other");
    let wrong_response = GetCampaignResponse::new(
        &other,
        snapshot("current"),
        lineage("lineage"),
        policy("policy"),
        CampaignState::Running,
    )
    .expect("wrong response");
    let (client_stream, mut peer) = UnixStream::pair().expect("stream pair");
    let peer_thread = thread::spawn(move || {
        read_frame(
            &mut peer,
            GET_CAMPAIGN_REQUEST_KIND,
            std::time::Duration::from_secs(1),
        )
        .expect("read request");
        write_frame(
            &mut peer,
            GET_CAMPAIGN_RESPONSE_KIND,
            &wrong_response.canonical_bytes(),
            std::time::Duration::from_secs(1),
        )
        .expect("write response");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("client close"), 0);
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert!(client.get_campaign(&served).is_err());
    peer_thread.join().expect("peer thread");
}

struct DenyAll;

impl CampaignPrincipalAuthorizer for DenyAll {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crucible_campaign::CampaignAuthorizationError> {
        Err(crucible_campaign::CampaignAuthorizationError::Unauthorized)
    }
}

#[test]
fn campaign_loopback_preserves_authorization_before_repository_access() {
    let request = get_request("absent");
    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("campaign-loopback-auth", u64::MAX)),
            Arc::new(MemoryRefBackend::new()),
        );
        let service = RepositoryCampaignService::new(&repository, DenyAll);
        assert!(matches!(
            serve_loopback_campaign_once(&mut server_stream, &service),
            Err(LoopbackCampaignServerError::Service(
                RepositoryCampaignServiceError::Authorization(
                    crucible_campaign::CampaignAuthorizationError::Unauthorized
                )
            ))
        ));
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert!(client.get_campaign(&request).is_err());
    server.join().expect("server thread");
}

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("campaign-loopback-test", label.as_bytes())
}

fn snapshot(label: &str) -> CampaignSnapshotId {
    CampaignSnapshotId::parse(&format!(
        "crucible.campaign.snapshot@{}",
        ContentId::for_bytes(ObjectKind::CampaignSnapshot, 2, label.as_bytes()).encode()
    ))
    .expect("snapshot id")
}

fn lineage(label: &str) -> CampaignLineageId {
    CampaignLineageId::parse(&format!(
        "crucible.campaign.lineage@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, label.as_bytes()).encode()
    ))
    .expect("lineage id")
}

fn policy(label: &str) -> CampaignPolicyId {
    CampaignPolicyId::parse(&format!(
        "crucible.campaign.policy@{}",
        ContentId::for_bytes(ObjectKind::Policy, 1, label.as_bytes()).encode()
    ))
    .expect("policy id")
}

fn principal() -> CampaignPrincipal {
    CampaignPrincipal::new("operator:alice").expect("principal")
}

fn get_request(name: &str) -> GetCampaignRequest {
    GetCampaignRequest::new(principal(), CampaignName::new(name).expect("campaign name"))
        .expect("get request")
}

fn apply_request(name: &str) -> ApplyCampaignCommandRequest {
    ApplyCampaignCommandRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("resume")),
            expected_snapshot: snapshot("command-prior"),
            action: CampaignControlAction::Resume,
        },
    )
    .expect("apply request")
}

fn branch_submission(name: &str) -> SubmitCampaignBranchRequest {
    SubmitCampaignBranchRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot("branch-prior"),
        BranchRequest::new(
            BranchPointId::from_hash(hash("branch-point")),
            ConfigurationArtifactId::parse(&format!(
                "crucible.campaign.configuration-artifact@{}",
                ContentId::for_bytes(ObjectKind::Configuration, 1, b"parent").encode()
            ))
            .expect("parent id"),
            ChoiceOpportunityId::parse(&format!(
                "crucible.campaign.choice-opportunity@{}",
                ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"opportunity").encode()
            ))
            .expect("opportunity id"),
            ChoiceDomainId::parse(&format!(
                "crucible.campaign.choice-domain@{}",
                ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"domain").encode()
            ))
            .expect("domain id"),
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                .expect("finite source"),
            BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("branch-command"))),
            BranchBudget::new(1, 1).expect("branch budget"),
            StopCondition::NextChoice,
        )
        .expect("branch request"),
    )
    .expect("branch submission")
}
