#![allow(clippy::expect_used)]

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use crucible_campaign::{
    CampaignAuthorizationError, CampaignClient, CampaignClientError, CampaignHash, CampaignName,
    CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository, CampaignServiceFailure,
    CampaignServiceOperation, GetCampaignRequest,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};
use tempfile::tempdir;

use super::*;
use crate::{
    CampaignAccessGrant, CampaignAccessScope, CampaignLoopbackEndpointConfig,
    LoopbackCampaignService, UnixPeerCampaignBinding, UnixPeerCampaignCredentials,
    UnixPeerCampaignIdentity, UnixPeerCampaignPolicy, UnixPeerCampaignPrincipalResolver,
};

struct AllowAll;

impl CampaignPrincipalAuthorizer for AllowAll {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

struct RecordingResolver {
    observed: mpsc::Sender<UnixPeerCampaignCredentials>,
}

struct DenyResolver;

impl UnixPeerCampaignPrincipalResolver for DenyResolver {
    fn resolve_campaign_principal(
        &self,
        _credentials: UnixPeerCampaignCredentials,
    ) -> Result<CampaignPrincipal, CampaignAuthorizationError> {
        Err(CampaignAuthorizationError::Unauthorized)
    }
}

impl UnixPeerCampaignPrincipalResolver for RecordingResolver {
    fn resolve_campaign_principal(
        &self,
        credentials: UnixPeerCampaignCredentials,
    ) -> Result<CampaignPrincipal, CampaignAuthorizationError> {
        self.observed
            .send(credentials)
            .map_err(|_| CampaignAuthorizationError::Unavailable)?;
        CampaignPrincipal::new("operator:alice")
            .map_err(|_| CampaignAuthorizationError::Unavailable)
    }
}

fn request() -> GetCampaignRequest {
    GetCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("absent").expect("campaign name"),
    )
    .expect("get request")
}

fn repository(label: &str) -> Arc<CampaignRepository> {
    Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(label, u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ))
}

fn listener() -> (tempfile::TempDir, UnixListener, std::path::PathBuf) {
    let directory = tempdir().expect("temporary listener directory");
    let socket = directory.path().join("campaign.sock");
    let listener = UnixListener::bind(&socket).expect("bind campaign listener");
    (directory, listener, socket)
}

fn wait_for_no_active_connections(shutdown: &CampaignLoopbackServerShutdown) {
    for _ in 0..100 {
        if shutdown.active_connections() == 0 {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("campaign listener did not release its active connection");
}

#[test]
fn listener_reuses_one_authenticated_principal_and_joins_on_shutdown() {
    let (_directory, listener, socket) = listener();
    let (observed_tx, observed_rx) = mpsc::channel();
    let server = CampaignLoopbackServer::new(
        listener,
        repository("campaign-listener-reuse"),
        Arc::new(RecordingResolver {
            observed: observed_tx,
        }),
        Arc::new(AllowAll),
        CampaignLoopbackServerConfig::default(),
    )
    .expect("campaign server");
    let shutdown = server.shutdown_handle();
    let server_thread = thread::spawn(move || server.serve().expect("serve campaign listener"));

    let stream = UnixStream::connect(socket).expect("connect campaign client");
    let client = CampaignClient::new(LoopbackCampaignService::new(stream).expect("loopback"));
    for _ in 0..2 {
        assert!(matches!(
            client.get_campaign(&request()),
            Err(CampaignClientError::Service(
                CampaignServiceFailure::NotFound
            ))
        ));
    }
    let peer = observed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("one peer resolution");
    assert_eq!(
        peer.process_id(),
        i32::try_from(std::process::id()).expect("process id")
    );
    assert!(matches!(
        observed_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    drop(client);
    wait_for_no_active_connections(&shutdown);
    shutdown.shutdown();
    let report = server_thread.join().expect("server thread");
    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.completed_connections(), 1);
    assert_eq!(report.capacity_rejections(), 0);
    assert_eq!(report.peer_rejections(), 0);
    assert_eq!(report.protocol_failures(), 0);
}

#[test]
fn listener_request_ceiling_forces_reentry_through_connection_admission() {
    let (_directory, listener, socket) = listener();
    let (observed_tx, observed_rx) = mpsc::channel();
    let config = CampaignLoopbackServerConfig::new(
        1,
        1,
        1,
        Duration::from_millis(5),
        LoopbackCampaignTimeouts::default(),
    )
    .expect("server config");
    let server = CampaignLoopbackServer::new(
        listener,
        repository("campaign-listener-request-limit"),
        Arc::new(RecordingResolver {
            observed: observed_tx,
        }),
        Arc::new(AllowAll),
        config,
    )
    .expect("campaign server");
    let shutdown = server.shutdown_handle();
    let server_thread = thread::spawn(move || server.serve().expect("serve campaign listener"));

    let stream = UnixStream::connect(socket).expect("connect campaign client");
    let client = CampaignClient::new(LoopbackCampaignService::new(stream).expect("loopback"));
    assert!(matches!(
        client.get_campaign(&request()),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::NotFound
        ))
    ));
    assert!(matches!(
        client.get_campaign(&request()),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unavailable
        ))
    ));
    observed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("one peer resolution");
    assert!(matches!(
        observed_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    drop(client);
    wait_for_no_active_connections(&shutdown);
    shutdown.shutdown();
    let report = server_thread.join().expect("server thread");
    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.completed_connections(), 1);
    assert_eq!(report.capacity_rejections(), 0);
    assert_eq!(report.peer_rejections(), 0);
    assert_eq!(report.protocol_failures(), 0);
}

#[test]
fn listener_bounds_workers_queue_and_interrupts_active_shutdown() {
    let (_directory, listener, socket) = listener();
    let (observed_tx, observed_rx) = mpsc::channel();
    let config = CampaignLoopbackServerConfig::new(
        1,
        1,
        8,
        Duration::from_millis(5),
        LoopbackCampaignTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
            .expect("timeouts"),
    )
    .expect("server config");
    let server = CampaignLoopbackServer::new(
        listener,
        repository("campaign-listener-capacity"),
        Arc::new(RecordingResolver {
            observed: observed_tx,
        }),
        Arc::new(AllowAll),
        config,
    )
    .expect("campaign server");
    let shutdown = server.shutdown_handle();
    let server_thread = thread::spawn(move || server.serve().expect("serve campaign listener"));

    let mut active = UnixStream::connect(&socket).expect("active client");
    observed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("active peer resolution");
    assert_eq!(shutdown.active_connections(), 1);
    let queued = UnixStream::connect(&socket).expect("queued client");
    thread::sleep(Duration::from_millis(30));
    let mut rejected = UnixStream::connect(&socket).expect("rejected client");
    rejected
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("rejected read timeout");
    let mut byte = [0_u8; 1];
    assert_eq!(rejected.read(&mut byte).expect("capacity close"), 0);

    shutdown.shutdown();
    active
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("active read timeout");
    assert_eq!(active.read(&mut byte).expect("shutdown active client"), 0);
    drop(queued);
    let report = server_thread.join().expect("server thread");
    assert_eq!(report.accepted_connections(), 3);
    assert_eq!(report.capacity_rejections(), 1);
    assert_eq!(report.completed_connections(), 0);
    assert_eq!(report.peer_rejections(), 0);
    assert_eq!(report.protocol_failures(), 0);
}

#[test]
fn listener_rejects_denied_peers_before_reading_a_request() {
    let (_directory, listener, socket) = listener();
    let server = CampaignLoopbackServer::new(
        listener,
        repository("campaign-listener-denied-peer"),
        Arc::new(DenyResolver),
        Arc::new(AllowAll),
        CampaignLoopbackServerConfig::default(),
    )
    .expect("campaign server");
    let shutdown = server.shutdown_handle();
    let server_thread = thread::spawn(move || server.serve().expect("serve campaign listener"));

    let mut denied = UnixStream::connect(socket).expect("denied client");
    denied
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("denied read timeout");
    let mut byte = [0_u8; 1];
    assert_eq!(denied.read(&mut byte).expect("denied close"), 0);
    wait_for_no_active_connections(&shutdown);

    shutdown.shutdown();
    let report = server_thread.join().expect("server thread");
    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.capacity_rejections(), 0);
    assert_eq!(report.completed_connections(), 0);
    assert_eq!(report.peer_rejections(), 1);
    assert_eq!(report.protocol_failures(), 0);
}

#[test]
fn listener_enforces_the_immutable_unix_peer_policy_end_to_end() {
    let (_directory, listener, socket) = listener();
    let operator = CampaignPrincipal::new("operator:alice").expect("operator");
    let policy = Arc::new(
        UnixPeerCampaignPolicy::new(
            [UnixPeerCampaignBinding::new(
                UnixPeerCampaignIdentity::new(
                    rustix::process::geteuid().as_raw(),
                    rustix::process::getegid().as_raw(),
                ),
                operator.clone(),
            )],
            [CampaignAccessGrant::new(
                operator,
                CampaignServiceOperation::GetCampaign,
                CampaignAccessScope::Campaign(
                    CampaignName::new("absent").expect("granted campaign"),
                ),
            )],
        )
        .expect("peer policy"),
    );
    let server = CampaignLoopbackServer::new(
        listener,
        repository("campaign-listener-policy"),
        Arc::clone(&policy),
        policy,
        CampaignLoopbackServerConfig::default(),
    )
    .expect("campaign server");
    let shutdown = server.shutdown_handle();
    let server_thread = thread::spawn(move || server.serve().expect("serve campaign listener"));

    let stream = UnixStream::connect(socket).expect("connect campaign client");
    let client = CampaignClient::new(LoopbackCampaignService::new(stream).expect("loopback"));
    assert!(matches!(
        client.get_campaign(&request()),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::NotFound
        ))
    ));
    let ungranted = GetCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("operator"),
        CampaignName::new("other").expect("campaign name"),
    )
    .expect("ungranted request");
    assert!(matches!(
        client.get_campaign(&ungranted),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unauthorized
        ))
    ));
    let mismatched = GetCampaignRequest::new(
        CampaignPrincipal::new("operator:bob").expect("mismatched principal"),
        CampaignName::new("absent").expect("campaign name"),
    )
    .expect("mismatched request");
    assert!(matches!(
        client.get_campaign(&mismatched),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unauthorized
        ))
    ));

    drop(client);
    wait_for_no_active_connections(&shutdown);
    shutdown.shutdown();
    let report = server_thread.join().expect("server thread");
    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.completed_connections(), 1);
    assert_eq!(report.peer_rejections(), 0);
    assert_eq!(report.protocol_failures(), 0);
}

#[test]
fn managed_endpoint_and_loaded_policy_form_one_authenticated_server_boundary() {
    let directory = tempdir().expect("managed server directory");
    let metadata = std::fs::metadata(directory.path()).expect("managed directory metadata");
    let socket = directory.path().join("campaign.sock");
    let endpoint =
        CampaignLoopbackEndpointConfig::new(&socket, metadata.uid(), metadata.gid(), 0o600)
            .expect("managed endpoint config")
            .bind()
            .expect("bind managed endpoint");
    let policy_text = format!(
        r#"
schema = "crucible.campaign-local-policy"
version = 1
[[bindings]]
user_id = {}
group_id = {}
principal = "operator:alice"
[[grants]]
principal = "operator:alice"
operation = "get-campaign"
campaign = "absent"
"#,
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let policy = Arc::new(
        UnixPeerCampaignPolicy::from_toml_bytes(policy_text.as_bytes())
            .expect("load deployment policy"),
    );
    let server = CampaignLoopbackServer::from_managed_listener(
        endpoint,
        repository("campaign-managed-listener-policy"),
        Arc::clone(&policy),
        policy,
        CampaignLoopbackServerConfig::default(),
    )
    .expect("managed campaign server");
    let shutdown = server.shutdown_handle();
    let server_thread = thread::spawn(move || server.serve().expect("serve managed endpoint"));

    let stream = UnixStream::connect(&socket).expect("connect managed campaign client");
    let client = CampaignClient::new(LoopbackCampaignService::new(stream).expect("loopback"));
    assert!(matches!(
        client.get_campaign(&request()),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::NotFound
        ))
    ));
    drop(client);
    wait_for_no_active_connections(&shutdown);
    shutdown.shutdown();
    let report = server_thread.join().expect("managed server thread");
    assert_eq!(report.completed_connections(), 1);
    assert!(!socket.exists());
}

#[test]
fn listener_configuration_is_strictly_bounded() {
    let timeouts = LoopbackCampaignTimeouts::default();
    assert_eq!(
        CampaignLoopbackServerConfig::new(0, 1, 1, Duration::from_millis(10), timeouts),
        Err(CampaignLoopbackServerConfigError::InvalidWorkerCount)
    );
    assert_eq!(
        CampaignLoopbackServerConfig::new(
            MAX_CAMPAIGN_LISTENER_WORKERS + 1,
            1,
            1,
            Duration::from_millis(10),
            timeouts,
        ),
        Err(CampaignLoopbackServerConfigError::InvalidWorkerCount)
    );
    assert_eq!(
        CampaignLoopbackServerConfig::new(1, 0, 1, Duration::from_millis(10), timeouts),
        Err(CampaignLoopbackServerConfigError::InvalidPendingCount)
    );
    assert_eq!(
        CampaignLoopbackServerConfig::new(
            1,
            MAX_CAMPAIGN_PENDING_CONNECTIONS + 1,
            1,
            Duration::from_millis(10),
            timeouts,
        ),
        Err(CampaignLoopbackServerConfigError::InvalidPendingCount)
    );
    assert_eq!(
        CampaignLoopbackServerConfig::new(1, 1, 0, Duration::from_millis(10), timeouts),
        Err(CampaignLoopbackServerConfigError::InvalidRequestCount)
    );
    assert_eq!(
        CampaignLoopbackServerConfig::new(
            1,
            1,
            MAX_CAMPAIGN_REQUESTS_PER_CONNECTION + 1,
            Duration::from_millis(10),
            timeouts,
        ),
        Err(CampaignLoopbackServerConfigError::InvalidRequestCount)
    );
    assert_eq!(
        CampaignLoopbackServerConfig::new(1, 1, 1, Duration::ZERO, timeouts),
        Err(CampaignLoopbackServerConfigError::InvalidPollInterval)
    );
    assert_eq!(
        CampaignLoopbackServerConfig::new(1, 1, 1, Duration::from_secs(2), timeouts),
        Err(CampaignLoopbackServerConfigError::InvalidPollInterval)
    );
}

#[test]
fn shutdown_is_sticky_before_worker_startup() {
    let (_directory, listener, _socket) = listener();
    let server = CampaignLoopbackServer::new(
        listener,
        repository("campaign-listener-prestart-shutdown"),
        Arc::new(DenyResolver),
        Arc::new(AllowAll),
        CampaignLoopbackServerConfig::default(),
    )
    .expect("campaign server");
    let shutdown = server.shutdown_handle();
    shutdown.shutdown();

    let report = server.serve().expect("stopped server");
    assert!(shutdown.is_shutdown());
    assert_eq!(shutdown.active_connections(), 0);
    assert_eq!(report, CampaignLoopbackServerReport::default());
}
