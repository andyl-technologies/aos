//! Actual capture descriptors and authenticated listener refusal under pressure.

// crucible-lint: allow panic-shortcut -- owned descriptor fixtures localize assertion failures.
#![allow(clippy::expect_used)]

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

use crucible_campaign::{
    CampaignAuthorizationError, CampaignClient, CampaignClientError, CampaignHash, CampaignName,
    CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository, CampaignServiceFailure,
    CampaignServiceFailureCategory, CampaignServiceOperation, GetCampaignRequest,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};
use crucible_daemon::{
    CampaignConnectionDiagnostic, CampaignLoopbackServer, CampaignLoopbackServerConfig,
    LoopbackCampaignService, LoopbackCampaignTimeouts, UnixPeerCampaignCredentials,
    UnixPeerCampaignPrincipalResolver,
};

use super::*;

fn failure() -> CampaignServiceDiagnostic {
    CampaignServiceDiagnostic::RequestFailure {
        operation: CampaignServiceOperation::SubmitBranchRequest,
        request_digest: CampaignHash::derive("failure-diagnostic-test", b"request"),
        failure: CampaignServiceFailure::Unavailable,
    }
}

fn contents(file: &File) -> String {
    let mut reader = file.try_clone().expect("capture reader");
    reader
        .seek(SeekFrom::Start(0))
        .expect("read capture from start");
    let mut result = String::new();
    reader
        .read_to_string(&mut result)
        .expect("read ASCII capture");
    result
}

fn destination_identity(sink: &BoundedFailureDiagnostics) -> (i32, u64, u64) {
    let destination = sink.destination.lock().expect("owned destination");
    let metadata = destination.metadata().expect("destination identity");
    (destination.as_raw_fd(), metadata.dev(), metadata.ino())
}

fn assert_closed((descriptor, device, inode): (i32, u64, u64)) {
    // Inspect only the exact descriptor we owned. Other parallel tests may reuse
    // the number, but cannot own this private capture object.
    if let Ok(metadata) = std::fs::metadata(format!("/proc/self/fd/{descriptor}")) {
        assert_ne!((metadata.dev(), metadata.ino()), (device, inode));
    }
}

#[test]
fn disabled_exhausted_and_interleaved_capture_preserve_original_bytes() {
    assert!(diagnostic_sink(None).is_none());
    let mut capture = tempfile::tempfile().expect("capture");
    let flags = rustix::fs::fcntl_getfl(&capture).expect("original flags");
    let sink = BoundedFailureDiagnostics::from_descriptor(2, &capture).expect("sink");
    let destination_identity = destination_identity(&sink);
    assert!(
        rustix::io::fcntl_getfd(&*sink.destination.lock().expect("regular destination"))
            .expect("regular descriptor flags")
            .contains(rustix::io::FdFlags::CLOEXEC)
    );

    capture
        .write_all(b"original-before\n")
        .expect("original write");
    sink.record(failure());
    capture
        .write_all(b"original-between\n")
        .expect("interleaved write");
    sink.record(failure());
    let held = sink.destination.lock().expect("hold exhausted destination");
    sink.record(failure());
    drop(held);
    capture
        .write_all(b"original-after\n")
        .expect("final original write");

    assert_eq!(
        rustix::fs::fcntl_getfl(&capture).expect("retained flags"),
        flags
    );
    assert_eq!(sink.remaining.load(Ordering::Relaxed), 0);
    drop(sink);
    assert_closed(destination_identity);
    assert_eq!(
        contents(&capture),
        format!(
            "original-before\n{}original-between\n{}original-after\n",
            format_record(failure()),
            format_record(failure()),
        )
    );
}

#[test]
fn finite_records_fit_the_bound_and_failed_writes_are_nonfatal() {
    let capture = tempfile::tempfile().expect("capture");
    let sink = BoundedFailureDiagnostics::from_descriptor(256, &capture).expect("sink");
    let request_digest = CampaignHash::derive("failure-diagnostic-test", b"longest");

    sink.record(CampaignServiceDiagnostic::RequestFailure {
        operation: CampaignServiceOperation::GetCampaignFindingTriageReplaySegment,
        request_digest,
        failure: CampaignServiceFailure::AuthorizationUnavailable,
    });
    for category in [
        CampaignServiceFailureCategory::Missing,
        CampaignServiceFailureCategory::Unavailable,
        CampaignServiceFailureCategory::Io,
        CampaignServiceFailureCategory::StreamIo,
    ] {
        sink.record(CampaignServiceDiagnostic::RequestFailureSource {
            operation: CampaignServiceOperation::SubmitBranchRequest,
            request_digest,
            category,
        });
    }
    sink.record(CampaignServiceDiagnostic::ConnectionFailure(
        CampaignConnectionDiagnostic::CapacityRejected,
    ));
    let named = tempfile::NamedTempFile::new().expect("read-only capture");
    let read_only = File::open(named.path()).expect("read-only descriptor");
    let broken = BoundedFailureDiagnostics::from_descriptor(1, &read_only).expect("broken sink");
    broken.record(failure());

    let text = contents(&capture);
    assert_eq!(text.lines().count(), 6);
    assert!(text.is_ascii());
    assert!(text.lines().all(|line| line.len() < MAX_RECORD_BYTES));
    assert!(text.contains("source=StreamIo"));
    assert!(text.contains("kind=connection category=CapacityRejected"));
    assert_eq!(broken.remaining.load(Ordering::Relaxed), 0);
    assert!(contents(&read_only).is_empty());
}

struct AuthenticatedPeer;

impl UnixPeerCampaignPrincipalResolver for AuthenticatedPeer {
    fn resolve_campaign_principal(
        &self,
        credentials: UnixPeerCampaignCredentials,
    ) -> Result<CampaignPrincipal, CampaignAuthorizationError> {
        if credentials.user_id() != rustix::process::geteuid().as_raw() {
            return Err(CampaignAuthorizationError::Unauthorized);
        }
        CampaignPrincipal::new("operator:alice")
            .map_err(|_| CampaignAuthorizationError::Unavailable)
    }
}

impl CampaignPrincipalAuthorizer for AuthenticatedPeer {
    fn authorize(
        &self,
        _: &CampaignPrincipal,
        _: CampaignServiceOperation,
        _: &CampaignName,
        _: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

fn assert_listener_refusal(sink: Arc<BoundedFailureDiagnostics>, release: impl FnOnce()) {
    let directory = tempfile::tempdir().expect("listener owner");
    let socket = directory.path().join("campaign.sock");
    let listener = UnixListener::bind(&socket).expect("listener");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("backpressure", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let server = CampaignLoopbackServer::new(
        listener,
        repository,
        Arc::new(AuthenticatedPeer),
        Arc::new(AuthenticatedPeer),
        CampaignLoopbackServerConfig::default(),
    )
    .expect("server")
    .with_diagnostic_sink(sink);
    let shutdown = server.shutdown_handle();
    let server_thread = thread::spawn(move || server.serve());
    let stream = UnixStream::connect(socket).expect("connect real peer");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("finite response wait");
    let client = CampaignClient::new(
        LoopbackCampaignService::with_timeouts(
            stream,
            LoopbackCampaignTimeouts::new(Duration::from_secs(2), Duration::from_secs(2))
                .expect("finite exchange"),
        )
        .expect("client"),
    );
    let request = GetCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("absent").expect("campaign"),
    )
    .expect("request");

    let result = client.get_campaign(&request);
    drop(client);
    release();
    shutdown.shutdown();
    let joined = server_thread.join().expect("owned listener joined");

    assert!(matches!(
        result,
        Err(CampaignClientError::Service(
            CampaignServiceFailure::NotFound
        ))
    ));
    assert!(joined.is_ok());
}

#[test]
fn full_pipe_and_busy_destination_do_not_strand_authenticated_refusal() {
    let pipe_owner = tempfile::tempdir().expect("owned FIFO directory");
    let pipe_path = pipe_owner.path().join("diagnostics");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &pipe_path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .expect("owned FIFO");
    let reader = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(&pipe_path)
        .expect("owned pipe reader");
    let writer = OpenOptions::new()
        .write(true)
        .open(&pipe_path)
        .expect("original blocking writer");
    let flags = rustix::fs::fcntl_getfl(&writer).expect("original writer flags");
    let sink = Arc::new(BoundedFailureDiagnostics::from_descriptor(3, &writer).expect("pipe sink"));
    let destination_identity = destination_identity(&sink);
    let destination = sink.destination.lock().expect("fill private destination");
    assert!(
        rustix::io::fcntl_getfd(&*destination)
            .expect("private descriptor flags")
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    assert!(
        rustix::fs::fcntl_getfl(&*destination)
            .expect("private flags")
            .contains(rustix::fs::OFlags::NONBLOCK)
    );
    let mut full = false;
    for _ in 0..1024 {
        match rustix::io::write(&*destination, &[0; 4096]) {
            Ok(_) => {}
            Err(rustix::io::Errno::AGAIN) => {
                full = true;
                break;
            }
            Err(error) => panic!("fill private pipe: {error}"),
        }
    }
    assert!(full, "finite pipe capacity reached");
    drop(destination);

    assert_listener_refusal(sink.clone(), || {
        let mut drain = [0; 4096];
        let _ =
            rustix::io::read(&reader, &mut drain).expect("release full destination before join");
    });
    let held = sink.destination.lock().expect("busy destination");
    assert_listener_refusal(sink.clone(), || drop(held));

    assert_eq!(
        rustix::fs::fcntl_getfl(&writer).expect("original flags unchanged"),
        flags
    );
    assert_eq!(sink.remaining.load(Ordering::Relaxed), 1);
    drop(sink);
    assert_closed(destination_identity);
    drop(writer);
    let mut reader = reader;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).expect("owned pipe EOF");
    assert!(!bytes.is_empty());
}

#[test]
fn unsupported_socket_destination_is_refused_without_changing_flags() {
    let (writer, _reader) = UnixStream::pair().expect("owned socket pair");
    let flags = rustix::fs::fcntl_getfl(&writer).expect("original socket flags");

    let result = BoundedFailureDiagnostics::from_descriptor(1, &writer);

    assert!(result.is_err());
    assert_eq!(
        rustix::fs::fcntl_getfl(&writer).expect("retained flags"),
        flags
    );
}
