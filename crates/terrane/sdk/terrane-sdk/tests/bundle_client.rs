//! Checks private bundle reception through actual generated-client HTTP streams.
//!
//! The byte-serving peers are framing fixtures, not authorized repository servers.

#![cfg(all(feature = "tokio", not(target_arch = "wasm32")))]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use buffa::Message;
use connectrpc::client::CallOptions;
use terrane_format::chunking::ChunkProfile;
use terrane_sdk::{
    pack::{BundleObject, EntryKind},
    repository::MetadataValidator,
    store::{ContentValidator, MetaUpload, StoreFailure},
    wire::{
        bundle::{BundleError, BundleLimits},
        client::{BundleClientError, get_bundle},
        v1::{self, bundle_frame::Frame, get_bundle_request::Root},
    },
};
use tokio::net::TcpListener;

#[path = "support/rpc_peer.rs"]
mod rpc_peer;
use rpc_peer::{Peer, TestError, TestResult, client, envelope};

fn options() -> CallOptions {
    CallOptions::default()
        .with_timeout(Duration::from_secs(2))
        .with_max_message_size(4096)
        .with_element_memory_limit(16384)
}

fn limits() -> Result<BundleLimits, BundleError> {
    BundleLimits::new(8, 2048, 4096, 1024)
}

fn request(include_profile: bool) -> Result<v1::GetBundleRequest, TestError> {
    Ok(v1::GetBundleRequest {
        root: Some(Root::TreeRoot(Box::new(v1::Hash {
            value: node()?.hash().to_vec(),
            ..Default::default()
        }))),
        include_profile,
        ..Default::default()
    })
}

fn data(frame: Frame) -> Result<Vec<u8>, TestError> {
    envelope(
        0,
        &v1::BundleFrame {
            frame: Some(frame),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn node() -> Result<BundleObject, TestError> {
    Ok(BundleObject::new(
        EntryKind::Node,
        vec![0xa2, 1, 0, 2, 0x80],
    )?)
}

fn object(value: &BundleObject) -> v1::MetaObject {
    v1::MetaObject {
        hash: v1::Hash {
            value: value.hash().to_vec(),
            ..Default::default()
        }
        .into(),
        kind: value.kind() as u32,
        encoded: value.bytes().to_vec(),
        ..Default::default()
    }
}

fn metadata() -> Result<Vec<u8>, TestError> {
    data(Frame::Object(Box::new(object(&node()?))))
}

fn end() -> Result<Vec<u8>, TestError> {
    envelope(2, b"{}")
}

struct Validator {
    inner: MetadataValidator,
    calls: AtomicUsize,
    delay: Duration,
}

impl Validator {
    fn new(delay: Duration) -> Self {
        Self {
            inner: MetadataValidator::new(ChunkProfile::cdc_1m([42; 32])),
            calls: AtomicUsize::new(0),
            delay,
        }
    }
}

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        self.inner.validate_meta(upload)
    }
}

#[tokio::test]
async fn successful_terminal_metadata_allows_registered_schema_and_requested_profile() -> TestResult
{
    let body = [
        metadata()?,
        data(Frame::AccessProfile(vec![0xff, 0]))?,
        end()?,
    ]
    .concat();
    let peer = Peer::complete(body).await?;
    let validator = Validator::new(Duration::ZERO);

    let bundle = get_bundle(
        &client(peer.address)?,
        request(true)?,
        options(),
        limits()?,
        &validator,
    )
    .await?;

    assert_eq!(bundle.objects(), [node()?]);
    assert_eq!(bundle.access_profile(), Some([0xff, 0].as_slice()));
    assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
    peer.stop().await
}

#[tokio::test]
async fn protocol_error_after_metadata_discards_objects_before_schema_validation() -> TestResult {
    let body = [
        metadata()?,
        envelope(
            2,
            br#"{"error":{"code":"unavailable","message":"fixture refusal"}}"#,
        )?,
    ]
    .concat();
    let peer = Peer::complete(body).await?;
    let validator = Validator::new(Duration::ZERO);

    let result = get_bundle(
        &client(peer.address)?,
        request(false)?,
        options(),
        limits()?,
        &validator,
    )
    .await;

    assert!(matches!(result, Err(BundleClientError::Transport(_))));
    assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
    peer.stop().await
}

#[tokio::test]
async fn plain_body_eof_incomplete_termination_and_transport_cutoff_never_complete() -> TestResult {
    let mut incomplete = [metadata()?, end()?].concat();
    incomplete.pop();
    for (body, extra_promised) in [(metadata()?, 0), (incomplete, 0), (metadata()?, 100)] {
        let promised = body.len() + extra_promised;
        let peer = Peer::start(body, promised, false).await?;
        let validator = Validator::new(Duration::ZERO);

        let result = get_bundle(
            &client(peer.address)?,
            request(false)?,
            options(),
            limits()?,
            &validator,
        )
        .await;

        assert!(matches!(result, Err(BundleClientError::Transport(_))));
        assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
        peer.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn whole_call_deadline_drops_pending_response_without_exposing_metadata() -> TestResult {
    let body = metadata()?;
    let peer = Peer::start(body.clone(), body.len() + 100, true).await?;
    let validator = Validator::new(Duration::ZERO);
    let bounded = options().with_timeout(Duration::from_millis(100));

    let result = get_bundle(
        &client(peer.address)?,
        request(false)?,
        bounded,
        limits()?,
        &validator,
    )
    .await;

    match result {
        Err(BundleClientError::Deadline) => {}
        Err(BundleClientError::Transport(error)) => {
            assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
        }
        _ => return Err("pending response did not reach its deadline".into()),
    }
    assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
    let disconnected = Arc::clone(&peer.disconnected);
    peer.stop().await?;
    assert!(disconnected.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn caller_cancellation_closes_the_actual_response_stream() -> TestResult {
    let body = metadata()?;
    let mut peer = Peer::start(body.clone(), body.len() + 100, true).await?;
    let validator = Arc::new(Validator::new(Duration::ZERO));
    let read_validator = Arc::clone(&validator);
    let client = client(peer.address)?;
    let resources = limits()?;
    let selected = request(false)?;
    let read = tokio::spawn(async move {
        get_bundle(
            &client,
            selected,
            options(),
            resources,
            read_validator.as_ref(),
        )
        .await
    });
    (&mut peer.sent).await?;

    read.abort();

    assert!(read.await.is_err_and(|error| error.is_cancelled()));
    let disconnected = Arc::clone(&peer.disconnected);
    peer.stop().await?;
    assert!(disconnected.load(Ordering::SeqCst));
    assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn decoder_bounds_and_metadata_refusals_return_no_partial_result() -> TestResult {
    let mut wrong = object(&node()?);
    wrong.hash = v1::Hash {
        value: vec![0; 32],
        ..Default::default()
    }
    .into();
    let invalid_schema = BundleObject::new(EntryKind::Node, vec![0xa1, 1, 0])?;
    let mut oversized = object(&node()?);
    oversized.encoded = vec![0; 8192];
    for (frame, transport_error) in [
        (Frame::Object(Box::new(wrong)), false),
        (Frame::Object(Box::new(object(&invalid_schema))), false),
        (Frame::AccessProfile(vec![1]), false),
        (Frame::Object(Box::new(oversized)), true),
    ] {
        let peer = Peer::complete([data(frame)?, end()?].concat()).await?;
        let validator = Validator::new(Duration::ZERO);

        let result = get_bundle(
            &client(peer.address)?,
            request(false)?,
            options(),
            limits()?,
            &validator,
        )
        .await;

        if transport_error {
            assert!(matches!(result, Err(BundleClientError::Transport(_))));
        } else {
            assert!(matches!(result, Err(BundleClientError::Bundle(_))));
        }
        peer.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn missing_zero_and_unrepresentable_call_limits_refuse_before_connecting() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = client(listener.local_addr()?)?;
    let validator = Validator::new(Duration::ZERO);
    for bounds in [
        CallOptions::default(),
        CallOptions::default()
            .with_timeout(Duration::from_secs(1))
            .with_max_message_size(4096),
        options().with_timeout(Duration::ZERO),
        options().with_timeout(Duration::MAX),
        options().with_max_message_size(0),
        options().with_element_memory_limit(0),
    ] {
        assert!(matches!(
            get_bundle(&client, request(false)?, bounds, limits()?, &validator).await,
            Err(BundleClientError::Limits)
        ));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn synchronous_schema_completion_after_deadline_is_refused() -> TestResult {
    let peer = Peer::complete([metadata()?, end()?].concat()).await?;
    let validator = Validator::new(Duration::from_millis(200));
    let bounded = options().with_timeout(Duration::from_millis(100));

    let result = get_bundle(
        &client(peer.address)?,
        request(false)?,
        bounded,
        limits()?,
        &validator,
    )
    .await;

    assert!(matches!(result, Err(BundleClientError::Deadline)));
    assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
    peer.stop().await
}

#[tokio::test]
async fn clean_protocol_termination_accepts_all_held_empty_results() -> TestResult {
    for profile in [false, true] {
        let peer = Peer::complete(end()?).await?;
        let validator = Validator::new(Duration::ZERO);
        let mut selected = request(profile)?;
        selected.have_nodes.push(v1::Hash {
            value: node()?.hash().to_vec(),
            ..Default::default()
        });

        let result = get_bundle(
            &client(peer.address)?,
            selected,
            options(),
            limits()?,
            &validator,
        )
        .await?;

        assert!(result.objects().is_empty());
        assert!(result.access_profile().is_none());
        assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
        peer.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn aggregate_bundle_limit_refuses_after_valid_metadata_before_validation() -> TestResult {
    let body = [metadata()?, data(Frame::AccessProfile(vec![1]))?, end()?].concat();
    let peer = Peer::complete(body).await?;
    let validator = Validator::new(Duration::ZERO);
    let bytes = node()?.bytes().len();
    let bounded = BundleLimits::new(8, bytes, bytes, bytes)?;

    let result = get_bundle(
        &client(peer.address)?,
        request(true)?,
        options(),
        bounded,
        &validator,
    )
    .await;

    assert!(matches!(
        result,
        Err(BundleClientError::Bundle(BundleError::Limit))
    ));
    assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
    peer.stop().await
}
