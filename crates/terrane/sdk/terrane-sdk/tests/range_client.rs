//! Checks private exact range reception through actual generated-client sockets.
//!
//! Framing peers supply untrusted bytes and establish no repository authority.

#![cfg(all(feature = "tokio", not(target_arch = "wasm32")))]

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use buffa::Message;
use connectrpc::client::CallOptions;
use terrane_sdk::wire::{
    client::range::{RangeClientError, RangeLimits, get_range},
    v1,
};
use tokio::net::TcpListener;

#[path = "support/rpc_peer.rs"]
mod rpc_peer;
use rpc_peer::{Peer, TestError, TestResult, client, envelope};

fn options() -> CallOptions {
    CallOptions::default()
        .with_timeout(Duration::from_secs(2))
        .with_max_message_size(5 * 1024 * 1024)
        .with_element_memory_limit(16384)
}

fn limits() -> Result<RangeLimits, RangeClientError> {
    RangeLimits::new(8 * 1024 * 1024, 8)
}

fn request(offset: u64, length: u64) -> v1::GetRangeRequest {
    v1::GetRangeRequest {
        range: v1::Range {
            pack: v1::PackId {
                value: vec![17; 16],
                ..Default::default()
            }
            .into(),
            offset,
            length,
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }
}

fn data(offset: u64, bytes: &[u8]) -> Result<Vec<u8>, TestError> {
    envelope(
        0,
        &v1::GetRangeFrame {
            offset,
            data: bytes.to_vec(),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn end() -> Result<Vec<u8>, TestError> {
    envelope(2, b"{}")
}

#[tokio::test]
async fn contiguous_absolute_offsets_and_successful_termination_return_exact_private_bytes()
-> TestResult {
    let body = [data(19, b"abc")?, data(22, b"de")?, end()?].concat();
    let peer = Peer::complete(body).await?;

    let range = get_range(&client(peer.address)?, request(19, 5), options(), limits()?).await?;

    assert_eq!(range.pack(), &[17; 16]);
    assert_eq!(range.offset(), 19);
    assert_eq!(range.bytes(), b"abcde");
    assert_eq!(range.into_bytes(), b"abcde");
    peer.stop().await
}

#[tokio::test]
async fn exact_coverage_never_substitutes_for_successful_protocol_termination() -> TestResult {
    for closing in [
        Vec::new(),
        envelope(2, b"{")?,
        envelope(
            2,
            br#"{"error":{"code":"unavailable","message":"refused"}}"#,
        )?,
    ] {
        let body = [data(19, b"abcde")?, closing].concat();
        let peer = Peer::complete(body).await?;

        let result = get_range(&client(peer.address)?, request(19, 5), options(), limits()?).await;

        assert!(matches!(result, Err(RangeClientError::Transport(_))));
        peer.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn gaps_overlap_reordering_empty_frames_and_short_results_are_refused() -> TestResult {
    let bodies = [
        vec![data(20, b"abcde")?],
        vec![data(19, b"abc")?, data(21, b"de")?],
        vec![data(22, b"de")?, data(19, b"abc")?],
        vec![data(19, b"")?],
        vec![data(19, b"abcd")?],
        vec![],
        vec![data(19, b"abcde")?, data(24, b"")?],
    ];
    for frames in bodies {
        let body = [frames.concat(), end()?].concat();
        let peer = Peer::complete(body).await?;

        let result = get_range(&client(peer.address)?, request(19, 5), options(), limits()?).await;

        assert!(matches!(result, Err(RangeClientError::Coverage)));
        peer.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn excess_bytes_frames_and_protocol_frame_size_are_refused() -> TestResult {
    let bodies = [
        (vec![data(19, b"abcdef")?], request(19, 5), limits()?),
        (
            vec![data(19, b"a")?, data(20, b"b")?],
            request(19, 2),
            RangeLimits::new(2, 1)?,
        ),
        (
            vec![data(19, &vec![0; 4 * 1024 * 1024 + 1])?],
            request(19, 4 * 1024 * 1024 + 1),
            limits()?,
        ),
    ];
    for (frames, selected, resources) in bodies {
        let body = [frames.concat(), end()?].concat();
        let peer = Peer::complete(body).await?;

        let result = get_range(&client(peer.address)?, selected, options(), resources).await;

        assert!(matches!(result, Err(RangeClientError::Limit)));
        peer.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn empty_range_requires_successful_termination_without_data() -> TestResult {
    let peer = Peer::complete(end()?).await?;

    let range = get_range(
        &client(peer.address)?,
        request(u64::MAX, 0),
        options(),
        limits()?,
    )
    .await?;

    assert!(range.bytes().is_empty());
    assert_eq!(range.offset(), u64::MAX);
    peer.stop().await?;

    let peer = Peer::complete([data(19, b"a")?, end()?].concat()).await?;
    let result = get_range(&client(peer.address)?, request(19, 0), options(), limits()?).await;
    assert!(matches!(result, Err(RangeClientError::Limit)));
    peer.stop().await
}

#[tokio::test]
async fn malformed_requests_and_resource_excess_refuse_before_connecting() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = client(listener.local_addr()?)?;
    let mut missing_pack = request(19, 5);
    missing_pack
        .range
        .as_option_mut()
        .ok_or("missing fixture range")?
        .pack = Default::default();
    let mut invalid_pack = request(19, 5);
    invalid_pack
        .range
        .as_option_mut()
        .ok_or("missing fixture range")?
        .pack
        .as_option_mut()
        .ok_or("missing fixture pack")?
        .value = vec![17; 15];
    for selected in [
        v1::GetRangeRequest::default(),
        missing_pack,
        invalid_pack,
        request(u64::MAX, 1),
    ] {
        let result = get_range(&client, selected, options(), limits()?).await;
        assert!(matches!(result, Err(RangeClientError::Request)));
    }
    let result = get_range(&client, request(19, 3), options(), RangeLimits::new(2, 1)?).await;
    assert!(matches!(result, Err(RangeClientError::Limit)));
    for bounded in [
        CallOptions::default(),
        options().with_timeout(Duration::ZERO),
        options().with_timeout(Duration::MAX),
        options().with_max_message_size(0),
        options().with_element_memory_limit(0),
    ] {
        let result = get_range(&client, request(19, 5), bounded, limits()?).await;
        assert!(matches!(result, Err(RangeClientError::Limits)));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn decoder_and_transport_cutoff_refuse_without_partial_bytes() -> TestResult {
    let body = [data(19, &vec![0; 8192])?, end()?].concat();
    let peer = Peer::complete(body).await?;
    let result = get_range(
        &client(peer.address)?,
        request(19, 8192),
        options().with_max_message_size(4096),
        limits()?,
    )
    .await;
    assert!(matches!(result, Err(RangeClientError::Transport(_))));
    peer.stop().await?;

    let body = data(19, b"abcde")?;
    let peer = Peer::start(body.clone(), body.len() + 100, false).await?;
    let result = get_range(&client(peer.address)?, request(19, 5), options(), limits()?).await;
    assert!(matches!(result, Err(RangeClientError::Transport(_))));
    peer.stop().await
}

#[tokio::test]
async fn whole_call_deadline_closes_pending_actual_response_stream() -> TestResult {
    let body = data(19, b"abcde")?;
    let peer = Peer::start(body.clone(), body.len() + 100, true).await?;

    let result = get_range(
        &client(peer.address)?,
        request(19, 5),
        options().with_timeout(Duration::from_millis(100)),
        limits()?,
    )
    .await;

    match result {
        Err(RangeClientError::Deadline) => {}
        Err(RangeClientError::Transport(error)) => {
            assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded)
        }
        _ => return Err("pending range response did not reach its deadline".into()),
    }
    let disconnected = Arc::clone(&peer.disconnected);
    peer.stop().await?;
    assert!(disconnected.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn caller_cancellation_closes_actual_response_and_discards_pending_bytes() -> TestResult {
    let body = data(19, b"abcde")?;
    let mut peer = Peer::start(body.clone(), body.len() + 100, true).await?;
    let client = client(peer.address)?;
    let resources = limits()?;
    let read =
        tokio::spawn(async move { get_range(&client, request(19, 5), options(), resources).await });
    (&mut peer.sent).await?;

    read.abort();

    assert!(read.await.is_err_and(|error| error.is_cancelled()));
    let disconnected = Arc::clone(&peer.disconnected);
    peer.stop().await?;
    assert!(disconnected.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn unbounded_or_zero_buffer_limits_are_refused() {
    for (bytes, frames) in [(0, 1), (1, 0), (1024 * 1024 * 1024 + 1, 1), (1, 1_048_577)] {
        assert!(matches!(
            RangeLimits::new(bytes, frames),
            Err(RangeClientError::Limits)
        ));
    }
}

#[tokio::test]
async fn maximum_legal_frame_and_near_limit_offsets_preserve_exact_coverage() -> TestResult {
    let bytes = vec![31; 4 * 1024 * 1024];
    let body = [
        data(19, &bytes)?,
        data(19 + bytes.len() as u64, b"z")?,
        end()?,
    ]
    .concat();
    let peer = Peer::complete(body).await?;

    let range = get_range(
        &client(peer.address)?,
        request(19, bytes.len() as u64 + 1),
        options(),
        limits()?,
    )
    .await?;

    assert_eq!(&range.bytes()[..bytes.len()], bytes);
    assert_eq!(range.bytes().last(), Some(&b'z'));
    peer.stop().await?;

    let peer = Peer::complete([data(u64::MAX - 1, b"a")?, end()?].concat()).await?;
    let range = get_range(
        &client(peer.address)?,
        request(u64::MAX - 1, 1),
        options(),
        limits()?,
    )
    .await?;
    assert_eq!(range.bytes(), b"a");
    peer.stop().await?;

    let peer = Peer::complete([data(u64::MAX - 1, b"ab")?, end()?].concat()).await?;
    let result = get_range(
        &client(peer.address)?,
        request(u64::MAX - 1, 1),
        options(),
        limits()?,
    )
    .await;
    assert!(matches!(result, Err(RangeClientError::Coverage)));
    peer.stop().await
}
