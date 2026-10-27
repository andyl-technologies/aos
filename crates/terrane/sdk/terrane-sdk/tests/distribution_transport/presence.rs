//! Checks bounded membership reception against actual generated-service sockets.
//!
//! Fixture bitmaps are peer assertions, without repository or index authority.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use terrane_sdk::wire::{
    client::presence::{PresenceClientError, has},
    services::ContentServiceClient,
};

use super::{Running, Services, TestError, TestResult, transport};

fn client(address: std::net::SocketAddr) -> Result<ContentServiceClient<HttpClient>, TestError> {
    Ok(ContentServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(format!("http://{address}").parse()?),
    ))
}

fn options() -> CallOptions {
    CallOptions::default()
        .with_timeout(Duration::from_secs(2))
        .with_max_message_size(1024 * 1024)
        .with_element_memory_limit(1024 * 1024)
}

#[tokio::test]
async fn preserves_order_duplicates_and_maximum_batch() -> TestResult {
    let services = Arc::new(Services::default());
    let running = Running::start(transport(services.clone(), None).await?);
    let client = client(running.address)?;
    let hashes = (0..4096)
        .map(|position| if position % 3 == 0 { [7; 32] } else { [8; 32] })
        .collect::<Vec<_>>();

    let result = has(&client, &hashes, options()).await?;

    assert_eq!(
        result,
        (0..4096)
            .map(|position| position % 3 == 0)
            .collect::<Vec<_>>()
    );
    assert_eq!(services.calls.load(Ordering::SeqCst), 1);
    running.stop().await
}

#[tokio::test]
async fn empty_and_refused_requests_never_connect() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let client = client(listener.local_addr()?)?;

    assert!(has(&client, &[], options()).await?.is_empty());
    assert!(matches!(
        has(&client, &vec![[7; 32]; 4097], options()).await,
        Err(PresenceClientError::Batch)
    ));
    for invalid in [
        CallOptions::default(),
        options().with_timeout(Duration::ZERO),
        options().with_max_message_size(0),
        options().with_element_memory_limit(0),
    ] {
        assert!(matches!(
            has(&client, &[[7; 32]], invalid).await,
            Err(PresenceClientError::Limits)
        ));
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn refuses_missing_or_extra_bitmap_bytes_without_partial_hints() -> TestResult {
    for bitmap in [vec![], vec![1], vec![1, 0, 0]] {
        let services = Arc::new(Services {
            has_bitmap: Some(bitmap),
            ..Default::default()
        });
        let running = Running::start(transport(services, None).await?);

        let result = has(&client(running.address)?, &[[7; 32]; 9], options()).await;

        assert!(matches!(result, Err(PresenceClientError::Bitmap)));
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ignores_unused_bits_but_preserves_each_requested_bit() -> TestResult {
    let services = Arc::new(Services {
        has_bitmap: Some(vec![0b0101_0010, 0b1111_1110]),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);

    let result = has(&client(running.address)?, &[[7; 32]; 9], options()).await?;

    assert_eq!(
        result,
        [false, true, false, false, true, false, true, false, false]
    );
    running.stop().await
}

#[tokio::test]
async fn retains_transport_bounds_and_whole_call_deadline() -> TestResult {
    let services = Arc::new(Services {
        has_bitmap: Some(vec![0; 8192]),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);

    let result = has(
        &client(running.address)?,
        &[[7; 32]],
        options().with_max_message_size(1024),
    )
    .await;

    assert!(matches!(result, Err(PresenceClientError::Transport(_))));
    running.stop().await?;

    let services = Arc::new(Services {
        has_delay: Duration::from_millis(200),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);

    let result = has(
        &client(running.address)?,
        &[[7; 32]],
        options().with_timeout(Duration::from_millis(20)),
    )
    .await;

    match result {
        Err(PresenceClientError::Deadline) => {}
        Err(PresenceClientError::Transport(error)) => {
            assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
        }
        result => panic!("membership call completed beyond its deadline: {result:?}"),
    }
    running.stop().await
}
