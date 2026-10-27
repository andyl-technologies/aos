//! Exercises bounded negotiation reception through actual generated-service sockets.
//!
//! The fixture supplies untrusted graph and index hints, without implementing a
//! repository backend or establishing actual frontier or disclosure correctness.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use terrane_sdk::wire::{
    client::negotiation::{NegotiationClientError, NegotiationLimits, negotiate},
    services::ContentServiceClient,
    v1,
};

use super::{Running, Services, TestError, TestResult, transport};

fn hash(byte: u8) -> v1::Hash {
    v1::Hash {
        value: vec![byte; 32],
        ..Default::default()
    }
}

fn request() -> v1::NegotiateRequest {
    v1::NegotiateRequest {
        have_commits: vec![hash(7), hash(8), hash(7)],
        roots: vec![hash(9), hash(10)],
        hashes: vec![
            hash(7),
            hash(8),
            hash(7),
            hash(8),
            hash(8),
            hash(7),
            hash(7),
            hash(8),
            hash(7),
        ],
        ..Default::default()
    }
}

fn response() -> v1::NegotiateResponse {
    v1::NegotiateResponse {
        known_commits: vec![hash(7)],
        missing_nodes: vec![hash(11), hash(12)],
        missing_bitmap: vec![0b1001_1010, 0b1111_1110],
        ..Default::default()
    }
}

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

fn limits() -> Result<NegotiationLimits, NegotiationClientError> {
    NegotiationLimits::new(8, 8, 8)
}

#[tokio::test]
async fn combines_all_stages_and_preserves_maximum_request_order() -> TestResult {
    let services = Arc::new(Services::default());
    let running = Running::start(transport(services.clone(), None).await?);
    let client = client(running.address)?;

    for stages in 0..8 {
        let mut input = request();
        if stages & 1 == 0 {
            input.have_commits.clear();
        }
        if stages & 2 == 0 {
            input.roots.clear();
        }
        if stages & 4 == 0 {
            input.hashes.clear();
        }
        let hints = negotiate(&client, input, options(), limits()?).await?;

        assert_eq!(
            hints.known_commits(),
            if stages & 1 == 0 {
                &[][..]
            } else {
                &[[7; 32]; 2][..]
            }
        );
        assert_eq!(
            hints.missing_nodes(),
            if stages & 2 == 0 {
                &[][..]
            } else {
                &[[9; 32], [10; 32]][..]
            }
        );
        assert_eq!(
            hints.missing(),
            if stages & 4 == 0 {
                &[][..]
            } else {
                &[false, true, false, true, true, false, false, true, false][..]
            }
        );
    }

    let mut input = request();
    input.hashes = (0..4096)
        .map(|index| hash(if index % 3 == 0 { 7 } else { 8 }))
        .collect();
    let hints = negotiate(&client, input, options(), limits()?).await?;

    assert_eq!(
        hints.missing(),
        (0..4096).map(|index| index % 3 != 0).collect::<Vec<_>>()
    );
    assert_eq!(services.calls.load(Ordering::SeqCst), 8);
    running.stop().await
}

#[tokio::test]
async fn empty_and_invalid_inputs_never_connect() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let client = client(listener.local_addr()?)?;
    let hints = negotiate(
        &client,
        v1::NegotiateRequest::default(),
        options(),
        limits()?,
    )
    .await?;
    assert!(
        hints.known_commits().is_empty()
            && hints.missing_nodes().is_empty()
            && hints.missing().is_empty()
    );

    for (commits, roots, frontier) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert!(matches!(
            NegotiationLimits::new(commits, roots, frontier),
            Err(NegotiationClientError::Limits)
        ));
    }
    let mut excessive = request();
    excessive.hashes = vec![hash(7); 4097];
    let mut inputs = vec![excessive];
    for stage in 0..3 {
        let mut input = request();
        let values = match stage {
            0 => &mut input.have_commits,
            1 => &mut input.roots,
            _ => &mut input.hashes,
        };
        values[0].value.pop();
        inputs.push(input);
    }
    for input in inputs {
        assert!(matches!(
            negotiate(&client, input, options(), limits()?).await,
            Err(NegotiationClientError::Request)
        ));
    }
    for bound in [
        NegotiationLimits::new(2, 8, 8)?,
        NegotiationLimits::new(8, 1, 8)?,
    ] {
        assert!(matches!(
            negotiate(&client, request(), options(), bound).await,
            Err(NegotiationClientError::Request)
        ));
    }
    for invalid in [
        CallOptions::default(),
        options().with_timeout(Duration::ZERO),
        options().with_max_message_size(0),
        options().with_element_memory_limit(0),
    ] {
        assert!(matches!(
            negotiate(&client, request(), invalid, limits()?).await,
            Err(NegotiationClientError::Limits)
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
async fn refuses_unsolicited_and_malformed_hints_without_partial_results() -> TestResult {
    let mut invalid = Vec::new();
    let mut value = response();
    value.known_commits = vec![hash(99)];
    invalid.push(value);
    let mut value = response();
    value.known_commits[0].value.pop();
    invalid.push(value);
    let mut value = response();
    value.missing_nodes[0].value.push(0);
    invalid.push(value);
    for bitmap in [vec![], vec![0], vec![0; 3]] {
        let mut value = response();
        value.missing_bitmap = bitmap;
        invalid.push(value);
    }
    let mut value = response();
    value.known_commits = vec![hash(7); 4];
    invalid.push(value);
    let mut value = response();
    value.missing_nodes = vec![hash(11); 9];
    invalid.push(value);

    for value in invalid {
        let services = Arc::new(Services {
            negotiation_response: Some(value),
            ..Default::default()
        });
        let running = Running::start(transport(services, None).await?);

        let result = negotiate(&client(running.address)?, request(), options(), limits()?).await;

        assert!(matches!(result, Err(NegotiationClientError::Response)));
        running.stop().await?;
    }

    let services = Arc::new(Services {
        negotiation_response: Some(response()),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);
    let mut input = request();
    input.roots.clear();

    let result = negotiate(&client(running.address)?, input, options(), limits()?).await;

    assert!(matches!(result, Err(NegotiationClientError::Response)));
    running.stop().await
}

#[tokio::test]
async fn retains_transport_bounds_deadlines_and_unused_tail_bits() -> TestResult {
    let services = Arc::new(Services {
        negotiation_response: Some(response()),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);

    let hints = negotiate(&client(running.address)?, request(), options(), limits()?).await?;

    assert_eq!(hints.known_commits(), [[7; 32]]);
    assert_eq!(hints.missing_nodes(), [[11; 32], [12; 32]]);
    assert_eq!(
        hints.missing(),
        [false, true, false, true, true, false, false, true, false]
    );
    running.stop().await?;

    let mut oversized = response();
    oversized.missing_bitmap = vec![0; 8192];
    let services = Arc::new(Services {
        negotiation_response: Some(oversized),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);

    let result = negotiate(
        &client(running.address)?,
        request(),
        options().with_max_message_size(1024),
        limits()?,
    )
    .await;

    assert!(matches!(result, Err(NegotiationClientError::Transport(_))));
    running.stop().await?;

    let services = Arc::new(Services {
        negotiation_delay: Duration::from_millis(200),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);

    let result = negotiate(
        &client(running.address)?,
        request(),
        options().with_timeout(Duration::from_millis(20)),
        limits()?,
    )
    .await;

    match result {
        Err(NegotiationClientError::Deadline) => {}
        Err(NegotiationClientError::Transport(error)) => {
            assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded)
        }
        result => panic!("negotiation completed beyond its deadline: {result:?}"),
    }
    running.stop().await
}
