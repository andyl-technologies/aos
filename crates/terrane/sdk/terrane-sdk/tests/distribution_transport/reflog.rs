//! Checks bounded finite reflog reception across actual native service sockets.
//!
//! Fixture records establish no verified commit signature, committed history,
//! predecessor selection or current repository authority.

use std::{
    num::NonZeroUsize,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use terrane_format::refs::{Locality, RefLogReason, RefLogRecord, RefRecord};
use terrane_sdk::wire::{
    client::reflog::{RefLogClientError, RefLogLimits, get_ref_log},
    refs::{RefCodec, RefWireError},
    services::RefServiceClient,
    v1,
};

use super::{Running, Services, TestError, TestResult, transport};

const NAME: &str = "refs/heads/_/main";

fn client(address: std::net::SocketAddr) -> Result<RefServiceClient<HttpClient>, TestError> {
    Ok(RefServiceClient::new(
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

fn limits(entries: usize, bytes: usize) -> Result<RefLogLimits, TestError> {
    Ok(RefLogLimits {
        max_entries: NonZeroUsize::new(entries).ok_or("zero fixture entry bound")?,
        max_content_bytes: NonZeroUsize::new(bytes).ok_or("zero fixture byte bound")?,
    })
}

fn request(from_sequence: u64) -> v1::GetRefLogRequest {
    v1::GetRefLogRequest {
        name: NAME.into(),
        from_sequence,
        ..Default::default()
    }
}

fn record(sequence: u64) -> RefLogRecord {
    let mut current = RefRecord::first([7; 32], 13, Locality::default());
    current.seq = sequence;
    current.candidate_id = Some([9; 32]);
    let previous = (sequence > 1).then(|| {
        let mut previous = current.clone();
        previous.commit = [6; 32];
        previous.seq = sequence - 1;
        previous.candidate_id = Some([8; 32]);
        previous
    });
    RefLogRecord {
        record: current,
        previous_commit: previous.as_ref().map(|record| record.commit),
        principal: "reflog-fixture".into(),
        reason: RefLogReason::Commit,
        timestamp: 123,
        expected_previous: Some(previous),
        committed_previous: None,
    }
}

fn entry(sequence: u64) -> Result<v1::RefLogEntry, TestError> {
    Ok(RefCodec::new(4096)?.encode_log(&record(sequence), "terrane-v1", "advisory")?)
}

#[tokio::test]
async fn retains_ordered_complete_logs_until_independent_context_matches() -> TestResult {
    let services = Arc::new(Services {
        ref_log_entries: Some(vec![entry(1)?, entry(3)?]),
        ..Default::default()
    });
    let running = Running::start(transport(services.clone(), None).await?);
    let requested = request(1);

    let received = get_ref_log(
        &client(running.address)?,
        requested.clone(),
        options(),
        RefCodec::new(4096)?,
        limits(2, 8192)?,
    )
    .await?;

    assert_eq!(received.name, NAME);
    assert_eq!(received.entries.len(), 2);
    for (received, sequence) in received.entries.into_iter().zip([1, 3]) {
        assert_eq!(received.message, "advisory");
        assert_eq!(received.observation.sequence_hint(), sequence);
        assert_eq!(received.observation.commit_hint(), &[7; 32]);
        assert_eq!(received.observation.profile_hint(), "terrane-v1");
        assert!(matches!(
            received.observation.clone().verify(&[8; 32], "terrane-v1"),
            Err(RefWireError::CommitMismatch)
        ));
        assert!(matches!(
            received.observation.clone().verify(&[7; 32], "other"),
            Err(RefWireError::ProfileMismatch)
        ));
        assert_eq!(
            received.observation.verify(&[7; 32], "terrane-v1")?,
            record(sequence)
        );
    }
    assert_eq!(services.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *services
            .ref_log_requests
            .lock()
            .map_err(|_| "request mutex poisoned")?,
        [requested]
    );
    running.stop().await
}

#[tokio::test]
async fn accepts_empty_and_maximum_sequences_but_refuses_invalid_order_and_records() -> TestResult {
    for rows in [vec![], vec![entry(u64::MAX)?]] {
        let expected = rows.len();
        let running = Running::start(
            transport(
                Arc::new(Services {
                    ref_log_entries: Some(rows),
                    ..Default::default()
                }),
                None,
            )
            .await?,
        );

        let received = get_ref_log(
            &client(running.address)?,
            request(u64::MAX),
            options(),
            RefCodec::new(4096)?,
            limits(1, 8192)?,
        )
        .await?;

        assert_eq!(received.entries.len(), expected);
        running.stop().await?;
    }

    for rows in [
        vec![entry(1)?],
        vec![entry(3)?, entry(3)?],
        vec![entry(4)?, entry(3)?],
    ] {
        let running = Running::start(
            transport(
                Arc::new(Services {
                    ref_log_entries: Some(rows),
                    ..Default::default()
                }),
                None,
            )
            .await?,
        );

        let result = get_ref_log(
            &client(running.address)?,
            request(2),
            options(),
            RefCodec::new(4096)?,
            limits(2, 8192)?,
        )
        .await;

        assert!(matches!(result, Err(RefLogClientError::Sequence)));
        running.stop().await?;
    }

    for change in 0..4 {
        let mut malformed = entry(3)?;
        match change {
            0 => malformed.principal = "other-principal".into(),
            1 => {
                malformed
                    .at
                    .as_option_mut()
                    .ok_or("missing fixture timestamp")?
                    .nanos = 1
            }
            2 => malformed.canonical_ref_log_record.clear(),
            _ => {
                malformed
                    .value
                    .as_option_mut()
                    .ok_or("missing fixture value")?
                    .writer_epoch += 1
            }
        }
        let running = Running::start(
            transport(
                Arc::new(Services {
                    ref_log_entries: Some(vec![entry(2)?, malformed]),
                    ..Default::default()
                }),
                None,
            )
            .await?,
        );

        let result = get_ref_log(
            &client(running.address)?,
            request(2),
            options(),
            RefCodec::new(4096)?,
            limits(2, 8192)?,
        )
        .await;

        assert!(matches!(result, Err(RefLogClientError::Value(_))));
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn enforces_aggregate_entry_content_and_individual_record_message_bounds() -> TestResult {
    let exact = entry(1)?;
    let value = exact.value.as_option().ok_or("missing fixture value")?;
    let budget = exact.canonical_ref_log_record.len()
        + value.canonical_ref_record.len()
        + value.profile.len()
        + exact.principal.len()
        + exact.message.len();
    let running = Running::start(
        transport(
            Arc::new(Services {
                ref_log_entries: Some(vec![exact]),
                ..Default::default()
            }),
            None,
        )
        .await?,
    );
    let rpc_client = client(running.address)?;

    let received = get_ref_log(
        &rpc_client,
        request(1),
        options(),
        RefCodec::new(4096)?,
        limits(1, budget)?,
    )
    .await?;
    assert_eq!(received.entries.len(), 1);
    let result = get_ref_log(
        &rpc_client,
        request(1),
        options(),
        RefCodec::new(4096)?,
        limits(1, budget - 1)?,
    )
    .await;
    assert!(matches!(result, Err(RefLogClientError::Resources)));
    running.stop().await?;

    let mut large = entry(2)?;
    large.message = "x".repeat(4096);
    for (rows, bound) in [
        (vec![entry(1)?, entry(2)?], limits(1, 8192)?),
        (vec![large], limits(1, 512)?),
    ] {
        let running = Running::start(
            transport(
                Arc::new(Services {
                    ref_log_entries: Some(rows),
                    ..Default::default()
                }),
                None,
            )
            .await?,
        );

        let result = get_ref_log(
            &client(running.address)?,
            request(1),
            options(),
            RefCodec::new(4096)?,
            bound,
        )
        .await;

        assert!(matches!(result, Err(RefLogClientError::Resources)));
        running.stop().await?;
    }

    let running = Running::start(
        transport(
            Arc::new(Services {
                ref_log_entries: Some(vec![entry(1)?]),
                ..Default::default()
            }),
            None,
        )
        .await?,
    );
    let rpc_client = client(running.address)?;

    let result = get_ref_log(
        &rpc_client,
        request(1),
        options(),
        RefCodec::new(1)?,
        limits(1, 8192)?,
    )
    .await;
    assert!(matches!(
        result,
        Err(RefLogClientError::Value(RefWireError::RecordTooLarge))
    ));
    let result = get_ref_log(
        &rpc_client,
        request(1),
        options().with_max_message_size(64),
        RefCodec::new(4096)?,
        limits(1, 8192)?,
    )
    .await;
    assert!(matches!(result, Err(RefLogClientError::Transport(_))));
    running.stop().await
}

#[tokio::test]
async fn terminal_failure_deadline_and_cancellation_never_deliver_partial_logs() -> TestResult {
    for rows in [None, Some(vec![entry(1)?])] {
        let running = Running::start(
            transport(
                Arc::new(Services {
                    ref_log_entries: rows,
                    ref_log_error: true,
                    ..Default::default()
                }),
                None,
            )
            .await?,
        );

        let result = get_ref_log(
            &client(running.address)?,
            request(1),
            options(),
            RefCodec::new(4096)?,
            limits(2, 8192)?,
        )
        .await;

        assert!(matches!(result, Err(RefLogClientError::Transport(_))));
        running.stop().await?;
    }

    let services = Arc::new(Services {
        ref_log_entries: Some(vec![entry(1)?]),
        ref_log_pending: true,
        ..Default::default()
    });
    let running = Running::start(transport(services.clone(), None).await?);
    let rpc_client = client(running.address)?;

    let result = get_ref_log(
        &rpc_client,
        request(1),
        options().with_timeout(Duration::from_millis(200)),
        RefCodec::new(4096)?,
        limits(2, 8192)?,
    )
    .await;

    match result {
        Err(RefLogClientError::Deadline) => {}
        Err(RefLogClientError::Transport(error)) => {
            assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
        }
        result => panic!("pending reflog completed despite missing termination: {result:?}"),
    }
    running.stop().await?;

    let running = Running::start(
        transport(
            Arc::new(Services {
                ref_log_entries: Some(vec![entry(1)?, entry(2)?, entry(3)?, entry(4)?]),
                ref_log_delay: Duration::from_millis(150),
                ..Default::default()
            }),
            None,
        )
        .await?,
    );

    let result = get_ref_log(
        &client(running.address)?,
        request(1),
        options().with_timeout(Duration::from_millis(400)),
        RefCodec::new(4096)?,
        limits(4, 8192)?,
    )
    .await;

    match result {
        Err(RefLogClientError::Deadline) => {}
        Err(RefLogClientError::Transport(error)) => {
            assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
        }
        result => panic!("reflog progress reset its whole-call deadline: {result:?}"),
    }
    running.stop().await?;

    let services = Arc::new(Services {
        ref_log_entries: Some(vec![entry(1)?]),
        ref_log_pending: true,
        ..Default::default()
    });
    let running = Running::start(transport(services.clone(), None).await?);
    let rpc_client = client(running.address)?;
    let codec = RefCodec::new(4096)?;
    let bound = limits(2, 8192)?;
    let operation =
        tokio::spawn(
            async move { get_ref_log(&rpc_client, request(1), options(), codec, bound).await },
        );
    tokio::time::timeout(Duration::from_secs(1), async {
        while services.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    operation.abort();
    match operation.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(result) => panic!("cancelled reflog delivered a result: {result:?}"),
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while !services.dropped_stream.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    running.stop().await
}

#[tokio::test]
async fn invalid_names_and_missing_call_limits_refuse_before_connecting() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let rpc_client = client(listener.local_addr()?)?;
    for (name, bounds) in [
        ("../main", options()),
        (NAME, options().with_max_message_size(1)),
        (NAME, CallOptions::default()),
        (NAME, options().with_timeout(Duration::ZERO)),
        (NAME, options().with_element_memory_limit(0)),
    ] {
        let mut requested = request(0);
        requested.name = name.into();

        let result = get_ref_log(
            &rpc_client,
            requested,
            bounds,
            RefCodec::new(4096)?,
            limits(1, 8192)?,
        )
        .await;

        assert!(matches!(
            result,
            Err(RefLogClientError::Request | RefLogClientError::Limits)
        ));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}
