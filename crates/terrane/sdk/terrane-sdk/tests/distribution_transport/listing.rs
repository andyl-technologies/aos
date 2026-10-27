//! Checks finite ref listing bounds and failure atomicity over native sockets.
//!
//! These fixtures establish no inventory completeness or repository authority.

use std::{
    num::NonZeroUsize,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use terrane_format::refs::{Locality, RefRecord};
use terrane_sdk::wire::{
    client::listing::{RefListClientError, RefListLimits, list_refs},
    refs::{RefCodec, RefWireError},
    services::RefServiceClient,
    v1,
};

use super::{Running, Services, TestError, TestResult, transport};

const PATTERN: &str = "refs/heads/**";
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

fn limits(entries: usize, bytes: usize) -> Result<RefListLimits, TestError> {
    Ok(RefListLimits {
        max_entries: NonZeroUsize::new(entries).ok_or("zero fixture entry bound")?,
        max_content_bytes: NonZeroUsize::new(bytes).ok_or("zero fixture byte bound")?,
    })
}

fn request(pattern: &str) -> v1::ListRefsRequest {
    v1::ListRefsRequest {
        pattern: pattern.into(),
        ..Default::default()
    }
}

fn record() -> RefRecord {
    let mut record = RefRecord::first(
        [7; 32],
        13,
        Locality {
            region: Some("region".into()),
            zone: Some("zone".into()),
            host: Some("host".into()),
        },
    );
    record.candidate_id = Some([9; 32]);
    record
}

fn row(name: &str) -> Result<v1::RefState, TestError> {
    Ok(v1::RefState {
        name: name.into(),
        value: RefCodec::new(4096)?
            .encode_value(&record(), "terrane-v1")?
            .into(),
        home: v1::Locality {
            region: "region".into(),
            zone: "zone".into(),
            host: "host".into(),
            ..Default::default()
        }
        .into(),
        fenced: true,
        staleness_ms: 17,
        ..Default::default()
    })
}

async fn start(rows: Vec<v1::RefState>) -> Result<Running, TestError> {
    Ok(Running::start(
        transport(
            Arc::new(Services {
                ref_list_entries: Some(rows),
                ..Default::default()
            }),
            None,
        )
        .await?,
    ))
}

#[tokio::test]
async fn preserves_matching_delivery_order_and_private_complete_records() -> TestResult {
    let services = Arc::new(Services {
        ref_list_entries: Some(vec![row("refs/heads/z")?, row(NAME)?]),
        ..Default::default()
    });
    let running = Running::start(transport(services.clone(), None).await?);
    let requested = request(PATTERN);

    let received = list_refs(
        &client(running.address)?,
        requested.clone(),
        options(),
        RefCodec::new(4096)?,
        limits(2, 8192)?,
    )
    .await?;

    assert_eq!(received.pattern, PATTERN);
    assert_eq!(
        received
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["refs/heads/z", NAME]
    );
    for entry in received.entries {
        assert!(entry.fenced);
        assert_eq!(entry.staleness_ms, 17);
        assert_eq!(entry.home.ok_or("missing home")?.host, "host");
        let observation = entry.value.ok_or("missing value")?;
        assert_eq!(observation.commit_hint(), &[7; 32]);
        assert!(matches!(
            observation.clone().verify(&[8; 32], "terrane-v1"),
            Err(RefWireError::CommitMismatch)
        ));
        assert!(matches!(
            observation.clone().verify(&[7; 32], "other"),
            Err(RefWireError::ProfileMismatch)
        ));
        assert_eq!(observation.verify(&[7; 32], "terrane-v1")?, record());
    }
    assert_eq!(
        *services
            .ref_list_requests
            .lock()
            .map_err(|_| "request mutex poisoned")?,
        [requested]
    );
    assert_eq!(services.calls.load(Ordering::SeqCst), 1);
    running.stop().await?;

    for rows in [
        vec![],
        vec![v1::RefState {
            name: NAME.into(),
            ..Default::default()
        }],
    ] {
        let count = rows.len();
        let running = start(rows).await?;
        let received = list_refs(
            &client(running.address)?,
            request(PATTERN),
            options(),
            RefCodec::new(4096)?,
            limits(1, 8192)?,
        )
        .await?;
        assert_eq!(received.entries.len(), count);
        if count == 1 {
            assert!(received.entries[0].value.is_none());
        }
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn rejects_duplicate_nonmatching_malformed_names_and_inconsistent_records() -> TestResult {
    for (pattern, names) in [
        (PATTERN, vec![NAME, NAME]),
        (PATTERN, vec![NAME, "refs/tags/v1"]),
        ("refs/heads/*", vec![NAME]),
        (PATTERN, vec![NAME, "refs/heads/../main"]),
    ] {
        let rows = names.into_iter().map(row).collect::<Result<Vec<_>, _>>()?;
        let running = start(rows).await?;

        let result = list_refs(
            &client(running.address)?,
            request(pattern),
            options(),
            RefCodec::new(4096)?,
            limits(2, 8192)?,
        )
        .await;

        assert!(matches!(result, Err(RefListClientError::Name)));
        running.stop().await?;
    }

    let mut bad_summary = row("refs/heads/second")?;
    bad_summary
        .value
        .as_option_mut()
        .ok_or("missing value")?
        .sequence += 1;
    let mut bad_home = row("refs/heads/second")?;
    bad_home.home.as_option_mut().ok_or("missing home")?.host = "changed".into();
    let mut missing_record = row("refs/heads/second")?;
    missing_record
        .value
        .as_option_mut()
        .ok_or("missing value")?
        .canonical_ref_record
        .clear();
    let mut empty_profile = row("refs/heads/second")?;
    empty_profile
        .value
        .as_option_mut()
        .ok_or("missing value")?
        .profile
        .clear();
    for bad in [bad_summary, bad_home, missing_record, empty_profile] {
        let running = start(vec![row(NAME)?, bad]).await?;

        let result = list_refs(
            &client(running.address)?,
            request(PATTERN),
            options(),
            RefCodec::new(4096)?,
            limits(2, 8192)?,
        )
        .await;

        assert!(matches!(result, Err(RefListClientError::Value(_))));
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn enforces_exact_aggregate_and_individual_record_message_bounds() -> TestResult {
    let rows = vec![row(NAME)?, row("refs/heads/second")?];
    let bytes = rows
        .iter()
        .map(|entry| {
            let value = entry.value.as_option().ok_or("missing value")?;
            let home = entry.home.as_option().ok_or("missing home")?;
            Ok::<usize, TestError>(
                entry.name.len()
                    + value.canonical_ref_record.len()
                    + value.profile.len()
                    + value
                        .commit
                        .as_option()
                        .ok_or("missing commit")?
                        .value
                        .len()
                    + home.region.len()
                    + home.zone.len()
                    + home.host.len(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    let running = start(rows).await?;
    let rpc_client = client(running.address)?;

    let received = list_refs(
        &rpc_client,
        request(PATTERN),
        options(),
        RefCodec::new(4096)?,
        limits(2, bytes)?,
    )
    .await?;
    assert_eq!(received.entries.len(), 2);
    for bound in [limits(2, bytes - 1)?, limits(1, bytes)?] {
        let result = list_refs(
            &rpc_client,
            request(PATTERN),
            options(),
            RefCodec::new(4096)?,
            bound,
        )
        .await;
        assert!(matches!(result, Err(RefListClientError::Resources)));
    }
    let result = list_refs(
        &rpc_client,
        request(PATTERN),
        options(),
        RefCodec::new(1)?,
        limits(2, bytes)?,
    )
    .await;
    assert!(matches!(
        result,
        Err(RefListClientError::Value(RefWireError::RecordTooLarge))
    ));
    let result = list_refs(
        &rpc_client,
        request(PATTERN),
        options().with_max_message_size(64),
        RefCodec::new(4096)?,
        limits(2, bytes)?,
    )
    .await;
    assert!(matches!(result, Err(RefListClientError::Transport(_))));
    running.stop().await?;

    // Home strings count even when no canonical value is present to check them.
    let running = start(vec![v1::RefState {
        name: NAME.into(),
        home: v1::Locality {
            host: "x".repeat(4096),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }])
    .await?;
    let result = list_refs(
        &client(running.address)?,
        request(PATTERN),
        options(),
        RefCodec::new(4096)?,
        limits(1, 512)?,
    )
    .await;
    assert!(matches!(result, Err(RefListClientError::Resources)));
    running.stop().await
}

#[tokio::test]
async fn terminal_failure_deadline_and_cancellation_discard_private_listings() -> TestResult {
    for entries in [None, Some(vec![row(NAME)?])] {
        let running = Running::start(
            transport(
                Arc::new(Services {
                    ref_list_entries: entries,
                    ref_list_error: true,
                    ..Default::default()
                }),
                None,
            )
            .await?,
        );

        let result = list_refs(
            &client(running.address)?,
            request(PATTERN),
            options(),
            RefCodec::new(4096)?,
            limits(2, 8192)?,
        )
        .await;

        assert!(matches!(result, Err(RefListClientError::Transport(_))));
        running.stop().await?;
    }
    for (entries, pending, delay) in [
        (vec![row(NAME)?], true, Duration::ZERO),
        (
            vec![
                row(NAME)?,
                row("refs/heads/second")?,
                row("refs/heads/third")?,
            ],
            false,
            Duration::from_millis(150),
        ),
    ] {
        let running = Running::start(
            transport(
                Arc::new(Services {
                    ref_list_entries: Some(entries),
                    ref_list_pending: pending,
                    ref_list_delay: delay,
                    ..Default::default()
                }),
                None,
            )
            .await?,
        );

        let result = list_refs(
            &client(running.address)?,
            request(PATTERN),
            options().with_timeout(Duration::from_millis(350)),
            RefCodec::new(4096)?,
            limits(3, 8192)?,
        )
        .await;

        match result {
            Err(RefListClientError::Deadline) => {}
            Err(RefListClientError::Transport(error)) => {
                assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded)
            }
            result => panic!("incomplete listing escaped its whole-call deadline: {result:?}"),
        }
        running.stop().await?;
    }
    let services = Arc::new(Services {
        ref_list_entries: Some(vec![row(NAME)?]),
        ref_list_pending: true,
        ..Default::default()
    });
    let running = Running::start(transport(services.clone(), None).await?);
    let rpc_client = client(running.address)?;
    let bound = limits(2, 8192)?;
    let codec = RefCodec::new(4096)?;
    let operation = tokio::spawn(async move {
        list_refs(&rpc_client, request(PATTERN), options(), codec, bound).await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while services.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    operation.abort();
    match operation.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(result) => panic!("cancelled listing delivered a result: {result:?}"),
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
async fn invalid_patterns_and_missing_call_bounds_refuse_before_connecting() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let rpc_client = client(listener.local_addr()?)?;
    for pattern in [
        "",
        "../main",
        "refs/heads/../main",
        "refs/heads/**:/root",
        "refs/heads//main",
    ] {
        let result = list_refs(
            &rpc_client,
            request(pattern),
            options(),
            RefCodec::new(4096)?,
            limits(1, 8192)?,
        )
        .await;
        assert!(matches!(result, Err(RefListClientError::Request)));
    }
    for bounds in [
        CallOptions::default(),
        options().with_timeout(Duration::ZERO),
        options().with_element_memory_limit(0),
        options().with_max_message_size(0),
    ] {
        let result = list_refs(
            &rpc_client,
            request(PATTERN),
            bounds,
            RefCodec::new(4096)?,
            limits(1, 8192)?,
        )
        .await;
        assert!(matches!(result, Err(RefListClientError::Limits)));
    }
    let result = list_refs(
        &rpc_client,
        request(PATTERN),
        options().with_max_message_size(1),
        RefCodec::new(4096)?,
        limits(1, 8192)?,
    )
    .await;
    assert!(matches!(result, Err(RefListClientError::Request)));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}
