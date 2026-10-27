//! Checks exact-name ref reception across actual generated-service sockets.
//!
//! The fixture supplies representation claims, without verified commit signatures,
//! fresh repository authorization or evidence of actual home execution.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use terrane_format::refs::{Locality, RefPolicy, RefRecord, Retention};
use terrane_sdk::wire::{
    client::references::{RefClientError, get_ref},
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

fn request(freshness: v1::Freshness) -> v1::GetRefRequest {
    v1::GetRefRequest {
        name: NAME.into(),
        freshness: freshness.into(),
        bound_ms: if freshness == v1::Freshness::Bounded {
            7
        } else {
            0
        },
        ..Default::default()
    }
}

fn record() -> RefRecord {
    let mut record = RefRecord::first(
        [7; 32],
        13,
        Locality {
            host: Some("fixture-home".into()),
            ..Default::default()
        },
    );
    record.candidate_id = Some([9; 32]);
    record.policy = Some(RefPolicy {
        multi_writer: Some(false),
        retention: Some(Retention::Ttl(3600)),
        ..Default::default()
    });
    record
}

fn response() -> Result<v1::RefState, TestError> {
    Ok(v1::RefState {
        name: NAME.into(),
        value: RefCodec::new(4096)?
            .encode_value(&record(), "terrane-v1")?
            .into(),
        fenced: true,
        staleness_ms: 7,
        home: v1::Locality {
            host: "fixture-home".into(),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    })
}

#[tokio::test]
async fn retains_complete_record_until_independent_context_matches() -> TestResult {
    let expected = response()?;
    let services = Arc::new(Services {
        ref_response: Some(expected.clone()),
        ..Default::default()
    });
    let running = Running::start(transport(services.clone(), None).await?);
    let requested = request(v1::Freshness::Bounded);

    let received = get_ref(
        &client(running.address)?,
        requested.clone(),
        options(),
        RefCodec::new(4096)?,
    )
    .await?;

    assert_eq!(received.name, NAME);
    assert!(received.fenced);
    assert_eq!(received.staleness_ms, 7);
    assert_eq!(received.home.as_ref(), expected.home.as_option());
    let value = received.value.ok_or("missing ref observation")?;
    assert_eq!(value.commit_hint(), &[7; 32]);
    assert_eq!(value.profile_hint(), "terrane-v1");
    assert!(matches!(
        value.clone().verify(&[8; 32], "terrane-v1"),
        Err(RefWireError::CommitMismatch)
    ));
    assert!(matches!(
        value.clone().verify(&[7; 32], "different-profile"),
        Err(RefWireError::ProfileMismatch)
    ));
    assert_eq!(value.verify(&[7; 32], "terrane-v1")?, record());
    assert_eq!(services.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *services
            .ref_requests
            .lock()
            .map_err(|_| "request mutex poisoned")?,
        [requested]
    );
    running.stop().await
}

#[tokio::test]
async fn accepts_absence_and_exact_freshness_boundaries_as_peer_claims() -> TestResult {
    for (freshness, staleness_ms) in [
        (v1::Freshness::Any, u32::MAX),
        (v1::Freshness::Bounded, 7),
        (v1::Freshness::Linearizable, 0),
    ] {
        let services = Arc::new(Services {
            ref_response: Some(v1::RefState {
                name: NAME.into(),
                staleness_ms,
                ..Default::default()
            }),
            ..Default::default()
        });
        let running = Running::start(transport(services, None).await?);

        let received = get_ref(
            &client(running.address)?,
            request(freshness),
            options(),
            RefCodec::new(4096)?,
        )
        .await?;

        assert!(received.value.is_none());
        assert_eq!(received.staleness_ms, staleness_ms);
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn invalid_requests_and_call_limits_never_connect() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let client = client(listener.local_addr()?)?;
    let mut invalid = request(v1::Freshness::Bounded);
    invalid.bound_ms = 0;
    let mut unknown = request(v1::Freshness::Any);
    unknown.freshness = buffa::EnumValue::Unknown(123);
    let mut name = request(v1::Freshness::Any);
    name.name = "refs/heads/../main".into();
    for request in [invalid, unknown, name] {
        assert!(matches!(
            get_ref(&client, request, options(), RefCodec::new(4096)?).await,
            Err(RefClientError::Request)
        ));
    }
    assert!(matches!(
        get_ref(
            &client,
            request(v1::Freshness::Any),
            options().with_max_message_size(16),
            RefCodec::new(4096)?
        )
        .await,
        Err(RefClientError::Request)
    ));
    for options in [
        CallOptions::default(),
        options().with_timeout(Duration::ZERO),
        options().with_max_message_size(0),
        options().with_element_memory_limit(0),
    ] {
        assert!(matches!(
            get_ref(
                &client,
                request(v1::Freshness::Any),
                options,
                RefCodec::new(4096)?
            )
            .await,
            Err(RefClientError::Limits)
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
async fn refuses_changed_names_invalid_values_and_exceeded_freshness() -> TestResult {
    let original = response()?;
    let mut wrong_name = original.clone();
    wrong_name.name = "refs/heads/_/other".into();
    let mut wrong_summary = original.clone();
    wrong_summary
        .value
        .as_option_mut()
        .ok_or("missing fixture value")?
        .sequence += 1;
    let mut missing_record = original.clone();
    missing_record
        .value
        .as_option_mut()
        .ok_or("missing fixture value")?
        .canonical_ref_record
        .clear();
    let mut empty_profile = original.clone();
    empty_profile
        .value
        .as_option_mut()
        .ok_or("missing fixture value")?
        .profile
        .clear();
    let mut wrong_home = original.clone();
    wrong_home
        .home
        .as_option_mut()
        .ok_or("missing fixture home")?
        .host = "other-home".into();
    for (state, expected) in [
        (wrong_name, "name"),
        (wrong_summary, "value"),
        (missing_record, "value"),
        (empty_profile, "value"),
        (wrong_home, "value"),
    ] {
        let services = Arc::new(Services {
            ref_response: Some(state),
            ..Default::default()
        });
        let running = Running::start(transport(services, None).await?);

        let result = get_ref(
            &client(running.address)?,
            request(v1::Freshness::Any),
            options(),
            RefCodec::new(4096)?,
        )
        .await;

        assert!(matches!(
            (&result, expected),
            (Err(RefClientError::Name), "name") | (Err(RefClientError::Value(_)), "value")
        ));
        running.stop().await?;
    }
    for freshness in [v1::Freshness::Bounded, v1::Freshness::Linearizable] {
        let services = Arc::new(Services {
            ref_response: Some(v1::RefState {
                staleness_ms: 8,
                ..original.clone()
            }),
            ..Default::default()
        });
        let running = Running::start(transport(services, None).await?);

        let result = get_ref(
            &client(running.address)?,
            request(freshness),
            options(),
            RefCodec::new(4096)?,
        )
        .await;

        assert!(matches!(result, Err(RefClientError::Freshness)));
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn preserves_record_message_transport_and_whole_call_bounds() -> TestResult {
    let services = Arc::new(Services {
        ref_response: Some(response()?),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);
    let rpc_client = client(running.address)?;

    let result = get_ref(
        &rpc_client,
        request(v1::Freshness::Any),
        options(),
        RefCodec::new(1)?,
    )
    .await;

    assert!(matches!(
        result,
        Err(RefClientError::Value(RefWireError::RecordTooLarge))
    ));
    let result = get_ref(
        &rpc_client,
        request(v1::Freshness::Any),
        options().with_max_message_size(64),
        RefCodec::new(4096)?,
    )
    .await;
    assert!(matches!(result, Err(RefClientError::Transport(_))));
    running.stop().await?;

    let running = Running::start(transport(Arc::new(Services::default()), None).await?);
    let result = get_ref(
        &client(running.address)?,
        request(v1::Freshness::Any),
        options(),
        RefCodec::new(4096)?,
    )
    .await;
    assert!(matches!(result, Err(RefClientError::Transport(_))));
    running.stop().await?;

    let services = Arc::new(Services {
        ref_response: Some(response()?),
        ref_delay: Duration::from_millis(150),
        ..Default::default()
    });
    let running = Running::start(transport(services, None).await?);
    let result = get_ref(
        &client(running.address)?,
        request(v1::Freshness::Any),
        options().with_timeout(Duration::from_millis(20)),
        RefCodec::new(4096)?,
    )
    .await;
    match result {
        Err(RefClientError::Deadline) => {}
        Err(RefClientError::Transport(error)) => {
            assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
        }
        result => panic!("ref call completed beyond its deadline: {result:?}"),
    }
    running.stop().await
}
