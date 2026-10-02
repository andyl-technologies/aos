//! Receipt separation from authenticated transport and final caller acceptance.

use std::collections::BTreeMap;

use tracing_subscriber::layer::SubscriberExt as _;

use crate::storage_work::telemetry::{tests::RecordedEvents, ExchangeTelemetry};

fn authenticated_exchange() -> ExchangeTelemetry<'static> {
    let mut exchange = ExchangeTelemetry::control("fixture-original", "external_copy_control");
    exchange.offer_control("/_internal/storage/external-copy/v1", b"private-request");
    exchange.authenticated_control(b"private-reply");
    exchange.finish("success");
    exchange
}

#[test]
fn authenticated_transport_without_final_sql_emits_no_final_context() {
    let recorded = RecordedEvents::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());
    tracing::subscriber::with_default(subscriber, || {
        let exchange = authenticated_exchange();
        assert!(exchange.control_observation().is_some());
        drop(exchange);
    });
    assert_eq!(recorded.authenticated_controls().len(), 1);
    assert!(recorded.final_sql().is_empty());
}

#[test]
fn refused_or_cancelled_transport_has_no_final_sql_token() {
    for outcome in ["error", "cancelled"] {
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());
        tracing::subscriber::with_default(subscriber, || {
            let mut exchange = authenticated_exchange();
            exchange.finish(outcome);
            assert!(exchange.control_observation().is_none());
        });
        assert!(recorded.final_sql().is_empty());
        assert!(recorded.authenticated_controls().is_empty());
    }
}

#[test]
fn final_context_preserves_exact_call_and_body_commitments_without_private_values() {
    let recorded = RecordedEvents::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());
    tracing::subscriber::with_default(subscriber, || {
        let exchange = authenticated_exchange();
        exchange.control_observation().unwrap().after_sql(
            "external_copy_current_sql",
            BTreeMap::from([("bindingStateSha256", "a".repeat(64))]),
        );
    });
    let authenticated = recorded.authenticated_controls();
    let sql = recorded.final_sql();
    assert_eq!(sql.len(), 1);
    assert_eq!(sql[0]["exchange"], authenticated[0]);
    assert_eq!(sql[0]["contextKind"], "external_copy_current_sql");
    assert!(
        sql[0]["completedAtUnixMicros"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    let encoded = sql[0].to_string();
    assert!(!encoded.contains("private-request"));
    assert!(!encoded.contains("private-reply"));
}

#[test]
fn malformed_or_unreviewed_context_omits_only_instrumentation() {
    for (kind, value) in [
        ("external_copy_current_sql", "private-key".to_owned()),
        ("unknown_context", "a".repeat(64)),
    ] {
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());
        tracing::subscriber::with_default(subscriber, || {
            let exchange = authenticated_exchange();
            exchange
                .control_observation()
                .unwrap()
                .after_sql(kind, BTreeMap::from([("bindingStateSha256", value)]));
        });
        assert!(recorded.final_sql().is_empty());
        assert_eq!(recorded.authenticated_controls().len(), 1);
    }
}
