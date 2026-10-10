//! Checks exact plugin-barrier version admission at the public QMP boundary.

use super::{QmpClient, QmpCommandKind, QmpError, scripted_qmp};
use serde_json::{Value, json};
use std::error::Error;

#[test]
fn plugin_barrier_accepts_schema_seven_without_private_worker_identities()
-> Result<(), Box<dyn Error>> {
    let response = barrier_response();
    let mut client = client_with_response(&response)?;
    let state = client.query_hot_fork_plugin_barrier()?;

    assert_eq!(crucible_qemu::QMP_HOT_FORK_PLUGIN_BARRIER_SCHEMA_VERSION, 7);
    assert!(state.quiescent());
    assert_eq!(state.worker_mask(), 3);
    assert_eq!(state.parked_worker_mask(), 3);
    Ok(())
}

#[test]
fn plugin_barrier_rejects_old_and_future_versions_with_valid_barrier_state()
-> Result<(), Box<dyn Error>> {
    for version in [6, 8, u64::MAX] {
        let mut response = barrier_response();
        response["return"]["schema-version"] = json!(version);
        let mut client = client_with_response(&response)?;

        assert!(matches!(
            client.query_hot_fork_plugin_barrier(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkPluginBarrier,
                ..
            })
        ));
    }
    Ok(())
}

fn client_with_response(
    response: &Value,
) -> Result<QmpClient<super::ScriptedQmpStream>, Box<dyn Error>> {
    let encoded = serde_json::to_string(response)?;
    Ok(QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &encoded,
    ]))?)
}

fn barrier_response() -> Value {
    json!({"return": {
        "schema-version": 7,
        "generation": 2,
        "registered": true,
        "manifest-consistent": true,
        "held": true,
        "teardown-closed": false,
        "mapping-dontfork": true,
        "in-flight": 0,
        "ring-count": 9,
        "rings-held": 9,
        "ring-producers-in-flight": 0,
        "ring-consumers-in-flight": 0,
        "worker-mask": 3,
        "parked-worker-mask": 3,
        "pending-worker-mask": 0,
        "worker-operations-in-flight": 0,
        "quiescent": true
    }})
}
