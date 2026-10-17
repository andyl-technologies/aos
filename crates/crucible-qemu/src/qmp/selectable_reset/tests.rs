//! Actual typed command routing over a bounded scripted component stream.

use super::*;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct ScriptedStream {
    replies: io::Cursor<Vec<u8>>,
    writes: Arc<Mutex<Vec<u8>>>,
    close_on_read: Option<Arc<HostOperationGuard>>,
}

impl Read for ScriptedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some(original) = self.close_on_read.take() {
            original.complete().map_err(io::Error::other)?;
        }
        let count = bytes.len().min(1);
        self.replies.read(&mut bytes[..count])
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes
            .lock()
            .expect("component write log")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for ScriptedStream {
    fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
    fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

fn original() -> (HostOperationSupervisor, Arc<HostOperationGuard>) {
    let supervisor = HostOperationSupervisor::new(
        crucible_linux_resource::host_supervision::HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )
    .expect("finite component operation");
    let guard = Arc::new(
        supervisor
            .begin(HostOperationClass::Preparation)
            .expect("original component guard"),
    );
    (supervisor, guard)
}

fn pending() -> SelectablePlanPendingRequest {
    SelectablePlanPendingRequest::new(
        crucible_protocol::SelectionRequest::new(3, "flight.ready", "w001", None, 97)
            .expect("public canonical request"),
        9,
        11,
        0,
        0x7000,
    )
}

fn event(name: &str, correlation: u64, outcome: (&str, Value)) -> Value {
    let mut data = json!({
        "schema-version":1, "correlation":correlation, "request-sequence":3,
        "raw-icount":9, "trap-tick-ps":11, "vcpu-index":0,
    });
    data.as_object_mut()
        .expect("event data")
        .insert(outcome.0.into(), outcome.1);
    json!({"event":name,"data":data})
}

fn completed(correlation: u64, generation: u64) -> Value {
    event(
        COMPLETED_EVENT,
        correlation,
        ("observation-generation", json!(generation)),
    )
}

fn client(lines: &[Value]) -> QmpClient<ScriptedStream> {
    let mut replies = vec![
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
    ];
    replies.extend_from_slice(lines);
    let text = replies
        .iter()
        .map(|value| format!("{value}\r\n"))
        .collect::<String>();
    QmpClient::connect(ScriptedStream {
        replies: io::Cursor::new(text.into_bytes()),
        writes: Arc::new(Mutex::new(Vec::new())),
        close_on_read: None,
    })
    .expect("actual client negotiation")
}

fn requests(client: &QmpClient<ScriptedStream>) -> Vec<Value> {
    let bytes = client
        .stream
        .get_ref()
        .writes
        .lock()
        .expect("component request bytes")
        .clone();
    String::from_utf8(bytes)
        .expect("actual UTF8 requests")
        .lines()
        .map(|line| serde_json::from_str(line).expect("actual command JSON"))
        .collect()
}

#[test]
fn selectable_reset_requires_both_ack_and_terminal_event_in_either_order() {
    for lines in [
        vec![json!({"return":{}}), completed(1, 7)],
        vec![completed(1, 7), json!({"return":{}})],
    ] {
        let (_supervisor, guard) = original();
        let mut client = client(&lines);
        let completion = client
            .reset_selectable_under_original(&pending(), &guard)
            .expect("matched terminal completion");
        assert_eq!(completion.correlation(), 1);
        assert_eq!(completion.observation_generation(), 7);
        assert!(guard.wait_slice().is_ok());
        assert!(!client.poisoned);
        let actual = requests(&client);
        assert_eq!(actual[1]["execute"], "crucible-selectable-reset-v1");
        let bytes = pending().request().encode().expect("canonical bytes");
        let expected = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual[1]["arguments"]["request-hex"], expected);
        assert_eq!(actual[1]["arguments"]["reply-address"], 0x7000);
    }
}

#[test]
fn selectable_reset_generic_reset_and_ack_cannot_prove_completion() {
    let (_supervisor, guard) = original();
    let mut client = client(&[json!({"event":"RESET"}), json!({"return":{}})]);
    assert!(
        client
            .reset_selectable_under_original(&pending(), &guard)
            .is_err()
    );
    let sent = requests(&client);
    assert!(matches!(
        client.reset_selectable_under_original(&pending(), &guard),
        Err(QmpError::ConnectionPoisoned)
    ));
    assert_eq!(requests(&client), sent);
}

#[test]
fn selectable_reset_preserves_negative_native_status_and_retains_uncertainty() {
    let (_supervisor, guard) = original();
    let mut client = client(&[
        json!({"return":{}}),
        event(FAILED_EVENT, 1, ("status", json!(-116))),
    ]);
    assert_eq!(
        client.reset_selectable_under_original(&pending(), &guard),
        Err(QmpError::SelectableResetFailed { status: -116 })
    );
    let sent = requests(&client);
    assert!(matches!(
        client.reset_selectable_under_original(&pending(), &guard),
        Err(QmpError::ConnectionPoisoned)
    ));
    assert_eq!(requests(&client), sent);
    assert!(guard.wait_slice().is_ok());
}

#[test]
fn selectable_reset_rejects_each_changed_identity_before_host_completion() {
    for (field, wrong) in [
        ("schema-version", json!(2)),
        ("correlation", json!(2)),
        ("request-sequence", json!(4)),
        ("raw-icount", json!(10)),
        ("trap-tick-ps", json!(12)),
        ("vcpu-index", json!(1)),
        ("observation-generation", json!(0)),
    ] {
        let (_supervisor, guard) = original();
        let mut bad = completed(1, 7);
        bad["data"][field] = wrong;
        let mut client = client(&[json!({"return":{}}), bad]);
        assert!(
            matches!(
                client.reset_selectable_under_original(&pending(), &guard),
                Err(QmpError::MalformedTypedResponse { .. })
            ),
            "{field}"
        );
        let sent = requests(&client);
        assert!(matches!(
            client.reset_selectable_under_original(&pending(), &guard),
            Err(QmpError::ConnectionPoisoned)
        ));
        assert_eq!(requests(&client), sent);
    }
}

#[test]
fn selectable_reset_malformed_accepted_ack_blocks_a_second_command() {
    for value in [json!(null), json!([]), json!({"extra":1})] {
        let (_supervisor, guard) = original();
        let mut client = client(&[json!({"return":value}), completed(1, 7)]);
        assert!(
            client
                .reset_selectable_under_original(&pending(), &guard)
                .is_err()
        );
        let sent = requests(&client);
        assert!(matches!(
            client.reset_selectable_under_original(&pending(), &guard),
            Err(QmpError::ConnectionPoisoned)
        ));
        assert_eq!(requests(&client), sent);
    }
}

#[test]
fn selectable_reset_pre_effect_command_refusal_stays_typed_and_does_not_poison() {
    let (_supervisor, guard) = original();
    let mut client = client(&[
        json!({"error":{"class":"CommandNotFound","desc":"old native protocol"}}),
        json!({"return":{}}),
        completed(2, 7),
    ]);
    let error = client
        .reset_selectable_under_original(&pending(), &guard)
        .expect_err("native command refusal");
    assert!(
        matches!(error, QmpError::Command { command:QmpCommandKind::SelectableReset, class, description }
        if class=="CommandNotFound" && description=="old native protocol")
    );
    assert!(!client.poisoned);
    assert_eq!(
        client
            .reset_selectable_under_original(&pending(), &guard)
            .expect("independent second operation")
            .correlation(),
        2
    );
}

#[test]
fn selectable_reset_closed_original_cannot_use_ambient_supervisor() {
    let (_supervisor, guard) = original();
    guard.complete().expect("close original");
    let (ambient, unrelated) = original();
    let mut client = client(&[json!({"return":{}}), completed(1, 7)]);
    client.set_host_operation_supervisor(ambient);
    let sent = requests(&client);
    assert!(matches!(
        client.reset_selectable_under_original(&pending(), &guard),
        Err(QmpError::OperationalSupervision { .. })
    ));
    assert_eq!(requests(&client), sent);
    assert_eq!(
        unrelated
            .status()
            .expect("ambient status")
            .completed_work_units,
        0
    );
}

#[test]
fn selectable_reset_original_closure_during_observation_poison_retains_first_cause() {
    let (_supervisor, guard) = original();
    let mut client = client(&[json!({"return":{}}), completed(1, 7)]);
    client.stream.get_mut().close_on_read = Some(Arc::clone(&guard));
    assert!(matches!(
        client.reset_selectable_under_original(&pending(), &guard),
        Err(QmpError::OperationalSupervision { .. })
    ));
    let sent = requests(&client);
    assert!(matches!(
        client.reset_selectable_under_original(&pending(), &guard),
        Err(QmpError::ConnectionPoisoned)
    ));
    assert_eq!(requests(&client), sent);
}

#[test]
fn selectable_reset_cont_borrows_original_and_refuses_closed_owner_before_write() {
    let (_supervisor, guard) = original();
    let mut client = client(&[json!({"return":{}})]);
    client
        .exchange_under(QmpCommand::Cont, &guard)
        .expect("same original cont ACK");
    assert_eq!(requests(&client)[1]["execute"], "cont");
    assert!(guard.wait_slice().is_ok());
    let sent = requests(&client);

    guard.complete().expect("close original");
    assert!(matches!(
        client.exchange_under(QmpCommand::Cont, &guard),
        Err(QmpError::OperationalSupervision { .. })
    ));
    assert_eq!(requests(&client), sent);
}
