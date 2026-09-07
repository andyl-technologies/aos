//! Exercises bounded retained-template advancement through typed QMP exchanges.

use std::io::{self, Cursor, Read, Write};
use std::time::Duration;

use serde_json::{Value, json};

use super::{QMP_HOT_FORK_AIO_PROOF, native_worker_tests::prepared_report};
use crate::{QmpClient, QmpError, QmpJobPollPolicy, QmpTimeoutStream};

#[test]
fn acquisition_advances_prepare_until_non_plugin_proofs_are_complete()
-> Result<(), Box<dyn std::error::Error>> {
    let complete = barriers_report();
    let mut pending = complete.clone();
    pending["bh-timer-barrier"]["admissions-in-flight"] = json!(1);
    pending["bh-timer-barrier"]["quiescent"] = json!(false);
    pending["acknowledged-proofs"] = json!(55);
    pending["missing-proofs"] = json!(72);
    let mut client = client([pending, complete], 3)?;

    let state = client.prepare_hot_fork_template_barriers(&[])?;
    assert_eq!(state.generation(), 4);
    assert_eq!(state.acknowledged_proofs(), 63);
    assert_eq!(state.missing_proofs(), 64);
    assert!(!state.ready());

    let requests = requests(&client)?;
    assert_eq!(requests.len(), 3);
    for request in &requests[1..] {
        assert_eq!(request["exec-oob"], "crucible-hot-fork-template");
        assert_eq!(request["arguments"]["action"], "prepare");
        assert_eq!(request["arguments"]["block-snapshot-bindings"], json!([]));
    }
    Ok(())
}

#[test]
fn missing_native_workers_exhausts_the_bound_without_replacing_or_aborting()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pending = barriers_report();
    pending["acknowledged-proofs"] = json!(55);
    pending["missing-proofs"] = json!(72);
    let mut client = client([pending.clone(), pending.clone(), pending], 2)?;

    assert_eq!(
        client.prepare_hot_fork_template_barriers(&[]),
        Err(QmpError::HotForkTemplateNotQuiescent {
            generation: 4,
            polls: 2,
            missing_proofs: QMP_HOT_FORK_AIO_PROOF,
        })
    );
    let requests = requests(&client)?;
    assert_eq!(requests.len(), 3);
    assert!(
        requests[1..]
            .iter()
            .all(|request| { request["arguments"]["action"] == "prepare" })
    );
    // A bound does not poison or discard the caller's retained transaction.
    assert_eq!(client.query_hot_fork_template()?.generation(), 4);
    Ok(())
}

#[test]
fn acquisition_rejects_generation_replacement_before_accepting_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pending = barriers_report();
    pending["acknowledged-proofs"] = json!(55);
    pending["missing-proofs"] = json!(72);
    let mut replaced = barriers_report();
    replaced["generation"] = json!(5);
    let mut client = client([pending, replaced], 3)?;

    assert_eq!(
        client.prepare_hot_fork_template_barriers(&[]),
        Err(QmpError::HotForkTemplateGenerationChanged {
            expected: 4,
            actual: 5,
        })
    );
    assert_eq!(requests(&client)?.len(), 3);
    Ok(())
}

fn barriers_report() -> Value {
    let mut report = prepared_report();
    report["acknowledged-proofs"] = json!(63);
    report["missing-proofs"] = json!(64);
    report["outcome"] = json!("draining");
    report["ready"] = json!(false);
    if let Some(stage) = report["resource-stage"].as_object_mut() {
        for (key, value) in stage {
            if key != "schema-version" {
                *value = if value.is_boolean() {
                    json!(false)
                } else {
                    json!(0)
                };
            }
        }
    }
    report
}

#[test]
fn abort_retains_pending_block_release_and_source_restoration()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = abort_pending_report();
    let completed = completed_report("aborted");
    let mut restoring = completed.clone();
    restoring["outcome"] = json!("draining");
    restoring["transaction-active"] = json!(true);
    restoring["rollback-complete"] = json!(false);
    let mut client = client([pending, restoring, completed], 3)?;

    let releasing = client.abort_hot_fork_template()?;
    assert!(releasing.transaction_active());
    assert!(releasing.block_barrier().held());
    assert!(releasing.block_barrier().snapshot_sources().frozen());
    assert!(!releasing.rollback_complete());
    let restoring = client.abort_hot_fork_template()?;
    assert_eq!(restoring.generation(), releasing.generation());
    assert!(restoring.transaction_active());
    assert!(!restoring.block_barrier().held());
    assert!(!restoring.rollback_complete());
    let released = client.abort_hot_fork_template()?;
    assert_eq!(released.generation(), releasing.generation());
    assert!(released.rollback_complete());
    assert!(!released.block_barrier().snapshot_sources().frozen());
    assert!(
        requests(&client)?[1..]
            .iter()
            .all(|request| request["arguments"]["action"] == "abort")
    );
    Ok(())
}

#[test]
fn pending_completion_is_delivered_before_the_next_template_action()
-> Result<(), Box<dyn std::error::Error>> {
    let mut client = client(
        [
            completed_report("blocked"),
            completed_report("aborted"),
            completed_report("aborted"),
            completed_report("blocked"),
        ],
        4,
    )?;
    assert!(client.query_hot_fork_template()?.rollback_complete());
    assert!(client.query_hot_fork_template()?.rollback_complete());
    assert!(client.prepare_hot_fork_template(&[])?.rollback_complete());
    assert!(client.abort_hot_fork_template()?.rollback_complete());
    Ok(())
}

#[test]
fn abort_rejects_a_prepared_response() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = client([prepared_report()], 1)?;
    assert!(matches!(
        client.abort_hot_fork_template(),
        Err(QmpError::MalformedTypedResponse { .. })
    ));
    Ok(())
}

#[test]
fn abort_draining_response_must_release_ordinary_barriers() -> Result<(), Box<dyn std::error::Error>>
{
    let mut client = client([barriers_report()], 1)?;
    assert!(matches!(
        client.abort_hot_fork_template(),
        Err(QmpError::MalformedTypedResponse { .. })
    ));
    Ok(())
}

fn abort_pending_report() -> Value {
    let mut report = barriers_report();
    report["acknowledged-proofs"] = json!(39);
    report["missing-proofs"] = json!(88);
    for barrier in ["plugin-barrier", "rcu-barrier", "bh-timer-barrier"] {
        report[barrier]["held"] = json!(false);
        report[barrier]["quiescent"] = json!(false);
    }
    report["plugin-barrier"]["mapping-dontfork"] = json!(false);
    report["plugin-barrier"]["rings-held"] = json!(0);
    report["rcu-barrier"]["owner-thread-id"] = json!(0);
    report["bh-timer-barrier"]["owner-thread-id"] = json!(0);
    report
}

fn completed_report(outcome: &str) -> Value {
    let mut report = abort_pending_report();
    report["outcome"] = json!(outcome);
    report["transaction-active"] = json!(false);
    report["rollback-complete"] = json!(true);
    report["acknowledged-proofs"] = json!(7);
    report["missing-proofs"] = json!(120);
    let block = &mut report["block-barrier"];
    for field in [
        "held",
        "graph-held",
        "graph-stable",
        "snapshot-bound",
        "snapshot-complete",
        "quiescent",
    ] {
        block[field] = json!(false);
    }
    for field in [
        "owner-thread-id",
        "graph-owner-thread-id",
        "held-graph-mutation-generation",
        "snapshot-backend-generation",
        "snapshot-graph-mutation-generation",
        "snapshot-owner-thread-id",
        "quiesced-rooted-backends",
    ] {
        block[field] = json!(0);
    }
    block["writable-backends"] = json!(1);
    block["writable-rooted-backends"] = json!(1);
    block["snapshot-roots"] = json!([]);
    block["snapshot-sources"] = json!({
        "schema-version": 1, "frozen": false, "root-count": 0, "node-count": 0,
        "originally-writable-root-count": 0, "originally-writable-backend-count": 0
    });
    report
}

fn client<const N: usize>(
    reports: [Value; N],
    maximum_polls: usize,
) -> Result<QmpClient<ScriptedStream>, QmpError> {
    let mut input =
        String::from("{\"QMP\":{\"version\":{},\"capabilities\":[]}}\r\n{\"return\":{}}\r\n");
    for report in reports {
        input.push_str(&json!({ "return": report }).to_string());
        input.push_str("\r\n");
    }
    QmpClient::connect_with_job_poll_policy(
        ScriptedStream {
            input: Cursor::new(input.into_bytes()),
            output: Vec::new(),
        },
        QmpJobPollPolicy::fast_test(maximum_polls),
    )
}

fn requests(client: &QmpClient<ScriptedStream>) -> Result<Vec<Value>, serde_json::Error> {
    String::from_utf8_lossy(&client.stream.get_ref().output)
        .lines()
        .map(serde_json::from_str)
        .collect()
}

struct ScriptedStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for ScriptedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for ScriptedStream {
    fn set_qmp_read_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }

    fn set_qmp_write_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
}
