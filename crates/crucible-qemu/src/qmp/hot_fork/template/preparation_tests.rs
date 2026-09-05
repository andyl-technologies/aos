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
