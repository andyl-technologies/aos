//! Modeled QMP replies exercise the real held Host original and used begin path.
//!
//! These transport controls never issue a native request or stop receipt.

use super::*;
use std::io::{self, Cursor, Read, Write};

struct Stream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Stream {
    fn new(response: Value) -> Self {
        let mut input =
            b"{\"QMP\":{\"version\":{},\"capabilities\":[]}}\n{\"return\":{}}\n".to_vec();
        input.extend_from_slice(
            serde_json::to_string(&json!({ "return": response }))
                .unwrap()
                .as_bytes(),
        );
        input.push(b'\n');
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}

impl Write for Stream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for Stream {
    fn set_qmp_read_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
    fn set_qmp_write_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
}

fn response(arm: CheckpointArmReceipt, epoch: u64) -> Value {
    json!({
        "arm-request-digest": digest_hex(arm.request_digest()),
        "request-generation": arm.request_generation(),
        "connection-epoch": epoch,
    })
}

#[test]
fn begin_requires_actual_original_then_saves_the_same_connection_receipt() {
    let arm = CheckpointArmReceipt::wire_fixture();
    let mut client = QmpClient::connect(Stream::new(response(arm, 11))).unwrap();
    let before = client.stream.get_ref().output.len();
    assert!(matches!(
        client.begin_checkpoint_receiving(arm),
        Err(QmpError::InvalidBound { .. })
    ));
    assert_eq!(client.stream.get_ref().output.len(), before);
    let (_owner, original, supervisor, _event, _account) =
        crate::node::checkpoint_original_loan_fixture();
    client.bind_checkpoint_original(original).unwrap();

    client.begin_checkpoint_receiving(arm).unwrap();
    let sent = client.stream.get_ref().output.len();
    client.begin_checkpoint_receiving(arm).unwrap();

    assert_eq!(client.stream.get_ref().output.len(), sent);
    assert_eq!(client.checkpoint_request.unwrap().connection_epoch, 11);
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    assert!(!client.poisoned);
}

#[test]
fn begin_refuses_a_mismatched_or_absent_connection_receipt_and_poisoning_blocks_retry() {
    let arm = CheckpointArmReceipt::wire_fixture();
    for value in [
        response(arm, 0),
        json!({ "arm-request-digest": digest_hex(arm.request_digest()), "request-generation": 8, "connection-epoch": 11 }),
        json!({ "arm-request-digest": "00".repeat(32), "request-generation": 7, "connection-epoch": 11 }),
    ] {
        let (_owner, original, _supervisor, _event, _account) =
            crate::node::checkpoint_original_loan_fixture();
        let mut client = QmpClient::connect(Stream::new(value)).unwrap();
        client.bind_checkpoint_original(original).unwrap();
        assert!(matches!(
            client.begin_checkpoint_receiving(arm),
            Err(QmpError::MalformedTypedResponse { .. })
        ));
        assert!(client.poisoned);
        let before = client.stream.get_ref().output.len();
        assert!(client.begin_checkpoint_receiving(arm).is_err());
        assert_eq!(client.stream.get_ref().output.len(), before);
    }
}
