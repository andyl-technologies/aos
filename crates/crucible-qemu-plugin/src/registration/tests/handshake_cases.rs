//! Control-protocol handshake sequencing cases.

use super::*;

use std::io::{Cursor, Read, Write};

use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};

#[test]
fn registration_order_performs_control_handshake_after_parse() {
    let mut sequence = PluginRegistrationSequence::new();
    let args = sequence
        .parse_arguments("simfd=3,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576")
        .unwrap_or_else(|error| panic!("valid arguments should parse: {error}"));
    let mut io = handshake_io(1, 4);

    let handshake = sequence
        .perform_control_handshake(&mut io, &args)
        .unwrap_or_else(|error| panic!("handshake should succeed: {error}"));

    assert_eq!(handshake.proto_version(), CONTROL_PROTOCOL_VERSION);
    assert_eq!(handshake.abi_version(), ABI_VERSION);
    assert_eq!(handshake.slot_index(), 1);
    assert_eq!(handshake.launch_slot(), 1);
    assert_eq!(handshake.node_count(), 4);
    assert!(!io.written().is_empty());
    assert_eq!(io.flush_count(), 1);
    assert_eq!(
        sequence.completed_steps(),
        &[
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
        ]
    );
}

#[test]
fn registration_order_rejects_control_handshake_before_parse_without_io() {
    let mut sequence = PluginRegistrationSequence::new();
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576",
    );
    let mut io = handshake_io(0, 1);

    assert_eq!(
        sequence.perform_control_handshake(&mut io, &args),
        Err(PluginRegistrationSequenceError::OutOfOrderStep {
            expected: PluginRegistrationStep::ParseArguments,
            actual: PluginRegistrationStep::ControlHandshake,
        })
    );
    assert!(io.written().is_empty());
    assert_eq!(io.flush_count(), 0);
}

#[test]
fn registration_order_fails_loud_when_handshake_slot_disagrees_with_launch_args() {
    let mut sequence = PluginRegistrationSequence::new();
    let args = sequence
        .parse_arguments("simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576")
        .unwrap_or_else(|error| panic!("valid arguments should parse: {error}"));
    let mut io = handshake_io(1, 2);

    let error = sequence
        .perform_control_handshake(&mut io, &args)
        .err()
        .unwrap_or_else(|| panic!("slot mismatch should fail"));
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected step failure, got {error:?}");
    };

    assert_eq!(failure.step(), PluginRegistrationStep::ControlHandshake);
    assert!(failure.diagnostic().contains("launch slot 0"));
    assert!(failure.diagnostic().contains("handshake slot 1"));
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::RequestTimeControl),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::ControlHandshake,
            blocked_step: PluginRegistrationStep::RequestTimeControl,
        })
    );
}

fn handshake_io(slot_index: u32, node_count: u32) -> ScriptedIo {
    ScriptedIo::from_input(control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
        slot_index,
        node_count,
    }))
}

struct ScriptedIo {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    flush_count: usize,
}

impl ScriptedIo {
    fn from_input(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
            flush_count: 0,
        }
    }

    fn written(&self) -> Vec<u8> {
        self.output.clone()
    }

    const fn flush_count(&self) -> usize {
        self.flush_count
    }
}

impl Read for ScriptedIo {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for ScriptedIo {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}
