//! Checks setup-completion acknowledgement ordering and scheduling refusal.

#![forbid(unsafe_code)]

use std::io::{Cursor, Read, Write};

use crucible_protocol::{
    HostMsg, PluginMsg, SETUP_ACK_STATUS_READY, SetupCompletionError, control_encode_host_msg,
    control_encode_plugin_msg, host_accept_setup_ack, host_validate_setup_ack,
    plugin_send_setup_ack,
};

#[test]
fn plugin_sends_setup_ack_status_and_flushes() {
    let mut io = ScriptedIo::from_input(Vec::new());

    assert_eq!(
        plugin_send_setup_ack(&mut io, SETUP_ACK_STATUS_READY),
        Ok(())
    );
    assert_eq!(
        io.written(),
        control_encode_plugin_msg(&PluginMsg::SetupAck {
            status: SETUP_ACK_STATUS_READY,
        })
    );
    assert_eq!(io.flush_count(), 1);
}

#[test]
fn host_accepts_zero_setup_ack_as_schedulable() {
    let ack = control_encode_plugin_msg(&PluginMsg::SetupAck {
        status: SETUP_ACK_STATUS_READY,
    });
    let mut io = ScriptedIo::from_input(ack);

    let setup = match host_accept_setup_ack(&mut io) {
        Ok(setup) => setup,
        Err(error) => panic!("zero setup acknowledgement should be schedulable: {error}"),
    };

    assert!(setup.can_schedule());
    assert_eq!(setup.setup_ack_status(), SETUP_ACK_STATUS_READY);
}

#[test]
fn host_refuses_nonzero_setup_ack_before_scheduling() {
    assert_eq!(
        host_validate_setup_ack(PluginMsg::SetupAck { status: 7 }),
        Err(SetupCompletionError::NonZeroSetupAck { status: 7 })
    );

    let ack = control_encode_plugin_msg(&PluginMsg::SetupAck { status: 7 });
    let mut io = ScriptedIo::from_input(ack);
    assert_eq!(
        host_accept_setup_ack(&mut io),
        Err(SetupCompletionError::NonZeroSetupAck { status: 7 })
    );
}

#[test]
fn host_rejects_unexpected_or_malformed_setup_ack() {
    assert_eq!(
        host_validate_setup_ack(PluginMsg::Hello {
            proto_version: 1,
            abi_version: 1,
        }),
        Err(SetupCompletionError::UnexpectedPluginMessage {
            message: PluginMsg::Hello {
                proto_version: 1,
                abi_version: 1,
            },
        })
    );

    let wrong_direction = control_encode_host_msg(&HostMsg::Quit);
    let mut io = ScriptedIo::from_input(wrong_direction);
    assert!(matches!(
        host_accept_setup_ack(&mut io),
        Err(SetupCompletionError::Decode { .. })
    ));
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

    fn flush_count(&self) -> usize {
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
