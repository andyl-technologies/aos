//! Plugin-side control-protocol handshake validation.
//!
//! The protocol crate owns the wire-level `Hello`/`HelloAck` exchange. This
//! module binds that exchange to the QEMU plugin's launch arguments and compiled
//! ABI constants so setup cannot proceed unless the host's assigned slot matches
//! the `slot=N` argument QEMU used to load this plugin instance.

use std::io::{Read, Write};

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, HandshakeError, NegotiatedHandshake, PluginHandshakeConfig,
    plugin_start_handshake,
};
use crucible_shmem::ABI_VERSION;
use thiserror::Error;

use crate::PluginArgs;

/// Result of a completed plugin control handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginControlHandshake {
    negotiated: NegotiatedHandshake,
    launch_slot: u32,
}

impl PluginControlHandshake {
    /// Returns the full negotiated protocol result.
    #[must_use]
    pub const fn negotiated(self) -> NegotiatedHandshake {
        self.negotiated
    }

    /// Returns the negotiated control-protocol version.
    #[must_use]
    pub const fn proto_version(self) -> u32 {
        self.negotiated.proto_version
    }

    /// Returns the exact shared-memory ABI version accepted by the handshake.
    #[must_use]
    pub const fn abi_version(self) -> u32 {
        self.negotiated.abi_version
    }

    /// Returns the authoritative host-assigned slot index.
    #[must_use]
    pub const fn slot_index(self) -> u32 {
        self.negotiated.slot_index
    }

    /// Returns the launch-argument slot that matched the host assignment.
    #[must_use]
    pub const fn launch_slot(self) -> u32 {
        self.launch_slot
    }

    /// Returns the node count that bounded the slot assignment.
    #[must_use]
    pub const fn node_count(self) -> u32 {
        self.negotiated.node_count
    }
}

/// Returns the plugin's compiled handshake version offer.
#[must_use]
pub const fn plugin_handshake_config() -> PluginHandshakeConfig {
    PluginHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
    }
}

/// Runs the plugin-side `Hello`/`HelloAck` handshake and cross-checks the slot.
///
/// # Errors
///
/// Returns [`PluginHandshakeError`] when the frame exchange fails, protocol or
/// ABI versions do not match, the host-assigned slot is outside `node_count`, the
/// launch slot is outside `node_count`, or the host-assigned slot differs from
/// the launch slot.
pub fn perform_plugin_handshake<S>(
    stream: &mut S,
    args: &PluginArgs,
) -> Result<PluginControlHandshake, PluginHandshakeError>
where
    S: Read + Write,
{
    let negotiated = plugin_start_handshake(stream, plugin_handshake_config())
        .map_err(|source| PluginHandshakeError::Protocol { source })?;
    validate_plugin_handshake(args, negotiated)
}

/// Validates a decoded handshake result against plugin launch arguments.
///
/// # Errors
///
/// Returns [`PluginHandshakeError::LaunchSlotOutOfRange`] when `slot=N` is not in
/// `0..node_count`, or [`PluginHandshakeError::LaunchSlotMismatch`] when `slot=N`
/// differs from the host-assigned `HelloAck.slot_index`.
pub fn validate_plugin_handshake(
    args: &PluginArgs,
    negotiated: NegotiatedHandshake,
) -> Result<PluginControlHandshake, PluginHandshakeError> {
    let launch_slot = args.slot();
    if launch_slot >= negotiated.node_count {
        return Err(PluginHandshakeError::LaunchSlotOutOfRange {
            launch_slot,
            node_count: negotiated.node_count,
        });
    }
    if launch_slot != negotiated.slot_index {
        return Err(PluginHandshakeError::LaunchSlotMismatch {
            launch_slot,
            handshake_slot: negotiated.slot_index,
        });
    }

    Ok(PluginControlHandshake {
        negotiated,
        launch_slot,
    })
}

/// An error produced while performing the plugin control handshake.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginHandshakeError {
    /// The protocol-level `Hello`/`HelloAck` exchange failed.
    #[error("control protocol handshake failed: {source}")]
    Protocol {
        /// The lower-level protocol handshake error.
        source: HandshakeError,
    },
    /// The launch-argument slot is outside the host's declared node range.
    #[error("launch slot {launch_slot} is outside node_count {node_count}")]
    LaunchSlotOutOfRange {
        /// Slot from `-plugin ...,slot=N`.
        launch_slot: u32,
        /// Node count from `HelloAck`.
        node_count: u32,
    },
    /// The launch-argument slot disagrees with the host-assigned handshake slot.
    #[error("launch slot {launch_slot} does not match handshake slot {handshake_slot}")]
    LaunchSlotMismatch {
        /// Slot from `-plugin ...,slot=N`.
        launch_slot: u32,
        /// Slot from `HelloAck`.
        handshake_slot: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Cursor, Read, Write};

    use crucible_protocol::{HostMsg, control_encode_host_msg, control_encode_plugin_msg};

    #[test]
    fn plugin_handshake_sends_compiled_versions_and_accepts_matching_slot() {
        let ack = control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index: 2,
            node_count: 4,
        });
        let mut io = ScriptedIo::from_input(ack);
        let args = plugin_args(
            "simfd=3,slot=2,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1",
        );

        let handshake = perform_plugin_handshake(&mut io, &args)
            .unwrap_or_else(|error| panic!("handshake should succeed: {error}"));

        assert_eq!(handshake.proto_version(), CONTROL_PROTOCOL_VERSION);
        assert_eq!(handshake.abi_version(), ABI_VERSION);
        assert_eq!(handshake.slot_index(), 2);
        assert_eq!(handshake.launch_slot(), 2);
        assert_eq!(handshake.node_count(), 4);
        assert_eq!(
            io.written(),
            control_encode_plugin_msg(&crucible_protocol::PluginMsg::Hello {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
            })
        );
        assert_eq!(io.flush_count(), 1);
    }

    #[test]
    fn plugin_handshake_rejects_launch_slot_outside_node_count() {
        let args = plugin_args(
            "simfd=3,slot=4,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1",
        );
        let negotiated = NegotiatedHandshake {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index: 2,
            node_count: 4,
        };

        assert_eq!(
            validate_plugin_handshake(&args, negotiated),
            Err(PluginHandshakeError::LaunchSlotOutOfRange {
                launch_slot: 4,
                node_count: 4,
            })
        );
    }

    #[test]
    fn plugin_handshake_rejects_launch_slot_disagreement() {
        let args = plugin_args(
            "simfd=3,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1",
        );
        let negotiated = NegotiatedHandshake {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index: 2,
            node_count: 4,
        };

        assert_eq!(
            validate_plugin_handshake(&args, negotiated),
            Err(PluginHandshakeError::LaunchSlotMismatch {
                launch_slot: 1,
                handshake_slot: 2,
            })
        );
    }

    #[test]
    fn plugin_handshake_preserves_protocol_failures() {
        assert_eq!(ABI_VERSION, 12);
        for host_abi in [1, ABI_VERSION + 1] {
            let ack = control_encode_host_msg(&HostMsg::HelloAck {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: host_abi,
                slot_index: 0,
                node_count: 1,
            });
            let mut io = ScriptedIo::from_input(ack);
            let args = plugin_args(
                "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1",
            );

            assert!(matches!(
                perform_plugin_handshake(&mut io, &args),
                Err(PluginHandshakeError::Protocol {
                    source: HandshakeError::AbiMismatch {
                        plugin_abi: ABI_VERSION,
                        host_abi: rejected,
                    },
                }) if rejected == host_abi
            ));
        }
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

    fn plugin_args(raw: &str) -> PluginArgs {
        PluginArgs::parse(raw).unwrap_or_else(|error| panic!("test args should parse: {error}"))
    }
}
