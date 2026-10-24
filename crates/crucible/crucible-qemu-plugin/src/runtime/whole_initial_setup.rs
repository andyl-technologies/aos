//! Fixed initial protocol cursors on the constructor's original socket actor.
//!
//! Initial HELLO, ACK, SCM setup and setup ACK all spend the same lifetime
//! administrative credit used by later staged operations. Partial frames and
//! every received original descriptor remain in the actor. Local setup
//! completion is distinct from an installed native source-ready exchange.

use std::sync::Arc;

use crucible_qemu_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycle, ControlLifecycleEvent, TAG_HELLO, TAG_SETUP_ACK,
    control_decode_host_msg, plugin_validate_handshake_ack,
};
use thiserror::Error;

use crate::{
    PluginArgs, PluginControlHandshake, plugin_handshake_config, validate_plugin_handshake,
};

use super::whole_original_socket::{OriginalWholeSocket, WholeSocketError};

#[derive(Debug, Error)]
pub(crate) enum WholeInitialSetupError {
    #[error("original selected initial socket failed: {0}")]
    Socket(#[from] WholeSocketError),
    #[error("original selected initial protocol was refused")]
    Protocol,
    #[error("original selected initial socket closed")]
    Closed,
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Actual socket/lifecycle controls fail on invariant violations.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crucible_qemu_protocol::bounded_setup::SetupSendJournal;
    use crucible_qemu_protocol::whole_control::staged::administrative::AdministrativeIoBudget;
    use crucible_qemu_protocol::whole_control::{
        WholeControlProfile, staged::StagedControlProfile,
    };
    use crucible_qemu_protocol::{HostMsg, control_encode_host_msg};
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    fn actor() -> (
        OriginalWholeInitialSetup,
        UnixStream,
        PluginArgs,
        StagedControlProfile,
    ) {
        let profile = StagedControlProfile {
            compute: WholeControlProfile {
                scope: [9; 32],
                operation_capacity: 2,
                body_byte_limit: 1024,
                native_history_byte_limit: 1_000_000,
                provider_history_byte_limit: 1_000_000,
                administrative_read_attempt_limit: 100,
                administrative_read_byte_limit: 100_000,
                administrative_write_attempt_limit: 100,
                administrative_write_byte_limit: 100_000,
                deadline_monotonic_ns: 1000,
                cpu_retirement_limit: 100,
                event_step_limit: 100,
                input_byte_limit: 100,
                input_record_limit: 10,
                output_byte_limit: 100,
                output_record_limit: 10,
            },
            input_stage_limit: 3,
            stage_body_byte_limit: 1024,
        };
        let (source, host) = UnixStream::pair().unwrap();
        let raw = source.as_raw_fd();
        let socket = Arc::new(OriginalWholeSocket::prepare(&profile, 0).unwrap());
        socket.install_original_socket(source).unwrap();
        let args = PluginArgs::parse(&format!("simfd={raw},slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576")).unwrap();
        (OriginalWholeInitialSetup::new(socket), host, args, profile)
    }

    fn hello_ack() -> Vec<u8> {
        control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: crucible_qemu_shmem::ABI_VERSION,
            slot_index: 0,
            node_count: 2,
        })
    }

    #[test]
    fn partial_initial_frames_and_scm_keep_the_same_actor_and_credit_into_staged_io() {
        let (mut initial, mut host, args, profile) = actor();
        assert!(!initial.poll_setup(&args, 0).unwrap());
        let mut hello = [0; 13];
        host.read_exact(&mut hello).unwrap();
        assert_eq!(hello, initial.hello);
        let acknowledgement = hello_ack();
        host.write_all(&acknowledgement[..5]).unwrap();
        assert!(!initial.poll_setup(&args, 0).unwrap());
        assert_eq!(initial.hello_ack_received, 5);
        host.write_all(&acknowledgement[5..]).unwrap();
        assert!(!initial.poll_setup(&args, 0).unwrap());

        let descriptors: [OwnedFd; 3] = std::array::from_fn(|_| {
            let (fd, _peer) = UnixStream::pair().unwrap();
            fd.into()
        });
        let mut sender = SetupSendJournal::new(4096, descriptors);
        let mut host_budget = AdministrativeIoBudget::new(&profile).unwrap();
        assert!(
            sender
                .try_send_step(host.as_fd(), &mut host_budget, 0)
                .unwrap()
                .complete
        );
        assert!(!initial.poll_setup(&args, 0).unwrap());
        assert!(initial.poll_setup(&args, 0).unwrap());
        assert_eq!(initial.handshake().unwrap().slot_index(), 0);
        assert_eq!(initial.handshake().unwrap().node_count(), 2);
        assert!(initial.poll_setup_ack(0, 0).unwrap());

        let mut setup_ack = [0; 6];
        host.read_exact(&mut setup_ack).unwrap();
        assert_eq!(setup_ack, initial.setup_ack);
        let counters = initial.socket().counters().unwrap();
        assert_eq!(counters.read_bytes, 34);
        assert_eq!(counters.offered_write_bytes, 19);
        initial.socket().write_step(b"next", 0).unwrap();
        assert_eq!(initial.socket().counters().unwrap().offered_write_bytes, 23);
        assert_eq!(
            initial
                .socket()
                .received_setup()
                .unwrap()
                .region_len()
                .unwrap(),
            4096
        );
    }

    #[test]
    fn malformed_complete_ack_retains_original_bytes_and_sticky_initial_refusal() {
        let (mut initial, mut host, args, _profile) = actor();
        initial.poll_setup(&args, 0).unwrap();
        let mut malformed = hello_ack();
        malformed[8] ^= 1;
        host.write_all(&malformed).unwrap();
        assert!(initial.poll_setup(&args, 0).is_err());
        assert_eq!(initial.hello_ack.as_slice(), malformed);
        let counters = initial.socket().counters().unwrap();
        assert_eq!(counters.read_bytes, 21);
        assert!(initial.poll_setup(&args, 0).is_err());
        assert_eq!(initial.socket().counters().unwrap(), counters);
        assert!(initial.poll_setup_ack(0, 0).is_err());
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InitialPhase {
    OfferHello,
    ReceiveHelloAck,
    ReceiveSetup,
    Prepared,
    OfferSetupAck,
    Completed,
    Refused,
}

/// Retains fixed preallocated cursors alongside the same original socket owner.
pub(crate) struct OriginalWholeInitialSetup {
    socket: Arc<OriginalWholeSocket>,
    process: u32,
    lifecycle: ControlLifecycle,
    phase: InitialPhase,
    hello: [u8; 13],
    hello_written: usize,
    hello_ack: [u8; 21],
    hello_ack_received: usize,
    setup_ack: [u8; 6],
    setup_ack_written: usize,
    handshake: Option<PluginControlHandshake>,
}

impl OriginalWholeInitialSetup {
    /// Prepares fixed initial backing without copying or replacing its actor.
    pub(crate) fn new(socket: Arc<OriginalWholeSocket>) -> Self {
        let mut hello = [0; 13];
        hello[..4].copy_from_slice(&9u32.to_be_bytes());
        hello[4] = TAG_HELLO;
        hello[5..9].copy_from_slice(&CONTROL_PROTOCOL_VERSION.to_be_bytes());
        hello[9..13].copy_from_slice(&crucible_qemu_shmem::ABI_VERSION.to_be_bytes());
        let mut setup_ack = [0; 6];
        setup_ack[..4].copy_from_slice(&2u32.to_be_bytes());
        setup_ack[4] = TAG_SETUP_ACK;

        Self {
            socket,
            process: std::process::id(),
            lifecycle: ControlLifecycle::new(),
            phase: InitialPhase::OfferHello,
            hello,
            hello_written: 0,
            hello_ack: [0; 21],
            hello_ack_received: 0,
            setup_ack,
            setup_ack_written: 0,
            handshake: None,
        }
    }

    /// Returns the next fixed initial cursor's readiness interest.
    pub(super) fn readiness_interest(&self) -> Result<i16, WholeInitialSetupError> {
        if self.process != std::process::id() {
            return Err(WholeInitialSetupError::Protocol);
        }
        match self.phase {
            InitialPhase::OfferHello | InitialPhase::Prepared | InitialPhase::OfferSetupAck => {
                Ok(libc::POLLOUT)
            }
            InitialPhase::ReceiveHelloAck | InitialPhase::ReceiveSetup => Ok(libc::POLLIN),
            _ => Err(WholeInitialSetupError::Protocol),
        }
    }

    /// Offers at most one physical syscall before returning its retained state.
    ///
    /// # Errors
    /// Refuses a changed process, failed transfer, malformed ACK, launch-slot
    /// mismatch or invalid lifecycle. Refusal does not drop bytes or FDs.
    pub(crate) fn poll_setup(
        &mut self,
        args: &PluginArgs,
        now_monotonic_ns: u64,
    ) -> Result<bool, WholeInitialSetupError> {
        if self.process != std::process::id() || self.phase == InitialPhase::Refused {
            return Err(WholeInitialSetupError::Protocol);
        }
        let result = self.poll_setup_inner(args, now_monotonic_ns);
        if result.is_err() {
            self.phase = InitialPhase::Refused;
        }
        result
    }

    fn poll_setup_inner(
        &mut self,
        args: &PluginArgs,
        now: u64,
    ) -> Result<bool, WholeInitialSetupError> {
        match self.phase {
            InitialPhase::OfferHello => {
                if self.lifecycle.state()
                    == crucible_qemu_protocol::ControlLifecycleState::Disconnected
                {
                    self.socket.descriptor()?;
                    self.lifecycle
                        .observe(ControlLifecycleEvent::ConnectUnixStreamSocketPair)
                        .map_err(|_| WholeInitialSetupError::Protocol)?;
                }
                let progress = self
                    .socket
                    .write_step(&self.hello[self.hello_written..], now)?;
                if progress.peer_closed {
                    return Err(WholeInitialSetupError::Closed);
                }
                self.hello_written += progress.actual_bytes;
                if self.hello_written == self.hello.len() {
                    self.lifecycle
                        .observe(ControlLifecycleEvent::PluginHello)
                        .map_err(|_| WholeInitialSetupError::Protocol)?;
                    self.phase = InitialPhase::ReceiveHelloAck;
                }
            }
            InitialPhase::ReceiveHelloAck => {
                let progress = self
                    .socket
                    .read_step(&mut self.hello_ack[self.hello_ack_received..], now)?;
                if progress.peer_closed {
                    return Err(WholeInitialSetupError::Closed);
                }
                self.hello_ack_received += progress.actual_bytes;
                if self.hello_ack_received == self.hello_ack.len() {
                    let message = control_decode_host_msg(&self.hello_ack)
                        .map_err(|_| WholeInitialSetupError::Protocol)?;
                    let negotiated =
                        plugin_validate_handshake_ack(message, plugin_handshake_config())
                            .map_err(|_| WholeInitialSetupError::Protocol)?;
                    self.handshake = Some(
                        validate_plugin_handshake(args, negotiated)
                            .map_err(|_| WholeInitialSetupError::Protocol)?,
                    );
                    self.lifecycle
                        .observe(ControlLifecycleEvent::HostHelloAck)
                        .map_err(|_| WholeInitialSetupError::Protocol)?;
                    self.phase = InitialPhase::ReceiveSetup;
                }
            }
            InitialPhase::ReceiveSetup => {
                if self.socket.receive_setup_step(now)?.complete {
                    self.lifecycle
                        .observe(ControlLifecycleEvent::HostSetup)
                        .map_err(|_| WholeInitialSetupError::Protocol)?;
                    self.phase = InitialPhase::Prepared;
                }
            }
            InitialPhase::Prepared => return Ok(true),
            _ => return Err(WholeInitialSetupError::Protocol),
        }
        Ok(self.phase == InitialPhase::Prepared)
    }

    /// Borrows the same actor for mapped setup and subsequent staged custody.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
        )
    )]
    pub(crate) fn socket(&self) -> &Arc<OriginalWholeSocket> {
        &self.socket
    }

    /// Returns the exact completed handshake after full initial frame validation.
    ///
    /// # Errors
    /// Refuses an absent handshake, foreign process or incomplete setup phase.
    pub(crate) fn handshake(&self) -> Result<PluginControlHandshake, WholeInitialSetupError> {
        if self.process != std::process::id() || self.phase != InitialPhase::Prepared {
            return Err(WholeInitialSetupError::Protocol);
        }
        self.handshake.ok_or(WholeInitialSetupError::Protocol)
    }

    /// Sends the fixed setup ACK after actual caller-owned callback registration.
    ///
    /// This method records only setup transport completion. Its caller supplies
    /// a status after its typed registration sequence; it cannot arm the host's
    /// source-ready facade. Every failed partial transfer stays in this actor.
    ///
    /// # Errors
    /// Refuses phase/PID mismatch, changed repeated status or physical I/O failure.
    pub(crate) fn poll_setup_ack(
        &mut self,
        status: u8,
        now: u64,
    ) -> Result<bool, WholeInitialSetupError> {
        if self.process != std::process::id() {
            return Err(WholeInitialSetupError::Protocol);
        }
        match self.phase {
            InitialPhase::Prepared => {
                self.setup_ack[5] = status;
                self.phase = InitialPhase::OfferSetupAck;
            }
            InitialPhase::OfferSetupAck if self.setup_ack[5] == status => {}
            InitialPhase::Completed if self.setup_ack[5] == status => return Ok(true),
            _ => {
                self.phase = InitialPhase::Refused;
                return Err(WholeInitialSetupError::Protocol);
            }
        }
        let result = self
            .socket
            .write_step(&self.setup_ack[self.setup_ack_written..], now);
        let progress = match result {
            Ok(progress) if !progress.peer_closed => progress,
            Ok(_) => {
                self.phase = InitialPhase::Refused;
                return Err(WholeInitialSetupError::Closed);
            }
            Err(error) => {
                self.phase = InitialPhase::Refused;
                return Err(error.into());
            }
        };
        self.setup_ack_written += progress.actual_bytes;
        if self.setup_ack_written == self.setup_ack.len() {
            if self
                .lifecycle
                .observe(ControlLifecycleEvent::PluginSetupAck { status })
                .is_err()
            {
                self.phase = InitialPhase::Refused;
                return Err(WholeInitialSetupError::Protocol);
            }
            self.phase = InitialPhase::Completed;
        }
        Ok(self.phase == InitialPhase::Completed)
    }
}
