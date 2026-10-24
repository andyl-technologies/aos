//! Preowned initial handshake, byte histories and physical-attempt custody.
//!
//! Each poll performs at most one physical syscall. Partial HELLO, ACK, SCM
//! setup and SetupACK cursors remain in the same actor from before child exec.
//! Ordinary setup completion grants no native whole-source readiness.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crucible_qemu_protocol::bounded_setup::{BoundedSetupError, SetupSendJournal};
use crucible_qemu_protocol::{
    ControlLifecycle, ControlLifecycleEvent, ControlLifecycleState, HostHandshakeConfig,
    NegotiatedHandshake, SchedulableNodeSetup, TAG_HELLO_ACK, TAG_SETUP, control_decode_plugin_msg,
    host_negotiate_handshake, host_validate_setup_ack,
};

use super::*;

#[derive(Clone, Copy, Default)]
struct Attempt {
    offered: usize,
    returned: usize,
    retryable: bool,
    errno: i32,
}

struct InitialSetup {
    config: HostHandshakeConfig,
    lifecycle: ControlLifecycle,
    hello: [u8; 13],
    hello_received: usize,
    acknowledgement: [u8; 21],
    acknowledgement_sent: usize,
    setup: SetupSendJournal,
    setup_body: [u8; 13],
    setup_sent: usize,
    setup_acknowledgement: [u8; 6],
    setup_acknowledgement_received: usize,
    negotiated: Option<NegotiatedHandshake>,
    completed: Option<SchedulableNodeSetup>,
}

pub(super) struct InitialIoJournal {
    reads: Vec<Attempt>,
    writes: Vec<Attempt>,
    read_bytes: Vec<u8>,
    offered_write_bytes: Vec<u8>,
    read_extent: usize,
    write_extent: usize,
    setup: Option<InitialSetup>,
    frozen: bool,
}

impl InitialIoJournal {
    pub(super) fn required_bytes(profile: &StagedControlProfile) -> Option<usize> {
        let profile = &profile.compute;
        let attempts = usize::try_from(profile.administrative_read_attempt_limit)
            .ok()?
            .checked_add(usize::try_from(profile.administrative_write_attempt_limit).ok()?)?;
        let bytes = usize::try_from(profile.administrative_read_byte_limit)
            .ok()?
            .checked_add(usize::try_from(profile.administrative_write_byte_limit).ok()?)?;
        attempts
            .checked_mul(std::mem::size_of::<Attempt>())?
            .checked_add(bytes)?
            .checked_add(std::mem::size_of::<Self>())
    }

    pub(super) fn new(profile: &StagedControlProfile) -> Result<Self, NativeWholeControlError> {
        let profile = &profile.compute;
        let counts =
            |count| usize::try_from(count).map_err(|_| NativeWholeControlError::Allocation);
        let attempts = |count| -> Result<Vec<Attempt>, NativeWholeControlError> {
            let mut backing = Vec::new();
            backing
                .try_reserve_exact(count)
                .map_err(|_| NativeWholeControlError::Allocation)?;
            backing.resize(count, Attempt::default());
            Ok(backing)
        };
        Ok(Self {
            reads: attempts(counts(profile.administrative_read_attempt_limit)?)?,
            writes: attempts(counts(profile.administrative_write_attempt_limit)?)?,
            read_bytes: allocated(counts(profile.administrative_read_byte_limit)?)?,
            offered_write_bytes: allocated(counts(profile.administrative_write_byte_limit)?)?,
            read_extent: 0,
            write_extent: 0,
            setup: None,
            frozen: false,
        })
    }
}

/// Owns the initial protocol and the original actor's later staged histories.
///
/// Preparation moves the original three offered descriptors into retained
/// custody before child execution. No socket, budget or descriptor is replaced
/// after a partial exchange. Completion establishes ordinary setup correlation
/// only; the actual source-issued readiness exchange remains separate.
pub(crate) struct InitialWholeControlSocket {
    actor: NativeStagedControlTransport,
}

impl InitialWholeControlSocket {
    pub(super) fn from_actor(actor: NativeStagedControlTransport) -> Self {
        Self { actor }
    }

    /// Moves original descriptor custody into the initial journal before I/O.
    ///
    /// # Errors
    /// Refuses repeated preparation, prior I/O or missing initial backing.
    pub(crate) fn prepare(
        &mut self,
        config: HostHandshakeConfig,
        region_length: u64,
        descriptors: [OwnedFd; 3],
    ) -> Result<(), NativeWholeControlError> {
        self.actor.live()?;
        if self.actor.used || region_length == 0 {
            return self.actor.refuse(NativeWholeControlError::Custody);
        }
        let custody = self.actor.custody_mut()?;
        let initial = custody
            .initial
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?;
        if initial.setup.is_some() || initial.frozen {
            return self.actor.refuse(NativeWholeControlError::Custody);
        }
        let mut lifecycle = ControlLifecycle::new();
        lifecycle
            .observe(ControlLifecycleEvent::ConnectUnixStreamSocketPair)
            .map_err(protocol_error)?;
        let mut acknowledgement = [0; 21];
        acknowledgement[..4].copy_from_slice(&17u32.to_be_bytes());
        acknowledgement[4] = TAG_HELLO_ACK;
        for (index, value) in [
            config.proto_version,
            config.abi_version,
            config.slot_index,
            config.node_count,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 5 + index * 4;
            acknowledgement[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        let mut setup_body = [0; 13];
        setup_body[..4].copy_from_slice(&9u32.to_be_bytes());
        setup_body[4] = TAG_SETUP;
        setup_body[5..].copy_from_slice(&region_length.to_be_bytes());
        initial.setup = Some(InitialSetup {
            config,
            lifecycle,
            hello: [0; 13],
            hello_received: 0,
            acknowledgement,
            acknowledgement_sent: 0,
            setup: SetupSendJournal::new(region_length, descriptors),
            setup_body,
            setup_sent: 0,
            setup_acknowledgement: [0; 6],
            setup_acknowledgement_received: 0,
            negotiated: None,
            completed: None,
        });
        self.actor.used = true;
        Ok(())
    }

    /// Advances at most one initial physical syscall under the original budget.
    ///
    /// # Errors
    /// Retains originals and refuses malformed frames, closure, exhaustion or a
    /// failed physical attempt. Retryable attempts preserve all existing cursors.
    pub(crate) fn poll(&mut self) -> Result<bool, NativeWholeControlError> {
        match self.poll_inner() {
            Ok(complete) => Ok(complete),
            Err(error) => self.actor.refuse(error),
        }
    }

    fn poll_inner(&mut self) -> Result<bool, NativeWholeControlError> {
        self.actor.live()?;
        self.actor.used = true;
        let custody = self.actor.custody_mut()?;
        let initial = custody
            .initial
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?;
        if initial.frozen {
            return Err(NativeWholeControlError::Custody);
        }
        let setup = initial
            .setup
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?;
        let now = monotonic_ns()?;
        let before = custody.administrative.counters();
        let mut received = [0; 13];

        let (result, outbound): (_, Option<&[u8]>) = match setup.lifecycle.state() {
            ControlLifecycleState::Connected => (
                read_once(
                    custody.socket.as_fd(),
                    &mut received[..13 - setup.hello_received],
                    &mut custody.administrative,
                    now,
                ),
                None,
            ),
            ControlLifecycleState::HelloSent => {
                let bytes = &setup.acknowledgement[setup.acknowledgement_sent..];
                (
                    write_once(
                        custody.socket.as_fd(),
                        bytes,
                        &mut custody.administrative,
                        now,
                    ),
                    Some(bytes),
                )
            }
            ControlLifecycleState::HelloAcknowledged => {
                let bytes = &setup.setup_body[setup.setup_sent..];
                let progress = setup.setup.try_send_step(
                    custody.socket.as_fd(),
                    &mut custody.administrative,
                    now,
                );
                (
                    progress.map(|progress| {
                        crucible_qemu_protocol::bounded_setup::AdministrativeIoProgress {
                            actual_bytes: progress.actual_bytes,
                            retryable: progress.actual_bytes == 0 && !progress.complete,
                            peer_closed: false,
                        }
                    }),
                    Some(bytes),
                )
            }
            ControlLifecycleState::SetupSent => (
                read_once(
                    custody.socket.as_fd(),
                    &mut received[..6 - setup.setup_acknowledgement_received],
                    &mut custody.administrative,
                    now,
                ),
                None,
            ),
            ControlLifecycleState::SetupAcknowledged => return Ok(true),
            _ => return Err(NativeWholeControlError::Custody),
        };
        let after = custody.administrative.counters();
        if let Some(bytes) = outbound {
            if after.write_attempts > before.write_attempts {
                let offered =
                    usize::try_from(after.offered_write_bytes - before.offered_write_bytes)
                        .map_err(|_| NativeWholeControlError::Custody)?;
                let attempt = initial
                    .writes
                    .get_mut((after.write_attempts - 1) as usize)
                    .ok_or(NativeWholeControlError::Custody)?;
                *attempt = attempt_record(offered, &result);
                let end = initial
                    .write_extent
                    .checked_add(offered)
                    .ok_or(NativeWholeControlError::Custody)?;
                initial
                    .offered_write_bytes
                    .get_mut(initial.write_extent..end)
                    .ok_or(NativeWholeControlError::Custody)?
                    .copy_from_slice(
                        bytes
                            .get(..offered)
                            .ok_or(NativeWholeControlError::Custody)?,
                    );
                initial.write_extent = end;
            }
        } else if after.read_attempts > before.read_attempts {
            let count = usize::try_from(after.read_bytes - before.read_bytes)
                .map_err(|_| NativeWholeControlError::Custody)?;
            let remaining = match setup.lifecycle.state() {
                ControlLifecycleState::Connected => 13 - setup.hello_received,
                _ => 6 - setup.setup_acknowledgement_received,
            };
            let offered = remaining.min(initial.read_bytes.len() - initial.read_extent);
            let attempt = initial
                .reads
                .get_mut((after.read_attempts - 1) as usize)
                .ok_or(NativeWholeControlError::Custody)?;
            *attempt = attempt_record(offered, &result);
            let end = initial
                .read_extent
                .checked_add(count)
                .ok_or(NativeWholeControlError::Custody)?;
            initial
                .read_bytes
                .get_mut(initial.read_extent..end)
                .ok_or(NativeWholeControlError::Custody)?
                .copy_from_slice(&received[..count]);
            initial.read_extent = end;
        }
        let progress = result.map_err(protocol_error)?;
        if progress.peer_closed {
            return Err(protocol_error(BoundedSetupError::Closed));
        }
        if progress.retryable {
            return Ok(false);
        }
        let count = progress.actual_bytes;
        match setup.lifecycle.state() {
            ControlLifecycleState::Connected => {
                let end = setup.hello_received + count;
                setup.hello[setup.hello_received..end].copy_from_slice(&received[..count]);
                setup.hello_received = end;
                if end == setup.hello.len() {
                    let hello = control_decode_plugin_msg(&setup.hello).map_err(protocol_error)?;
                    setup.negotiated = Some(
                        host_negotiate_handshake(hello, setup.config).map_err(protocol_error)?,
                    );
                    setup
                        .lifecycle
                        .observe(ControlLifecycleEvent::PluginHello)
                        .map_err(protocol_error)?;
                }
            }
            ControlLifecycleState::HelloSent => {
                setup.acknowledgement_sent += count;
                if setup.acknowledgement_sent == setup.acknowledgement.len() {
                    setup
                        .lifecycle
                        .observe(ControlLifecycleEvent::HostHelloAck)
                        .map_err(protocol_error)?;
                }
            }
            ControlLifecycleState::HelloAcknowledged => {
                setup.setup_sent += count;
                if setup.setup_sent == setup.setup_body.len() {
                    setup
                        .lifecycle
                        .observe(ControlLifecycleEvent::HostSetup)
                        .map_err(protocol_error)?;
                }
            }
            ControlLifecycleState::SetupSent => {
                let end = setup.setup_acknowledgement_received + count;
                setup.setup_acknowledgement[setup.setup_acknowledgement_received..end]
                    .copy_from_slice(&received[..count]);
                setup.setup_acknowledgement_received = end;
                if end == setup.setup_acknowledgement.len() {
                    let message = control_decode_plugin_msg(&setup.setup_acknowledgement)
                        .map_err(protocol_error)?;
                    setup.completed =
                        Some(host_validate_setup_ack(message.clone()).map_err(protocol_error)?);
                    setup
                        .lifecycle
                        .observe(ControlLifecycleEvent::from_plugin_msg(&message))
                        .map_err(protocol_error)?;
                }
            }
            _ => return Err(NativeWholeControlError::Custody),
        }
        Ok(setup.completed.is_some())
    }

    /// Borrows the same original descriptors offered during SCM setup.
    pub(crate) fn descriptors(&self) -> Result<[BorrowedFd<'_>; 3], NativeWholeControlError> {
        let custody = self
            .actor
            .custody
            .as_ref()
            .ok_or(NativeWholeControlError::Custody)?;
        let setup = custody
            .initial
            .as_ref()
            .and_then(|initial| initial.setup.as_ref())
            .ok_or(NativeWholeControlError::Custody)?;
        Ok(setup.setup.descriptors())
    }

    fn validate_initial_history(&self) -> Result<(), NativeWholeControlError> {
        let custody = self
            .actor
            .custody
            .as_ref()
            .ok_or(NativeWholeControlError::Custody)?;
        let initial = custody
            .initial
            .as_ref()
            .ok_or(NativeWholeControlError::Custody)?;
        let counters = custody.administrative.counters();
        let validate = |attempts: &[Attempt],
                        count: u64,
                        offered: bool|
         -> Result<usize, NativeWholeControlError> {
            let count = usize::try_from(count).map_err(|_| NativeWholeControlError::Custody)?;
            attempts
                .get(..count)
                .ok_or(NativeWholeControlError::Custody)?
                .iter()
                .try_fold(0usize, |sum, attempt| {
                    if attempt.returned > attempt.offered
                        || attempt.errno != 0
                        || (attempt.retryable && attempt.returned != 0)
                    {
                        return Err(NativeWholeControlError::Custody);
                    }
                    sum.checked_add(if offered {
                        attempt.offered
                    } else {
                        attempt.returned
                    })
                    .ok_or(NativeWholeControlError::Custody)
                })
        };
        if validate(&initial.reads, counters.read_attempts, false)? != initial.read_extent
            || validate(&initial.writes, counters.write_attempts, true)? != initial.write_extent
        {
            return Err(NativeWholeControlError::Custody);
        }
        Ok(())
    }

    /// Freezes a complete original setup without renewing storage or I/O credit.
    ///
    /// # Errors
    /// Refuses incomplete setup, prior refusal or expired original time.
    pub(crate) fn finish_initial(
        original: &mut Option<Self>,
    ) -> Result<NativeStagedControlTransport, NativeWholeControlError> {
        let initial_owner = original.as_mut().ok_or(NativeWholeControlError::Custody)?;
        let validation = (|| {
            initial_owner.actor.live()?;
            initial_owner.validate_initial_history()?;
            let custody = initial_owner.actor.custody_mut()?;
            let initial = custody
                .initial
                .as_mut()
                .ok_or(NativeWholeControlError::Custody)?;
            if initial
                .setup
                .as_ref()
                .is_none_or(|setup| setup.completed.is_none())
            {
                return Err(NativeWholeControlError::Custody);
            }
            initial.frozen = true;
            Ok(())
        })();
        if let Err(error) = validation {
            return initial_owner.actor.refuse(error);
        }

        // Every fallible check precedes this exclusive move. On refusal the
        // caller still owns the same original actor and all initial histories.
        let initial_owner = original.take().ok_or(NativeWholeControlError::Custody)?;
        Ok(initial_owner.actor)
    }
}

fn attempt_record(
    offered: usize,
    result: &Result<
        crucible_qemu_protocol::bounded_setup::AdministrativeIoProgress,
        BoundedSetupError,
    >,
) -> Attempt {
    match result {
        Ok(progress) => Attempt {
            offered,
            returned: progress.actual_bytes,
            retryable: progress.retryable,
            errno: 0,
        },
        Err(BoundedSetupError::Syscall(errno)) => Attempt {
            offered,
            errno: *errno,
            ..Attempt::default()
        },
        Err(_) => Attempt {
            offered,
            ..Attempt::default()
        },
    }
}

fn protocol_error(
    error: impl std::error::Error + Send + Sync + 'static,
) -> NativeWholeControlError {
    io::Error::other(error).into()
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Invalid fixture custody is a test failure.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_qemu_protocol::{
        CONTROL_PROTOCOL_VERSION, PluginMsg, control_encode_plugin_msg, recv_setup_with_descriptors,
    };
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};

    fn descriptors() -> [OwnedFd; 3] {
        std::array::from_fn(|_| {
            // SAFETY: The static name is NUL terminated; success transfers one
            // original descriptor into the uniquely owning test fixture.
            let raw = unsafe {
                libc::memfd_create(c"initial-control-fixture".as_ptr(), libc::MFD_CLOEXEC)
            };
            assert!(raw >= 0);
            // SAFETY: successful memfd_create returned this fresh descriptor;
            // no other owner was constructed, and ownership transfers exactly once.
            unsafe { OwnedFd::from_raw_fd(raw) }
        })
    }

    fn actor() -> (InitialWholeControlSocket, UnixStream, [i32; 3]) {
        let (host, peer) = UnixStream::pair().unwrap();
        let mut profile = super::super::tests::profile();
        profile.compute.provider_history_byte_limit = 32 * 1024 * 1024;
        let mut actor = NativeStagedControlTransport::new_for_setup(host, profile).unwrap();
        let originals = descriptors();
        let raw = originals.each_ref().map(AsRawFd::as_raw_fd);
        actor
            .prepare(
                HostHandshakeConfig {
                    proto_version: CONTROL_PROTOCOL_VERSION,
                    abi_version: 7,
                    slot_index: 0,
                    node_count: 1,
                },
                4096,
                originals,
            )
            .unwrap();
        (actor, peer, raw)
    }

    #[test]
    fn partial_initial_handshake_retains_original_cursors_descriptors_and_lifetime_budget() {
        let (mut actor, mut peer, originals) = actor();
        let hello = control_encode_plugin_msg(&PluginMsg::Hello {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: 7,
        });
        peer.write_all(&hello[..5]).unwrap();
        assert!(!actor.poll().unwrap());
        assert!(!actor.poll().unwrap());
        let custody = actor.actor.custody.as_ref().unwrap();
        let initial = custody.initial.as_ref().unwrap();
        assert_eq!(initial.setup.as_ref().unwrap().hello_received, 5);
        assert_eq!(initial.reads[0].offered, 13);
        assert_eq!(initial.reads[0].returned, 5);
        assert!(initial.reads[1].retryable);
        assert_eq!(initial.reads[1].errno, 0);

        peer.write_all(&hello[5..]).unwrap();
        assert!(!actor.poll().unwrap());
        assert!(!actor.poll().unwrap());
        let mut acknowledgement = [0; 21];
        peer.read_exact(&mut acknowledgement).unwrap();
        assert_eq!(acknowledgement[4], TAG_HELLO_ACK);
        assert!(!actor.poll().unwrap());
        let received = recv_setup_with_descriptors(peer.as_raw_fd()).unwrap();
        assert_eq!(received.region_len, 4096);
        assert_eq!(
            actor.descriptors().unwrap().map(|fd| fd.as_raw_fd()),
            originals
        );
        let setup_ack = control_encode_plugin_msg(&PluginMsg::SetupAck { status: 0 });
        peer.write_all(&setup_ack[..2]).unwrap();
        assert!(!actor.poll().unwrap());
        peer.write_all(&setup_ack[2..]).unwrap();
        assert!(actor.poll().unwrap());
        let counters = actor
            .actor
            .custody
            .as_ref()
            .unwrap()
            .administrative
            .counters();
        assert_eq!(counters.read_attempts, 5);
        assert_eq!(counters.read_bytes, 19);
        assert_eq!(counters.write_attempts, 2);
        assert_eq!(counters.offered_write_bytes, 34);

        let mut original = Some(actor);
        let staged = InitialWholeControlSocket::finish_initial(&mut original).unwrap();
        assert!(original.is_none());
        let custody = staged.custody.as_ref().unwrap();
        assert_eq!(custody.administrative.counters(), counters);
        let initial = custody.initial.as_ref().unwrap();
        assert!(initial.frozen);
        assert_eq!(
            &initial.read_bytes[..initial.read_extent],
            [hello, setup_ack].concat()
        );
        assert_eq!(initial.write_extent, 34);
        assert!(staged.epoch.is_none());
        assert_eq!(custody.stage_count, 0);
        assert_eq!(custody.compute_count, 0);
    }

    #[test]
    fn incomplete_initial_setup_cannot_finish_or_replace_original_descriptor_custody() {
        let (mut actor, _peer, originals) = actor();
        assert!(
            actor
                .prepare(
                    HostHandshakeConfig {
                        proto_version: CONTROL_PROTOCOL_VERSION,
                        abi_version: 7,
                        slot_index: 0,
                        node_count: 1,
                    },
                    4096,
                    descriptors()
                )
                .is_err()
        );
        assert_eq!(
            actor.descriptors().unwrap().map(|fd| fd.as_raw_fd()),
            originals
        );
        let mut original = Some(actor);
        assert!(InitialWholeControlSocket::finish_initial(&mut original).is_err());
        assert!(original.as_ref().is_some_and(|actor| actor.actor.refused));
        for raw in originals {
            // SAFETY: fcntl only inspects the still-quarantined original fd.
            assert!(unsafe { libc::fcntl(raw, libc::F_GETFD) } >= 0);
        }
    }

    #[test]
    fn malformed_initial_hello_retains_full_original_bytes_and_never_offers_acknowledgement() {
        let (mut actor, mut peer, _) = actor();
        let hello = control_encode_plugin_msg(&PluginMsg::Hello {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: 8,
        });
        peer.write_all(&hello).unwrap();
        assert!(actor.poll().is_err());
        let custody = actor.actor.custody.as_ref().unwrap();
        let initial = custody.initial.as_ref().unwrap();
        assert_eq!(&initial.read_bytes[..initial.read_extent], hello);
        assert_eq!(initial.setup.as_ref().unwrap().hello, hello.as_slice());
        assert_eq!(custody.administrative.counters().write_attempts, 0);
        let mut original = Some(actor);
        assert!(InitialWholeControlSocket::finish_initial(&mut original).is_err());
        assert!(original.as_ref().is_some_and(|actor| actor.actor.refused));
    }
}
