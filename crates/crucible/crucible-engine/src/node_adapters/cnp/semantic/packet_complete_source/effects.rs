//! Retains three original effect receivers without duplicating their descriptors.
//!
//! Source and factory aliases may inspect the same queues. A separate noncloneable
//! reader owns the consuming role. This kernel ownership component authenticates
//! neither a stopped native frontier nor publication equality or capture rights.

use std::{os::unix::net::UnixDatagram, path::Path, rc::Rc, thread::ThreadId};

use super::super::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics;
use super::{OperationFailure, refused};

#[path = "effects/host_setup17.rs"]
mod host_setup17;

const ORIGINAL_GROUP_PROCESS_REFUSAL: &str = "effect receiver belongs to another creator process";
const ORIGINAL_GROUP_THREAD_REFUSAL: &str = "effect receiver belongs to another creator thread";
const ORIGINAL_GROUP_NONEMPTY_REFUSAL: &str = "original effect receiver still has a datagram";
const ORIGINAL_GROUP_PEEK_REFUSAL: &str = "original effect receiver peek failed";
const ORIGINAL_READER_GROUP_REFUSAL: &str = "effect reader has another original group";

/// Retains the original three receiver descriptors behind inspection-only aliases.
///
/// The group has no source or oracle backreference. Its original creator process
/// and thread precede every kernel access; no raw descriptor or socket loan is
/// exposed. The source factory separately joins the same group with its original
/// launches, source identities and stopped native emission frontier.
pub struct PacketCompleteEffectReceiverGroup {
    process: u32,
    thread: ThreadId,
    receivers: [UnixDatagram; 3],
}

/// Retains the sole library-issued consuming role for an original receiver group.
///
/// This role has no Clone or Deserialize implementation. Moving it into the
/// complete oracle retains the same descriptors, without creating another reader.
pub struct PacketCompleteEffectReceiverReader {
    group: Rc<PacketCompleteEffectReceiverGroup>,
}

impl PacketCompleteEffectReceiverGroup {
    /// Moves three actual sockets once into a group and its sole consuming role.
    ///
    /// The fixed group and Rc storage must be charged before child construction.
    /// The source/factory may clone the returned inspection alias; the consuming
    /// role moves once into the oracle. Construction grants no capture authority.
    pub fn from_original_receivers(
        receivers: [UnixDatagram; 3],
    ) -> (Rc<Self>, PacketCompleteEffectReceiverReader) {
        let group = Rc::new(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            receivers,
        });
        let reader = PacketCompleteEffectReceiverReader {
            group: Rc::clone(&group),
        };
        (group, reader)
    }

    fn ensure_origin(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() {
            return Err(refused(ORIGINAL_GROUP_PROCESS_REFUSAL));
        }
        if self.thread != std::thread::current().id() {
            return Err(refused(ORIGINAL_GROUP_THREAD_REFUSAL));
        }
        Ok(())
    }

    /// Counts this actual receiver Rc allocation without a descriptor operation.
    ///
    /// The closed group owns only creator IDs and three inline UnixDatagram
    /// descriptors. Their kernel queues/resources remain separate; this observes
    /// requested Rust storage and grants no receiver, frontier or Capture right.
    ///
    /// # Errors
    /// Refuses another creator, checked layout overflow or the supplied maximum.
    pub fn original_retained_requested_storage_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.ensure_origin()?;
        let Self {
            process: _,
            thread: _,
            receivers: _,
        } = self.as_ref();
        let header = crate::node_contract::NodeRuntime::capture_protocol_shared_header_storage(
            1,
            std::mem::align_of::<Self>(),
            maximum,
        )
        .map_err(|_| refused("original receiver group shared layout refused"))?;
        std::mem::size_of::<Self>()
            .checked_add(header)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| refused("original receiver group storage exhausted"))
    }

    /// Counts the same receiver group with raw precredit failures.
    ///
    /// This reads only Rust ownership/layout. Descriptor queues and native
    /// frontier emptiness retain their independent authenticated kernel checks.
    ///
    /// # Errors
    /// Refuses another creator/thread or checked requested-storage exhaustion.
    pub fn original_retained_requested_storage_precredit_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::{NodeRuntime, RuntimeError};
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let header = NodeRuntime::capture_protocol_shared_header_storage(
            1,
            std::mem::align_of::<Self>(),
            maximum,
        )?;
        std::mem::size_of::<Self>()
            .checked_add(header)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Authenticates an actual original bound address against its selected launch path.
    ///
    /// # Errors
    /// Refuses a foreign creator, invalid member, inaccessible kernel address,
    /// unnamed receiver or a path differing from the selected original launch.
    pub fn authenticate_original_path(
        &self,
        member: usize,
        expected: &Path,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let receiver = self
            .receivers
            .get(member)
            .ok_or_else(|| refused("effect receiver member is outside the original roster"))?;
        let address = receiver
            .local_addr()
            .map_err(|_| refused("original effect receiver address is unavailable"))?;
        self.ensure_origin()?;
        if address.as_pathname() != Some(expected) {
            return Err(refused("original effect receiver has another launch path"));
        }
        Ok(())
    }

    /// Authenticates empty original queues with nonconsuming nonblocking kernel peeks.
    ///
    /// Every queued datagram is refused, including a zero-length datagram. The
    /// caller must independently bracket this observation with the same stopped
    /// native source frontier and exact emission equality; emptiness alone grants
    /// no capture permission and does not advance the consuming reader.
    ///
    /// # Errors
    /// Refuses a foreign creator, any queued datagram or a kernel read failure.
    pub fn authenticate_empty(&self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let result = (|| {
            for receiver in &self.receivers {
                let mut byte = [0; 1];
                match rustix::net::recv(
                    receiver,
                    &mut byte,
                    rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
                ) {
                    Err(rustix::io::Errno::AGAIN) => {}
                    Ok(_) => return Err(refused(ORIGINAL_GROUP_NONEMPTY_REFUSAL)),
                    Err(_) => return Err(refused(ORIGINAL_GROUP_PEEK_REFUSAL)),
                }
            }
            Ok(())
        })();
        self.ensure_origin()?;
        result
    }
}

impl PacketCompleteEffectReceiverReader {
    /// Authenticates the exact inspection group paired with this consuming role.
    ///
    /// This check invokes no descriptor operation and clones no ownership. It
    /// prevents an oracle from pairing one source-bound group with another group's
    /// consuming reader. The factory still authenticates the source and frontier.
    ///
    /// # Errors
    /// Refuses a foreign creator or a different actual group allocation.
    pub fn authenticate_original_group(
        &self,
        group: &Rc<PacketCompleteEffectReceiverGroup>,
    ) -> Result<(), OperationFailure> {
        self.group.ensure_origin()?;
        if !Rc::ptr_eq(&self.group, group) {
            return Err(refused(ORIGINAL_READER_GROUP_REFUSAL));
        }
        Ok(())
    }

    /// Receives one original datagram without changing the socket's blocking mode.
    ///
    /// A drained queue returns None. A queued zero-length datagram returns Some(0)
    /// and remains distinguishable from an empty queue. The complete oracle keeps
    /// its independent payload, oversized-frame and native-frontier checks.
    ///
    /// # Errors
    /// Refuses a foreign creator, invalid member, empty receive buffer or a kernel
    /// failure. The same group and descriptor ownership remain in this reader.
    pub fn receive(
        &self,
        member: usize,
        bytes: &mut [u8],
    ) -> Result<Option<usize>, OperationFailure> {
        self.group.ensure_origin()?;
        let receiver = self
            .group
            .receivers
            .get(member)
            .ok_or_else(|| refused("effect reader member is outside the original roster"))?;
        if bytes.is_empty() {
            return Err(refused("original effect reader buffer is empty"));
        }
        let result = match rustix::net::recv(receiver, bytes, rustix::net::RecvFlags::DONTWAIT) {
            Ok((_, length)) => Ok(Some(length)),
            Err(rustix::io::Errno::AGAIN) => Ok(None),
            Err(_) => Err(refused("original effect receiver read failed")),
        };
        self.group.ensure_origin()?;
        result
    }
}

pub(super) struct OriginalCompleteEffectReceiver {
    group: Rc<PacketCompleteEffectReceiverGroup>,
    member: usize,
    path: std::path::PathBuf,
}

impl super::PacketCompleteSemanticSource {
    /// Binds the same original receiver group before sharing or native association.
    ///
    /// This retains one inspection alias and the original launch path. It grants
    /// neither a stopped frontier nor capture permission. The complete factory
    /// independently joins this binding with the same oracle and native launches.
    ///
    /// # Errors
    /// Refuses a foreign creator, repeated binding, prior native association,
    /// invalid member or a receiver address differing from the original path.
    pub fn bind_original_effect_receiver(
        &mut self,
        group: Rc<PacketCompleteEffectReceiverGroup>,
        member: usize,
        path: std::path::PathBuf,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.effect_receiver.is_some() {
            return Err(refused("original source effect receiver is already bound"));
        }
        let unbound = match &self.original {
            super::CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound()
            }
            super::CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound()
            }
        }?;
        if !unbound {
            return Err(refused(
                "effect receiver binding follows native association",
            ));
        }
        group.authenticate_original_path(member, &path)?;
        self.effect_receiver = Some(OriginalCompleteEffectReceiver {
            group,
            member,
            path,
        });
        Ok(())
    }

    /// Authenticates the exact source-held group, member and original launch path.
    ///
    /// # Errors
    /// Refuses foreign custody, an absent binding, a different actual Rc group,
    /// changed member/path or inaccessible original kernel address.
    pub fn authenticate_original_effect_receiver_binding(
        &self,
        group: &Rc<PacketCompleteEffectReceiverGroup>,
        member: usize,
        path: &Path,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original_effect_receiver_binding_data(group, member, path)?;
        group.authenticate_original_path(member, path)?;
        self.ensure_origin()
    }

    /// Authenticates original receiver allocation/member/path without kernel IO.
    ///
    /// This reads only retained identity data and grants no queue/frontier right.
    /// The existing kernel-path validator remains independent and unchanged.
    ///
    /// # Errors
    /// Refuses another creator, missing binding or another actual group/member/path.
    pub fn authenticate_original_effect_receiver_binding_data(
        &self,
        group: &Rc<PacketCompleteEffectReceiverGroup>,
        member: usize,
        path: &Path,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        group.ensure_origin()?;
        let original = self
            .effect_receiver
            .as_ref()
            .ok_or_else(|| refused("original source effect receiver is absent"))?;
        if !Rc::ptr_eq(&original.group, group) || original.member != member || original.path != path
        {
            return Err(refused(
                "source effect receiver has another original association",
            ));
        }
        self.ensure_origin()
    }

    /// Counts an actually retained optional receiver group view before native birth.
    ///
    /// An absent binding has no group allocation. Repeated actual aliases may be
    /// conservatively charged per view; equal paths/labels never refund storage.
    ///
    /// # Errors
    /// Refuses another creator, group origin, checked overflow or the bound.
    pub fn original_effect_receiver_retained_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        self.ensure_origin()?;
        let bytes = self
            .effect_receiver
            .as_ref()
            .map(|original| {
                original
                    .group
                    .original_retained_requested_storage_data(maximum)
            })
            .transpose()?;
        self.ensure_origin()?;
        Ok(bytes)
    }

    /// Counts the same optional group view with allocation-free failures.
    ///
    /// # Errors
    /// Refuses foreign creator/thread or checked requested-storage exhaustion.
    pub fn original_effect_receiver_retained_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        self.storage_origin_with_error::<RuntimeError>()?;
        let bytes = self
            .effect_receiver
            .as_ref()
            .map(|original| {
                original
                    .group
                    .original_retained_requested_storage_precredit_data(maximum)
            })
            .transpose()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(bytes)
    }

    /// Peeks the original shared queues between current source/capsule guards.
    ///
    /// Queue emptiness alone does not establish the stopped native frontier or
    /// exact emission equality. The factory and journal issuer must conjoin those
    /// facts against the same original oracle before authorizing capture.
    ///
    /// # Errors
    /// Refuses changed native/source custody, absent original receiver binding,
    /// changed address, any queued datagram or a kernel read failure.
    pub fn authenticate_original_effect_queues_empty(
        &self,
        scope: &super::CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_witness_scope(scope)?;
        let original = self
            .effect_receiver
            .as_ref()
            .ok_or_else(|| refused("original source effect receiver is absent"))?;
        original
            .group
            .authenticate_original_path(original.member, &original.path)?;
        let result = original.group.authenticate_empty();
        self.authenticate_witness_scope(scope)?;
        result
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Assertion panics are control verdicts.
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn receivers() -> ([UnixDatagram; 3], [UnixDatagram; 3]) {
        let (send0, recv0) = UnixDatagram::pair().unwrap();
        let (send1, recv1) = UnixDatagram::pair().unwrap();
        let (send2, recv2) = UnixDatagram::pair().unwrap();
        ([send0, send1, send2], [recv0, recv1, recv2])
    }

    #[test]
    fn complete_effect_group_peek_preserves_zero_and_nonempty_datagrams() {
        let (senders, receivers) = receivers();
        let (group, reader) = PacketCompleteEffectReceiverGroup::from_original_receivers(receivers);
        let alias = Rc::clone(&group);
        group.authenticate_empty().unwrap();
        let mut bytes = [0; 8];
        assert_eq!(reader.receive(0, &mut bytes).unwrap(), None);

        senders[0].send(&[]).unwrap();
        assert!(group.authenticate_empty().is_err());
        assert!(alias.authenticate_empty().is_err());
        assert_eq!(reader.receive(0, &mut bytes).unwrap(), Some(0));
        assert_eq!(reader.receive(0, &mut bytes).unwrap(), None);
        alias.authenticate_empty().unwrap();

        senders[2].send(b"original").unwrap();
        assert!(group.authenticate_empty().is_err());
        assert_eq!(reader.receive(2, &mut bytes).unwrap(), Some(8));
        assert_eq!(&bytes, b"original");
        group.authenticate_empty().unwrap();
    }

    #[test]
    fn complete_effect_reader_refuses_foreign_group_without_consuming_original_queue() {
        let (senders, original_receivers) = receivers();
        let (group, reader) =
            PacketCompleteEffectReceiverGroup::from_original_receivers(original_receivers);
        let (_foreign_senders, foreign_receivers) = receivers();
        let (foreign, foreign_reader) =
            PacketCompleteEffectReceiverGroup::from_original_receivers(foreign_receivers);
        senders[0].send(&[]).unwrap();

        reader.authenticate_original_group(&group).unwrap();
        foreign_reader
            .authenticate_original_group(&foreign)
            .unwrap();
        assert!(reader.authenticate_original_group(&foreign).is_err());
        assert!(foreign_reader.authenticate_original_group(&group).is_err());
        assert!(group.authenticate_empty().is_err());
        let mut byte = [0; 1];
        assert_eq!(reader.receive(0, &mut byte).unwrap(), Some(0));
        group.authenticate_empty().unwrap();
    }

    #[test]
    fn complete_effect_reader_preserves_oversize_and_refuses_invalid_loans() {
        let (senders, receivers) = receivers();
        let (group, reader) = PacketCompleteEffectReceiverGroup::from_original_receivers(receivers);
        let original = vec![7; 65_537];
        senders[1].send(&original).unwrap();
        let mut bytes = vec![0; 65_537];

        assert!(reader.receive(3, &mut bytes).is_err());
        assert!(reader.receive(1, &mut []).is_err());
        assert!(group.authenticate_empty().is_err());
        assert_eq!(reader.receive(1, &mut bytes).unwrap(), Some(65_537));
        assert_eq!(bytes, original);
        group.authenticate_empty().unwrap();
    }

    #[test]
    fn complete_effect_storage_observation_preserves_original_queues_and_exact_bound() {
        let (senders, receivers) = receivers();
        let (mut group, reader) =
            PacketCompleteEffectReceiverGroup::from_original_receivers(receivers);
        senders[0].send(&[]).unwrap();
        let maximum = 1024 * 1024;

        let extent = group
            .original_retained_requested_storage_data(maximum)
            .unwrap();
        assert!(extent >= std::mem::size_of::<PacketCompleteEffectReceiverGroup>());
        assert_eq!(
            group
                .original_retained_requested_storage_data(extent)
                .unwrap(),
            extent
        );
        assert!(
            group
                .original_retained_requested_storage_data(extent - 1)
                .is_err()
        );
        let mut byte = [0; 1];
        assert_eq!(reader.receive(0, &mut byte).unwrap(), Some(0));

        drop(reader);
        let original_process = group.process;
        Rc::get_mut(&mut group).unwrap().process = 0;
        assert!(
            group
                .original_retained_requested_storage_data(maximum)
                .is_err()
        );
        Rc::get_mut(&mut group).unwrap().process = original_process;
        assert_eq!(
            group
                .original_retained_requested_storage_data(maximum)
                .unwrap(),
            extent
        );
    }

    #[test]
    fn complete_effect_group_creator_refusal_precedes_kernel_access() {
        let (senders, receivers) = receivers();
        let (mut group, reader) =
            PacketCompleteEffectReceiverGroup::from_original_receivers(receivers);
        senders[0].send(&[]).unwrap();
        drop(reader);
        let original_process = group.process;
        Rc::get_mut(&mut group).unwrap().process = 0;

        assert!(group.authenticate_empty().is_err());
        assert!(
            group
                .authenticate_original_path(3, Path::new("absent"))
                .is_err()
        );
        Rc::get_mut(&mut group).unwrap().process = original_process;
        // An altered creator marker is an inert negative, not an actual fork.
        // Restored original custody still sees the unconsumed real zero datagram.
        assert!(group.authenticate_empty().is_err());
    }
}

impl super::PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_original_effect_receiver_source_binding(
        &self,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let original = self
            .effect_receiver
            .as_ref()
            .ok_or_else(|| refused("complete mechanism original receiver absent"))?;
        original
            .group
            .authenticate_original_path(original.member, &original.path)?;
        self.ensure_origin()
    }
}

impl OriginalCompleteEffectReceiver {
    pub(super) fn retained_path_storage_data(&self) -> usize {
        self.path.capacity()
    }
}

impl PacketCompleteEffectReceiverGroup {
    /// Counts the same three retained effect receiver descriptors as data.
    ///
    /// Rc inspection aliases and the sole consuming reader share these actual
    /// sockets. This reads ownership only; it performs no kernel operation and
    /// grants no socket acquisition, emission, frontier or capture permission.
    ///
    /// # Errors
    /// Refuses another creator process or thread before reading the owner row.
    pub fn retained_descriptor_views_precredit_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let Self {
            process: _,
            thread: _,
            receivers,
        } = self;
        Ok(receivers.len())
    }
}

impl PacketCompleteEffectReceiverGroup {
    /// Names fixed views used by the original nonconsuming empty-queue check.
    ///
    /// The caller separately funds its own error conversion and observation
    /// scope. This pure layout declaration performs no descriptor operation and
    /// grants neither a stopped frontier nor any source or consuming authority.
    pub fn original_empty_queue_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<&PacketCompleteEffectReceiverReader>()
            + size_of::<&Rc<Self>>()
            + size_of::<std::slice::Iter<'static, UnixDatagram>>()
            + size_of::<[u8; 1]>()
            + size_of::<rustix::net::RecvFlags>()
            + size_of::<Result<usize, rustix::io::Errno>>()
            + size_of::<Result<(), OperationFailure>>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<u32>()
            + OriginalInitialLifecycleDiagnostics::counter_scratch_bytes()
            + size_of::<usize>() // actual maximum literal cause in the failure quote
    }
}

impl PacketCompleteEffectReceiverGroup {
    /// Quotes the largest actual reason String from the selected empty-queue guard.
    ///
    /// Only one unchanged refusal branch returns per call. Both ordinary and
    /// selected initial diagnostics are priced by their actual defining owner;
    /// the reason moves into the caller's failure owner without another clone.
    /// Origin/reader checks and kernel peeks grant no allocation permission.
    pub fn original_empty_queue_failure_transient_storage_data() -> usize {
        let cause_bytes = ORIGINAL_GROUP_PROCESS_REFUSAL
            .len()
            .max(ORIGINAL_GROUP_THREAD_REFUSAL.len())
            .max(ORIGINAL_GROUP_NONEMPTY_REFUSAL.len())
            .max(ORIGINAL_GROUP_PEEK_REFUSAL.len())
            .max(ORIGINAL_READER_GROUP_REFUSAL.len());
        OriginalInitialLifecycleDiagnostics::borrowed_refusal_requested_storage_data(cause_bytes)
    }
}

#[cfg(test)]
mod original_empty_queue_failure_controls {
    use super::*;

    #[test]
    fn actual_origin_refusal_string_fits_the_defining_transient_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let [(a, peer_a), (b, peer_b), (c, peer_c)] = [
            UnixDatagram::pair()?,
            UnixDatagram::pair()?,
            UnixDatagram::pair()?,
        ];
        let (mut group, reader) =
            PacketCompleteEffectReceiverGroup::from_original_receivers([a, b, c]);
        drop(reader);
        // This negative primitive test changes the real retained creator field;
        // no Source, native execution or replacement consuming role is created.
        Rc::get_mut(&mut group).unwrap().process = std::process::id().wrapping_add(1);

        let failure = group.authenticate_empty().unwrap_err();
        let transient =
            PacketCompleteEffectReceiverGroup::original_empty_queue_failure_transient_storage_data(
            );

        assert_eq!(failure.reason, ORIGINAL_GROUP_PROCESS_REFUSAL);
        assert!(failure.reason.capacity() <= transient);
        {
            let _selected = OriginalInitialLifecycleDiagnostics::begin();
            let selected = group.authenticate_empty().unwrap_err();
            assert!(selected.reason.ends_with(ORIGINAL_GROUP_PROCESS_REFUSAL));
            assert!(selected.reason.len() > failure.reason.len());
            assert_eq!(selected.reason.capacity(), transient);
        }
        let restored = group.authenticate_empty().unwrap_err();
        assert_eq!(restored.reason, failure.reason);
        assert_eq!(restored.reason.capacity(), failure.reason.capacity());
        drop((peer_a, peer_b, peer_c));
        Ok(())
    }
}
