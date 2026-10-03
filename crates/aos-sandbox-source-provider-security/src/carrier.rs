//! Sealed descriptor-subject carrier operations for SourceProvider records.

use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_FRAME_BYTES, MAXIMUM_INVENTORY_READBACK_PACKET_BYTES, SourceRootObservationV1,
    VerifiedStorageNativeAcquireV3, source_root_descriptor_commitment_v1,
};

use crate::SourceProviderSecurityError;
use crate::execution::ProcessExecutionEvidenceV1;
use crate::source_root_snapshot::{
    SourceRootObservationProfileV1, SourceRootSnapshotV1, observe_source_root_snapshot,
};

/// Owns one provider SourceRoot descriptor observed twice for an exact send handoff.
///
/// Construction performs kernel-backed checks and exposes no descriptor
/// extraction. Provider send methods consume the value, match its observation
/// to the committed receipt, and reobserve it immediately around `sendmsg`.
pub struct ProviderSourceRootHandoffV1 {
    descriptor: OwnedFd,
    snapshot: SourceRootSnapshotV1,
    observation: SourceRootObservationV1,
    native_acceptance: Option<VerifiedStorageNativeAcquireV3>,
}

impl core::fmt::Debug for ProviderSourceRootHandoffV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderSourceRootHandoffV1([validated descriptor])")
    }
}

impl ProviderSourceRootHandoffV1 {
    /// Observes and seals one provider SourceRoot descriptor for a reply handoff.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless two consecutive kernel
    /// observations establish the same `O_PATH`, close-on-exec, directory,
    /// read-only mount, namespace, device, inode, mount ID, and current boot.
    pub fn observe(descriptor: OwnedFd) -> Result<Self, SourceProviderSecurityError> {
        Self::observe_with_acceptance(descriptor, None)
    }

    /// Observes original native custody against an already verified Storage graph.
    ///
    /// The graph selects detached physical inspection, not namespace or live
    /// admission authority. It must match the actual FD identity; the protected
    /// Provider completion and authenticated send checks remain independent.
    ///
    /// # Errors
    ///
    /// Rejects changed physical facts or an original descriptor identity that
    /// differs from the verified native acceptance.
    #[doc(hidden)]
    pub fn observe_native(
        descriptor: OwnedFd,
        native: &VerifiedStorageNativeAcquireV3,
    ) -> Result<Self, SourceProviderSecurityError> {
        Self::observe_with_acceptance(descriptor, Some(native.clone()))
    }

    fn observe_with_acceptance(
        descriptor: OwnedFd,
        native_acceptance: Option<VerifiedStorageNativeAcquireV3>,
    ) -> Result<Self, SourceProviderSecurityError> {
        let profile = handoff_profile(native_acceptance.as_ref());
        let first = observe_source_root_snapshot(&descriptor, profile, None)?;
        let second = observe_source_root_snapshot(&descriptor, profile, None)?;
        if first != second {
            return Err(SourceProviderSecurityError::DescriptorObservation);
        }
        let observation = SourceRootObservationV1::new(
            first.physical.boot_id,
            first.physical.device,
            first.physical.inode,
            first.physical.mount_id.get(),
            true,
            true,
            true,
        )
        .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
        if let Some(native) = &native_acceptance {
            native
                .require_original_descriptor(&observation)
                .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
        }
        Ok(Self {
            descriptor,
            snapshot: first,
            observation,
            native_acceptance,
        })
    }

    pub(crate) const fn observation(&self) -> &SourceRootObservationV1 {
        &self.observation
    }

    pub(crate) fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        let profile = handoff_profile(self.native_acceptance.as_ref());
        let first = observe_source_root_snapshot(&self.descriptor, profile, None)?;
        let second = observe_source_root_snapshot(&self.descriptor, profile, None)?;
        if let Some(native) = &self.native_acceptance {
            native
                .require_original_descriptor(&self.observation)
                .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
        }
        if first == self.snapshot
            && second == self.snapshot
            && source_root_descriptor_commitment_v1(&self.observation)
                != aos_sandbox_core::ObjectDigest::from_bytes([0; 32])
        {
            Ok(())
        } else {
            Err(SourceProviderSecurityError::DescriptorObservation)
        }
    }

    pub(crate) const fn descriptor(&self) -> &OwnedFd {
        &self.descriptor
    }

    pub(crate) const fn native_acceptance(&self) -> Option<&VerifiedStorageNativeAcquireV3> {
        self.native_acceptance.as_ref()
    }
}

const fn handoff_profile(
    native: Option<&VerifiedStorageNativeAcquireV3>,
) -> SourceRootObservationProfileV1 {
    match native {
        Some(_) => SourceRootObservationProfileV1::NativeDetached,
        None => SourceRootObservationProfileV1::Attached,
    }
}

pub(crate) struct ReceivedSourceProviderRecordV1 {
    pub(crate) payload: Vec<u8>,
    pub(crate) descriptors: Vec<OwnedFd>,
    pub(crate) execution: ProcessExecutionEvidenceV1,
}

/// Keeps typed receive custody through origin and execution verification errors.
pub(crate) enum RetainedSourceProviderRecordV5 {
    Received(ReceivedDescriptorRecord),
    Bound(ReceivedSourceProviderRecordV1),
}

impl RetainedSourceProviderRecordV5 {
    pub(crate) fn bound(&self) -> Option<&ReceivedSourceProviderRecordV1> {
        match self {
            Self::Bound(record) => Some(record),
            _ => None,
        }
    }
}

pub(crate) struct InertSourceProviderCarrierV1 {
    socket: DescriptorSubjectSocket,
    poisoned: bool,
    interrupted_retries: u8,
    original_delivery_retention: bool,
}

pub(crate) struct ClosedSourceProviderCarrierV1 {
    _carrier: InertSourceProviderCarrierV1,
}

impl InertSourceProviderCarrierV1 {
    pub(crate) fn adopt(
        socket: DescriptorSubjectSocket,
    ) -> Result<Self, SourceProviderSecurityError> {
        socket
            .provision_packet_capacity(MAXIMUM_INVENTORY_READBACK_PACKET_BYTES)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        Ok(Self {
            socket,
            poisoned: false,
            interrupted_retries: 0,
            original_delivery_retention: false,
        })
    }

    pub(crate) const fn socket(&self) -> &DescriptorSubjectSocket {
        &self.socket
    }

    pub(crate) fn close(&mut self) {
        self.poisoned = true;
        self.socket.close();
    }

    pub(crate) fn close_owned(mut self) -> ClosedSourceProviderCarrierV1 {
        self.close();
        ClosedSourceProviderCarrierV1 { _carrier: self }
    }

    // Negative retention never opens a channel or authenticates a writer.
    pub(crate) fn begin_original_delivery_retention_v5(&mut self) {
        self.socket.begin_original_retention_v1();
        self.original_delivery_retention = true;
    }

    pub(crate) fn end_original_delivery_if_started_v5(&mut self) {
        if self.original_delivery_retention {
            self.close();
        }
    }

    pub(crate) fn send_original_held_retaining_v5(
        &mut self,
        payload: &[u8],
    ) -> Result<(), SeqpacketError> {
        if self.poisoned {
            return Err(SeqpacketError::Closed);
        }
        self.socket.send_retaining(payload)
    }

    pub(crate) fn send_original_complete_retaining_v5(
        &mut self,
        payload: &[u8],
        source_root: &OwnedFd,
    ) -> Result<(), SeqpacketError> {
        if self.poisoned {
            return Err(SeqpacketError::Closed);
        }
        self.socket.send_with_descriptors_retaining(payload, &[source_root.as_fd()])
    }

    pub(crate) fn send(&mut self, payload: &[u8]) -> Result<(), CarrierFailureV1> {
        if self.poisoned {
            return Err(CarrierFailureV1::Fatal(
                SourceProviderSecurityError::Poisoned,
            ));
        }
        match self.socket.send(payload) {
            Ok(()) => {
                self.interrupted_retries = 0;
                Ok(())
            }
            Err(SeqpacketError::WouldBlock) => Err(CarrierFailureV1::Retryable),
            Err(SeqpacketError::Interrupted) => self.interrupted_retry(),
            Err(_) => {
                self.close();
                Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ))
            }
        }
    }

    pub(crate) fn send_optional_source_root(
        &mut self,
        payload: &[u8],
        source_root: Option<&OwnedFd>,
    ) -> Result<(), CarrierFailureV1> {
        let result = match source_root {
            Some(source_root) => self
                .socket
                .send_with_descriptors(payload, &[source_root.as_fd()]),
            None => return self.send(payload),
        };
        match result {
            Ok(()) => {
                self.interrupted_retries = 0;
                Ok(())
            }
            Err(SeqpacketError::WouldBlock) => Err(CarrierFailureV1::Retryable),
            Err(SeqpacketError::Interrupted) => self.interrupted_retry(),
            Err(_) => {
                self.close();
                Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ))
            }
        }
    }

    pub(crate) fn receive_zero_descriptors(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedSourceProviderRecordV1, CarrierFailureV1> {
        self.receive(false, maximum_bytes)
    }

    pub(crate) fn receive_optional_source_root(
        &mut self,
    ) -> Result<ReceivedSourceProviderRecordV1, CarrierFailureV1> {
        self.receive(true, MAXIMUM_FRAME_BYTES)
    }

    /// Parks the actual typed record before any binding or execution check.
    pub(crate) fn receive_original_retaining_v5(
        &mut self,
        slot: &mut Option<RetainedSourceProviderRecordV5>,
    ) -> Result<bool, CarrierFailureV1> {
        self.receive_retaining(true, MAXIMUM_FRAME_BYTES, slot)
    }

    /// Keeps the exact zero-descriptor profile while retaining typed packets.
    pub(crate) fn receive_zero_descriptors_retaining_v5(
        &mut self,
        maximum_bytes: usize,
        slot: &mut Option<RetainedSourceProviderRecordV5>,
    ) -> Result<bool, CarrierFailureV1> {
        self.receive_retaining(false, maximum_bytes, slot)
    }

    fn receive_retaining(
        &mut self,
        optional_source_root: bool,
        maximum_bytes: usize,
        slot: &mut Option<RetainedSourceProviderRecordV5>,
    ) -> Result<bool, CarrierFailureV1> {
        if slot.is_some() {
            return Err(CarrierFailureV1::Fatal(
                SourceProviderSecurityError::SessionContinuity,
            ));
        }

        let received = self.receive_raw(optional_source_root, maximum_bytes)?;
        *slot = Some(RetainedSourceProviderRecordV5::Received(received));
        let Some(RetainedSourceProviderRecordV5::Received(received)) = slot.as_ref() else {
            return Err(CarrierFailureV1::Fatal(
                SourceProviderSecurityError::SessionContinuity,
            ));
        };
        if self.socket.validate_received_origin(received).is_err() {
            self.close();
            return Err(CarrierFailureV1::Fatal(
                SourceProviderSecurityError::SessionContinuity,
            ));
        }

        if let Err(error) =
            ProcessExecutionEvidenceV1::capture_parked_record(self.socket.peer(), slot)
        {
            self.close();
            return Err(CarrierFailureV1::Fatal(error));
        }

        self.interrupted_retries = 0;
        Ok(true)
    }

    fn receive(
        &mut self,
        optional_source_root: bool,
        maximum_bytes: usize,
    ) -> Result<ReceivedSourceProviderRecordV1, CarrierFailureV1> {
        let received = self.receive_raw(optional_source_root, maximum_bytes)?;
        let bound = match self.socket.bind_received(received) {
            Ok(bound) => bound,
            Err(_) => {
                self.close();
                return Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        self.interrupted_retries = 0;
        let (payload, subject, descriptors, peer) = bound.into_parts();
        let execution = match ProcessExecutionEvidenceV1::capture(peer, subject) {
            Ok(execution) => execution,
            Err(error) => {
                self.close();
                return Err(CarrierFailureV1::Fatal(error));
            }
        };
        Ok(ReceivedSourceProviderRecordV1 {
            payload,
            descriptors,
            execution,
        })
    }

    fn receive_raw(
        &mut self,
        optional_source_root: bool,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, CarrierFailureV1> {
        if self.poisoned {
            return Err(CarrierFailureV1::Fatal(
                SourceProviderSecurityError::Poisoned,
            ));
        }
        let received = if optional_source_root {
            self.socket.receive_optional_descriptor_reply(maximum_bytes)
        } else {
            self.socket.receive(maximum_bytes, 0)
        };
        match received {
            Ok(received) => Ok(received),
            Err(SeqpacketError::WouldBlock) => {
                return Err(CarrierFailureV1::Retryable);
            }
            Err(SeqpacketError::Interrupted) => return self.interrupted_retry(),
            Err(_) => {
                self.close();
                return Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        }
    }

    fn interrupted_retry<T>(&mut self) -> Result<T, CarrierFailureV1> {
        match self.interrupted_retries.checked_add(1) {
            Some(retries) if retries <= 8 => {
                self.interrupted_retries = retries;
                Err(CarrierFailureV1::Retryable)
            }
            _ => {
                self.close();
                Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ))
            }
        }
    }
}

pub(crate) enum CarrierFailureV1 {
    Retryable,
    Fatal(SourceProviderSecurityError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_source_provider_protocol::{
        InventoryReadbackQueryV1, SignedInventoryReadbackV1, SourceProviderKeyUsageV1,
        SourceProviderSigningKeyV1,
    };
    use ed25519_dalek::SigningKey;
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    fn remote_pair() -> (InertSourceProviderCarrierV1, DescriptorSubjectSocket) {
        let (receiver, sender) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let receiver = DescriptorSubjectSocket::from_owned(receiver).unwrap();
        let sender = DescriptorSubjectSocket::from_owned(sender).unwrap();
        (
            InertSourceProviderCarrierV1 {
                socket: receiver,
                poisoned: false,
                interrupted_retries: 0,
            },
            sender,
        )
    }

    #[test]
    fn remote_inventory_reply_rejects_a_transferred_descriptor() {
        let (mut receiver, mut sender) = remote_pair();
        assert!(matches!(
            receiver.receive_zero_descriptors(64),
            Err(CarrierFailureV1::Retryable)
        ));

        let directory = std::fs::File::open("/").unwrap();
        sender
            .send_with_descriptors(b"reply", &[directory.as_fd()])
            .unwrap();
        assert!(matches!(
            receiver.receive_zero_descriptors(64),
            Err(CarrierFailureV1::Fatal(_))
        ));
        assert!(matches!(
            receiver.socket.as_fd(),
            Err(SeqpacketError::Closed)
        ));
    }

    #[test]
    fn lost_remote_reply_never_becomes_an_empty_response() {
        let (mut receiver, sender) = remote_pair();
        assert!(matches!(
            receiver.receive_zero_descriptors(64),
            Err(CarrierFailureV1::Retryable)
        ));
        drop(sender);

        assert!(matches!(
            receiver.receive_zero_descriptors(64),
            Err(CarrierFailureV1::Fatal(_))
        ));
        assert!(matches!(
            receiver.socket.as_fd(),
            Err(SeqpacketError::Closed)
        ));
    }

    #[test]
    fn maximum_historical_inventory_crosses_zero_descriptor_carrier() {
        let (receiver, mut sender) = remote_pair();
        let mut receiver = InertSourceProviderCarrierV1::adopt(receiver.socket).unwrap();
        sender
            .provision_packet_capacity(MAXIMUM_INVENTORY_READBACK_PACKET_BYTES)
            .unwrap();

        let key = SigningKey::from_bytes(&[9; 32]);
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [3; 16],
            1,
            ObjectDigest::from_bytes([7; 32]),
            [8; 16],
            1,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        )
        .unwrap();
        let query = InventoryReadbackQueryV1::new(
            ObjectDigest::from_bytes([1; 32]),
            [2; 32],
            1,
            [3; 16],
            [4; 16],
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
        )
        .unwrap();
        let answer = SignedInventoryReadbackV1::sign(
            &query,
            Some((vec![42; MAXIMUM_FRAME_BYTES], 10, 20)),
            signer.clone(),
            &key,
        )
        .unwrap();

        sender.send(&answer.to_canonical_bytes()).unwrap();
        let received = receiver
            .receive_zero_descriptors(MAXIMUM_INVENTORY_READBACK_PACKET_BYTES)
            .unwrap_or_else(|_| panic!("maximum signed readback must cross carrier"));
        assert!(received.descriptors.is_empty());
        let decoded = SignedInventoryReadbackV1::from_canonical_bytes(&received.payload).unwrap();
        decoded
            .verify_for_query(&query, &signer, &key.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(decoded.completed().unwrap().0.len(), MAXIMUM_FRAME_BYTES);
    }
}
