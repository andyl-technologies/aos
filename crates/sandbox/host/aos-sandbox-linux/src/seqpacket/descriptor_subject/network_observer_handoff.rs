//! Sends one public-only observer record on the existing retained endpoint.
//!
//! The closed six-right profile is separate from ordinary descriptor sends.
//! It authenticates no credential content, Source, signed request or effect;
//! those owners stay continuously resident on the genuine parent caller.

use super::*;
use crate::seqpacket::NetworkWorkerNativeCutoffV4;

impl DescriptorSubjectSocket {
    /// Sends the exact canonical H03 prefix before its six-right full record.
    ///
    /// The parent retains the same full packet and supplies its first 528 bytes;
    /// this method builds no second header. Original D is checked immediately
    /// before native send by the same retained sender engine.
    ///
    /// # Errors
    /// Retains transport and rejected clock causes, and refuses another width.
    pub fn send_network_observer_handoff_header_retaining_v3(
        &mut self,
        header: &[u8],
        cutoff: NetworkWorkerNativeCutoffV4,
    ) -> (
        Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>,
        Option<Error>,
    ) {
        if header.len() != 528 {
            return (Err(SeqpacketError::InvalidMaximum), None);
        }
        self.send_worker_record_with_gate_v4(header, &[], Some(&mut || cutoff.check_v4()))
    }

    /// Prices the exact retained zero-right header send and its clock cause.
    #[must_use]
    pub fn network_observer_handoff_header_send_obligations_v3() -> Option<usize> {
        DescriptorWorkerNativeSendAttemptV1::requested_bytes_v1()?
            .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?)
    }

    /// Sends the six original public credential rights in their domain order.
    ///
    /// The original cutoff is checked before native entry. The same retained
    /// sender and endpoint disposition retain actual transport failure; this
    /// does not widen ordinary one-or-two descriptor sends or export secrets.
    ///
    /// # Errors
    /// Refuses an invalid packet, expired original cutoff, closed endpoint,
    /// actual native send failure or a short atomic record.
    pub fn send_network_observer_handoff_retaining_v2(
        &mut self,
        payload: &[u8],
        descriptors: [BorrowedFd<'_>; 6],
        cutoff: NetworkWorkerNativeCutoffV4,
    ) -> (
        Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>,
        Option<Error>,
    ) {
        if !(528..=MAXIMUM_PACKET_BYTES).contains(&payload.len()) {
            return (Err(SeqpacketError::InvalidMaximum), None);
        }
        self.send_network_observer_record_with_gate_v2(payload, descriptors, &mut || {
            cutoff.check_v4()
        })
    }

    /// Prices the same retained sender with its dedicated six-right control.
    #[must_use]
    pub fn network_observer_handoff_send_obligations_v2() -> Option<usize> {
        DescriptorWorkerNativeSendAttemptV1::requested_bytes_v1()?
            .checked_sub(rustix::cmsg_space!(ScmRights(
                MAXIMUM_TRANSFERRED_DESCRIPTORS
            )))?
            .checked_add(rustix::cmsg_space!(ScmRights(6)))?
            .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cutoff() -> NetworkWorkerNativeCutoffV4 {
        let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let baseline = u64::try_from(boot.tv_sec).unwrap() * 1_000_000_000
            + u64::try_from(boot.tv_nsec).unwrap();
        NetworkWorkerNativeCutoffV4::new(
            baseline,
            wall.tv_sec,
            baseline + 5_000_000_000,
            Some(wall.tv_sec + 5),
        )
    }

    #[test]
    fn six_public_rights_share_native_receipt_and_original_order() {
        let (first, second) = aos_linux_descriptors::native::seqpacket_pair().unwrap();
        let mut sender = DescriptorSubjectSocket::from_owned_retaining(first).unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned_retaining(second).unwrap();
        let files: [std::fs::File; 6] = std::array::from_fn(|_| tempfile::tempfile().unwrap());
        let descriptors = std::array::from_fn(|index| files[index].as_fd());
        // Structural/role admission belongs to the independent domain codec.
        let payload = [7; 528];
        let (sent, gate) =
            sender.send_network_observer_handoff_retaining_v2(&payload, descriptors, cutoff());
        assert!(gate.is_none());
        let sent = sent.unwrap();
        assert!(sent.is_sent());
        sent.require_same_socket(&sender).unwrap();
        let record = receiver
            .receive_network_observer_handoff_retaining_v2(payload.len(), cutoff())
            .unwrap();
        assert_eq!(record.payload(), payload);
        assert_eq!(record.descriptors().len(), 6);
        for (received, original) in record.descriptors().iter().zip(&files) {
            let received = rustix::fs::fstat(received).unwrap();
            let original = rustix::fs::fstat(original).unwrap();
            assert_eq!(
                (received.st_dev, received.st_ino),
                (original.st_dev, original.st_ino)
            );
        }
    }
}
