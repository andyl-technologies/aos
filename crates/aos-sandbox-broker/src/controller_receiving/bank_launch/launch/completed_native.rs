//! Retains whole completed launch records after their final native use.
//!
//! Only the parent's complete Confirm/profile/name interval invokes this private
//! move. Each packet stays byte-for-byte intact beside its kernel credentials
//! and initial pidfd info; descriptor identities and all native Result originals
//! remain in the parent KernelPost/ConfirmDescriptors. No grant is constructed.

use aos_sandbox_linux::seqpacket::{PeerCredentials, RecordCredentials};

use super::*;

type ChannelSlotV1 = Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>;
type RecordSlotV1 = Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>;

struct CompletedRecordV1 {
    payload: Vec<u8>,
    credentials: RecordCredentials,
    subject_info: PidFdInfo,
    descriptors: usize,
}

impl CompletedRecordV1 {
    fn from_completed_v1(record: ReceivedDescriptorRecord) -> Self {
        let credentials = record.subject().credentials();
        let subject_info = record.subject().initial_info();
        let descriptors = record.descriptors().len();
        let (payload, subject, native) = record.into_parts();
        // The caller's complete protocol/descriptor comparison has ended.
        // These are the actual owning pidfd/right values, not copied identity
        // Arcs. Close before publishing the completed carrier to its owner.
        drop(native);
        drop(subject);
        Self { payload, credentials, subject_info, descriptors }
    }

    fn is_complete_v1(&self) -> bool {
        self.payload.len() == PACKET_BYTES && self.descriptors == 1
            && self.subject_info.pid() == self.credentials.pid().get()
    }
}

pub(super) struct CompletedLaunchNativeV1 {
    cookie: std::num::NonZeroU64,
    credentials: PeerCredentials,
    peer_info: PidFdInfo,
    offer: CompletedRecordV1,
    confirm: CompletedRecordV1,
}

impl CompletedLaunchNativeV1 {
    // This has no public entrance or caller completion flag. Parent invokes it
    // only after its exact native/semantic/final-post conjunction. Preflight is
    // borrow-only: every incomplete/error prefix stays in its original slot.
    pub(super) fn take_completed_v1(
        channel: &mut ChannelSlotV1,
        offer: &mut RecordSlotV1,
        confirm: &mut RecordSlotV1,
    ) -> Result<Self, ControllerBankLaunchErrorV1> {
        let ready = matches!(channel, Some(Ok(_)))
            && [offer.as_ref(), confirm.as_ref()].into_iter().all(|slot| match slot {
                Some(Ok(record)) => record.payload().len() == PACKET_BYTES
                    && record.descriptors().len() == 1,
                _ => false,
            });
        if !ready { return Err(ControllerBankLaunchErrorV1::Conflict); }
        let originals = (channel.take(), offer.take(), confirm.take());
        match originals {
            (Some(Ok(channel)), Some(Ok(offer)), Some(Ok(confirm))) => {
                let cookie = channel.peer().socket_cookie();
                let credentials = channel.peer().credentials();
                let peer_info = channel.peer().initial_info();
                let offer = CompletedRecordV1::from_completed_v1(offer);
                let confirm = CompletedRecordV1::from_completed_v1(confirm);
                drop(channel);
                Ok(Self { cookie, credentials, peer_info, offer, confirm })
            }
            (original_channel, original_offer, original_confirm) => {
                *channel = original_channel;
                *offer = original_offer;
                *confirm = original_confirm;
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    pub(super) fn is_complete_v1(&self) -> bool {
        self.cookie.get() != 0 && self.peer_info.pid() == self.credentials.pid().get()
            && self.offer.is_complete_v1() && self.confirm.is_complete_v1()
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;

    use aos_sandbox_linux::seqpacket::RecordSubjectSeqpacketPairOriginalV2;

    use super::*;

    fn pair() -> (SeqpacketSocket, SeqpacketSocket) {
        let mut pair = RecordSubjectSeqpacketPairOriginalV2::new();
        pair.prepare_retaining_v2().unwrap();
        let receiver = pair.take_parent_socket().unwrap();
        let sender = SeqpacketSocket::from_owned(pair.take_child_endpoint().unwrap()).unwrap();
        (sender, receiver)
    }

    fn receive(sender: &mut SeqpacketSocket, receiver: &mut SeqpacketSocket, tag: u8)
        -> ReceivedDescriptorRecord
    {
        let file = std::fs::File::open("/dev/null").unwrap();
        sender.send_with_descriptors(&[tag; PACKET_BYTES], &[file.as_fd()]).unwrap();
        receiver.receive_with_descriptors_retaining(PACKET_BYTES, 1).unwrap()
    }

    #[test]
    fn completed_records_preserve_every_packet_byte_and_close_six_actual_descriptors() {
        const SELECTOR: &str = "AOS_TEST_COMPLETED_LAUNCH_NATIVE";
        if std::env::var_os(SELECTOR).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "controller_receiving::bank_launch::launch::completed_native::tests::completed_records_preserve_every_packet_byte_and_close_six_actual_descriptors"])
                .env(SELECTOR, "1").status().unwrap();
            assert!(status.success());
            return;
        }
        let (mut sender, mut receiver) = pair();
        let offer = receive(&mut sender, &mut receiver, 0x51);
        let confirm = receive(&mut sender, &mut receiver, 0xa7);
        let native = [
            receiver.as_fd().unwrap().as_raw_fd(), receiver.peer().pidfd().as_fd().as_raw_fd(),
            offer.subject().pidfd().as_fd().as_raw_fd(), offer.descriptors()[0].as_raw_fd(),
            confirm.subject().pidfd().as_fd().as_raw_fd(), confirm.descriptors()[0].as_raw_fd(),
        ];
        let offer_info = offer.subject().initial_info();
        let confirm_info = confirm.subject().initial_info();
        let mut channel = Some(Ok(receiver));
        let mut offer = Some(Ok(offer));
        let mut confirm = Some(Ok(confirm));

        let completed = CompletedLaunchNativeV1::take_completed_v1(
            &mut channel, &mut offer, &mut confirm,
        ).unwrap();

        assert!(completed.is_complete_v1());
        assert_eq!(completed.offer.payload, [0x51; PACKET_BYTES]);
        assert_eq!(completed.confirm.payload, [0xa7; PACKET_BYTES]);
        assert_eq!(completed.offer.subject_info, offer_info);
        assert_eq!(completed.confirm.subject_info, confirm_info);
        assert!(channel.is_none() && offer.is_none() && confirm.is_none());
        for descriptor in native {
            assert_eq!(std::fs::read_link(format!("/proc/self/fd/{descriptor}"))
                .unwrap_err().kind(), std::io::ErrorKind::NotFound);
        }
    }

    #[test]
    fn failed_confirm_keeps_real_offer_and_original_native_failure() {
        let (mut sender, mut receiver) = pair();
        let offer = receive(&mut sender, &mut receiver, 0x51);
        let before = rustix::fs::fstat(&offer.descriptors()[0]).unwrap();
        let failed = receiver.receive_with_descriptors_retaining(PACKET_BYTES, 1);
        assert!(failed.is_err());
        let mut channel = Some(Ok(receiver));
        let mut offer = Some(Ok(offer));
        let mut confirm = Some(failed);
        let first = confirm.as_ref().unwrap().as_ref().err().unwrap()
            as *const RetainedSeqpacketReceiveErrorV1;

        assert!(CompletedLaunchNativeV1::take_completed_v1(
            &mut channel, &mut offer, &mut confirm,
        ).is_err());

        let held = offer.as_ref().unwrap().as_ref().ok().unwrap();
        assert_eq!(held.payload(), &[0x51; PACKET_BYTES]);
        assert_eq!(rustix::fs::fstat(&held.descriptors()[0]).unwrap().st_ino, before.st_ino);
        assert!(std::ptr::eq(first,
            confirm.as_ref().unwrap().as_ref().err().unwrap()));
        assert!(channel.is_some());
    }
}
