//! One-shot checkpoint original transfer on the existing registered RAM client.
//!
//! The original owner admits transport storage before encoding. Exactly one
//! kernel alias accompanies the first framing byte; partial or uncertain I/O
//! poisons the cursor and never authorizes an ancillary resend or new original.

use std::io::{IoSlice, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use super::*;
use crate::{CheckpointArmLoan, CheckpointOriginalCause, CheckpointOriginalError};

/// Retains an authenticated observation of the actual pending native request.
///
/// The private constructor is used only after the existing client validates the
/// complete response. Its digest and generation select a retained native owner;
/// they grant no stop, page-proof, execution, or capture authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointArmReceipt {
    request_digest: [u8; 32],
    native: RamControlCheckpointArmReceipt,
}

impl CheckpointArmReceipt {
    #[cfg(test)]
    pub(crate) const fn wire_fixture() -> Self {
        // Wire observations only; no native owner or capture eligibility exists.
        Self {
            request_digest: [5; 32],
            native: RamControlCheckpointArmReceipt {
                disposition: RamControlDisposition::Accepted,
                request_generation: 7,
                first_status: 0,
                post_status: 0,
            },
        }
    }

    pub(crate) fn request_digest(self) -> [u8; 32] {
        self.request_digest
    }

    pub(crate) fn request_generation(self) -> u64 {
        self.native.request_generation
    }
}

fn transport(error: RamControlError) -> CheckpointOriginalError {
    if let RamControlError::Io(error) = &error
        && let Some(source) = error.get_ref().and_then(|source| {
            source.downcast_ref::<crucible_host_resources::host_supervision::HostSupervisionError>()
        })
    {
        return CheckpointOriginalError::before(CheckpointOriginalCause::Original(*source));
    }
    CheckpointOriginalError::before(CheckpointOriginalCause::Transport(error.into()))
}

impl RamControlClient {
    /// Transfers the actual retained original under its existing supervision.
    ///
    /// The caller supplies a nominal, non-cloneable loan from the real child.
    /// This exchange neither begins nor completes an independent operation.
    /// Native receipt is recorded before any native or host postcut can refuse.
    ///
    /// # Errors
    /// Refuses a different supervisor/target, insufficient original-account
    /// capacity, uncertain I/O, invalid reply binding, or a failed native receipt.
    pub fn checkpoint_arm(
        &mut self,
        mut loan: CheckpointArmLoan<'_>,
    ) -> Result<CheckpointArmReceipt, CheckpointOriginalError> {
        let original = loan.original().clone();
        let work = self.checkpoint_arm_exchange(&mut loan);
        let original_after = original.check().err();
        if original_after.is_some() {
            self.usable = false;
        }
        match (work, original_after) {
            (Err(mut first), original_after) => {
                first.original_after = first.original_after.or(original_after);
                Err(first)
            }
            (Ok(_), Some(source)) => Err(CheckpointOriginalError {
                source: CheckpointOriginalCause::Original(source),
                original_after: Some(source),
            }),
            (Ok(receipt), None) => Ok(receipt),
        }
    }

    fn checkpoint_arm_exchange(
        &mut self,
        loan: &mut CheckpointArmLoan<'_>,
    ) -> Result<CheckpointArmReceipt, CheckpointOriginalError> {
        if !self.usable
            || self.target != target_to_wire(loan.target())
            || self
                .supervisor
                .as_ref()
                .is_none_or(|owner| !loan.matches_supervisor(owner))
        {
            return Err(transport(RamControlError::AuthorityMismatch));
        }
        loan.wait_slice()?;
        // The original account admits fixed transport scratch before encoding
        // or sendmsg. ARM encoding/digest/reply verification allocate no heap.
        let _transport = loan
            .account()
            .reserve_resources(
                0,
                0,
                2 * RAM_CONTROL_MAX_BYTES as u64
                    + HostServiceLease::metadata_bytes()
                    + rustix::cmsg_space!(ScmRights(1)) as u64,
            )
            .map_err(|source| {
                CheckpointOriginalError::before(CheckpointOriginalCause::Account(source))
            })?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| transport(RamControlError::AuthorityMismatch))?;
        let frame = RamControlFrame {
            session: self.session,
            sequence,
            target: self.target,
            message: RamControlMessage::Request(RamControlRequest::CheckpointArm {
                original: *loan.basis(),
            }),
        };
        let request_digest = ram_control_request_digest(&frame).map_err(transport)?;
        let mut body = [0; RAM_CONTROL_CHECKPOINT_MAX_BYTES];
        let body_length = encode_ram_checkpoint_control(&frame, &mut body).map_err(transport)?;
        let length = u32::try_from(body_length)
            .map_err(|_| transport(RamControlError::TooLarge))?
            .to_be_bytes();
        let original = loan.original().clone();

        // Publish uncertainty before the first possible semantic byte. Only
        // negative, no-byte syscalls may retry with this same descriptor alias.
        self.usable = false;
        let descriptors = [loan.cancellation().as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err(transport(RamControlError::InvalidFrame));
        }
        loop {
            self.stream
                .set_write_timeout(Some(loan.wait_slice()?.min(Duration::from_millis(10))))
                .map_err(|source| transport(source.into()))?;
            match sendmsg(
                &self.stream,
                &[IoSlice::new(&length[..1])],
                &mut ancillary,
                SendFlags::NOSIGNAL,
            ) {
                Ok(1) => break,
                Ok(_) => {
                    return Err(transport(
                        std::io::Error::from(std::io::ErrorKind::WriteZero).into(),
                    ));
                }
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => continue,
                Err(source) => return Err(transport(std::io::Error::from(source).into())),
            }
        }
        // The positive sendmsg has transferred ancillary custody once. Drain
        // the remaining fixed cursor using ordinary writes, never sendmsg again.
        let mut stream = DeadlineStream {
            stream: &mut self.stream,
            deadline: None,
            guard: Some(original.guard()),
            checkpoint_original: Some(&original),
        };
        stream
            .write_all(&length[1..])
            .map_err(|source| transport(source.into()))?;
        stream
            .write_all(&body[..body_length])
            .map_err(|source| transport(source.into()))?;
        stream.flush().map_err(|source| transport(source.into()))?;
        let reply = read_ram_control(&mut stream)
            .map_err(transport)?
            .ok_or_else(|| transport(RamControlError::AuthorityMismatch))?;
        if reply.session != self.session
            || reply.sequence != sequence
            || reply.target != self.target
        {
            return Err(transport(RamControlError::AuthorityMismatch));
        }
        let RamControlMessage::CheckpointArmReply {
            request_digest: observed,
            receipt: native,
        } = reply.message
        else {
            return Err(transport(RamControlError::InvalidFrame));
        };
        if observed != request_digest {
            return Err(transport(RamControlError::AuthorityMismatch));
        }
        let receipt = CheckpointArmReceipt {
            request_digest,
            native,
        };
        loan.record_receipt(receipt);
        if native.disposition != RamControlDisposition::Accepted {
            return Err(CheckpointOriginalError::before(
                CheckpointOriginalCause::NativeReceipt {
                    disposition: native.disposition,
                    first_status: native.first_status,
                    post_status: native.post_status,
                },
            ));
        }
        self.sequence = sequence;
        self.usable = true;
        Ok(receipt)
    }
}
