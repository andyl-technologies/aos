//! Shares the existing two-rights-first framed worker sender and native loop.
//!
//! Only positively completed local frames may release their wire/native
//! scratch. The immutable whole request stays on the outer attempt through
//! validation, cleanup and the genuine Native disposal token.

use super::*;
use aos_sandbox_linux::seqpacket::bounded::{
    DescriptorWorkerSendAttemptV1, DescriptorWorkerSendKindV1,
    send_descriptor_worker_record_v1,
};

pub(crate) trait WorkerFramesV1 { fn next_frame_v1(&mut self) -> Option<Vec<u8>>; }

impl WorkerFramesV1 for WorkspacePinRequestFrameEncoder<'_> {
    fn next_frame_v1(&mut self) -> Option<Vec<u8>> { self.next_frame() }
}

impl WorkerFramesV1 for crate::observation_protocol::WorkspaceCatalogObservationFrameEncoder<'_> {
    fn next_frame_v1(&mut self) -> Option<Vec<u8>> { self.next_frame() }
}

pub(crate) struct WorkerFrameSendOriginalV1 {
    frame: Option<Vec<u8>>,
    sent: Option<DescriptorWorkerSendAttemptV1>,
    encoding: Option<Result<(), ZfsWorkerError>>,
    completed: Option<Result<(), ZfsWorkerError>>,
    entered: bool,
}

impl WorkerFrameSendOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { frame: None, sent: None, encoding: None, completed: None,
            entered: false }
    }

    pub(crate) fn send_catalog_once(&mut self, socket: &mut DescriptorSubjectSocket,
        bytes: &[u8], rights: [BorrowedFd<'_>; 2], deadline: u64,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered { return Err(marker()); }
        self.entered = true;
        let mut frames = match crate::observation_protocol::WorkspaceCatalogObservationFrameEncoder::new(bytes) {
            Ok(frames) => frames,
            Err(error) => { self.encoding = Some(Err(error)); return Err(marker()); }
        };
        self.encoding = Some(Ok(()));
        send_frames_before_v1(socket, &mut frames, rights, deadline, Some(self))
    }

    pub(crate) fn send_pin_once(&mut self, socket: &mut DescriptorSubjectSocket,
        bytes: &[u8], rights: [BorrowedFd<'_>; 2], deadline: u64,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered { return Err(marker()); }
        self.entered = true;
        let mut frames = match WorkspacePinRequestFrameEncoder::new(bytes) {
            Ok(frames) => frames,
            Err(error) => { self.encoding = Some(Err(error)); return Err(marker()); }
        };
        self.encoding = Some(Ok(()));
        send_frames_before_v1(socket, &mut frames, rights, deadline, Some(self))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.encoding.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.sent.as_ref()?.failure())
            .or_else(|| self.completed.as_ref()?.as_ref().err().map(|error| error as _))
    }

    pub(crate) fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * MAXIMUM_PIN_WORKER_PACKET_BYTES)?
            .checked_add(DescriptorWorkerSendAttemptV1::requested_bytes_v1()?)?
            .checked_add(std::mem::size_of::<WorkspacePinRequestFrameEncoder<'static>>())?
            .checked_add(std::mem::size_of::<crate::observation_protocol::WorkspaceCatalogObservationFrameEncoder<'static>>())?
            .checked_add(crate::observation_protocol::digest_construction_bytes_v1()?)?
            .checked_add(4 * 256)
    }
}

pub(crate) fn send_frames_before_v1(
    socket: &mut DescriptorSubjectSocket, frames: &mut impl WorkerFramesV1,
    rights: [BorrowedFd<'_>; 2], deadline: u64,
    mut retained: Option<&mut WorkerFrameSendOriginalV1>,
) -> Result<(), ZfsWorkerError> {
    let mut first = true;
    while let Some(frame) = frames.next_frame_v1() {
        if let Some(original) = retained.as_deref_mut() {
            original.frame = Some(frame);
            let kind = if first { DescriptorWorkerSendKindV1::RequestFirst }
                else { DescriptorWorkerSendKindV1::RequestContinuation };
            let descriptors = if first { &rights[..] } else { &[][..] };
            let Some(frame) = original.frame.as_ref() else { std::process::abort() };
            original.sent = Some(send_descriptor_worker_record_v1(socket, frame, descriptors, kind, deadline));
            if !original.sent.as_ref().is_some_and(DescriptorWorkerSendAttemptV1::is_sent) {
                return Err(marker());
            }
            // The same native sender's socket posts and trailing cutoff are
            // positive. This completed frame contains no remaining local debt.
            drop(original.sent.take());
            drop(original.frame.take());
        } else {
            // This is the previous ordinary loop, with exactly its original
            // before-clock/send/wait and terminal deadline ordering.
            loop {
                ensure_before_deadline(deadline)?;
                let result = if first { socket.send_with_descriptors(&frame, &rights) }
                    else { socket.send(&frame) };
                match result {
                    Ok(()) => break,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                        wait_before(socket.as_fd()?, rustix::event::PollFlags::OUT, deadline)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        first = false;
    }
    let result = ensure_before_deadline(deadline);
    match retained {
        None => result,
        Some(original) => {
            original.completed = Some(result);
            if matches!(original.completed, Some(Ok(()))) { Ok(()) } else { Err(marker()) }
        }
    }
}

fn marker() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("descriptor worker frame original retained")
}
