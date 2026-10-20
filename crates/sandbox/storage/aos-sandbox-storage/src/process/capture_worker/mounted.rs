//! Owns the actual two-pipe send and both original lifetime observations.
//!
//! This phase lends rights from the real anonymous-pipe owner. A reported
//! mount, a successful syscall or this local completion never releases the
//! child's duplicate writers; only the separately authenticated parent ACK can.

use super::*;

#[derive(Clone, Copy)]
enum Failure { Before, Encoding, Send, After }

pub(super) struct CaptureMountedSendOriginalV3 {
    clocks: crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3<2>,
    statuses: [Option<Result<(), ()>>; 2],
    encoded: Option<Result<[u8; wire::MOUNTED_BYTES_V3], ZfsWorkerError>>,
    sent: Option<aos_sandbox_linux::seqpacket::bounded::ZfsWorkerSendAttemptV1>,
    first: Option<Failure>,
    entered: bool,
}

impl CaptureMountedSendOriginalV3 {
    pub(super) fn from_worker_v3(context: &AuthenticatedCaptureWorkerContextV3<'_>)
        -> Result<Self, ZfsWorkerError>
    {
        let (_, _, _, _, _, boot, cutoff) = crate::execution_output::capture_worker_inputs_v3(context)
            .map_err(|_| ZfsWorkerError::Authority)?;
        Ok(Self { clocks: crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3::from_worker_v3(context, boot, cutoff),
            statuses: [None, None], encoded: None, sent: None, first: None, entered: false })
    }

    pub(super) fn send_once_v3(
        &mut self, socket: &mut SeqpacketSocket,
        context: &AuthenticatedCaptureWorkerContextV3<'_>,
        catalog: &CaptureWorkerCatalogOriginalV3,
        writer: &crate::execution_capture_zfs_worker::PreparedDetachedCaptureWriterV1,
        pipes: &drain::CaptureDrainOriginalV3,
        cutoff: u64,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered { return Err(ZfsWorkerError::Authority); }
        self.entered = true;
        let body = (|| {
            self.first = Some(Failure::Before);
            self.statuses[0] = Some(self.clocks.observe_once_v3(0));
            if !matches!(self.statuses[0], Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = Some(Failure::Encoding);
            let identities = pipes.identities_data_v3().ok_or(ZfsWorkerError::Authority)?;
            self.encoded = Some(wire::encode_mounted_v3(context, catalog, writer, identities));
            let Some(Ok(bytes)) = self.encoded.as_ref() else { return Err(worker_entry::retained()); };
            let rights = pipes.writer_fds_v3().ok_or(ZfsWorkerError::Authority)?;
            self.first = Some(Failure::Send);
            self.sent = Some(aos_sandbox_linux::seqpacket::bounded::send_capture_worker_pipes_v3(
                socket, bytes, rights, cutoff,
            ));
            if self.sent.as_ref().is_none_or(|sent| !sent.is_sent()) { return Err(worker_entry::retained()); }
            self.first = None;
            Ok(())
        })();
        self.statuses[1] = Some(self.clocks.observe_once_v3(1));
        if body.is_err() { return body; }
        if !matches!(self.statuses[1], Some(Ok(()))) {
            self.first = Some(Failure::After);
            return Err(worker_entry::retained());
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Before => self.clocks.failure_at_v3(0),
            Failure::After => self.clocks.failure_at_v3(1),
            Failure::Encoding => self.encoded.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Send => self.sent.as_ref()?.failure(),
        }
    }
}
