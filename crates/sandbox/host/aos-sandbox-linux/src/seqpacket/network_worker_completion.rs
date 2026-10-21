//! Receives the fixed PID1 worker-reap status on its original Source channel.
//!
//! The same native subject/preview/consume engine owns the zero-right carrier.
//! The domain compares the complete Birth affinity and real exit/status fields;
//! a native packet alone grants no Source, currentness or operation success.

use super::*;

impl SeqpacketSocket {
    /// Receives the exact176-byte zero-right PID1 completion carrier.
    ///
    /// This is an already-prepaid reply to the original K. The actual owner
    /// separately retains PID1 identity, original birth and all native posts.
    ///
    /// # Errors
    /// Retains every reached native prefix, unexpected right and original FD.
    pub fn receive_network_worker_completion_retaining_v3(
        &mut self,
    ) -> Result<descriptor_subject::ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_descriptor_with_disposition(
            176,
            receive_custody::SubjectProfileV1::Descriptors {
                expected: 0,
                allow_empty: false,
            },
            uapi::ReceiveControlProfileV1::WorkerObserver,
            receive_custody::ReceiveFailureDispositionV4::RetainUncapturedOriginal,
        )
    }

    /// Prices the concrete status payload, original native models and FD prefix.
    #[must_use]
    pub fn network_worker_completion_receive_obligations_v3() -> Option<(usize, usize)> {
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let bytes =
            Self::requested_receive_bytes(176, control, 2).checked_add(std::mem::size_of::<
                Result<
                    descriptor_subject::ReceivedDescriptorRecord,
                    RetainedSeqpacketReceiveErrorV1,
                >,
            >())?;
        let hostile = control
            .bytes()
            .checked_sub(std::mem::size_of::<libc::cmsghdr>())?
            / std::mem::size_of::<std::os::fd::RawFd>();
        Some((bytes, hostile.checked_add(3)?))
    }

    /// Checks the status's original channel while retaining its actual cookie.
    ///
    /// # Errors
    /// Refuses a missing/changed original endpoint or foreign record; preserves
    /// the original cookie syscall separately from the closed binding cause.
    pub fn require_network_worker_completion_origin_retaining_v3(
        &self,
        record: &descriptor_subject::ReceivedDescriptorRecord,
        native: &mut Option<aos_linux_descriptors::Result<u64>>,
    ) -> Result<(), RecordBindingError> {
        let fd = self
            .fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or_else(RecordBindingError::closed)?;
        self.peer
            .binding
            .require_current_with_originals_v1(fd, Some(native))?;
        record.require_origin(self.peer.binding)
    }
}
