//! Joins mounted Capture reports to the actual same-resident worker and pipes.
//!
//! Native rights, fstat/fcntl results and all source-clock posts remain resident
//! through the physical lifetime. Only the exact authenticated report and both
//! FIFO roles permit the parent ACK; an ACK does not complete the worker.

use super::*;
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use aos_sandbox_linux::seqpacket::bounded::WorkerObserverReceiveErrorV1;
use rustix::fs::{Stat, OFlags, FileType, fstat, fcntl_getfl};

#[derive(Clone, Copy)]
enum Failure { Native, Before, Encoding, Send, Receive, Subject, Membership,
    Decode, Identity(usize), Flags(usize), Role, After, AckBefore, Ack, AckAfter }

pub(super) struct CaptureMountedParentOriginalV3 {
    entered: bool,
    native: Option<Result<(), StorageReceivingClosedV1>>,
    clocks: Option<crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3<4>>,
    clock_status: [Option<Result<(), ()>>; 4],
    encoded: Option<Result<[u8; capture_worker::wire::CATALOG_BYTES_V3], ZfsWorkerError>>,
    sent: Option<ZfsWorkerSendAttemptV1>,
    received: Option<Result<ReceivedDescriptorRecord, WorkerObserverReceiveErrorV1>>,
    transferred_packet: Option<(Vec<u8>, aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject)>,
    stop_aliases: aos_sandbox_linux::seqpacket::capture_stop::CaptureWriterAliasCloseOriginalV4,
    stop_packet: Option<(Vec<u8>, aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject, Vec<std::os::fd::OwnedFd>)>,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: ExactCgroupMembershipReadbackV1,
    membership_status: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    decoded: Option<Result<capture_worker::wire::CaptureMountedReportDataV3, ZfsWorkerError>>,
    identities: [Option<Result<Stat, rustix::io::Errno>>; 2],
    flags: [Option<Result<OFlags, rustix::io::Errno>>; 2],
    role: Option<Result<(), ZfsWorkerError>>,
    acknowledged: Option<ZfsWorkerSendAttemptV1>,
    first: Option<Failure>,
}

impl CaptureMountedParentOriginalV3 {
    pub(super) fn completed_v3(&self) -> bool {
        self.entered && self.first.is_none()
            && self.clock_status.iter().all(|status| matches!(status, Some(Ok(()))))
            && self.acknowledged.as_ref().is_some_and(|ack| ack.is_sent())
    }

    pub(super) fn pipe_endpoints_v3(&self) -> Option<&[std::os::fd::OwnedFd]> {
        if !self.completed_v3() || self.transferred_packet.is_some() { return None; }
        let descriptors = self.received.as_ref()?.as_ref().ok()?.descriptors();
        if descriptors.len() != 2 { return None; }
        Some(descriptors)
    }

    pub(super) fn retire_transferred_pipe_aliases_v3(&mut self) {
        if !self.completed_v3() || self.transferred_packet.is_some() { std::process::abort(); }
        let Some(Ok(record)) = self.received.take() else { std::process::abort(); };
        let (payload, subject, descriptors) = record.into_parts();
        self.transferred_packet = Some((payload, subject));
        drop(descriptors);
    }

    // Only this actual mounted owner can retire its exact ordered FIFO aliases.
    // Fresh Stop is independent of the expired positive Capture deadline, and
    // neither the old mounted failure nor any native close error is cleared.
    pub(super) fn retire_stop_pipe_aliases_v4<E>(&mut self,
        permission: &aos_sandbox_broker::VerifiedStorageCaptureStopCleanupV4,
        native: &NativeCaptureCreateOriginalV3,
        current: &mut dyn FnMut() -> Result<(), E>,
    ) -> (Result<(), ZfsWorkerError>, Option<E>) {
        if permission.require_source_v4(native.admission_v3().source_v3()).is_err() {
            return (Err(ZfsWorkerError::Authority), None);
        }
        if self.transferred_packet.is_some() { return (Ok(()), None); }
        if self.stop_packet.is_some() { return (Err(worker_entry::retained()), None); }
        // These native identity/role observations were completed on the same
        // original before either Host handoff or this own-resource cleanup.
        if !self.completed_v3() { return (Err(worker_entry::retained()), None); }
        let Some(Ok(record)) = self.received.as_ref() else { return (Err(worker_entry::retained()), None); };
        if record.descriptors().len() != 2 { return (Err(ZfsWorkerError::Authority), None); }
        let Some(Ok(record)) = self.received.take() else { std::process::abort(); };
        let (payload, subject, descriptors) = record.into_parts();
        self.stop_packet = Some((payload, subject, descriptors));
        let Some((_, _, descriptors)) = self.stop_packet.as_mut() else { std::process::abort(); };
        let (result, gate) = self.stop_aliases.close_once_with_current_cut_v4(descriptors, current);
        (result.map_err(|_| worker_entry::retained()), gate)
    }

    pub(super) fn stop_pipe_alias_failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stop_aliases.failure()
    }

    pub(super) fn report_v3(&self) -> Option<&capture_worker::wire::CaptureMountedReportDataV3> {
        if !self.completed_v3() { return None; }
        self.decoded.as_ref()?.as_ref().ok()
    }

    pub(super) fn new() -> Self {
        Self { entered: false, native: None, clocks: None, clock_status: [None, None, None, None],
            encoded: None, sent: None, received: None, transferred_packet: None,
            stop_aliases: aos_sandbox_linux::seqpacket::capture_stop::CaptureWriterAliasCloseOriginalV4::new(),
            stop_packet: None, subject: None,
            membership: ExactCgroupMembershipReadbackV1::new(), membership_status: None,
            decoded: None, identities: std::array::from_fn(|_| None),
            flags: std::array::from_fn(|_| None), role: None, acknowledged: None, first: None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Native => self.native.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Before => self.clocks.as_ref()?.failure_at_v3(0),
            Failure::After => self.clocks.as_ref()?.failure_at_v3(1),
            Failure::AckBefore => self.clocks.as_ref()?.failure_at_v3(2),
            Failure::AckAfter => self.clocks.as_ref()?.failure_at_v3(3),
            Failure::Encoding => self.encoded.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Send => self.sent.as_ref()?.failure(),
            Failure::Receive => self.received.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Subject => self.subject.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Membership => self.membership.failure().map(|cause| cause as _),
            Failure::Decode => self.decoded.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Identity(index) => self.identities[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Flags(index) => self.flags[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Role => self.role.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Ack => self.acknowledged.as_ref()?.failure(),
        }
    }
}

impl CapturePhysicalPreparationOriginalV3 {
    pub(crate) fn prepare_mounted_pipes_once_v3(
        &mut self, state: &aos_sandbox::Journal,
        receiving: &mut StorageStateRecoveryEncodingLoanV1<'_, '_>,
    ) -> Result<(), ZfsWorkerError> {
        if self.first.is_some() || self.mounted.entered
            || !matches!(self.catalog_result, Some(Ok(())))
            || !matches!(self.physical_result, Some(Ok(())))
        { return Err(ZfsWorkerError::Authority); }
        self.first = Some(CaptureFailureV3::Mounted);
        self.mounted.entered = true;
        self.mounted.first = Some(Failure::Native);
        let Some(Ok(resident)) = self.resident.as_mut() else { return Err(worker_entry::retained()); };
        let Some(Ok(socket)) = self.exchange.connection.as_mut() else { return Err(worker_entry::retained()); };
        let Some(anchor) = self.exchange.cgroup.anchor() else { return Err(worker_entry::retained()); };
        let Some(population) = self.exchange.cgroup.population() else { return Err(worker_entry::retained()); };
        let Some(ready) = self.ready.as_ref() else { return Err(worker_entry::retained()); };
        let mut worker = match receiving.resume_capture_worker_v3(state, resident, socket, anchor, population) {
            Ok(worker) => worker,
            Err(cause) => { self.mounted.native = Some(Err(cause)); return Err(worker_entry::retained()); }
        };
        self.mounted.native = Some(Ok(()));
        let lifetime = self.native.admission_v3().lifetime_v3();
        let cutoff = lifetime.ongoing_deadline_v3();
        self.mounted.clocks = Some(crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3::from_verified_v3(lifetime));
        let Some(clocks) = self.mounted.clocks.as_mut() else { std::process::abort(); };
        let body = (|| {
            self.mounted.first = Some(Failure::Before);
            self.mounted.clock_status[0] = Some(clocks.observe_verified_once_v3(0, lifetime));
            if !matches!(self.mounted.clock_status[0], Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.mounted.first = Some(Failure::Encoding);
            self.mounted.encoded = Some(capture_worker::wire::encode_catalog_from_native_v3(
                &self.native, &self.exchange.request, &self.catalog, &self.physical,
            ));
            let Some(Ok(encoded)) = self.mounted.encoded.as_ref() else { return Err(worker_entry::retained()); };
            self.mounted.first = Some(Failure::Send);
            self.mounted.sent = Some(send_zfs_worker_record_v1(worker.socket_mut_v2(), encoded,
                ZfsWorkerSendKindV1::Request, cutoff));
            if self.mounted.sent.as_ref().is_none_or(|sent| !sent.is_sent()) { return Err(worker_entry::retained()); }
            self.mounted.first = Some(Failure::Receive);
            self.mounted.received = Some(aos_sandbox_linux::seqpacket::bounded::receive_capture_worker_pipes_v3(
                worker.socket_mut_v2(), cutoff,
            ));
            let Some(Ok(record)) = self.mounted.received.as_ref() else { return Err(worker_entry::retained()); };
            self.mounted.first = Some(Failure::Subject);
            self.mounted.subject = Some(verify_same_live_subject(ready.subject(), record.subject()));
            if !matches!(self.mounted.subject, Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.mounted.first = Some(Failure::Membership);
            self.mounted.membership_status = Some(self.mounted.membership.capture_once(anchor, record.subject().pidfd()));
            if !matches!(self.mounted.membership_status, Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.mounted.first = Some(Failure::Decode);
            self.mounted.decoded = Some(capture_worker::wire::decode_mounted_v3(record.payload(),
                &self.exchange.request, &self.native, &self.catalog, &self.physical));
            let Some(Ok(decoded)) = self.mounted.decoded.as_ref() else { return Err(worker_entry::retained()); };
            if record.descriptors().len() != 2 { return Err(worker_entry::retained()); }
            for (index, fd) in record.descriptors().iter().enumerate() {
                self.mounted.first = Some(Failure::Identity(index));
                self.mounted.identities[index] = Some(fstat(fd));
                let Some(Ok(stat)) = self.mounted.identities[index].as_ref() else { return Err(worker_entry::retained()); };
                self.mounted.first = Some(Failure::Flags(index));
                self.mounted.flags[index] = Some(fcntl_getfl(fd));
                let Some(Ok(flags)) = self.mounted.flags[index].as_ref() else { return Err(worker_entry::retained()); };
                self.mounted.first = Some(Failure::Role);
                self.mounted.role = Some(if FileType::from_raw_mode(stat.st_mode) == FileType::Fifo
                    && (*flags & OFlags::ACCMODE) == OFlags::WRONLY
                    && (stat.st_dev as u64, stat.st_ino as u64) == decoded.pipe_identities[index]
                { Ok(()) } else { Err(ZfsWorkerError::Authority) });
                if !matches!(self.mounted.role, Some(Ok(()))) { return Err(worker_entry::retained()); }
            }
            self.mounted.first = None;
            Ok(())
        })();
        self.mounted.clock_status[1] = Some(clocks.observe_verified_once_v3(1, lifetime));
        let outcome = if body.is_err() { body } else if !matches!(self.mounted.clock_status[1], Some(Ok(()))) {
            self.mounted.first = Some(Failure::After);
            Err(worker_entry::retained())
        } else {
            self.mounted.first = Some(Failure::AckBefore);
            self.mounted.clock_status[2] = Some(clocks.observe_verified_once_v3(2, lifetime));
            if matches!(self.mounted.clock_status[2], Some(Ok(()))) {
                self.mounted.first = Some(Failure::Ack);
                self.mounted.acknowledged = Some(send_zfs_worker_record_v1(worker.socket_mut_v2(),
                    &encode_ack(), ZfsWorkerSendKindV1::Acknowledgment, cutoff));
                let sent = self.mounted.acknowledged.as_ref().is_some_and(|sent| sent.is_sent());
                self.mounted.clock_status[3] = Some(clocks.observe_verified_once_v3(3, lifetime));
                if !sent { Err(worker_entry::retained()) }
                else if !matches!(self.mounted.clock_status[3], Some(Ok(()))) {
                    self.mounted.first = Some(Failure::AckAfter);
                    Err(worker_entry::retained())
                } else { self.mounted.first = None; Ok(()) }
            } else { Err(worker_entry::retained()) }
        };
        // Even a failed send/report/ACK keeps the SAME F interval occupied.
        // No failure path claims worker exit, EOF or positive native disposal.
        worker.park_v2();
        if outcome.is_ok() { self.first = None; }
        outcome
    }
}
