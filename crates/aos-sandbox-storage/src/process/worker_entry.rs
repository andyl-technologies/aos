//! Retains the selected inherited worker's actual startup and wire prefix.
//!
//! The outer worker frame owns this destination while its existing aggregate
//! guard aborts a failed selected operation. It creates no role or worker grant.
//! Ordinary calls use the same startup order with their existing consuming
//! admissions and receive loop; selected calls park raw failures before refusal.

use super::*;
use aos_sandbox_linux::cgroup::{CgroupRootOriginalV2, ExactCgroupMembershipReadbackV1};
use aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1;
use aos_sandbox_linux::seqpacket::bounded::{
    ZfsWorkerReceiveErrorV1, ZfsWorkerRecordKindV1, receive_zfs_worker_record_v1,
    zfs_worker_record_obligations_v1,
};

/// Keeps the actual entry owners outside every fallible inner worker frame.
pub(super) struct WorkerEntryOriginalV3 {
    pub(super) acknowledgement: Option<WorkerAcknowledgementOriginalV3>,
    pub(super) request: Option<ReceivedRecord>,
    request_receive: Option<Result<ReceivedRecord, ZfsWorkerReceiveErrorV1>>,
    pub(super) ready_path: Option<String>,
    ready: Option<Vec<u8>>,
    cgroup_bytes: Vec<u8>,
    cgroup_file: Option<File>,
    pub(super) socket: Option<SeqpacketSocket>,
    admission: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    pub(super) storaged: Option<RetainedCgroupAnchor>,
    root: Option<CgroupV2Root>,
    root_admission: CgroupRootOriginalV2,
    pub(super) pin: Option<PinnedExecutable>,
    pin_evidence: capture_observation::CaptureToolEvidenceV3,
    pub(super) pin_checks: [Option<std::fs::Metadata>; 2],
    pub(super) contract: Option<ZfsHelperContract>,
    pub(super) memberships: [ExactCgroupMembershipReadbackV1; 3],
    contract_error: Option<ZfsTransactionError>,
    failure: Option<ZfsWorkerError>,
    disposition: Option<Result<(), ZfsWorkerError>>,
    pub(super) deadline: Option<Deadline>,
    pub(super) selected: bool,
}

// These loans split the actual retained entry without cloning native owners.
// Only this module can construct the successful parent borrower. The socket
// stays separately mutable on the same carrier through later protocol turns.
pub(super) struct CaptureParentBorrowV3<'entry> {
    request: &'entry ReceivedRecord,
    parent: &'entry RetainedCgroupAnchor,
}

impl CaptureParentBorrowV3<'_> {
    pub(super) fn request_v3(&self) -> &ReceivedRecord { self.request }
    pub(super) fn parent_v3(&self) -> &RetainedCgroupAnchor { self.parent }
}

pub(super) struct CaptureEntryLoansV3<'entry> {
    pub(super) parent: CaptureParentBorrowV3<'entry>,
    pub(super) socket: &'entry mut SeqpacketSocket,
    pub(super) contract: &'entry ZfsHelperContract,
    pub(super) path: &'entry str,
}

impl WorkerEntryOriginalV3 {
    pub(super) fn new() -> Self {
        Self {
            acknowledgement: None, request: None, request_receive: None,
            ready_path: None, ready: None, cgroup_bytes: Vec::new(), cgroup_file: None,
            socket: None, admission: None, storaged: None, root: None,
            root_admission: CgroupRootOriginalV2::new(), pin: None,
            pin_evidence: capture_observation::CaptureToolEvidenceV3 { named: None, opened: None },
            pin_checks: [None, None], contract: None,
            memberships: std::array::from_fn(|_| ExactCgroupMembershipReadbackV1::new()),
            contract_error: None, failure: None, disposition: None, deadline: None, selected: false,
        }
    }

    pub(super) fn capture_once(
        &mut self, configured_zfs: PathBuf,
        aggregate: &mut Option<&mut worker_aggregate::WorkerAggregateV1>,
    ) -> Result<(), ZfsWorkerError> {
        self.selected = aggregate.is_some();
        let result = self.capture_inner(configured_zfs, aggregate);
        if self.selected {
            if let Err(cause) = result {
                self.failure = Some(cause);
                return Err(retained());
            }
            Ok(())
        } else { result }
    }

    fn capture_inner(
        &mut self, configured_zfs: PathBuf,
        aggregate: &mut Option<&mut worker_aggregate::WorkerAggregateV1>,
    ) -> Result<(), ZfsWorkerError> {
        self.contract = Some(match ZfsHelperContract::new(configured_zfs) {
            Ok(contract) => contract,
            Err(cause) if self.selected => {
                self.contract_error = Some(cause);
                return Err(retained());
            }
            Err(cause) => return Err(ZfsWorkerError::Executable(cause.to_string())),
        });
        let Some(contract) = self.contract.as_ref() else { return Err(retained()); };
        if self.selected {
            PinnedExecutable::capture_open_into_v3(
                contract, &mut self.pin, Some(&mut self.pin_evidence),
            )?;
        } else { self.pin = Some(PinnedExecutable::open(contract)?); }
        self.root = Some(if self.selected {
            aos_sandbox::normal_root::open_storage_cgroup_root_retaining_v3(&mut self.root_admission)
                .map_err(|cause| match cause {
                    aos_sandbox::normal_root::StorageCgroupRootErrorV3::Kernel(cause) => ZfsWorkerError::Kernel(cause),
                    aos_sandbox::normal_root::StorageCgroupRootErrorV3::Linux(cause) => ZfsWorkerError::Linux(cause),
                })?
        } else { open_cgroup_root()? });
        let Some(root) = self.root.as_ref() else { return Err(retained()); };
        self.storaged = Some(match aggregate.as_deref_mut() {
            Some(original) => original.take_main()?,
            None => root.resolve(Path::new(STORAGED_CGROUP))?,
        });
        let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
        if self.selected {
            self.admission = Some(SeqpacketSocket::from_owned_storage_worker_retaining_v3(descriptor));
            self.socket = match self.admission.take() {
                Some(Ok(socket)) => Some(socket),
                failed => { self.admission = failed; return Err(retained()); }
            };
        } else { self.socket = Some(SeqpacketSocket::from_owned(descriptor)?); }
        let Some(socket) = self.socket.as_mut() else { return Err(retained()); };
        let Some(storaged) = self.storaged.as_ref() else { return Err(retained()); };
        verify_storaged_peer_into_v3(socket.peer(), storaged,
            self.selected.then_some(&mut self.memberships[0]))?;
        socket.enable_record_subjects()?;
        let deadline = Deadline::after(PROCESS_TIMEOUT);
        self.deadline = Some(deadline);
        self.ready_path = Some(if self.selected {
            current_cgroup_path_into_v3(Some((&mut self.cgroup_file, &mut self.cgroup_bytes)))?
        } else { current_cgroup()? });
        if self.selected {
            let Some(path) = self.ready_path.as_ref() else { return Err(retained()); };
            validate_selected_worker_cgroup_v1(path)?;
        }
        let Some(path) = self.ready_path.as_ref() else { return Err(retained()); };
        self.ready = Some(encode_ready(path)?);
        let Some(ready) = self.ready.as_ref() else { return Err(retained()); };
        send_before(socket, ready, deadline)?;
        if self.selected {
            self.request_receive = Some(receive_zfs_worker_record_v1(socket,
                ZfsWorkerRecordKindV1::Request, deadline.absolute_nanoseconds_v3()?));
            self.request = match self.request_receive.take() {
                Some(Ok(request)) => Some(request),
                failed => { self.request_receive = failed; return Err(retained()); }
            };
        } else { self.request = Some(receive_before(socket, MAXIMUM_REQUEST_BYTES, deadline)?); }
        let Some(request) = self.request.as_ref() else { return Err(retained()); };
        verify_same_subject(socket.peer(), request.subject())?;
        verify_membership_into_v3(storaged, request.subject().pidfd(),
            self.selected.then_some(&mut self.memberships[1]))?;
        Ok(())
    }

    pub(super) fn borrow_capture_entry_v3(&mut self) -> Option<CaptureEntryLoansV3<'_>> {
        if !self.selected || self.failure().is_some() || self.pin.is_none()
            || !matches!(self.memberships[0].result(), Some(Ok(_)))
            || !matches!(self.memberships[1].result(), Some(Ok(_)))
        { return None; }
        let parent = CaptureParentBorrowV3 {
            request: self.request.as_ref()?, parent: self.storaged.as_ref()?,
        };
        Some(CaptureEntryLoansV3 { parent, socket: self.socket.as_mut()?,
            contract: self.contract.as_ref()?, path: self.ready_path.as_deref()? })
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.contract_error.as_ref().map(|cause| cause as _)
            .or_else(|| self.root_admission.failure().map(|cause| cause as _))
            .or_else(|| self.admission.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.memberships[0].failure().map(|cause| cause as _))
            .or_else(|| self.request_receive.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.memberships[1].failure().map(|cause| cause as _))
            .or_else(|| self.failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.acknowledgement.as_ref()?.failure())
            .or_else(|| self.memberships[2].failure().map(|cause| cause as _))
            .or_else(|| self.disposition.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(super) fn finish_body_v3(&mut self, result: Result<(), ZfsWorkerError>)
        -> Result<(), ZfsWorkerError>
    {
        if !self.selected { return result; }
        self.disposition = Some(result);
        if matches!(self.disposition, Some(Ok(()))) { return Ok(()); }
        if let Some(cause) = self.failure() {
            eprintln!("fixed Storage worker entry refused: {cause}");
        }
        Err(retained())
    }

    /// Prices the actual selected startup reservoirs before inherited entry.
    pub(super) fn requested_bytes_v3() -> Option<usize> {
        let request = zfs_worker_record_obligations_v1(ZfsWorkerRecordKindV1::Request)?.0;
        let ack = zfs_worker_record_obligations_v1(ZfsWorkerRecordKindV1::Acknowledgement)?.0;
        let admission = SeqpacketSocket::storage_worker_admission_obligations_v3()?.0;
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(request)?.checked_add(ack)?.checked_add(admission)?
            .checked_add(CgroupRootOriginalV2::receiving_obligations_v2()?.0)?
            .checked_add(3 * ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?
            .checked_add(2 * (MAXIMUM_CGROUP_TEXT_BYTES + 1))?
            .checked_add(2 * MAXIMUM_REQUEST_BYTES)?
            .checked_add(2 * 4096)
    }
}

pub(super) fn retained() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("selected inherited worker entry original is retained")
}

pub(super) fn verify_membership_into_v3(
    anchor: &RetainedCgroupAnchor, process: &aos_sandbox_linux::pidfd::PidFd,
    original: Option<&mut ExactCgroupMembershipReadbackV1>,
) -> Result<(), ZfsWorkerError> {
    match original {
        None => { anchor.verify_exact_membership(process)?; }
        Some(original) => { original.capture_once(anchor, process).map_err(|_| retained())?; }
    }
    Ok(())
}

/// Holds the actual selected ACK result beside the request and original socket.
pub(super) enum WorkerAcknowledgementOriginalV3 {
    Ordinary(ReceivedRecord),
    Selected(Result<ReceivedRecord, ZfsWorkerReceiveErrorV1>),
}

impl WorkerAcknowledgementOriginalV3 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Selected(Err(cause)) => Some(cause),
            _ => None,
        }
    }
}

pub(super) fn receive_ack_into_v3<'original>(
    socket: &mut SeqpacketSocket,
    deadline: Deadline,
    selected: bool,
    original: &'original mut Option<WorkerAcknowledgementOriginalV3>,
) -> Result<&'original ReceivedRecord, ZfsWorkerError> {
    if original.is_some() { return Err(retained()); }
    *original = Some(if selected {
        WorkerAcknowledgementOriginalV3::Selected(receive_zfs_worker_record_v1(
            socket, ZfsWorkerRecordKindV1::Acknowledgement, deadline.absolute_nanoseconds_v3()?,
        ))
    } else {
        WorkerAcknowledgementOriginalV3::Ordinary(receive_before(socket, MAXIMUM_ACK_BYTES, deadline)?)
    });
    match original.as_ref() {
        Some(WorkerAcknowledgementOriginalV3::Ordinary(record))
            | Some(WorkerAcknowledgementOriginalV3::Selected(Ok(record))) => Ok(record),
        _ => Err(retained()),
    }
}

// The native shared receiver follows the existing wire grammar's actual caps.
// This is compile-time comparison DATA, not permission to run a worker.
const _: () = assert!(ZfsWorkerRecordKindV1::Request.maximum_payload_bytes() == MAXIMUM_REQUEST_BYTES);
const _: () = assert!(ZfsWorkerRecordKindV1::Acknowledgement.maximum_payload_bytes() == MAXIMUM_ACK_BYTES);
