//! Owns the actual physical Capture pipe handoff on the held-output channel.
//!
//! Construction reserves native destinations only. The genuine Host purpose
//! must pay the complete shape and bind its signed source before entering.
//! This owner stays resident beyond firstObserve until the exact physical
//! completion and upper disposition. An Abort Ack ends only its transport
//! exchange; neither an attempt locator nor a borrowed FIFO is launch authority.

use std::error::Error;
use std::mem::size_of;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_model::{ObjectDigest, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::StorageOutputClientCgroupOriginalV2;
use aos_sandbox_linux::seqpacket::SeqpacketRightsRestrictionOriginalV6;
use aos_sandbox_protocol::storage_capture_grant::{
    StorageCaptureGrantSourceV1, StorageCaptureGrantSourceV2, ValidatedStorageCaptureAttemptV1,
};
use aos_sandbox_protocol::storage_capture_session::{
    CAPTURE_ACK_BYTES_V2, CAPTURE_PROOF_BYTES_V2,
    CAPTURE_TERMINAL_BYTES_V2, CAPTURE_NEGATIVE_TERMINAL_NANOSECONDS_V2,
    CaptureHeldAckDataV2,
    CaptureHeldProofDataV2, CaptureHeldTerminalDataV2, CaptureTerminalModeDataV2,
};
use aos_sandbox_protocol::storage_capture_session::ongoing::{
    CaptureHeldBeginDataV3, CAPTURE_BEGIN_BYTES_V3,
};
use rustix::fs::{FileType, OFlags};

mod stop;

use super::*;

struct HeldCaptureV2 {
    // Storage's original record subject and both actual rights remain together.
    subject: KernelAuthorizedRecordSubject,
    bytes: Vec<u8>,
    pipes: Vec<OwnedFd>,
    socket: DescriptorSubjectSocket,
    route: SocketRouteIdentity,
    manager: PidFdInfo,
    storage: PidFdInfo,
    begin: CaptureHeldBeginDataV3,
    proof: CaptureHeldProofDataV2,
}

/// Lends the two actual authenticated FIFO write endpoints without duplicating them.
pub(crate) struct StorageCapturePipeLoanV2<'held> {
    held: &'held HeldCaptureV2,
}

impl StorageCapturePipeLoanV2<'_> {
    pub(crate) fn borrowed_source_v1(&self) -> &StorageCaptureGrantSourceV1 {
        self.held.begin.source.original_source_v1()
    }

    /// Borrows the whole versioned source only from its actual verified held owner.
    pub(crate) fn borrowed_ongoing_source_v2(&self) -> Option<&StorageCaptureGrantSourceV2> {
        Some(&self.held.begin.source)
    }

    pub(crate) fn held_cutoff_v4(&self) -> u64 { self.held.begin.cutoff_boottime_nanoseconds }

    pub(crate) fn source_digest_v4(&self) -> ObjectDigest {
        self.held.begin.source.source_digest_v2()
    }

    pub(crate) fn stdout_v2(&self) -> Result<BorrowedFd<'_>> {
        self.held.pipes.first().map(|pipe| pipe.as_fd()).ok_or_else(refused)
    }

    pub(crate) fn stderr_v2(&self) -> Result<BorrowedFd<'_>> {
        self.held.pipes.get(1).map(|pipe| pipe.as_fd()).ok_or_else(refused)
    }
}

/// Borrows every entered terminal return without sampling or releasing custody.
///
/// These diagnostics provide no physical-retirement, EOF or permission proof.
pub(crate) struct StorageCaptureTerminalArchiveV3<'original> {
    /// Original once-only positive settlement check, if entered.
    pub(crate) settlement: &'original Option<Result<()>>,
    /// Original once-only terminal-entry check.
    pub(crate) entry: &'original Option<Result<()>>,
    /// Original terminal clock return, including its retained native error.
    pub(crate) clock: &'original Option<std::result::Result<u64, crate::storage_root_export::StorageClientTransportErrorV2>>,
    /// Original terminal construction and send return.
    pub(crate) send: &'original Option<Result<()>>,
    /// Independently owed receive, decode and exact terminal comparison.
    pub(crate) ack: &'original Option<Result<CaptureHeldAckDataV2>>,
    /// Original positive-use horizon; this comparison value is never renewed.
    pub(crate) positive_cutoff: Option<u64>,
    /// Prearmed terminal-only delivery horizon, never effect authority.
    pub(crate) negative_delivery_cutoff: Option<u64>,
}

/// Keeps the fixed client, raw handoff, FIFOs and terminal debt on one owner.
pub(crate) struct StorageCaptureOriginalV2 {
    stop: Option<Box<stop::CaptureStopOriginalV4>>,
    cgroups: StorageOutputClientCgroupOriginalV2,
    client: Option<StorageExistingOutputClientV1>,
    client_result: Option<Result<()>>,
    open: OpenOriginalV2,
    native: NativeOriginalV2,
    reply: ReplyOriginalV2,
    begin: Option<CaptureHeldBeginDataV3>,
    begin_bytes: Option<Vec<u8>>,
    begin_result: Option<Result<()>>,
    pipe_identity: [Option<rustix::fs::Stat>; 2],
    pipe_flags: [Option<OFlags>; 2],
    held: Option<HeldCaptureV2>,
    terminal_native: NativeOriginalV2,
    terminal_reply: ReplyOriginalV2,
    terminal: Option<CaptureHeldTerminalDataV2>,
    settlement_entry: Option<Result<()>>,
    terminal_entry: Option<Result<()>>,
    terminal_send: Option<Result<()>>,
    terminal_clock: Option<std::result::Result<u64, crate::storage_root_export::StorageClientTransportErrorV2>>,
    terminal_ack: Option<Result<CaptureHeldAckDataV2>>,
    terminal_complete: bool,
    negative_cutoff: Option<u64>,
    pipes_transferred: bool,
    begin_native_disposed: Option<Result<()>>,
    terminal_mode: SeqpacketRightsRestrictionOriginalV6,
    terminal_mode_result: Option<Result<()>>,
    started: bool,
}

/// Borrows comparison coordinates from the actual verified held Capture.
///
/// Construction is private to the retained client. This carries no new IO,
/// cancellation, completion or native receiving authority.
pub(crate) struct StorageCaptureStopParentV4<'held> {
    held: &'held HeldCaptureV2,
}

impl StorageCaptureStopParentV4<'_> {
    pub(crate) fn source_v4(&self) -> &StorageCaptureGrantSourceV2 { &self.held.begin.source }

    pub(crate) fn begin_v4(&self) -> CaptureHeldBeginDataV3 { self.held.begin }

    pub(crate) fn proof_v4(&self) -> CaptureHeldProofDataV2 { self.held.proof }
}

impl StorageCaptureOriginalV2 {
    pub(crate) fn stop_parent_v4(&self) -> Result<StorageCaptureStopParentV4<'_>> {
        // Once any Complete send entered, an absent completed getter cannot
        // prove that durable completion did not occur. Keep exact recovery.
        if self.terminal_send.is_some()
            && self.terminal.as_ref().is_some_and(|terminal|
                terminal.mode == CaptureTerminalModeDataV2::Complete)
        {
            return Err(refused());
        }
        let held = self.held.as_ref().ok_or_else(refused)?;
        if !matches!(self.begin_result, Some(Ok(())))
            || !matches!(self.begin_native_disposed, Some(Ok(())))
        {
            return Err(refused());
        }
        Ok(StorageCaptureStopParentV4 { held })
    }

    /// Constructs only destinations after the caller admits their full shape.
    pub(crate) fn new() -> Self {
        Self {
            stop: None,
            cgroups: StorageOutputClientCgroupOriginalV2::new(),
            client: None,
            client_result: None,
            open: OpenOriginalV2::new(),
            native: NativeOriginalV2::new(),
            reply: ReplyOriginalV2::new(),
            begin: None,
            begin_bytes: None,
            begin_result: None,
            pipe_identity: [None, None],
            pipe_flags: [None, None],
            held: None,
            terminal_native: NativeOriginalV2::new(),
            terminal_reply: ReplyOriginalV2::new(),
            terminal: None,
            settlement_entry: None,
            terminal_entry: None,
            terminal_send: None,
            terminal_clock: None,
            terminal_ack: None,
            terminal_complete: false,
            negative_cutoff: None,
            pipes_transferred: false,
            begin_native_disposed: None,
            terminal_mode: SeqpacketRightsRestrictionOriginalV6::new(),
            terminal_mode_result: None,
            started: false,
        }
    }

    /// Captures fixed client anchors from the genuine catalog root.
    ///
    /// # Errors
    /// Retains native anchor failures or refuses repeated entry.
    pub(crate) fn capture_client_once(&mut self, root: &CgroupV2Root) -> Result<()> {
        if self.client_result.is_some() {
            return Err(refused());
        }
        self.client_result = Some((|| {
            self.client = Some(capture_fixed_client_v2(root, &mut self.cgroups)?);
            Ok(())
        })());
        unit(&self.client_result)
    }

    /// Acquires the explicit ongoing version under the original short59 window.
    ///
    /// # Errors
    /// Retains every native/clock/proof refusal; refuses a nonmatching native
    /// V2 attempt, repeated entry or either exhausted original horizon.
    pub(crate) fn begin_ongoing_once_v4(&mut self, source: StorageCaptureGrantSourceV2,
        attempt: ValidatedStorageCaptureAttemptV1, original_acquisition_cutoff: u64) -> Result<()> {
        self.begin_recipe_once(source, attempt, original_acquisition_cutoff)
    }

    fn begin_recipe_once(&mut self, source: StorageCaptureGrantSourceV2,
        attempt: ValidatedStorageCaptureAttemptV1, original_cutoff: u64) -> Result<()> {
        if self.begin_result.is_some() || !matches!(self.client_result, Some(Ok(()))) {
            return Err(refused());
        }
        self.begin_result = Some(self.begin_inner(source, attempt, original_cutoff));
        unit(&self.begin_result)?;
        self.begin_native_disposed = Some(if self.open.positive_files_disposed_v5()
            && self.reply.positive_files_disposed_v5() && self.native.positive_files_disposed_v5()
            && self.cgroups.positive_prefix_is_disposed_v5() {
                Ok(())
            } else { Err(refused()) });
        unit(&self.begin_native_disposed)?;
        // The descriptor-bearing proof has fully returned and its raw attempt
        // is gone. Before exposing either writer to Guest, disable all future
        // rights and prove no earlier record remains queued on this socket.
        self.terminal_mode_result = Some((|| {
            let held = self.held.as_mut().ok_or_else(refused)?;
            held.socket.restrict_incoming_rights_retaining_v6(&mut self.terminal_mode)
                .map_err(|_| refused())?;
            held.socket.require_rights_restriction_current_v6(&self.terminal_mode)
                .map_err(|_| refused())
        })());
        unit(&self.terminal_mode_result)
    }

    fn begin_inner(
        &mut self,
        source: StorageCaptureGrantSourceV2,
        attempt: ValidatedStorageCaptureAttemptV1,
        original_cutoff: u64,
    ) -> Result<()> {
        let client = self.client.as_ref().ok_or_else(refused)?;
        let mut native = Some(&mut self.native);
        let effect_cutoff = attempt.effective_deadline_boottime_nanoseconds().ok_or_else(refused)?;
        let acquisition_cutoff = original_cutoff
            .min(source.original_source_v1().original_deadline_boottime_nanoseconds());
        let cutoff = source.effective_execution_deadline_v2().min(effect_cutoff);
        // This prearmed terminal-only interval never renews positive use and
        // never starts at the time a later Abort happens to arrive.
        self.negative_cutoff = Some(cutoff.checked_add(CAPTURE_NEGATIVE_TERMINAL_NANOSECONDS_V2)
            .ok_or_else(refused)?);
        let (nonce, deadline) = fresh_challenge_observed(Some(cutoff.min(acquisition_cutoff)), &mut native)?;
        self.begin = Some(capture(CaptureHeldBeginDataV3::new(
            nonce, cutoff, acquisition_cutoff, deadline, source, attempt), &mut native)?);
        let begin = self.begin.ok_or_else(refused)?;
        let (mut socket, route, manager) = client.open_capture_socket_retaining_v3(&mut self.open)?;
        if client.verify_activation_peer_observed(socket.get()?, &mut native)? != manager
            || validate_socket_route_observed(&mut native)? != route
        {
            return Err(refused());
        }
        self.begin_bytes = Some(capture(begin.encode(), &mut native)?.to_vec());
        let encoded = self.begin_bytes.as_ref().ok_or_else(refused)?;
        // From this point a peer may own an occupied physical continuation.
        self.started = true;
        send_observed(socket.get_mut()?, encoded, deadline, &mut native)?;
        let reply = client.receive_storage_record_kind_observed(
            socket.get_mut()?, manager, route, deadline, CAPTURE_PROOF_BYTES_V2,
            None, Some(&mut self.reply), true,
        )?;
        let proof = capture(CaptureHeldProofDataV2::decode(reply.bytes()?), &mut native)?;
        capture(proof.verify_begin_ongoing_v3(begin), &mut native)?;
        for (index, expected) in [proof.stdout, proof.stderr].iter().enumerate() {
            let pipe = reply.descriptors.get()?.get(index).ok_or_else(refused)?;
            self.pipe_identity[index] = Some(capture(rustix::fs::fstat(pipe), &mut native)?);
            self.pipe_flags[index] = Some(capture(rustix::fs::fcntl_getfl(pipe), &mut native)?);
            let identity = self.pipe_identity[index].as_ref().ok_or_else(refused)?;
            let flags = self.pipe_flags[index].ok_or_else(refused)?;
            if FileType::from_raw_mode(identity.st_mode) != FileType::Fifo
                || flags & OFlags::ACCMODE != OFlags::WRONLY
                || identity.st_dev != expected.device || identity.st_ino != expected.inode
            {
                return Err(refused());
            }
        }
        self.held = Some(HeldCaptureV2 {
            subject: reply.subject.take()?,
            bytes: reply.bytes.take()?,
            pipes: reply.descriptors.take()?,
            socket: socket.take()?,
            route,
            manager,
            storage: reply.storage,
            begin,
            proof,
        });
        Ok(())
    }

    /// Lends the verified native pipe owners without establishing currentness.
    ///
    /// # Errors
    /// Refuses absent, transferred or terminal-entered pipe custody.
    pub(crate) fn pipe_loan_v2(&self) -> Result<StorageCapturePipeLoanV2<'_>> {
        if self.terminal_entry.is_some() || self.pipes_transferred || !matches!(self.begin_native_disposed, Some(Ok(()))) {
            return Err(refused());
        }
        let held = self.held.as_ref().ok_or_else(refused)?;
        unit(&self.terminal_mode_result)?;
        held.socket.require_rights_restriction_current_v6(&self.terminal_mode)
            .map_err(|_| refused())?;
        Ok(StorageCapturePipeLoanV2 { held })
    }

    /// Borrows the original intersected positive horizon.
    ///
    /// # Errors
    /// Refuses absent or terminal-entered held custody.
    pub(crate) fn held_cutoff_v2(&self) -> Result<u64> {
        if self.terminal_entry.is_some() {
            return Err(refused());
        }
        self.held.as_ref().map(|held| held.begin.cutoff_boottime_nanoseconds).ok_or_else(refused)
    }

    /// Retires only Host's sent pipe aliases at the real authenticated Guest transfer frontier.
    ///
    /// The trusted Host caller owes the successful signed Agent response and
    /// Sent boundary before this mechanical disposal. The Storage channel,
    /// proof, physical worker and its financial original remain occupied.
    ///
    /// # Errors
    /// Refuses missing, already-transferred or terminal-entered aliases.
    pub(crate) fn retire_transferred_pipes_once(&mut self) -> Result<()> {
        if self.terminal_entry.is_some() || self.pipes_transferred {
            return Err(refused());
        }
        let held = self.held.as_mut().ok_or_else(refused)?;
        if held.pipes.len() != 2 {
            return Err(refused());
        }
        held.pipes.clear();
        self.pipes_transferred = true;
        Ok(())
    }

    /// Sends one terminal and independently attempts the already owed exact Ack.
    ///
    /// # Errors
    /// Retains any original send, receive, clock or full-result refusal; rejects
    /// missing transfer, a zero settlement or a repeated terminal.
    pub(crate) fn settle_once(&mut self, settlement: ObjectDigest) -> Result<()> {
        if self.settlement_entry.is_some() {
            return Err(refused());
        }
        self.settlement_entry = Some(if settlement.as_bytes() != &[0; 32] && self.pipes_transferred {
            Ok(())
        } else {
            Err(refused())
        });
        unit(&self.settlement_entry)?;
        self.terminal_once(CaptureTerminalModeDataV2::Complete, settlement)
    }

    /// Attempts the prearmed negative-only terminal and independent Ack.
    ///
    /// # Errors
    /// Retains original failures without renewing the delivery interval.
    /// An Ack supplies no physical or financial retirement proof.
    pub(crate) fn abort_once(&mut self) -> Result<()> {
        self.terminal_once(CaptureTerminalModeDataV2::Abort, ObjectDigest::from_bytes([0; 32]))
    }

    fn terminal_once(&mut self, mode: CaptureTerminalModeDataV2, settlement: ObjectDigest) -> Result<()> {
        if self.terminal_entry.is_some() {
            return Err(refused());
        }
        // An unsuccessful Begin cannot fabricate a verified terminal peer or
        // proof. Keep its original channel/prefix and the once-only refusal.
        self.terminal_entry = Some((|| {
            if self.client.is_none() { return Err(refused()); }
            let held = self.held.as_ref().ok_or_else(refused)?;
            unit(&self.terminal_mode_result)?;
            held.socket.require_rights_restriction_current_v6(&self.terminal_mode)
                .map_err(|_| refused())
        })());
        unit(&self.terminal_entry)?;
        let client = self.client.as_ref().ok_or_else(refused)?;
        let held = self.held.as_mut().ok_or_else(refused)?;
        let cutoff = match mode {
            CaptureTerminalModeDataV2::Complete => held.begin.cutoff_boottime_nanoseconds,
            CaptureTerminalModeDataV2::Abort => self.negative_cutoff.ok_or_else(refused)?,
        };
        let mut native = Some(&mut self.terminal_native);
        self.terminal_send = Some((|| {
            self.terminal = Some(capture(CaptureHeldTerminalDataV2::new_ongoing_v3(held.begin,
                held.proof, mode, settlement), &mut native)?);
            let terminal = self.terminal.ok_or_else(refused)?;
            let encoded = capture(terminal.encode(), &mut native)?;
            if mode == CaptureTerminalModeDataV2::Abort {
                // Preserve an actual fresh refusal, then enter both owed
                // destinations using the earlier immutable negative interval.
                self.terminal_clock = Some(crate::storage_root_export::boottime_v2());
            }
            send_observed(&mut held.socket, &encoded, cutoff, &mut native)
        })());
        // A send, clock or terminal-body refusal never skips the separately
        // prearmed receive. Without a valid local terminal this can retain raw
        // traffic but cannot validate an Ack or invent completed provenance.
        self.terminal_ack = Some((|| {
            let reply = client.receive_storage_record_observed(
                &mut held.socket, held.manager, held.route, cutoff, CAPTURE_ACK_BYTES_V2,
                Some((held.storage, &held.subject)), Some(&mut self.terminal_reply),
            )?;
            let ack = capture(CaptureHeldAckDataV2::decode(reply.bytes()?), &mut native)?;
            let terminal = self.terminal.ok_or_else(refused)?;
            match mode {
                CaptureTerminalModeDataV2::Complete => {
                    capture(ack.verify_complete_hold_ongoing_v3(held.begin, held.proof, terminal), &mut native)?;
                }
                CaptureTerminalModeDataV2::Abort => {
                    capture(ack.verify_terminal(terminal), &mut native)?;
                }
            }
            Ok(ack)
        })());
        // This flag closes this transport obligation only. Abort has no EOF,
        // durable output, physical-worker death or financial-retirement proof.
        self.terminal_complete = matches!(self.terminal_send, Some(Ok(())))
            && matches!(self.terminal_ack, Some(Ok(_)))
            && self.terminal_clock.as_ref().is_none_or(|clock| clock.is_ok())
            && self.terminal_native.failure().is_none()
            && self.terminal_reply.failure().is_none();
        if self.terminal_complete { Ok(()) } else { Err(refused()) }
    }

    /// Borrows actual terminal returns while keeping all native originals here.
    pub(crate) fn terminal_archive_v3(&self) -> StorageCaptureTerminalArchiveV3<'_> {
        StorageCaptureTerminalArchiveV3 {
            settlement: &self.settlement_entry,
            entry: &self.terminal_entry,
            clock: &self.terminal_clock,
            send: &self.terminal_send,
            ack: &self.terminal_ack,
            positive_cutoff: self.begin.as_ref().map(|begin| begin.cutoff_boottime_nanoseconds),
            negative_delivery_cutoff: self.negative_cutoff,
        }
    }

    /// Borrows the complete durable stream result from this authenticated terminal.
    ///
    /// This is comparison DATA backed by the same held native original. The
    /// upper execution owner must retain this whole session through its own
    /// Source/query/currentness posts and physical positive disposal.
    ///
    /// # Errors
    /// Refuses incomplete, failed or Abort-only terminal custody.
    pub(crate) fn completed_result_v2(&self)
        -> Result<&aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2>
    {
        if !self.terminal_complete || self.failure().is_some()
            || !matches!(self.terminal.as_ref().map(|terminal| terminal.mode),
                Some(CaptureTerminalModeDataV2::Complete))
        {
            return Err(refused());
        }
        self.terminal_ack.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|ack| ack.complete.as_ref()).ok_or_else(refused)
    }

    /// Borrows the first entered original failure in protocol order.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.cgroups.failure().map(|cause| cause as _)
            .or_else(|| self.client_result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.open.failure())
            .or_else(|| self.native.failure())
            .or_else(|| self.reply.failure())
            .or_else(|| self.begin_result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.begin_native_disposed.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.terminal_mode.failure())
            .or_else(|| self.terminal_mode_result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.settlement_entry.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.terminal_entry.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.terminal_clock.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.terminal_native.failure())
            .or_else(|| self.terminal_reply.failure())
            .or_else(|| self.terminal_send.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.terminal_ack.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(crate) fn held_terminal_files_v6() -> Option<u64> {
        let (_, receive) = DescriptorSubjectSocket::storage_zero_rights_reply_obligations_v6(CAPTURE_ACK_BYTES_V2)?;
        // Keep both actual Host writer aliases even on a failed Guest transfer.
        let held = StorageExistingOutputOriginalV2::held_native_files_v6()?.checked_add(2)?;
        u64::try_from(held.checked_add(receive)?).ok()
    }

    /// Describes all fixed client/native/terminal reservoirs before entry.
    pub(crate) fn preparation_demand_v2() -> Option<ResourceVector> {
        // The earlier complete finite supplier dominates route/membership/
        // client capture. Add this actual owner, larger frames and two rights;
        // keep all earlier reservoirs paid rather than claim cleanup credit.
        let base = StorageExistingOutputOriginalV2::preparation_demand_v2()?;
        let (native_bytes, native_files) = DescriptorSubjectSocket::storage_capture_pipes_obligations_v2(CAPTURE_PROOF_BYTES_V2)?;
        let (admission_bytes, admission_files) = DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()?;
        let (restriction_bytes, restriction_files) = SeqpacketRightsRestrictionOriginalV6::receiving_obligations_v6()?;
        let maximum_begin = CAPTURE_BEGIN_BYTES_V3;
        let frames = maximum_begin.checked_mul(2)?.checked_add(CAPTURE_PROOF_BYTES_V2.checked_mul(2)?)?
            .checked_add(CAPTURE_TERMINAL_BYTES_V2)?.checked_add(CAPTURE_ACK_BYTES_V2.checked_mul(2)?)?;
        let bytes = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<StorageCaptureTerminalArchiveV3<'static>>())?
            .checked_add(size_of::<StorageCaptureGrantSourceV2>().checked_mul(2)?)?
            .checked_add(size_of::<CaptureHeldBeginDataV3>().checked_mul(2)?)?
            .checked_add(native_bytes.checked_mul(2)?)?.checked_add(admission_bytes)?
            .checked_add(restriction_bytes)?.checked_add(frames)?;
        let traffic = maximum_begin.checked_add(CAPTURE_PROOF_BYTES_V2)?
            .checked_add(CAPTURE_TERMINAL_BYTES_V2)?.checked_add(CAPTURE_ACK_BYTES_V2)?
            .checked_add(1)?;
        let complete = aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2::receiving_demand_v2()?;
        let (_, constructor_files, _) = StorageOutputClientCgroupOriginalV2::receiving_demand_v2()?;
        let anchors = 2_usize;
        let connection = admission_files;
        let begin_peak = anchors.checked_add(connection)?.checked_add(native_files)?;
        // A failed Guest transfer can keep both Host FIFO aliases while the
        // independently owed Abort/Ack enters. Price those real aliases too.
        let held = anchors.checked_add(connection)?.checked_add(1)?.checked_add(2)?;
        let terminal_peak = usize::try_from(Self::held_terminal_files_v6()?).ok()?;
        let restriction_peak = held.checked_add(restriction_files)?;
        // No terminal receive can enter after a failed queue/mode transition.
        // Only full Begin+restriction exposes pipes to the next Guest phase.
        let file_peak = constructor_files.max(begin_peak).max(restriction_peak).max(terminal_peak);
        base.with(D::OpenFiles, 0).checked_add(complete).ok()?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(file_peak).ok()?)
            .with(D::NetworkBytes, u64::try_from(traffic).ok()?)
            .with(D::OutputBytes, u64::try_from(traffic).ok()?)).ok()
    }
}

impl Drop for StorageCaptureOriginalV2 {
    fn drop(&mut self) {
        // An Abort Ack cannot retire the retained physical continuation or
        // its aliases. Only the fully verified Complete record can reach the
        // upper positive disposal; every other started original stays held.
        let complete = self.terminal_complete
            && matches!(self.terminal.as_ref().map(|terminal| terminal.mode),
                Some(CaptureTerminalModeDataV2::Complete))
            && self.completed_result_v2().is_ok();
        if self.started && !complete {
            std::process::abort();
        }
    }
}

fn unit(result: &Option<Result<()>>) -> Result<()> {
    if matches!(result, Some(Ok(()))) { Ok(()) } else { Err(refused()) }
}

fn refused() -> HostError {
    query_error("physical Capture original refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_verified_hold_retains_once_only_entry_without_fabricating_ack() {
        let mut original = StorageCaptureOriginalV2::new();
        assert!(original.abort_once().is_err());
        let pointer = original.terminal_entry.as_ref().unwrap().as_ref().unwrap_err() as *const HostError;
        assert!(original.abort_once().is_err());
        assert_eq!(original.terminal_entry.as_ref().unwrap().as_ref().unwrap_err() as *const _, pointer);
        let archive = original.terminal_archive_v3();
        assert!(matches!(archive.entry, Some(Err(_))));
        assert!(archive.send.is_none());
        assert!(archive.ack.is_none());
        assert!(archive.positive_cutoff.is_none());
        assert!(archive.negative_delivery_cutoff.is_none());
    }

    #[test]
    fn refused_positive_settlement_stays_first_when_negative_entry_is_attempted() {
        let mut original = StorageCaptureOriginalV2::new();
        assert!(original.settle_once(ObjectDigest::from_bytes([0; 32])).is_err());
        let pointer = original.settlement_entry.as_ref().unwrap().as_ref().unwrap_err()
            as *const HostError;

        assert!(original.abort_once().is_err());
        assert!(original.settle_once(ObjectDigest::from_bytes([1; 32])).is_err());

        assert_eq!(original.failure().unwrap().downcast_ref::<HostError>().unwrap()
            as *const HostError, pointer);
        let archive = original.terminal_archive_v3();
        assert!(matches!(archive.settlement, Some(Err(_))));
        assert!(matches!(archive.entry, Some(Err(_))));
        assert!(archive.send.is_none());
        assert!(archive.ack.is_none());
    }

    #[test]
    fn failed_negative_clock_keeps_first_cause_and_both_owed_error_slots() {
        let mut original = StorageCaptureOriginalV2::new();
        original.terminal_clock = Some(Err(crate::storage_root_export::StorageClientTransportErrorV2::Kernel(
            rustix::io::Errno::IO)));
        let pointer = original.terminal_clock.as_ref().unwrap().as_ref().unwrap_err()
            as *const crate::storage_root_export::StorageClientTransportErrorV2;

        let mut destination = Some(&mut original.terminal_native);
        assert!(capture::<(), _>(Err(HostError::Fence("terminal send fixture")), &mut destination).is_err());
        assert!(capture::<(), _>(Err(HostError::Fence("terminal Ack fixture")), &mut destination).is_err());
        drop(destination);

        let cause = original.failure().unwrap().downcast_ref::<crate::storage_root_export::StorageClientTransportErrorV2>().unwrap();
        assert_eq!(cause as *const _, pointer);
        assert!(!original.terminal_complete);
        assert!(original.terminal_native.failure().is_some());
    }
}
