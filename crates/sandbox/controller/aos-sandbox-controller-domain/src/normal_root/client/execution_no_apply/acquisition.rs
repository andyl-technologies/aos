//! Retains a genuine fresh Root acquisition before new Host42/nonce43.
//!
//! The same fresh Source/C18 loan owns admission, native first clock, immutable
//! deadline, current Recover reference and physical Host Session. Its Root
//! connection survives installation and moves into the ordinary floor-to-ACK
//! programme after genuine RecoveryPreliminary. No old live-Recover loan,
//! detached packet, second connection or caller clock enters this path.

use super::*;
use crate::policy_compiler::execution_no_apply_root::RootNoApplyAcquisitionSelectionDataV2 as Selection;
use aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::*;
use aos_sandbox_protocol::host_execution_no_apply::{
    current_lease::HostNoApplyLeaseScopeV2,
    recovery_acquisition::RootNoApplyRecoveryAcquisitionDataV2,
};

pub(super) struct AcquisitionNativeV2 {
    selection: Selection,
    origin: RawPairedClockSample,
    cutoff: u64,
    query: Option<Result<ExecutionNoApplyAcquisitionQueryDataV2, HistoryErrorV1>>,
    query_bytes: [u8; ACQUISITION_QUERY_BYTES_V2],
    query_digest: [u8; 32],
    connection: Option<ControllerRootConnectionOriginalV1>,
    connected: Option<Result<(), HistoryErrorV1>>,
    reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    query_sender: FixedDeadlineStreamIoV1<ACQUISITION_QUERY_BYTES_V2>,
    query_sent: Option<Result<(), HistoryErrorV1>>,
    sender: FixedDeadlineStreamIoV1<4096>,
    sent: Option<Result<(), HistoryErrorV1>>,
    scratch: [u8; 4096],
    data_failure: Option<ApplyRootDataErrorV1>,
    reply: Reply,
    pub(super) bookends: [Bookend; 2],
    fields: EncodedSelection,
    body: Option<Result<(), Cause>>,
    binding: Option<Result<(), HistoryErrorV1>>,
    installed: Option<Result<(), ResourceReservationErrorV1>>,
    pending_after: bool,
    transferred: bool,
    first: Option<AcquisitionFirst>,
}

#[derive(Clone, Copy)]
enum AcquisitionFirst {
    Body,
    Before,
    After,
    Binding,
    Installed,
}

struct EncodedSelection {
    recover_original: [u8; 48],
    recover_cutoff: [u8; 8],
    recover_expiry: [u8; 8],
    first: [u8; 48],
    cutoff: [u8; 8],
    availability: [u8; 368],
    source: [u8; 216],
    marker: [u8; 448],
}

/// Borrows only a genuine completed acquisition on its continuously held Root connection.
///
/// The private constructor requires actual response and independent native
/// posts. Borrowed canonical DATA cannot construct a Source/C18 or Host owner.
pub struct RootExecutionNoApplyClientAcquisitionBorrowV2<'root> {
    owner: &'root mut RootExecutionNoApplyClientOriginalV2,
}

impl RootExecutionNoApplyClientOriginalV2 {
    /// Begins acquisition using only the actual fresh cleanup Source/C18 loan.
    ///
    /// # Errors
    /// Retains real Source funding, native Root/clock, transport and canonical
    /// association failures, independently running the prepaid Root after.
    pub fn begin_acquisition_once_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        if self.entry.is_some() || self.state.is_some() || self.acquisition.is_some() {
            return Err(self.refuse_reentry());
        }
        let profile = loan.root_transport_profile_v2();
        self.entry = Some((|| {
            let selection = loan.root_owned_acquisition_selection_v2()?;
            let (origin, cutoff) = loan.root_original_clock_data_v2()?;
            if origin != selection.controller_first || cutoff != selection.cleanup_cutoff {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.complete =
                Self::demand(profile)?.checked_add(AcquisitionNativeV2::demand(profile)?)?;
            let observations = BOOKENDS
                .checked_add(2)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let whole = self
                .complete
                .checked_add(resource_stream::peer_traffic_v1(observations)?)?;
            let funded = loan.admit_root_transport_complete_v2(whole);
            if funded.is_err() && loan.failure_v2().is_some() {
                self.funding_original = true;
            }
            funded?;
            self.observations = observations;
            self.acquisition = Some(Box::new(AcquisitionNativeV2::new(
                selection, origin, cutoff,
            )));
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first.get_or_insert(First::Entry);
            return Err(RootExecutionNoApplyClientClosedV2);
        }
        if let Some(native) = self.acquisition.as_mut() {
            native.pending_after = true;
        }
        let mut owed = AcquisitionAfter {
            owner: self,
            profile,
        };
        let result = owed.owner.acquisition_body(loan, profile);
        if let Some(native) = owed.owner.acquisition.as_mut() {
            if result.is_err() {
                native.first.get_or_insert(AcquisitionFirst::Body);
            }
            native.body = Some(result);
        }
        owed.finish();
        drop(owed);
        if self
            .acquisition
            .as_ref()
            .is_some_and(|native| native.require_complete().is_ok())
        {
            Ok(())
        } else {
            self.first.get_or_insert(First::Acquisition);
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    /// Installs only this actual Root response into the same genuine fresh Core loan.
    ///
    /// # Errors
    /// Refuses missing native posts, a foreign Source/Session, reentry or the
    /// genuine Core packet-receiving debit. No detached DATA unlocks Host42.
    pub fn install_acquisition_once_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        if self.first.is_some() || self.state.is_some() {
            return Err(self.refuse_reentry());
        }
        let native = self
            .acquisition
            .as_ref()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.require_complete()?;
        if native.installed.is_some() || native.transferred {
            return Err(self.refuse_reentry());
        }
        let result = {
            let mut actual = RootExecutionNoApplyClientAcquisitionBorrowV2 { owner: self };
            loan.install_root_acquisition_once_v2(&mut actual)
        };
        if result.is_err() && loan.failure_v2().is_some() {
            self.funding_original = true;
        }
        let native = self
            .acquisition
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        if result.is_err() {
            native.first.get_or_insert(AcquisitionFirst::Installed);
        }
        native.installed = Some(result);
        if matches!(native.installed, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(First::Acquisition);
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    fn acquisition_body(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), Cause> {
        let native = self
            .acquisition
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let mut nonce = [0; 16];
        nonce.copy_from_slice(&native.selection.controller_nonce[..16]);
        native.query = Some((|| {
            let subject = native.subject();
            let query = ExecutionNoApplyAcquisitionQueryDataV2 {
                controller_nonce: nonce,
                original_boot: native.origin.host_boot_id(),
                original_boottime_ns: native.origin.boottime_nanoseconds(),
                original_cutoff_ns: native.cutoff,
                subject_bytes: u64::try_from(subject.encoded_bytes_v2()?)
                    .map_err(|_| HistoryErrorV1::Extent)?,
                subject_digest: subject.digest_v2()?,
            };
            native.query_bytes = query.encode_v2()?;
            native.query_digest = query.digest_v2()?;
            Ok(query)
        })());
        positive(&native.query)?;
        let wire = ACQUISITION_QUERY_BYTES_V2
            .checked_add(ACQUISITION_SUBJECT_BYTES_V2)
            .ok_or(HistoryErrorV1::Extent)?;
        self.charge(
            loan,
            wire.checked_add(ACQUISITION_REPLY_HEADER_BYTES_V2)
                .ok_or(HistoryErrorV1::Extent)?,
            wire,
        )?;
        let native = self
            .acquisition
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.connected = Some(
            native
                .connection
                .as_mut()
                .ok_or(RootExecutionNoApplyClientClosedV2)?
                .connect_once(),
        );
        positive(&native.connected)?;
        self.acquisition_bookend(0, profile, false)?;
        let native = self
            .acquisition
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let connection = native
            .connection
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.reporting = Some(connection.stream_mut()?.enable_subject_reporting().map_err(aos_sandbox_linux::seqpacket::SeqpacketError::from));
        positive(&native.reporting)?;
        native.query_sent = Some(native.query_sender.run_once(
            connection.stream_mut()?,
            &mut native.query_bytes,
            native.cutoff,
            DeadlineStreamDirectionV1::Write,
        ));
        positive(&native.query_sent)?;
        let AcquisitionNativeV2 {
            selection,
            fields,
            connection,
            sender,
            sent,
            scratch,
            data_failure,
            cutoff,
            ..
        } = native.as_mut();
        let subject = subject_data(selection, fields);
        resource_stream::send_subject_v1(
            RootSubjectDataV1::ExecutionAcquisition(subject),
            connection
                .as_mut()
                .ok_or(RootExecutionNoApplyClientClosedV2)?,
            sender,
            sent,
            scratch,
            data_failure,
            *cutoff,
        )
        .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        self.receive_acquisition(loan, profile)?;
        let native = self
            .acquisition
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.binding = Some(native.require_reply());
        if !matches!(native.binding, Some(Ok(()))) {
            native.first.get_or_insert(AcquisitionFirst::Binding);
        }
        positive(&native.binding)?;
        Ok(())
    }

    fn receive_acquisition(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), Cause> {
        let native = self
            .acquisition
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let reply = &mut native.reply;
        let mut receive = RootReplyReceiveV1 {
            connection: native
                .connection
                .as_mut()
                .ok_or(RootExecutionNoApplyClientClosedV2)?,
            received: &mut reply.received,
            preparation: &mut reply.preparation,
            extension: &mut reply.extension,
            chunk: &mut reply.chunk,
            data_failure: &mut native.data_failure,
            peer_before: &native.bookends[0].peer,
            profile,
            cutoff: native.cutoff,
        };
        let mut funding = RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        receive
            .receive_reply_for_v2(
                RootReplyPurposeV1::ExecutionAcquisition,
                &mut RootClientLoanV1::ExecutionNoApply(loan),
                RootClientControllerContextV2::ExecutionOwned,
                &mut funding,
            )
            .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        Ok(())
    }

    fn acquisition_bookend(
        &mut self,
        index: usize,
        profile: &ProductionControllerNormalRootProfileV1,
        owed: bool,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        let native = self
            .acquisition
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        if native.bookends[index].sample.is_some() {
            return Err(self.refuse_reentry());
        }
        let stream = native.connection.as_ref().and_then(|connection| connection.stream().ok());
        let result = if index == 0 {
            native.bookends[0].observe_once(profile, stream, None,
                native.origin, native.cutoff, owed)
        } else {
            let (previous, current) = native.bookends.split_at_mut(index);
            let baseline = matches!(previous[0].observed, Some(Ok(()))).then_some(&previous[0]);
            current[0].observe_once(profile, stream, baseline,
                native.origin, native.cutoff, owed)
        };
        if result.is_err() {
            native.first.get_or_insert(if index == 0 {
                AcquisitionFirst::Before
            } else {
                AcquisitionFirst::After
            });
            return Err(RootExecutionNoApplyClientClosedV2);
        }
        Ok(())
    }

    pub(super) fn begin_after_acquisition_once_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        if self.first.is_some() || self.state.is_some() || self.phase != 0 {
            return Err(self.refuse_reentry());
        }
        let profile = loan.root_transport_profile_v2();
        let prepared = (|| -> Result<Native, Cause> {
            let acquired = self
                .acquisition
                .as_ref()
                .ok_or(RootExecutionNoApplyClientClosedV2)?;
            acquired.require_complete()?;
            if !matches!(acquired.installed, Some(Ok(()))) || acquired.transferred {
                return Err(RootExecutionNoApplyClientClosedV2.into());
            }
            let (current, cutoff) = loan.root_original_clock_data_v2()?;
            acquired
                .origin
                .validate_later_sample(current)
                .map_err(|_| HistoryErrorV1::Malformed)?;
            let lease = loan.root_owned_host_lease_data_v2()?;
            let selection = acquired.selection;
            let fields = lease.fields();
            if cutoff != acquired.cutoff || fields.scope != HostNoApplyLeaseScopeV2::RecoveryCleanup
                || fields.accepted_source != selection.accepted_source
                || fields.marker != aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(selection.marker)
                || fields.terminal_archive_head != selection.terminal_archive
                || fields.signed_terminal_outcome != selection.signed_terminal
                || fields.current_session != selection.host_session
                || fields.native_boot != selection.controller_first.host_boot_id()
            { return Err(HistoryErrorV1::Malformed.into()); }
            let cut = loan.controller_cut_data_v2()?;
            let (wall, predecessor, successor) = loan.controller_rows_data_v2()?;
            let mut next = Native::new(
                acquired.origin,
                acquired.cutoff,
                lease,
                cut.encode_canonical(),
                wall.to_be_bytes(),
                rows(predecessor),
                rows(successor),
            );
            next.query_digest = acquired.query_digest;
            Ok(next)
        })();
        let mut next = match prepared {
            Ok(next) => next,
            Err(cause) => return Err(self.refuse_validation(cause)),
        };
        let acquired = self
            .acquisition
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        next.connection = acquired
            .connection
            .take()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        acquired.transferred = true;
        self.state = Some(Box::new(next));
        self.pending = Some(1);
        let mut owed = OwedAfter {
            owner: self,
            profile,
        };
        let result = owed.owner.continue_acquired_open_body_v2(loan, profile);
        owed.owner.record_body(0, result);
        owed.finish();
        drop(owed);
        if self.first.is_none() {
            self.phase = 1;
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    fn continue_acquired_open_body_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), Cause> {
        let bytes = self.native()?.subject().encoded_bytes_v2()?;
        self.charge(
            loan,
            bytes.checked_add(20).ok_or(HistoryErrorV1::Extent)?,
            bytes,
        )?;
        self.observe_bookend(0, profile, false)?;
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let Native {
            preliminary_bytes,
            cut,
            wall,
            predecessor,
            successor,
            connection,
            sender,
            sent,
            scratch,
            data_failure,
            cutoff,
            ..
        } = native.as_mut();
        let subject = ExecutionNoApplySubjectDataV2 {
            preliminary_lease: preliminary_bytes,
            controller_cut: cut,
            wall,
            predecessor,
            successor,
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::ExecutionNoApplySubject(subject),
            connection,
            &mut sender[0],
            &mut sent[0],
            scratch,
            data_failure,
            *cutoff,
        )
        .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        self.receive(loan, profile, 0, RootReplyPurposeV1::ExecutionNoApplyNonce)?;
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let reply =
            ExecutionNoApplyNonceReplyDataV2::decode_v2(native.replies[0].received.bytes())?;
        if reply.query_digest != native.query_digest
            || reply.original_cutoff != native.source_cutoff.to_be_bytes()
        {
            return Err(HistoryErrorV1::Malformed.into());
        }
        native.root_nonce.copy_from_slice(reply.root_nonce);
        Ok(())
    }
}

impl RootExecutionNoApplyClientAcquisitionBorrowV2<'_> {
    /// Borrows canonical acquisition only after actual native response posts.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or already transferred Root original.
    pub fn canonical_acquisition_data_v2(
        &self,
    ) -> Result<&[u8], RootExecutionNoApplyClientClosedV2> {
        if self.owner.first.is_some() {
            return Err(RootExecutionNoApplyClientClosedV2);
        }
        let native = self
            .owner
            .acquisition
            .as_ref()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.require_complete()?;
        if native.transferred {
            return Err(RootExecutionNoApplyClientClosedV2);
        }
        ExecutionNoApplyAcquisitionReplyDataV2::decode_v2(native.reply.received.bytes())
            .map(|reply| reply.acquisition)
            .map_err(|_| RootExecutionNoApplyClientClosedV2)
    }

    /// Rejoins this native Root response to the same current fresh cleanup loan.
    ///
    /// # Errors
    /// Refuses another actual Source/clock/nonce/Session or failed native custody.
    pub fn require_same_cleanup_original_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        self.canonical_acquisition_data_v2()?;
        let selected = loan
            .root_owned_acquisition_selection_v2()
            .map_err(|cause| self.owner.refuse_validation(cause.into()))?;
        let native = self
            .owner
            .acquisition
            .as_ref()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        if !same_selection(native.selection, selected) {
            return Err(self
                .owner
                .refuse_validation(HistoryErrorV1::Malformed.into()));
        }
        Ok(())
    }
}

struct AcquisitionAfter<'owner> {
    owner: &'owner mut RootExecutionNoApplyClientOriginalV2,
    profile: &'owner ProductionControllerNormalRootProfileV1,
}

impl AcquisitionAfter<'_> {
    fn finish(&mut self) {
        if let Some(native) = self.owner.acquisition.as_mut() {
            native.pending_after = false;
        }
        let _owed = self.owner.acquisition_bookend(1, self.profile, true);
    }
}

impl Drop for AcquisitionAfter<'_> {
    fn drop(&mut self) {
        if self
            .owner
            .acquisition
            .as_ref()
            .is_some_and(|native| native.pending_after)
        {
            self.owner
                .reentry
                .get_or_insert(RootExecutionNoApplyClientClosedV2);
            self.owner.first.get_or_insert(First::Unwind);
            self.finish();
        }
    }
}

impl AcquisitionNativeV2 {
    fn new(selection: Selection, origin: RawPairedClockSample, cutoff: u64) -> Self {
        Self {
            selection,
            origin,
            cutoff,
            query: None,
            query_bytes: [0; ACQUISITION_QUERY_BYTES_V2],
            query_digest: [0; 32],
            connection: Some(Default::default()),
            connected: None,
            reporting: None,
            query_sender: Default::default(),
            query_sent: None,
            sender: Default::default(),
            sent: None,
            scratch: [0; 4096],
            data_failure: None,
            reply: Reply {
                received: Default::default(),
                preparation: None,
                extension: None,
                chunk: None,
            },
            bookends: std::array::from_fn(|_| Bookend::new()),
            fields: EncodedSelection {
                recover_original: encode_acquisition_raw_pair_data_v2(selection.admission.original),
                recover_cutoff: selection.admission.cutoff.to_be_bytes(),
                recover_expiry: selection.admission.wall_expiry.to_be_bytes(),
                first: encode_acquisition_raw_pair_data_v2(selection.controller_first),
                cutoff: cutoff.to_be_bytes(),
                availability: selection.historical_availability.encode_canonical(),
                source: selection.accepted_source.encode_canonical(),
                marker: selection.marker.encode_canonical(),
            },
            body: None,
            binding: None,
            installed: None,
            pending_after: false,
            transferred: false,
            first: None,
        }
    }

    fn demand(
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bad = || ResourceReservationErrorV1::Conflict;
        let peers =
            CreateStorageRootPeerReceivingOriginalsV1::provisioning_turn_native_peak_v1(profile)
                .ok_or_else(bad)?;
        let bytes = size_of::<Self>()
            .checked_mul(3)
            .and_then(|n| {
                n.checked_add(
                    (ACQUISITION_SUBJECT_BYTES_V2 + MAXIMUM_ACQUISITION_REPLY_BYTES_V2)
                        .checked_mul(2)?,
                )
            })
            .and_then(|n| {
                n.checked_add(
                    RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?
                        .checked_mul(2)?,
                )
            })
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
        let files = RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(2)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
        peers
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::OpenFiles, files)
                    .with(D::MetadataEntries, names),
            )
            .map_err(Into::into)
    }

    fn subject(&self) -> ExecutionNoApplyAcquisitionSubjectDataV2<'_> {
        subject_data(&self.selection, &self.fields)
    }

    fn require_reply(&self) -> Result<(), HistoryErrorV1> {
        let reply = ExecutionNoApplyAcquisitionReplyDataV2::decode_v2(self.reply.received.bytes())?;
        let acquired = RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(reply.acquisition)
            .map_err(|_| HistoryErrorV1::Malformed)?
            .fields_v2();
        let selection = self.selection;
        if reply.query_digest != self.query_digest
            || acquired.controller_nonce != selection.controller_nonce
            || acquired.host_node != selection.accepted_source.fields().node
            || acquired.host_boot != selection.controller_first.host_boot_id()
            || acquired.host_session != selection.host_session
            || acquired.first_clock != selection.controller_first.boottime_nanoseconds()
            || acquired.cutoff != selection.cleanup_cutoff
            || acquired.historical_availability != selection.historical_availability
            || acquired.accepted_source != selection.accepted_source
            || acquired.marker != selection.marker
            || acquired.terminal_archive != selection.terminal_archive
            || acquired.signed_terminal != selection.signed_terminal
        {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    pub(super) fn require_transferred(&self) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        self.require_complete()?;
        if self.transferred && matches!(self.installed, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    fn require_complete(&self) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        if self.first.is_some()
            || self.pending_after
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.binding, Some(Ok(())))
            || self.bookends.iter().any(|one| {
                !matches!(one.observed, Some(Ok(()))) || !matches!(one.time, Some(Ok(())))
            })
        {
            return Err(RootExecutionNoApplyClientClosedV2);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            AcquisitionFirst::Body => self
                .connection
                .as_ref()
                .and_then(|connection| connection.failure())
                .or_else(|| error(&self.query))
                .or_else(|| error(&self.reporting))
                .or_else(|| self.query_sender.failure())
                .or_else(|| error(&self.query_sent))
                .or_else(|| self.sender.failure())
                .or_else(|| error(&self.sent))
                .or_else(|| {
                    self.reply
                        .chunk
                        .as_ref()
                        .and_then(|chunk| chunk.failure(&self.reply.received))
                })
                .or_else(|| {
                    self.body
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref() as _)
                }),
            AcquisitionFirst::Before | AcquisitionFirst::After => {
                let one = &self.bookends
                    [usize::from(matches!(self.first, Some(AcquisitionFirst::After)))];
                one.peer
                    .failure()
                    .or_else(|| error(&one.observed))
                    .or_else(|| one.clock.failure())
                    .or_else(|| error(&one.sample))
                    .or_else(|| error(&one.time))
            }
            AcquisitionFirst::Binding => error(&self.binding),
            AcquisitionFirst::Installed => error(&self.installed),
        }
    }
}

fn subject_data<'held>(
    selection: &'held Selection,
    fields: &'held EncodedSelection,
) -> ExecutionNoApplyAcquisitionSubjectDataV2<'held> {
    ExecutionNoApplyAcquisitionSubjectDataV2 {
        admission_key: &selection.admission.key,
        admission: &selection.admission.commitment,
        recover_original: &fields.recover_original,
        recover_cutoff: &fields.recover_cutoff,
        recover_wall_expiry: &fields.recover_expiry,
        controller_nonce: &selection.controller_nonce,
        controller_first: &fields.first,
        cleanup_cutoff: &fields.cutoff,
        host_session: &selection.host_session,
        historical_availability: &fields.availability,
        accepted_source: &fields.source,
        marker: &fields.marker,
        terminal_archive: &selection.terminal_archive,
        signed_terminal: &selection.signed_terminal,
    }
}

fn same_selection(left: Selection, right: Selection) -> bool {
    left.admission.key == right.admission.key
        && left.admission.commitment == right.admission.commitment
        && left.admission.original == right.admission.original
        && left.admission.cutoff == right.admission.cutoff
        && left.admission.wall_expiry == right.admission.wall_expiry
        && left.controller_nonce == right.controller_nonce
        && left.controller_first == right.controller_first
        && left.cleanup_cutoff == right.cleanup_cutoff
        && left.host_session == right.host_session
        && left.historical_availability == right.historical_availability
        && left.accepted_source == right.accepted_source
        && left.marker == right.marker
        && left.terminal_archive == right.terminal_archive
        && left.signed_terminal == right.signed_terminal
}
