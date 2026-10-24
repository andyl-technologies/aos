//! Receives the actual Initial Ready transfer under its original Open interval.
//!
//! Fields retain real native frames, subject samples and independent posts. The
//! public programme supplies only finite same-owner stages; no raw reader, Vec,
//! completed-result adopter or mutable original escapes to the upper driver.

use std::collections::TryReserveError;
use std::error::Error;
use std::io::{self, Write as _};
use std::os::unix::net::UnixStream;

use aos_sandbox_broker::receiving::{
    RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootSelectedControllerSubjectSampleV1, RootSelectedStartupBorrowV1,
    RootSubjectReadinessV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, indexed_transfer::IndexedTransferPurposeDataV1,
    readback::HistoryPairReadbackDataV1,
    transport::{FRAME_HEADER_BYTES, INDEX_BYTES,
        FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1, TransferIndexV1},
};

use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::startup::RootCurrentWritersPredecessorV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1 as ReadyStageV1;
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1 as E,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES};
use super::initial_provision::RootInitialOpenProvisionOriginalV1;
use super::initial_subject::{RootInitialSubjectFrameBorrowV1, RootInitialSubjectOriginalV1};
use super::owned::RootCurrentAcceptedOriginalsV1;
use super::writers::RootCurrentWritersOriginalV1;
use super::initial_writer_sample::RootInitialWriterSampleOriginalV1;

pub(super) struct RootInitialReadyOriginalV1 {
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    fixed_predecessor: Option<RootObservationErrorV1>,
    variable_predecessor: Option<RootObservationErrorV1>,
    fixed: ReadyStageV1,
    variable: ReadyStageV1,
    enabled: Option<Result<(), SeqpacketError>>,
    hello_clock: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    hello_cutoff: Option<Result<(), E>>,
    hello_header: [u8; FRAME_HEADER_BYTES],
    hello_encoding: Option<Result<(), HistoryErrorV1>>,
    sent: usize,
    send: Option<io::Result<usize>>,
    send_shape: Option<io::Result<()>>,
    index_frame: RetainedSubjectStreamReadV1,
    index: Option<Result<TransferIndexV1, HistoryErrorV1>>,
    allocation: Option<Result<(), TryReserveError>>,
    bytes: Vec<u8>,
    frame: Option<RetainedSubjectStreamReadV1>,
    frame_binding: Option<Result<(), HistoryErrorV1>>,
    next_chunk: u32,
    chunks: RootInitialSubjectOriginalV1,
    digest: Option<Result<(), HistoryErrorV1>>,
    writers_post: RootInitialWriterSampleOriginalV1,
    readback: Option<Result<HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>, E>>,
    peer_history: Option<RootCurrentHistoryPostOriginalV1>,
    peer_arm: Option<Result<(), RootObservationErrorV1>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    clock: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    cutoff: Option<Result<(), E>>,
    entered: bool,
    closed: bool,
}

impl RootInitialReadyOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            geometry: RootSelectedControllerSubjectSampleV1::receive_geometry_v1(),
            fixed_predecessor: None,
            variable_predecessor: None,
            fixed: ReadyStageV1::new(),
            variable: ReadyStageV1::new(),

            enabled: None,
            hello_clock: None,
            hello_cutoff: None,
            hello_header: [0; FRAME_HEADER_BYTES],
            hello_encoding: None,
            sent: 0,
            send: None,
            send_shape: None,

            index_frame: RetainedSubjectStreamReadV1::new(),
            index: None,
            allocation: None,
            bytes: Vec::new(),
            frame: None,
            frame_binding: None,
            next_chunk: 0,
            chunks: RootInitialSubjectOriginalV1::new(),
            digest: None,

            writers_post: RootInitialWriterSampleOriginalV1::new(),
            readback: None,

            peer_history: None,
            peer_arm: None,
            peer: None,
            clock: None,
            cutoff: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn claim_entry_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn refuse_unentered_once_v1(&mut self) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.refuse_fixed_entry_v1(RootObservationErrorV1::Service);
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn refuse_fixed_entry_v1(&mut self, error: RootObservationErrorV1) {
        self.fixed_predecessor.get_or_insert(error);
        self.closed = true;
    }

    pub(super) fn refuse_variable_entry_v1(&mut self, error: RootObservationErrorV1) {
        self.variable_predecessor.get_or_insert(error);
        self.closed = true;
    }

    fn require_transfer_open_v1(&mut self) -> Result<(), E> {
        if !self.entered || self.closed || self.writers_post.entered_v1()
            || self.peer_arm.is_some() || self.peer.is_some()
        {
            self.closed = true;
            return Err(E::Boundary);
        }
        Ok(())
    }

    pub(super) fn require_entry_inputs_v1(&self, open: &RootInitialOpenPreparedOriginalV1) -> Result<(), E> {
        self.geometry.as_ref().map_err(|_| E::Boundary)?;
        open.committed_record_v1()?;
        Ok(())
    }

    pub(super) fn extent_v1(&self) -> Result<usize, E> {
        usize::try_from(positive(&self.index)?.total()).map_err(|_| E::Boundary)
    }

    pub(super) fn begin_fixed_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        provision: &RootInitialOpenProvisionOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if self.require_transfer_open_v1().is_err() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if self.fixed.entered || initial.failure().is_some() || self.closed {
            initial.latch_root_refusal_v1();
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        // The old geometry/body/record checks precede the once-only fixed slot.
        if self.geometry.is_err() || open.committed_record_v1().is_err() {
            return Err(RootObservationErrorV1::Service);
        }
        self.fixed.entered = true;
        self.fixed.financial = Some(financial.clone());
        self.fixed.permit = Some((|| {
            let body = open.body_v1().map_err(|_| NativeError::boundary())?;
            if !matches!(initial.recipient_binding_result_v1(), Some(Ok(()))) {
                return Err(NativeError::boundary());
            }
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            if (body.root_recipient, body.root_producer)
                != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || !provision.same_financial_v1(financial)
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let base = provision.completed_prefix_v1().map_err(|_| NativeError::boundary())?;
            let complete = base.checked_add(Self::fixed_demand_v1()?)
                .map_err(|_| NativeError::geometry())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, complete).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(complete)
        })());
        self.fixed.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn send_hello_once_v1(
        &mut self,
        originals: &mut RootCurrentAcceptedOriginalsV1<'_>,
        original: &UnixStream,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        self.require_transfer_open_v1()?;
        self.fixed.require_complete_v1()?;
        if self.enabled.is_some() || self.hello_clock.is_some() || self.closed {
            self.closed = true;
            return Err(E::Boundary);
        }
        let body = open.body_v1()?;
        let record = open.committed_record_v1()?;
        self.enabled = Some(originals.stream.enable_subject_reporting().map_err(aos_sandbox_linux::seqpacket::SeqpacketError::from));
        positive(&self.enabled)?;
        self.hello_clock = Some(aos_sandbox_broker::kernel_clock::ordinary_kernel_pair());
        self.hello_cutoff = Some((|| {
            let now = *positive(&self.hello_clock)?;
            open.clock_original_v1().require_current_v1(now, body.cutoff)?;
            Ok(())
        })());
        positive(&self.hello_cutoff)?;
        self.hello_encoding = Some(FrameCoordinatesV1 {
            kind: FrameKindV1::Hello, lane: body.open.lane, sequence: 1,
            root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce,
        }.encode_header(record).map(|header| self.hello_header = header));
        positive(&self.hello_encoding)?;
        self.send_hello_v1(original, record)?;
        self.index_frame.prepare_exact_once(FRAME_HEADER_BYTES + INDEX_BYTES)
            .map_err(|_| E::Boundary)
    }

    fn send_hello_v1(&mut self, original: &UnixStream, record: &[u8]) -> Result<(), E> {
        let length = FRAME_HEADER_BYTES.checked_add(record.len()).ok_or(E::Boundary)?;
        while self.sent < length {
            let bytes = if self.sent < FRAME_HEADER_BYTES {
                &self.hello_header[self.sent..]
            } else {
                &record[self.sent - FRAME_HEADER_BYTES..]
            };
            self.send = Some((&*original).write(bytes));
            let reached = *positive(&self.send)?;
            if reached == 0 || reached > bytes.len() {
                self.send_shape = Some(Err(io::Error::new(io::ErrorKind::WriteZero,
                    "Root Hello did not reach the original endpoint")));
                return Err(E::Boundary);
            }
            self.sent = self.sent.checked_add(reached).ok_or(E::Boundary)?;
        }
        self.send_shape = Some(Ok(()));
        Ok(())
    }

    pub(super) fn borrow_index_v1<'cut, 'startup>(
        &'cut mut self,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
    ) -> Result<RootInitialSubjectFrameBorrowV1<'cut, 'startup>, E> {
        self.require_transfer_open_v1()?;
        positive(&self.send_shape)?;
        if self.closed || self.index.is_some() {
            return Err(E::Boundary);
        }
        let geometry = *self.geometry.as_ref().map_err(|_| E::Boundary)?;
        self.chunks.borrow_frame_v1(&mut self.index_frame, originals, open, geometry)
    }

    pub(super) fn decode_index_once_v1(&mut self, open: &RootInitialOpenPreparedOriginalV1) -> Result<(), E> {
        self.require_transfer_open_v1()?;
        if self.index.is_some() || self.closed || !self.index_frame.completed_exact()
            || !self.chunks.disposed_v1()
        {
            self.closed = true;
            return Err(E::Boundary);
        }
        let body = open.body_v1()?;
        self.index = Some((|| {
            let frame = FrameEnvelopeV1::decode(self.index_frame.bytes(), FrameCoordinatesV1 {
                kind: FrameKindV1::ReadyIndex, lane: body.open.lane, sequence: 2,
                root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce,
            })?;
            let index = TransferIndexV1::decode(frame.payload())?;
            if index.digest() != body.open.ready {
                return Err(HistoryErrorV1::Correlation);
            }
            Ok(index)
        })());
        positive(&self.index).map(|_| ())
    }

    pub(super) fn begin_variable_once_v1(
        &mut self,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if self.require_transfer_open_v1().is_err() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if self.variable.entered || self.fixed.require_complete_v1().is_err()
            || initial.failure().is_some() || self.closed
        {
            initial.latch_root_refusal_v1();
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.variable.entered = true;
        self.variable.financial = Some(financial.clone());
        self.variable.permit = Some((|| {
            let fixed_financial = self.fixed.financial.as_ref().ok_or_else(NativeError::boundary)?;
            if !fixed_financial.same_original_data_v1(financial)
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let base = self.fixed.require_complete_v1().map_err(|_| NativeError::boundary())?;
            let index = *positive(&self.index).map_err(|_| NativeError::boundary())?;
            let complete = base.checked_add(Self::encoded_demand_v1(index)?)
                .map_err(|_| NativeError::geometry())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, complete).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(complete)
        })());
        self.variable.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn allocate_once_v1(&mut self) -> Result<(), E> {
        self.require_transfer_open_v1()?;
        self.variable.require_complete_v1()?;
        if self.allocation.is_some() || self.closed {
            self.closed = true;
            return Err(E::Boundary);
        }
        let index = *positive(&self.index)?;
        aos_sandbox_broker::root_indexed_transfer_extent_v1! { index: index, total: total, error: E::Boundary }
        let allocation = &mut self.allocation;
        let bytes = &mut self.bytes;
        aos_sandbox_broker::root_indexed_transfer_allocate_v1! {
            allocation: allocation, bytes: bytes, total: total, positive: positive,
        }
        Ok(())
    }

    pub(super) fn has_next_v1(&self) -> Result<bool, E> {
        positive(&self.allocation)?;
        Ok(self.next_chunk < positive(&self.index)?.count())
    }

    pub(super) fn prepare_frame_once_v1(&mut self) -> Result<(), E> {
        self.require_transfer_open_v1()?;
        if !self.has_next_v1()? || self.frame.is_some() || self.closed {
            self.closed = true;
            return Err(E::Boundary);
        }
        let index = *positive(&self.index)?;
        let next_chunk = &mut self.next_chunk;
        let frame = &mut self.frame;
        aos_sandbox_broker::root_indexed_transfer_prepare_frame_v1! {
            index: index, next_chunk: next_chunk, frame: frame,
            current_frame: current_frame, error: E::Boundary,
        }
        let _ = current_frame;
        Ok(())
    }

    pub(super) fn borrow_chunk_v1<'cut, 'startup>(
        &'cut mut self,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
    ) -> Result<RootInitialSubjectFrameBorrowV1<'cut, 'startup>, E> {
        self.require_transfer_open_v1()?;
        self.variable.require_complete_v1()?;
        if self.closed {
            return Err(E::Boundary);
        }
        let geometry = *self.geometry.as_ref().map_err(|_| E::Boundary)?;
        let frame = self.frame.as_mut().ok_or(E::Boundary)?;
        self.chunks.borrow_frame_v1(frame, originals, open, geometry)
    }

    pub(super) fn bind_copy_frame_once_v1(&mut self, open: &RootInitialOpenPreparedOriginalV1) -> Result<(), E> {
        self.require_transfer_open_v1()?;
        if self.closed || self.frame_binding.is_some() || !self.chunks.disposed_v1() {
            self.closed = true;
            return Err(E::Boundary);
        }
        let current_frame = self.frame.as_mut().ok_or(E::Boundary)?;
        if !current_frame.completed_exact() {
            return Err(E::Boundary);
        }
        let body = open.body_v1()?;
        let index = *positive(&self.index)?;
        let total = usize::try_from(index.total()).map_err(|_| E::Boundary)?;
        let purpose = IndexedTransferPurposeDataV1::Ready;
        let first_sequence = 3_u64;
        let frame_binding = &mut self.frame_binding;
        let next_chunk = &mut self.next_chunk;
        let bytes = &mut self.bytes;
        aos_sandbox_broker::root_indexed_transfer_bind_copy_v1! {
            frame_binding: frame_binding, current_frame: current_frame,
            purpose: purpose, body: body, first_sequence: first_sequence,
            next_chunk: next_chunk, index: index, bytes: bytes, total: total, positive: positive,
        }
        Ok(())
    }

    pub(super) fn dispose_frame_once_v1(&mut self) -> Result<(), E> {
        self.require_transfer_open_v1()?;
        positive(&self.frame_binding)?;
        if self.closed || !self.chunks.disposed_v1() {
            return Err(E::Boundary);
        }
        let frame = &mut self.frame;
        let frame_binding = &mut self.frame_binding;
        let next_chunk = &mut self.next_chunk;
        aos_sandbox_broker::root_indexed_transfer_dispose_frame_v1! {
            frame: frame, frame_binding: frame_binding, next_chunk: next_chunk, error: E::Boundary,
        }
        Ok(())
    }

    pub(super) fn digest_once_v1(&mut self) -> Result<(), E> {
        self.require_transfer_open_v1()?;
        if self.closed || self.digest.is_some() || self.has_next_v1()? || self.frame.is_some() {
            self.closed = true;
            return Err(E::Boundary);
        }
        let index = *positive(&self.index)?;
        let total = usize::try_from(index.total()).map_err(|_| E::Boundary)?;
        let digest = &mut self.digest;
        let bytes = &mut self.bytes;
        let purpose = IndexedTransferPurposeDataV1::Ready;
        aos_sandbox_broker::root_indexed_transfer_digest_v1! {
            digest: digest, bytes: bytes, total: total, purpose: purpose, index: index, positive: positive,
        }
    }

    pub(super) fn observe_names_and_readback_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if !self.entered || self.writers_post.entered_v1() || self.readback.is_some() {
            self.closed = true;
            return;
        }
        let opened = writers.opened_pair_view_v1();
        match opened {
            Ok((authority, policy)) => {
                self.writers_post.capture_once_v1(authority, policy, open);
                self.readback = Some(open.readback_current_v1(authority, policy));
            }
            Err(error) => {
                self.writers_post.refuse_pair_v1(error);
            }
        }
    }

    pub(super) fn arm_peer_post_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        if !self.entered || self.peer_history.is_some() || self.peer_arm.is_some() || self.peer.is_some()
            || !self.writers_post.entered_v1()
        {
            self.closed = true;
            return Err(());
        }
        self.peer_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(predecessor, startup, exclusion));
        self.peer_arm = Some(match &self.peer_history {
            Some(history) => history.require_armed_v1(),
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer_arm, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(super) fn park_peer_arm_refusal_v1(&mut self, error: RootObservationErrorV1) {
        if self.peer_arm.is_some() { self.closed = true; return; }
        self.peer_arm = Some(Err(error));
    }

    pub(super) fn refuse_external_peer_arm_once_v1(&mut self) {
        self.closed = true;
        if self.entered && self.peer_arm.is_none() && self.peer.is_none()
            && self.writers_post.entered_v1()
        {
            self.peer_arm = Some(Err(RootObservationErrorV1::Service));
        }
    }

    pub(super) fn observe_peer_and_clock_once_v1(
        &mut self,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if self.peer.is_some() || self.clock.is_some() || self.cutoff.is_some()
            || self.peer_arm.is_none() || !self.writers_post.entered_v1()
        {
            self.closed = true;
            return;
        }
        self.peer = Some(match &mut self.peer_history {
            Some(history) => match history.borrow_accepted_v1(&originals.peer, &originals.stream) {
                Ok(mut accepted) => accepted.observe_shared_once_v1(),
                Err(error) => Err(error),
            },
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer, Some(Ok(()))) {
            drop(self.peer_history.take());
        }
        self.clock = Some(aos_sandbox_broker::kernel_clock::ordinary_kernel_pair());
        self.cutoff = Some((|| {
            let current = *positive(&self.clock)?;
            let body = open.body_v1()?;
            open.clock_original_v1().require_current_v1(current, body.cutoff)?;
            Ok(())
        })());
    }

    pub(super) fn raw_ready_bytes_v1(&self) -> Result<&[u8], E> {
        if !self.entered || self.closed {
            return Err(E::Boundary);
        }
        self.fixed.require_complete_v1()?;
        positive(&self.enabled)?;
        positive(&self.hello_cutoff)?;
        positive(&self.hello_encoding)?;
        positive(&self.send_shape)?;
        positive(&self.index)?;
        self.variable.require_complete_v1()?;
        positive(&self.allocation)?;
        positive(&self.digest)?;
        self.writers_post.require_complete_v1()?;
        positive(&self.readback)?;
        positive(&self.peer_arm)?;
        positive(&self.peer)?;
        positive(&self.cutoff)?;
        if self.frame.is_some() || !self.chunks.disposed_v1() || self.has_next_v1()?
            || self.failure_v1().is_some()
        {
            return Err(E::Boundary);
        }
        Ok(&self.bytes)
    }

    // Copies the exact header and record already sent by this same Ready.
    pub(super) fn original_hello_frame_v1(
        &self,
        open: &RootInitialOpenPreparedOriginalV1,
        output: &mut [u8; 612],
    ) -> Result<(), HistoryErrorV1> {
        self.raw_ready_bytes_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        let record = open.committed_record_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        if self.sent != output.len() || record.len() != output.len() - FRAME_HEADER_BYTES
            || !matches!(self.hello_encoding, Some(Ok(())))
        {
            return Err(HistoryErrorV1::Correlation);
        }
        output[..FRAME_HEADER_BYTES].copy_from_slice(&self.hello_header);
        output[FRAME_HEADER_BYTES..].copy_from_slice(record);
        let original = open.body_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootHelloDataV1::decode(
            output, original.open,
        )?;
        Ok(())
    }

    pub(super) fn original_transfer_index_v1(&self) -> Result<TransferIndexV1, E> {
        self.raw_ready_bytes_v1()?;
        self.index.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(E::Boundary)
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.raw_ready_bytes_v1()?;
        self.fixed.require_complete_v1()?;
        self.variable.require_complete_v1()
    }

    pub(super) fn same_financial_v1(&self, financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1) -> bool {
        match &self.variable.financial {
            Some(original) => original.same_original_data_v1(financial),
            None => false,
        }
    }

    pub(super) fn completed_native_descriptor_peak_v1(&self) -> Result<u64, E> {
        self.raw_ready_bytes_v1()?;
        if !self.index_frame.completed_exact() || self.frame.is_some() || !self.chunks.disposed_v1() {
            return Err(E::Boundary);
        }
        let geometry = self.geometry.as_ref().map_err(|_| E::Boundary)?;
        u64::try_from(geometry.receive_obligations_v1().1).map_err(|_| E::Boundary)
    }

    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, NativeError> {
        let native: Result<ResourceVector, NativeError> = aos_sandbox_broker::root_subject_receiving_demand_v1! {
            sample: RootSelectedControllerSubjectSampleV1,
            readiness: RootSubjectReadinessV1,
            error: NativeError::geometry(),
        };
        let base: Result<ResourceVector, NativeError> = aos_sandbox_broker::root_ready_fixed_demand_v1! {
            native: native,
            owner: Self,
            clock: super::initial_ready_controls::clock_demand_v1(),
            error: NativeError::geometry(),
        };
        base
    }

    pub(super) fn owed_names_demand_v1() -> Result<ResourceVector, NativeError> {
        RootInitialWriterSampleOriginalV1::additional_native_demand_v1()
    }

    fn encoded_demand_v1(index: TransferIndexV1) -> Result<ResourceVector, NativeError> {
        aos_sandbox_broker::root_ready_encoded_demand_v1! {
            index: index,
            error: NativeError::geometry(),
        }
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry.as_ref().err().map(|error| error as _)
            .or_else(|| self.fixed.failure_v1())
            .or_else(|| self.fixed_predecessor.as_ref().map(|error| error as _))
            .or_else(|| cause(&self.enabled))
            .or_else(|| cause(&self.hello_clock))
            .or_else(|| cause(&self.hello_cutoff))
            .or_else(|| cause(&self.hello_encoding))
            .or_else(|| cause(&self.send))
            .or_else(|| cause(&self.send_shape))
            .or_else(|| self.index_frame.failure())
            .or_else(|| cause(&self.index))
            .or_else(|| self.variable.failure_v1())
            .or_else(|| self.variable_predecessor.as_ref().map(|error| error as _))
            .or_else(|| cause(&self.allocation))
            .or_else(|| self.frame.as_ref().and_then(|frame| frame.failure()))
            .or_else(|| match &self.frame {
                Some(frame) => self.chunks.failure_v1(frame),
                None => self.chunks.failure_v1(&self.index_frame),
            })
            .or_else(|| cause(&self.frame_binding))
            .or_else(|| cause(&self.digest))
            .or_else(|| self.writers_post.failure_v1())
            .or_else(|| cause(&self.readback))
            .or_else(|| self.peer_history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::failure_v1))
            .or_else(|| cause(&self.peer_arm))
            .or_else(|| cause(&self.peer))
            .or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.cutoff))
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Boundary)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
