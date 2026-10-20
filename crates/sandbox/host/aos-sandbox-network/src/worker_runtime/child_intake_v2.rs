//! Retains the actual Source-bound finite P frame intake and original namespace rights.
//!
//! All records use the existing native carrier, Source queries and frame codec.
//! Before allocating the aggregate, the first native-authenticated record must
//! carry the complete closed P2 DATA header. Native Source and original signed
//! method admission remain distinct; this receiver creates no effect permission.

use super::preparation_input_v2::{INPUT_HEADER_BYTES, header_data_v2};
use super::*;
use aos_sandbox_broker::receiving::{
    NetworkChildOriginClosedV2, NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2,
    NetworkChildSourceRecordOriginalV2,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    NetworkWorkerBootstrapWaitOriginalV3, NetworkWorkerBootstrapWaitRefusalV3,
    NetworkWorkerRetiredRecordDataV2, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{RecordBindingError, RetainedSeqpacketReceiveErrorV1};

/// Refuses intake while the actual owner retains its first original cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("actual P intake original retained")]
pub(crate) struct PreparationIntakeClosedV2;

/// Borrows one actual native disposition without granting a receive or effect.
///
/// Entered native failures and unreturned attempts are uncertain and must not
/// be retried. Retired positive records retain their original comparison DATA;
/// held native records still owe the caller's exact Source and channel checks.
pub(crate) enum NetworkPreparationFrameDispositionV3<'held> {
    Unentered,
    Record(&'held ReceivedDescriptorRecord),
    Retired(&'held NetworkWorkerRetiredRecordDataV2),
    Uncertain,
}

#[derive(Clone, Copy)]
enum FrameFirst {
    Before,
    Wait,
    Receive,
    Origin,
    Source,
    Shape,
    After,
    OriginAfter,
    Retirement,
}

struct FrameOriginal {
    before: NetworkChildSourceProbeOriginalV2,
    before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    wait: NetworkWorkerBootstrapWaitOriginalV3,
    wait_result: Option<Result<(), NetworkWorkerBootstrapWaitRefusalV3>>,
    receive: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    native_receive_entered: bool,
    origin: Option<Result<(), RecordBindingError>>,
    source: NetworkChildSourceRecordOriginalV2,
    source_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    shape: Option<Result<(), NetworkWorkerRuntimeError>>,
    after_entered: bool,
    after: NetworkChildSourceProbeOriginalV2,
    after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    origin_after_entered: bool,
    origin_after: Option<Result<(), RecordBindingError>>,
    retirement: Option<Result<(), NetworkChildOriginClosedV2>>,
    retired: Option<NetworkWorkerRetiredRecordDataV2>,
    first: Option<FrameFirst>,
}

impl FrameOriginal {
    fn new() -> Self {
        Self {
            before: NetworkChildSourceProbeOriginalV2::new(),
            before_result: None,
            wait: NetworkWorkerBootstrapWaitOriginalV3::new(),
            wait_result: None,
            receive: None,
            native_receive_entered: false,
            origin: None,
            source: NetworkChildSourceRecordOriginalV2::new(),
            source_result: None,
            shape: None,
            after_entered: false,
            after: NetworkChildSourceProbeOriginalV2::new(),
            after_result: None,
            origin_after_entered: false,
            origin_after: None,
            retirement: None,
            retired: None,
            first: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            FrameFirst::Before => self.before.failure(),
            FrameFirst::Wait => self.wait.failure(),
            FrameFirst::Receive => self
                .receive
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            FrameFirst::Origin => self.origin.as_ref()?.as_ref().err().map(|cause| cause as _),
            FrameFirst::Source | FrameFirst::Retirement => self.source.failure(),
            FrameFirst::Shape => self.shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            FrameFirst::After => self.after.failure(),
            FrameFirst::OriginAfter => self
                .origin_after
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
        }
        .or(Some(&PreparationIntakeClosedV2))
    }

    fn disposition(&self) -> NetworkPreparationFrameDispositionV3<'_> {
        if let Some(record) = self.retired.as_ref() {
            NetworkPreparationFrameDispositionV3::Retired(record)
        } else if let Some(Ok(record)) = self.receive.as_ref() {
            NetworkPreparationFrameDispositionV3::Record(record)
        } else if self.native_receive_entered || self.receive.is_some() {
            NetworkPreparationFrameDispositionV3::Uncertain
        } else {
            NetworkPreparationFrameDispositionV3::Unentered
        }
    }

    fn retire_completed(&mut self) -> Result<(), PreparationIntakeClosedV2> {
        if self.first.is_some() {
            return Err(PreparationIntakeClosedV2);
        }
        self.retirement = Some(self.source.retire_positive_stat_proof_once_v2());
        if !matches!(self.retirement, Some(Ok(()))) {
            self.first = Some(FrameFirst::Retirement);
            return Err(PreparationIntakeClosedV2);
        }
        let original = self.receive.take();
        if let Some(Ok(record)) = original {
            match record.retire_network_worker_positive_subject_data_v2() {
                Ok(data) => {
                    self.retired = Some(data);
                    return Ok(());
                }
                Err(record) => {
                    self.receive = Some(Ok(record));
                }
            }
        } else {
            self.receive = original;
        }
        self.first = Some(FrameFirst::Retirement);
        Err(PreparationIntakeClosedV2)
    }
}

struct FrameRun<'a, 'native> {
    source: &'a mut NetworkChildSourceLoanV2<'native>,
    socket: &'a mut DescriptorSubjectSocket,
    original: &'a mut FrameOriginal,
}

impl FrameRun<'_, '_> {
    fn capture(
        &mut self,
        first: bool,
        body: impl FnOnce(&mut ReceivedDescriptorRecord) -> Result<(), NetworkWorkerRuntimeError>,
    ) -> Result<(), PreparationIntakeClosedV2> {
        self.original.before_result = Some(
            self.source
                .require_live_before_once_v2(&mut self.original.before, None),
        );
        if !matches!(self.original.before_result, Some(Ok(()))) {
            self.original.first = Some(FrameFirst::Before);
        } else {
            self.original.first = Some(FrameFirst::Wait);
            let donor = self
                .source
                .original_netd_pidfd_for_worker_wait_v2()
                .map_err(|_| PreparationIntakeClosedV2)?;
            self.original.wait_result =
                Some(self.original.wait.observe_once_v3(self.socket, donor, None));
            if matches!(self.original.wait_result, Some(Ok(()))) {
                self.original.first = Some(FrameFirst::Receive);
                self.original.native_receive_entered = true;
                self.original.receive = Some(
                    self.socket
                        .receive_network_preparation_bootstrap_frame_retaining_v3(first),
                );
                if let Some(Ok(record)) = self.original.receive.as_mut() {
                    self.original.first = Some(FrameFirst::Origin);
                    self.original.origin =
                        Some(self.socket.validate_received_origin_retaining(record));
                    if matches!(self.original.origin, Some(Ok(()))) {
                        self.original.first = Some(FrameFirst::Source);
                        self.original.source_result =
                            Some(self.source.require_same_netd_record_once_v2(
                                record,
                                &mut self.original.source,
                            ));
                        if matches!(self.original.source_result, Some(Ok(()))) {
                            self.original.first = Some(FrameFirst::Shape);
                            self.original.shape = Some(body(record));
                            if matches!(self.original.shape, Some(Ok(()))) {
                                self.original.first = None;
                            }
                        }
                    }
                }
            }
        }
        self.finish_posts();
        if self.original.first.is_none() {
            Ok(())
        } else {
            Err(PreparationIntakeClosedV2)
        }
    }

    fn finish_posts(&mut self) {
        if !self.original.after_entered {
            self.original.after_entered = true;
            // Entered-but-unreturned native work stays a selected refusal on unwind.
            let previous = self.original.first;
            self.original.first.get_or_insert(FrameFirst::After);
            self.original.after_result =
                Some(if self.source.operation_binding_data_v2().is_some() {
                    self.source
                        .require_live_before_once_v2(&mut self.original.after, None)
                } else {
                    self.source
                        .observe_owed_native_after_once_v2(&mut self.original.after)
                });
            if matches!(self.original.after_result, Some(Ok(()))) {
                self.original.first = previous;
            }
        }
        if !self.original.origin_after_entered {
            self.original.origin_after_entered = true;
            if let Some(Ok(record)) = self.original.receive.as_ref() {
                let previous = self.original.first;
                self.original.first.get_or_insert(FrameFirst::OriginAfter);
                self.original.origin_after =
                    Some(self.socket.validate_received_origin_retaining(record));
                if matches!(self.original.origin_after, Some(Ok(()))) {
                    self.original.first = previous;
                }
            }
        }
    }
}

impl Drop for FrameRun<'_, '_> {
    fn drop(&mut self) {
        self.finish_posts();
    }
}

/// Owns actual framed P input, native namespace donors and all Source posts.
pub(crate) struct NetworkPreparationIntakeOriginalV2 {
    entered: bool,
    closed: bool,
    frames: Vec<FrameOriginal>,
    bytes: Vec<u8>,
    rights: Vec<OwnedFd>,
    expected_digest: Option<[u8; 32]>,
    expected_total: Option<usize>,
    rights_taken: bool,
    aggregate_gate: Option<Result<(), PreparationIntakeClosedV2>>,
    returned: Option<Result<(), PreparationIntakeClosedV2>>,
    first_frame: Option<usize>,
}

impl NetworkPreparationIntakeOriginalV2 {
    /// Borrows the reached native state without repeating an entered receive.
    ///
    /// Unallocated slots within the canonical ceiling have no native attempt.
    /// That fact grants no receive: the actor must independently derive its
    /// finite owed drain bound from the actual Source-bound canonical header.
    /// Indices outside the known count or canonical ceiling are uncertain.
    pub(crate) fn frame_disposition_original_v3(
        &self,
        index: usize,
    ) -> NetworkPreparationFrameDispositionV3<'_> {
        if let Some(frame) = self.frames.get(index) {
            return frame.disposition();
        }
        let bound = self.known_frame_count_data_v3().unwrap_or(
            MAXIMUM_NETWORK_WORKER_REQUEST_BYTES.div_ceil(MAXIMUM_FRAME_PAYLOAD_BYTES));
        if index < bound {
            NetworkPreparationFrameDispositionV3::Unentered
        } else {
            NetworkPreparationFrameDispositionV3::Uncertain
        }
    }

    /// Returns the total parsed from the actual Source-bound closed P2 header.
    pub(crate) fn known_total_bytes_data_v3(&self) -> Option<usize> {
        self.expected_total
    }

    /// Returns only that header's existing finite canonical frame count.
    pub(crate) fn known_frame_count_data_v3(&self) -> Option<usize> {
        self.expected_total
            .map(|total| total.div_ceil(MAXIMUM_FRAME_PAYLOAD_BYTES))
    }

    /// Counts allocated capture slots, including a slot failing before receive.
    pub(crate) fn entered_frame_slots_data_v3(&self) -> usize {
        self.frames.len()
    }

    /// Counts the consecutive frames whose positive native proofs retired.
    pub(crate) fn completed_frame_count_data_v3(&self) -> usize {
        self.frames
            .iter()
            .take_while(|frame| frame.retired.is_some())
            .count()
    }

    /// Reports successful whole intake, including its actual digest and posts.
    pub(crate) fn intake_complete_data_v3(&self) -> bool {
        self.completed_input_data_v2().is_some()
    }

    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            closed: false,
            frames: Vec::new(),
            bytes: Vec::new(),
            rights: Vec::new(),
            expected_digest: None,
            expected_total: None,
            rights_taken: false,
            aggregate_gate: None,
            returned: None,
            first_frame: None,
        }
    }

    /// Quotes all receiving destinations before the actual whole programme grows.
    pub(crate) fn receiving_demand_data_v2(width: usize) -> Option<ResourceVector> {
        if !(INPUT_HEADER_BYTES + 1..=MAXIMUM_NETWORK_WORKER_REQUEST_BYTES).contains(&width) {
            return None;
        }
        let count = width.div_ceil(MAXIMUM_FRAME_PAYLOAD_BYTES);
        let count_u64 = u64::try_from(count).ok()?;
        let native = DescriptorSubjectSocket::network_worker_receive_obligations_v4(
            aos_sandbox_linux::seqpacket::NetworkWorkerRecordKindV4::PreparationRequestFirstV2,
        )?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                std::mem::size_of::<FrameOriginal>()
                    .checked_mul(2)?
                    .checked_mul(count)?,
            )?
            .checked_add(
                native
                    .0
                    .checked_add(NetworkWorkerBootstrapWaitOriginalV3::receiving_bytes_v3()?)?
                    .checked_mul(count)?,
            )?
            .checked_add(width.checked_mul(2)?)?;
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(
                D::OpenFiles,
                u64::try_from(native.1.checked_add(2)?).ok()?,
            );
        let record = NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?;
        // Completed earlier frames retain all bytes/models, but their actual
        // automatic subject/stat proofs have already retired. Body failure
        // stops before another frame, so only one native/stat frontier overlaps
        // the two continuously held namespace donors. No earlier debit changes.
        demand = demand.checked_add(ResourceVector::ZERO.with(D::OpenFiles, record.get(D::OpenFiles))).ok()?;
        for _ in 0..count {
            demand = demand
                .checked_add(record.with(D::OpenFiles, 0))
                .ok()?;
        }
        demand
            .checked_add(
                NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(
                    count_u64.checked_mul(2)?,
                )?,
            )
            .ok()
    }

    /// Receives only on the actual P Source after the fixed prefix was prepaid.
    ///
    /// The once-only width callback checks the already-paid complete programme
    /// after the first Source-bound closed header and before aggregate or
    /// remaining-frame growth. Its caller retains the actual financial Result;
    /// this deny-only gate creates no bank, budget or effect permission.
    ///
    /// # Errors
    /// Retains reentry, Source, carrier, frame, aggregate-width gate, digest or
    /// independently owed post refusal. No failed native prefix is retired.
    pub(crate) fn capture_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        admit_width: impl FnOnce(usize) -> Result<(), PreparationIntakeClosedV2>,
    ) -> Result<(), PreparationIntakeClosedV2> {
        if self.entered {
            self.closed = true;
            return Err(PreparationIntakeClosedV2);
        }
        self.entered = true;
        if source
            .operation_binding_data_v2()
            .is_none_or(|binding| binding.purpose != 1)
        {
            self.returned = Some(Err(PreparationIntakeClosedV2));
            return Err(PreparationIntakeClosedV2);
        }
        let result = self.capture(source, socket, admit_width);
        self.returned = Some(result);
        result
    }

    fn capture(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        admit_width: impl FnOnce(usize) -> Result<(), PreparationIntakeClosedV2>,
    ) -> Result<(), PreparationIntakeClosedV2> {
        let mut admit_width = Some(admit_width);
        self.frames.reserve_exact(1);
        let mut index = 0usize;
        loop {
            self.frames.push(FrameOriginal::new());
            self.first_frame = Some(index);
            let bytes = &mut self.bytes;
            let rights = &mut self.rights;
            let expected_total = &mut self.expected_total;
            let expected_digest = &mut self.expected_digest;
            let aggregate_gate = &mut self.aggregate_gate;
            let original = self.frames.last_mut().ok_or(PreparationIntakeClosedV2)?;
            let mut run = FrameRun {
                source: &mut *source,
                socket: &mut *socket,
                original,
            };
            let result = run.capture(index == 0, |record| {
                let frame = decode_frame(record.payload())?;
                if frame.offset != bytes.len()
                    || frame.payload.len()
                        != MAXIMUM_FRAME_PAYLOAD_BYTES.min(frame.total - frame.offset)
                {
                    return Err(intake_marker());
                }
                if index == 0 {
                    let header = frame
                        .payload
                        .get(..INPUT_HEADER_BYTES)
                        .ok_or_else(intake_marker)?;
                    let (method, _, _, total) = header_data_v2(header).ok_or_else(intake_marker)?;
                    if total != frame.total
                        || record.descriptors().len() != if method == 63 { 1 } else { 2 }
                    {
                        return Err(intake_marker());
                    }
                    *expected_total = Some(total);
                    *expected_digest = Some(frame.digest);
                    let gate = admit_width.take().ok_or_else(intake_marker)?;
                    *aggregate_gate = Some(gate(total));
                    if !matches!(*aggregate_gate, Some(Ok(()))) {
                        return Err(intake_marker());
                    }
                    bytes.reserve_exact(total);
                } else if *expected_total != Some(frame.total)
                    || *expected_digest != Some(frame.digest)
                    || !record.descriptors().is_empty()
                {
                    return Err(intake_marker());
                }
                bytes.extend_from_slice(frame.payload);
                if index == 0 {
                    *rights = record
                        .take_network_preparation_frame_descriptors_data_v3()
                        .ok_or_else(intake_marker)?;
                }
                Ok(())
            });
            drop(run);
            if result.is_err() || original.retire_completed().is_err() {
                return Err(PreparationIntakeClosedV2);
            }
            self.first_frame = None;
            let total = self.expected_total.ok_or(PreparationIntakeClosedV2)?;
            if self.bytes.len() == total {
                break;
            }
            if index == 0 {
                self.frames.reserve_exact(
                    total
                        .div_ceil(MAXIMUM_FRAME_PAYLOAD_BYTES)
                        .saturating_sub(1),
                );
            }
            index = index.checked_add(1).ok_or(PreparationIntakeClosedV2)?;
        }
        if Some(<[u8; 32]>::from(Sha256::digest(&self.bytes))) != self.expected_digest
            || PreparationInputDataV2::decode(&self.bytes).is_none()
        {
            return Err(PreparationIntakeClosedV2);
        }
        Ok(())
    }

    /// Borrows original closed63/9 dispatch/fence DATA; admission remains owed.
    pub(crate) fn completed_input_data_v2(&self) -> Option<PreparationInputDataV2<'_>> {
        if self.closed || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        PreparationInputDataV2::decode(&self.bytes)
    }

    /// Moves the exact native role table only after every intake post succeeded.
    pub(crate) fn take_namespace_descriptors_data_once_v2(&mut self) -> Option<Vec<OwnedFd>> {
        self.completed_input_data_v2()?;
        if self.rights_taken {
            return None;
        }
        self.rights_taken = true;
        Some(std::mem::take(&mut self.rights))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(index) = self.first_frame {
            return self.frames.get(index)?.failure();
        }
        self.returned
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause as _)
            .or_else(|| self.closed.then_some(&PreparationIntakeClosedV2 as _))
    }

    /// Selects the closed caller's actual already-paid programme refusal.
    pub(crate) fn aggregate_gate_failure_selected_v2(&self) -> bool {
        self.first_frame == Some(0)
            && matches!(self.aggregate_gate, Some(Err(_)))
            && self
                .frames
                .first()
                .is_some_and(|frame| matches!(frame.first, Some(FrameFirst::Shape)))
    }
}

fn intake_marker() -> NetworkWorkerRuntimeError {
    NetworkWorkerRuntimeError::Protocol("original P frame Source and envelope required")
}

#[cfg(test)]
mod disposition_tests {
    use super::*;

    #[test]
    fn source_or_wait_refusal_leaves_native_receive_unentered() {
        let mut frame = FrameOriginal::new();
        for first in [FrameFirst::Before, FrameFirst::Wait] {
            frame.first = Some(first);
            assert!(matches!(
                frame.disposition(),
                NetworkPreparationFrameDispositionV3::Unentered
            ));
        }
        // An unwind after entering the real native call has no returned
        // record/error yet. It still cannot be retried or inferred absent.
        frame.native_receive_entered = true;
        frame.first = Some(FrameFirst::Receive);
        assert!(matches!(
            frame.disposition(),
            NetworkPreparationFrameDispositionV3::Uncertain
        ));
    }

    #[test]
    fn unallocated_slots_never_grant_a_finite_drain_bound() {
        let mut intake = NetworkPreparationIntakeOriginalV2::new();
        assert!(matches!(
            intake.frame_disposition_original_v3(0),
            NetworkPreparationFrameDispositionV3::Unentered
        ));
        assert!(matches!(
            intake.frame_disposition_original_v3(1),
            NetworkPreparationFrameDispositionV3::Unentered
        ));
        assert!(matches!(
            intake.frame_disposition_original_v3(
                MAXIMUM_NETWORK_WORKER_REQUEST_BYTES.div_ceil(MAXIMUM_FRAME_PAYLOAD_BYTES)),
            NetworkPreparationFrameDispositionV3::Uncertain
        ));
        assert_eq!(intake.known_total_bytes_data_v3(), None);
        assert!(!intake.intake_complete_data_v3());

        intake.expected_total = Some(MAXIMUM_FRAME_PAYLOAD_BYTES + 1);
        assert_eq!(intake.known_frame_count_data_v3(), Some(2));
        assert!(matches!(
            intake.frame_disposition_original_v3(1),
            NetworkPreparationFrameDispositionV3::Unentered
        ));
        assert!(matches!(
            intake.frame_disposition_original_v3(2),
            NetworkPreparationFrameDispositionV3::Uncertain
        ));
        assert_eq!(intake.entered_frame_slots_data_v3(), 0);
        assert_eq!(intake.completed_frame_count_data_v3(), 0);
        assert!(!intake.intake_complete_data_v3());
    }
}
