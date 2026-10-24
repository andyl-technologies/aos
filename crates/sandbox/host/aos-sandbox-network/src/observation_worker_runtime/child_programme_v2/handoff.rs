//! Joins fixed Source-bound H03 discovery to the exact six-public-original body.

use super::*;
use crate::observation_worker_runtime::read_admission_v2::{
    NetworkObserverReadOriginalV2, ObserverReadClosedV2,
};
use crate::observer_handoff_v2::{
    HEADER_BYTES, ObserverHandoffHeaderDataV3, observer_handoff_length_data_v2,
};
use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    NetworkWorkerBootstrapWaitOriginalV3, NetworkWorkerBootstrapWaitRefusalV3,
    NetworkWorkerRetiredRecordDataV2, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{
    NetworkWorkerRecordKindV4, RecordBindingError, RetainedSeqpacketReceiveErrorV1,
};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the observer's original bootstrap handoff is closed")]
pub(super) struct HandoffClosedV3;

#[derive(Clone, Copy)]
enum First {
    Order,
    HeaderBefore,
    HeaderWait,
    HeaderReceive,
    HeaderOrigin,
    HeaderSource,
    HeaderShape,
    HeaderOriginAfter,
    HeaderAfter,
    HeaderRetirement,
    Fee,
    FullBefore,
    FullWait,
    FullReceive,
    Prefix,
    Read,
    FullAfter,
    Panic,
}

/// Retains both bootstrap attempts and every reached original until handback.
pub(super) struct ObserverHandoffOriginalV3 {
    entered: bool,
    first: Option<First>,
    header_before: NetworkChildSourceProbeOriginalV2,
    header_before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    header_wait: NetworkWorkerBootstrapWaitOriginalV3,
    header_wait_result: Option<Result<(), NetworkWorkerBootstrapWaitRefusalV3>>,
    header: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    header_origin: Option<Result<(), RecordBindingError>>,
    header_source: NetworkChildSourceRecordOriginalV2,
    header_source_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    facts: Option<Result<ObserverHandoffHeaderDataV3, HandoffClosedV3>>,
    header_origin_after: Option<Result<(), RecordBindingError>>,
    header_after: NetworkChildSourceProbeOriginalV2,
    header_after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    stat_retirement: Option<Result<(), NetworkChildOriginClosedV2>>,
    retired_header: Option<NetworkWorkerRetiredRecordDataV2>,
    fee: Option<Result<ResourceVector, HandoffClosedV3>>,
    full_before: NetworkChildSourceProbeOriginalV2,
    full_before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    full_wait: NetworkWorkerBootstrapWaitOriginalV3,
    full_wait_result: Option<Result<(), NetworkWorkerBootstrapWaitRefusalV3>>,
    full: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    prefix: Option<Result<(), HandoffClosedV3>>,
    read_result: Option<Result<(), ObserverReadClosedV2>>,
    full_after: NetworkChildSourceProbeOriginalV2,
    full_after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
}

impl ObserverHandoffOriginalV3 {
    pub(super) fn header_slot_for_owed_custody_v3(
        &self,
    ) -> super::disposition::InputSlotOriginalV3<'_> {
        use super::disposition::InputSlotOriginalV3 as Slot;
        if matches!(self.first, Some(First::Panic)) {
            return Slot::Uncertain;
        }
        match (&self.header, &self.retired_header) {
            (Some(Ok(record)), _) => Slot::Record(record),
            (Some(Err(_)), _) => Slot::Uncertain,
            (None, Some(header)) => Slot::RetiredHeader(header),
            (None, None) => Slot::Unentered,
        }
    }

    pub(super) fn full_slot_for_owed_custody_v3<'held>(
        &'held self,
        read: &'held NetworkObserverReadOriginalV2,
    ) -> super::disposition::InputSlotOriginalV3<'held> {
        use super::disposition::InputSlotOriginalV3 as Slot;
        if matches!(self.first, Some(First::Panic)) {
            return Slot::Uncertain;
        }
        match self.full.as_ref() {
            Some(Ok(record)) => Slot::Record(record),
            Some(Err(_)) => Slot::Uncertain,
            None if self.read_result.is_some() => read
                .received_original_for_owed_custody_v3()
                .map(Slot::Record)
                .unwrap_or(Slot::Uncertain),
            None => Slot::Unentered,
        }
    }

    pub(super) fn new() -> Self {
        Self {
            entered: false,
            first: None,
            header_before: NetworkChildSourceProbeOriginalV2::new(),
            header_before_result: None,
            header_wait: NetworkWorkerBootstrapWaitOriginalV3::new(),
            header_wait_result: None,
            header: None,
            header_origin: None,
            header_source: NetworkChildSourceRecordOriginalV2::new(),
            header_source_result: None,
            facts: None,
            header_origin_after: None,
            header_after: NetworkChildSourceProbeOriginalV2::new(),
            header_after_result: None,
            stat_retirement: None,
            retired_header: None,
            fee: None,
            full_before: NetworkChildSourceProbeOriginalV2::new(),
            full_before_result: None,
            full_wait: NetworkWorkerBootstrapWaitOriginalV3::new(),
            full_wait_result: None,
            full: None,
            prefix: None,
            read_result: None,
            full_after: NetworkChildSourceProbeOriginalV2::new(),
            full_after_result: None,
        }
    }

    /// Receives no operation D until the actual exact full handoff is admitted.
    /// No-D waits grant no read; the already-issued native Source bridge and
    /// parent-held whole financial programme are independent prerequisites.
    pub(super) fn capture_once_v3(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        read: &mut NetworkObserverReadOriginalV2,
    ) -> Result<(), HandoffClosedV3> {
        if self.entered || self.first.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(HandoffClosedV3);
        }
        self.entered = true;
        let donor = source
            .original_netd_pidfd_for_worker_wait_v2()
            .map_err(|_| {
                self.first = Some(First::HeaderBefore);
                HandoffClosedV3
            })?;
        self.header_before_result =
            Some(source.require_live_before_once_v2(&mut self.header_before, None));
        if !matches!(self.header_before_result, Some(Ok(()))) {
            self.first = Some(First::HeaderBefore);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                self.capture_header(source, socket, donor);
            }
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Panic);
        }
        // The after is owed even after malformed DATA, native failure or panic.
        self.header_after_result = Some(source_after(source, &mut self.header_after));
        if !matches!(self.header_after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::HeaderAfter);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            return Err(HandoffClosedV3);
        }
        self.retire_header()?;

        let lengths = self
            .facts
            .as_ref()
            .and_then(|facts| facts.as_ref().ok())
            .ok_or(HandoffClosedV3)?
            .section_lengths_data_v3();
        // This is an additional deny-only comparison with the genuine native
        // bridge's preissued fee. It is not a complete-price proof or a debit;
        // the protected parent's whole pre-P/O invoice remains mandatory.
        self.fee = Some(
            observer_handoff_obligations_data_v3(lengths)
                .filter(|demand| {
                    source
                        .prepaid_fee_data_v2()
                        .is_some_and(|paid| paid.checked_sub(*demand).is_ok())
                })
                .ok_or(HandoffClosedV3),
        );
        if !matches!(self.fee, Some(Ok(_))) {
            self.first = Some(First::Fee);
            return Err(HandoffClosedV3);
        }
        self.full_before_result =
            Some(source.require_live_before_once_v2(&mut self.full_before, None));
        if !matches!(self.full_before_result, Some(Ok(()))) {
            self.first = Some(First::FullBefore);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                self.capture_full(source, socket, donor, read);
            }
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Panic);
        }
        self.full_after_result = Some(source_after(source, &mut self.full_after));
        if !matches!(self.full_after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::FullAfter);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            Err(HandoffClosedV3)
        } else {
            Ok(())
        }
    }

    fn capture_header(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        donor: &PidFd,
    ) {
        self.header_wait_result = Some(self.header_wait.observe_once_v3(socket, donor, None));
        if !matches!(self.header_wait_result, Some(Ok(()))) {
            self.first = Some(First::HeaderWait);
            return;
        }
        self.header = Some(socket.receive_network_observer_handoff_header_retaining_v3());
        let Some(Ok(record)) = self.header.as_ref() else {
            self.first = Some(First::HeaderReceive);
            return;
        };
        self.header_origin = Some(socket.validate_received_origin_retaining(record));
        if !matches!(self.header_origin, Some(Ok(()))) {
            self.first = Some(First::HeaderOrigin);
        }
        self.header_source_result =
            Some(source.require_same_netd_record_once_v2(record, &mut self.header_source));
        if !matches!(self.header_source_result, Some(Ok(()))) {
            self.first.get_or_insert(First::HeaderSource);
        }
        self.facts = Some(
            ObserverHandoffHeaderDataV3::decode(record.payload())
                .filter(|facts| {
                    source
                        .operation_binding_data_v2()
                        .is_some_and(|native| facts.matches_native(native))
                })
                .ok_or(HandoffClosedV3),
        );
        if !matches!(self.facts, Some(Ok(_))) {
            self.first.get_or_insert(First::HeaderShape);
        }
        self.header_origin_after = Some(socket.validate_received_origin_retaining(record));
        if !matches!(self.header_origin_after, Some(Ok(()))) {
            self.first.get_or_insert(First::HeaderOriginAfter);
        }
    }

    fn retire_header(&mut self) -> Result<(), HandoffClosedV3> {
        self.stat_retirement = Some(self.header_source.retire_positive_stat_proof_once_v2());
        if !matches!(self.stat_retirement, Some(Ok(()))) {
            self.first = Some(First::HeaderRetirement);
            return Err(HandoffClosedV3);
        }
        let Some(Ok(record)) = self.header.take() else {
            self.first = Some(First::HeaderRetirement);
            return Err(HandoffClosedV3);
        };
        match record.retire_network_worker_positive_subject_data_v2() {
            Ok(data) => self.retired_header = Some(data),
            Err(record) => {
                self.header = Some(Ok(record));
                self.first = Some(First::HeaderRetirement);
                return Err(HandoffClosedV3);
            }
        }
        Ok(())
    }

    fn capture_full(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        socket: &mut DescriptorSubjectSocket,
        donor: &PidFd,
        read: &mut NetworkObserverReadOriginalV2,
    ) {
        self.full_wait_result = Some(self.full_wait.observe_once_v3(socket, donor, None));
        if !matches!(self.full_wait_result, Some(Ok(()))) {
            self.first = Some(First::FullWait);
            return;
        }
        let Some(Ok(facts)) = self.facts.as_ref() else {
            self.first = Some(First::HeaderShape);
            return;
        };
        self.full =
            Some(socket.receive_network_observer_bootstrap_handoff_retaining_v3(facts.total_bytes));
        let Some(Ok(record)) = self.full.as_ref() else {
            self.first = Some(First::FullReceive);
            return;
        };
        self.prefix = Some(
            if record.payload().get(..HEADER_BYTES)
                == self.retired_header.as_ref().map(|header| header.payload())
            {
                Ok(())
            } else {
                Err(HandoffClosedV3)
            },
        );
        if !matches!(self.prefix, Some(Ok(()))) {
            self.first = Some(First::Prefix);
            return;
        }
        // The same actual record moves into the public/read owner. It retains
        // its native subject, all six rights, exact bytes and independent posts.
        let Some(Ok(record)) = self.full.take() else {
            self.first = Some(First::FullReceive);
            return;
        };
        self.read_result = Some(read.capture_once_v2(source, socket, record));
        if !matches!(self.read_result, Some(Ok(()))) {
            self.first = Some(First::Read);
        }
    }

    pub(super) fn section_lengths_data_v3(&self) -> Option<[usize; 9]> {
        if self.first.is_some() {
            return None;
        }
        Some(
            self.facts
                .as_ref()?
                .as_ref()
                .ok()?
                .section_lengths_data_v3(),
        )
    }

    pub(super) fn failure<'held>(
        &'held self,
        read: &'held NetworkObserverReadOriginalV2,
    ) -> Option<&'held (dyn Error + 'static)> {
        let cause = match self.first? {
            First::HeaderBefore => self.header_before.failure(),
            First::HeaderWait => self.header_wait.failure(),
            First::HeaderReceive => error(&self.header),
            First::HeaderOrigin => error(&self.header_origin),
            First::HeaderSource => self.header_source.failure(),
            First::HeaderShape => error(&self.facts),
            First::HeaderOriginAfter => error(&self.header_origin_after),
            First::HeaderAfter => self.header_after.failure(),
            First::HeaderRetirement => self
                .header_source
                .failure()
                .or_else(|| error(&self.stat_retirement)),
            First::Fee => error(&self.fee),
            First::FullBefore => self.full_before.failure(),
            First::FullWait => self.full_wait.failure(),
            First::FullReceive => error(&self.full),
            First::Prefix => error(&self.prefix),
            First::Read => read.failure(),
            First::FullAfter => self.full_after.failure(),
            First::Order | First::Panic => None,
        };
        cause.or(Some(&HandoffClosedV3))
    }
}

fn source_after(
    source: &mut NetworkChildSourceLoanV2<'_>,
    original: &mut NetworkChildSourceProbeOriginalV2,
) -> Result<(), NetworkChildOriginClosedV2> {
    if source.operation_binding_data_v2().is_some() {
        source.require_live_before_once_v2(original, None)
    } else {
        source.observe_owed_native_after_once_v2(original)
    }
}

/// Quotes the exact two-carrier handoff without allocation or authority.
pub(crate) fn observer_handoff_obligations_data_v3(lengths: [usize; 9]) -> Option<ResourceVector> {
    let total = observer_handoff_length_data_v2(lengths)?;
    let header = DescriptorSubjectSocket::network_worker_receive_obligations_v4(
        NetworkWorkerRecordKindV4::ObservationHandoffHeaderV3,
    )?;
    let full = DescriptorSubjectSocket::network_observer_handoff_receive_obligations_v2(total)?;
    let wait = NetworkWorkerBootstrapWaitOriginalV3::receiving_bytes_v3()?.checked_mul(2)?;
    let bytes = std::mem::size_of::<ObserverHandoffOriginalV3>()
        .checked_mul(2)?
        .checked_add(header.0)?
        .checked_add(full.0)?
        .checked_add(wait)?;
    let files = header.1.checked_add(full.1)?;
    ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(D::OpenFiles, u64::try_from(files).ok()?)
        .checked_add(NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?)
        .ok()?
        .checked_add(NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(4)?)
        .ok()
}
