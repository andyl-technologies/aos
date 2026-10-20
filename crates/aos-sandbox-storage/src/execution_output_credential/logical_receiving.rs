//! Keeps genuine same-F logical46/47 native work distinct from ordinary callers.
//!
//! No caller supplies a payer implementation. The finite adapter contains
//! either ordinary behavior or the actual lifecycle loan and retained writer.
//! Positive Output samples may reuse the same paid native peak; a failed
//! sample and every independently owed destination stay resident.

use super::*;
use aos_sandbox_core::{AccountingError, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

type Loan<'cut, 'original> = aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum LogicalOutputFundingErrorV1 {
    #[error("the same original logical Output interval is closed")]
    Closed,
    #[error(transparent)]
    Arithmetic(#[from] AccountingError),
    #[error(transparent)]
    Append(#[from] aos_sandbox::journal::JournalAppendReceivingDemandErrorV1),
    #[error(transparent)]
    Authorization(#[from] crate::StorageAdmissionError),
}

#[derive(Debug, thiserror::Error)]
enum LogicalClockErrorV1 {
    #[error("the original logical Output kernel clock is stale")]
    Stale,
    #[error(transparent)]
    Kernel(aos_sandbox_linux::Error),
}

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for LogicalClockErrorV1 {
    fn stale() -> Self { Self::Stale }
    fn kernel(error: aos_sandbox_linux::Error) -> Self { Self::Kernel(error) }
}

type Clock = aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<LogicalClockErrorV1>;

#[derive(Clone, Copy)]
enum EntryFirst { Arm, Demand, Payment, Post }

pub(crate) struct LogicalOutputEntryV1 {
    arm: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    demand: Option<Result<ResourceVector, LogicalOutputFundingErrorV1>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    post: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    first: Option<EntryFirst>,
    entered: bool,
}

impl LogicalOutputEntryV1 {
    pub(crate) const fn new() -> Self {
        Self { arm: None, demand: None, payment: None, post: None, first: None, entered: false }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            EntryFirst::Arm => self.arm.as_ref()?.as_ref().err().map(|error| error as _),
            EntryFirst::Demand => self.demand.as_ref()?.as_ref().err().map(|error| error as _),
            EntryFirst::Payment => self.payment.as_ref()?.as_ref().err().map(|error| error as _),
            EntryFirst::Post => self.post.as_ref()?.as_ref().err().map(|error| error as _),
        }
    }

    pub(crate) fn prepare(
        &mut self,
        lifecycle: &mut Loan<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        demand: Result<ResourceVector, LogicalOutputFundingErrorV1>,
    ) -> bool {
        if self.entered { return false; }
        self.entered = true;
        self.arm = Some(lifecycle.arm_operation_observation_post_v1(session, socket));
        if !matches!(self.arm, Some(Ok(()))) { self.first = Some(EntryFirst::Arm); return false; }
        self.demand = Some(demand);
        if let Some(Ok(demand)) = self.demand.as_ref() {
            self.payment = Some(lifecycle.reserve_domain_additional_v1(session, socket, *demand));
            if !matches!(self.payment, Some(Ok(()))) { self.first = Some(EntryFirst::Payment); }
        } else { self.first = Some(EntryFirst::Demand); }
        self.first.is_none()
    }

    pub(crate) fn finish(&mut self, lifecycle: &mut Loan<'_, '_>,
        session: &aos_sandbox::Journal, socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        if matches!(self.arm, Some(Ok(()))) && self.post.is_none() {
            self.post = Some(lifecycle.finish_operation_observation_post_v1(session, socket));
            if !matches!(self.post, Some(Ok(()))) { self.first.get_or_insert(EntryFirst::Post); }
        }
    }
}

pub(crate) struct LogicalOutputNativeOriginalV1 {
    clocks: [Clock; 5],
    samples: [Option<Result<RawPairedClockSample, LogicalClockErrorV1>>; 5],
    before: Option<Result<(), StorageServiceError>>,
    action: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    after: [currentness::StorageOutputOwedAfterV1; 2],
    prepared: [Option<Result<(), StorageServiceError>>; 2],
    finished: [Option<Result<(), StorageServiceError>>; 2],
    post: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
}

impl LogicalOutputNativeOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            clocks: std::array::from_fn(|_| Clock::default()), samples: std::array::from_fn(|_| None),
            before: None, action: None,
            after: std::array::from_fn(|_| currentness::StorageOutputOwedAfterV1::new()),
            prepared: [None, None], finished: [None, None], post: None,
        }
    }

    pub(crate) fn receiving_demand_v1(
        state: ResourceVector,
        output: &StorageExecutionOutputCustodyV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        host: Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1>,
    ) -> Result<ResourceVector, LogicalOutputFundingErrorV1> {
        let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let artifacts = request.authorization().ok_or(LogicalOutputFundingErrorV1::Closed)?;
        let authorization = crate::authorization::receiving_authorization_memory_v1(artifacts)?;
        let packet = request.canonical_packet().len()
            .checked_add(host.map_or(0, |outcome| outcome.canonical_packet().len()))
            .and_then(|bytes| bytes.checked_mul(4)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let clocks = Clock::dominant_requested_bytes_v1().and_then(|bytes| bytes.checked_mul(5))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(1024usize.checked_mul(4)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(overflow)?;
        let files = u64::try_from(Clock::MAXIMUM_RETAINED_FILES_V1).ok()
            .and_then(|files| files.checked_mul(5))
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
        let memory = authorization.checked_add(packet).and_then(|bytes| bytes.checked_add(clocks))
            .ok_or_else(overflow)?;
        let demand = state.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::OpenFiles, files))?;
        if request.method() == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT {
            Ok(demand.checked_add(output.ledger().original_reservation_receiving_demand_v1()?)?)
        } else { Ok(demand) }
    }

    pub(crate) fn clock_failure(&self, index: usize) -> Option<&(dyn std::error::Error + 'static)> {
        self.clocks.get(index)?.failure().or_else(||
            self.samples.get(index)?.as_ref()?.as_ref().err().map(|error| error as _))
    }

    pub(crate) fn custody_failure(&self, index: usize) -> Option<&(dyn std::error::Error + 'static)> {
        match index {
            0 => self.before.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
                .or_else(|| self.action.as_ref()?.as_ref().err().map(|error| error as _))
                .or_else(|| self.after[0].failure()),
            1 => self.after[0].failure().or_else(|| self.after[1].failure()),
            2 => self.after[1].failure(),
            _ => None,
        }
    }

    pub(crate) fn post_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.post.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
            .or_else(|| self.after[0].failure()).or_else(|| self.after[1].failure())
    }

    pub(crate) fn finish_owed_v1(&mut self, output: &StorageExecutionOutputCustodyV1,
        lifecycle: &mut Loan<'_, '_>, session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        // Every positively armed destination is attempted independently. No
        // new observer or payment is entered from this failure path.
        for index in 0..2 {
            if matches!(self.prepared[index], Some(Ok(()))) && self.finished[index].is_none() {
                self.finished[index] = Some(output.finish_owed_after_receiving_v1(lifecycle, &mut self.after[index]));
            }
        }
        if matches!(self.action, Some(Ok(()))) && self.post.is_none() {
            self.post = Some(lifecycle.finish_operation_observation_post_v1(session, socket));
        }
    }
}

pub(crate) enum OriginalOutputIntervalV1<'loan, 'cut, 'original> {
    Ordinary,
    Lifecycle {
        lifecycle: &'loan mut Loan<'cut, 'original>,
        session: &'loan aos_sandbox::Journal,
        socket: &'loan aos_sandbox_linux::seqpacket::SeqpacketSocket,
        original: &'loan mut LogicalOutputNativeOriginalV1,
    },
}

impl OriginalOutputIntervalV1<'_, '_, '_> {
    pub(crate) fn clock(&mut self, index: usize) -> Result<RawPairedClockSample, crate::StorageRuntimeError> {
        match self {
            Self::Ordinary => crate::runtime::trusted_paired_clock_sample(),
            Self::Lifecycle { original, .. } => {
                let Some(clock) = original.clocks.get_mut(index) else { return Err(crate::StorageRuntimeError::Recovery); };
                let Some(slot) = original.samples.get_mut(index) else { return Err(crate::StorageRuntimeError::Recovery); };
                if slot.is_some() { return Err(crate::StorageRuntimeError::Recovery); }
                *slot = Some(clock.observe_once(None));
                match slot { Some(Ok(sample)) => Ok(*sample), _ => Err(crate::StorageRuntimeError::Recovery) }
            }
        }
    }

    pub(crate) fn custody(&mut self, output: &mut StorageExecutionOutputCustodyV1, root: &Path, index: usize)
        -> Result<(), StorageServiceError>
    {
        match self {
            Self::Ordinary => output.recheck(root),
            Self::Lifecycle { lifecycle, session, socket, original } => {
                if index == 0 {
                    original.before = Some(output.recheck_session_receiving_v1(lifecycle, session, socket));
                    if !matches!(original.before, Some(Ok(()))) { return Err(invalid("initial logical Output custody failed")); }
                    original.action = Some(lifecycle.arm_operation_observation_post_v1(session, socket));
                    if !matches!(original.action, Some(Ok(()))) { return Err(invalid("logical Output action observation is not armed")); }
                    original.prepared[0] = Some(output.prepare_owed_after_receiving_v1(lifecycle, session, socket, &mut original.after[0]));
                    if !matches!(original.prepared[0], Some(Ok(()))) { return Err(invalid("final logical Output custody is not armed")); }
                } else {
                    let previous = index - 1;
                    if previous >= 2 || !matches!(original.prepared[previous], Some(Ok(())))
                        || original.finished[previous].is_some()
                    { return Err(invalid("logical Output custody destination is closed")); }
                    original.finished[previous] = Some(output.finish_owed_after_receiving_v1(lifecycle, &mut original.after[previous]));
                    if !matches!(original.finished[previous], Some(Ok(()))) { return Err(invalid("logical Output custody changed")); }
                    if index == 1 {
                        // Only a complete positive Output sample can release
                        // the shared native peak before response readback.
                        original.prepared[1] = Some(output.prepare_owed_after_receiving_v1(lifecycle, session, socket, &mut original.after[1]));
                        if !matches!(original.prepared[1], Some(Ok(()))) { return Err(invalid("response Output custody is not armed")); }
                    }
                }
                Ok(())
            }
        }
    }
}
