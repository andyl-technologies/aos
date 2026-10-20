//! Retains genuine Source/C18 and the same C writer through finite NoApply IO.
//!
//! Active entry borrows the original completed64/65 association, not copied
//! source/deadline DATA. Fresh cold cleanup has a separate current-control
//! Session purpose and does not enter through this active64 association.
//! The loan keeps concrete invariant Source lifetimes; no erased payer, detached
//! Session, callback or ready marker can construct the native loan.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::bounded_entropy::{EntropyError, RetainedKernelNonceOriginalV1};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_protocol::host_execution_no_apply::{
    BeforeArgumentNoApplySourceDataV2, ClosedHostTerminalArchiveDataV2,
    current_lease::CurrentHostNoApplyLeaseDataV2,
};

use super::public_admission::availability::native::ExecutionAvailabilitySessionNativeOriginalV2;
use super::*;

mod transport;
mod controller;
mod root_transport;
mod settlement;
mod completion;
mod cleanup;
pub use cleanup::ControllerExecutionNoApplyRecoveredMetadataV2;
pub use completion::{ControllerExecutionNoApplyCompletionV2, ControllerExecutionNoApplyDisposedOriginalV2,
    ControllerExecutionNoApplyTerminalRetirementV2};
pub(crate) use settlement::ControllerExecutionNoApplyAppendLoanV2;

/// Retains every reached finite NoApply prefix until genuine terminal disposal.
///
/// Construction is inert. Only its actual Source/C18 lender can fund and enter
/// the native prefix. There is no reset, owner-adoption or retirement factory.
pub struct ControllerExecutionNoApplyOriginalV2 {
    entered: bool,
    geometry: Option<Result<ResourceVector, crate::JournalError>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    association: Option<
        Result<(BeforeArgumentNoApplySourceDataV2, u64, [u8; 32]), ResourceReservationErrorV1>,
    >,
    native: Option<Box<Native>>,
    reentry: Option<ResourceReservationErrorV1>,
}

struct Native {
    cleanup: Option<Box<cleanup::CleanupOriginV2>>,
    session: ExecutionAvailabilitySessionNativeOriginalV2,
    io: crate::controller_resource_reservation::ExecutionNoApplyIoOriginalV2,
    nonce: [RetainedKernelNonceOriginalV1; 5],
    entropy: [Option<Result<[u8; 16], EntropyError>>; 5],
    source: BeforeArgumentNoApplySourceDataV2,
    cutoff: u64,
    host_session: [u8; 32],
    active: usize,
    terminal: Option<Result<ClosedHostTerminalArchiveDataV2, aos_sandbox_protocol::ProtocolValidationError>>,
    lease: Option<Result<CurrentHostNoApplyLeaseDataV2, aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodErrorV1>>,
    read_nonce: Option<[u8; 32]>,
    signed_current_outcome: Option<[u8; 32]>,
    current_outcome_packet: Option<Result<
        aos_sandbox_broker_session_protocol::projection::CanonicalBrokerResponseEnvelopeV1,
        aos_sandbox_broker_session_protocol::BrokerSessionProjectionError,
    >>,
    retirement_issued: bool,
    settlement: Option<Box<settlement::ControllerSettlementOriginalV2>>,
    settlement_geometry: Option<Result<ResourceVector, crate::JournalError>>,
    settlement_funding: Option<Result<(), ResourceReservationErrorV1>>,
    root_demand: ResourceVector,
    root_refusal: Option<ResourceReservationErrorV1>,
    controller_geometry: Option<Result<ResourceVector, crate::JournalError>>,
    controller_funding: Option<Result<(), ResourceReservationErrorV1>>,
    controller: Option<Box<controller::ControllerCutOriginalV2>>,
}

impl Native {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.cleanup.as_deref().and_then(|cleanup| error(&cleanup.acquisition_funding)
            .or_else(|| error(&cleanup.acquisition_fields)))
            .or_else(|| self.session
            .failure_v2()
            )
            .or_else(|| {
                self.nonce.iter().enumerate().find_map(|(index, nonce)| {
                    nonce.failure().or_else(|| error(&self.entropy[index]))
                })
            })
            .or_else(|| self.io.failure_v2())
            .or_else(|| error(&self.terminal))
            .or_else(|| error(&self.lease))
            .or_else(|| error(&self.current_outcome_packet))
            .or_else(|| error(&self.controller_geometry))
            .or_else(|| error(&self.controller_funding))
            .or_else(|| self.controller.as_deref().and_then(|original| original.failure()))
            .or_else(|| error(&self.settlement_geometry))
            .or_else(|| error(&self.settlement_funding))
            .or_else(|| self.settlement.as_deref().and_then(|original| original.failure()))
            .or_else(|| self.root_refusal.as_ref().map(|cause| cause as _))
    }
}

impl Default for ControllerExecutionNoApplyOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerExecutionNoApplyOriginalV2 {
    /// Constructs empty fixed custody without IO, funding or authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entered: false,
            geometry: None,
            funding: None,
            association: None,
            native: None,
            reentry: None,
        }
    }

    /// Borrows an active execution's actual Source/C18, C and64/65 association.
    ///
    /// The Security producer lends its actual private availability token and
    /// the actual continuously borrowed Host Session journal/socket/transcript.
    /// No accepted source, relative timeout or completed DATA can replace them.
    ///
    /// # Errors
    /// Retains reentry, funding, native Session, source or entropy failure.
    /// Failure never retires the already entered Source/C18 or SDK originals.
    pub fn borrow_active_no_apply_client_once_v2<'turn, 'source, 'original>(
        &'turn mut self,
        controller: &'turn mut Journal,
        bank: &'turn ControllerResourceBankOpeningV1,
        profile: &'turn ProductionControllerNormalRootProfileV1,
        receiving: &'turn mut ControllerExecutionReadReceivingLoanV1<'source, 'original>,
        association: &'turn ControllerExecutionAvailabilityPositiveRetirementV2,
        host_journal: &Journal,
        host_socket: &SeqpacketSocket,
        host_transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<
        ControllerExecutionNoApplyClientLoanV2<'turn, 'source, 'original>,
        ResourceReservationErrorV1,
    > {
        if self.entered {
            self.reentry
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.entered = true;
        self.geometry = Some(Self::fixed_demand_v2());
        let demand = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.funding = Some(receiving.admit_stage_v1(
            bank,
            controller,
            profile,
            Demand::from_demand_v1(demand),
        ));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.association = Some(
            association
                .no_apply_source_data_v2(controller, receiving.operation_v1())
                .and_then(|data| {
                    if data.2 != host_transcript.session_binding() {
                        return Err(ResourceReservationErrorV1::Conflict);
                    }
                    Ok(data)
                }),
        );
        let (source, cutoff, host_session) = self
            .association
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.native = Some(Box::new(Native {
            cleanup: None,
            session: ExecutionAvailabilitySessionNativeOriginalV2::new(),
            io: Default::default(),
            nonce: std::array::from_fn(|_| RetainedKernelNonceOriginalV1::new()),
            entropy: std::array::from_fn(|_| None),
            source,
            cutoff,
            host_session,
            active: 0,
            terminal: None,
            lease: None,
            read_nonce: None,
            signed_current_outcome: None,
            current_outcome_packet: None,
            retirement_issued: false,
            settlement: None,
            settlement_geometry: None,
            settlement_funding: None,
            root_demand: ResourceVector::ZERO,
            root_refusal: None,
            controller_geometry: None,
            controller_funding: None,
            controller: None,
        }));
        let native = self
            .native
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        native
            .session
            .capture_once_v2(host_journal, host_socket, host_transcript, true)?;
        native.entropy[0] = Some(native.nonce[0].observe_once());
        if !matches!(native.entropy[0], Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let base = *receiving.complete;
        Ok(ControllerExecutionNoApplyClientLoanV2 {
            native,
            reentry: &mut self.reentry,
            controller,
            bank,
            profile,
            source: Source::Active(receiving),
            base,
        })
    }

    fn fixed_demand_v2() -> Result<ResourceVector, crate::JournalError> {
        let bytes = size_of::<Self>()
            .checked_mul(2)
            .and_then(|n| n.checked_add(size_of::<Native>().checked_mul(2)?))
            .and_then(|n| {
                n.checked_add(
                    size_of::<ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|n| {
                n.checked_add(
                    RetainedKernelNonceOriginalV1::construction_bytes_v1()?.checked_mul(5)?,
                )
            })
            .and_then(|n| n.checked_add(size_of::<ControllerExecutionNoApplyTerminalRetirementV2>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<ControllerExecutionNoApplyDisposedOriginalV2>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<ControllerExecutionNoApplyCompletionV2>().checked_mul(2)?))
            // All five exact bounded command packets coexist with their
            // shared sender captures; later original geometry adds traffic.
            .and_then(|n| n.checked_add(8192_usize.checked_mul(20)?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(crate::JournalError::JournalTooLarge)?;
        ExecutionAvailabilitySessionNativeOriginalV2::fixed_demand_v2(true)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(crate::JournalError::ReceivingAccounting)
    }

    /// Borrows the actual reached cause without replacing any spent prefix.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.geometry)
            .or_else(|| error(&self.funding))
            .or_else(|| error(&self.association))
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

/// Holds the actual C writer and concrete live Source loan across each subturn.
///
/// The SDK must retain its same physical Host Session throughout this loan.
/// Every re-lent native part is checked against the original intrinsic owner
/// and socket cookie. No method supplies a detached prepared or ready token.
#[must_use]
pub struct ControllerExecutionNoApplyClientLoanV2<'turn, 'source, 'original> {
    native: &'turn mut Native,
    reentry: &'turn mut Option<ResourceReservationErrorV1>,
    controller: &'turn mut Journal,
    bank: &'turn ControllerResourceBankOpeningV1,
    profile: &'turn ProductionControllerNormalRootProfileV1,
    source: Source<'turn, 'source, 'original>,
    base: ResourceVector,
}

// Both arms retain the same concrete financial/native borrower. Cleanup owns
// the actual fresh split; active entry reborrows its existing Environment split.
enum Source<'turn, 'source, 'original> {
    Active(&'turn mut ControllerExecutionReadReceivingLoanV1<'source, 'original>),
    Cleanup(ControllerExecutionReadReceivingLoanV1<'source, 'original>),
}

impl<'source, 'original> std::ops::Deref for Source<'_, 'source, 'original> {
    type Target = ControllerExecutionReadReceivingLoanV1<'source, 'original>;

    fn deref(&self) -> &Self::Target {
        match self { Self::Active(source) => source, Self::Cleanup(source) => source }
    }
}

impl std::ops::DerefMut for Source<'_, '_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self { Self::Active(source) => source, Self::Cleanup(source) => source }
    }
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    fn native(&self) -> Result<&Native, ResourceReservationErrorV1> {
        if self.reentry.is_some() || self.native.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(self.native)
    }

    /// Borrows this entered prefix's original retained cause.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.native
            .failure()
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn require_transport_current_v2(
        &mut self,
    ) -> Result<(), ResourceReservationErrorV1> {
        let complete = *self.source.complete;
        self.require_transport_complete_v2(complete)
    }

    pub(crate) fn require_transport_complete_v2(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.bank.require_execution_source_read_complete_v1(
            &mut self.source.receiving,
            self.controller,
            self.profile,
            Demand::from_demand_v1(complete),
        )?;
        *self.source.complete = self.source.complete.componentwise_max(complete);
        Ok(())
    }

    pub(crate) fn complete_transport_base_v2(
        &mut self,
        incoming: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.base
            .checked_add(self.native()?.io.retained_demand_v2()?)?
            .checked_add(self.native()?.root_demand)?
            .checked_add(incoming)
            .map_err(Into::into)
    }
}
