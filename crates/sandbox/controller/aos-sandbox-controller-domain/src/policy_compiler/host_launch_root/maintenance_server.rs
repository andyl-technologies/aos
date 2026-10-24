//! Retains the actual distinct Maintenance Root purpose through its upper End.
//!
//! Unsigned DATA leaves the same purpose occupied. Only exact native31/fresh18,
//! rebuilt current models, strict EOF and every independent post can transfer
//! the whole graph into the existing Root native upper-disposal mechanism.

use super::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2;
use super::maintenance_native::{MaintenancePhaseV3, RootMaintenanceNativeOriginalV3};
use super::maintenance_final::RootMaintenanceFinalExchangeOriginalV3;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::NormalRootStartupErrorV1;
use crate::policy_compiler::RootCurrentPolicyInputDataV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use crate::policy_compiler::root_policy_prelude::RootMaintenanceStoragePreludeV3;
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::ResourceCompletionProofDataV2;

type Cause = Box<dyn std::error::Error>;
type Stop = crate::policy_compiler::create_storage_current::RootCreateStorageCurrentErrorV1;

#[derive(Clone, Copy)]
pub(super) enum MaintenanceFirstV3 { Opening, Native(MaintenancePhaseV3), Financial, Body(bool) }

/// Owns one genuine current Maintenance Storage Root purpose through final posts.
///
/// Construction consumes the whole actual purpose-specific native Prelude.
/// Incoming query, plan or proof DATA cannot manufacture this receiving owner.
pub struct RootMaintenanceStorageReceivingV3<'flight, 'listener, 'startup> {
    pub(super) prelude: RootMaintenanceStoragePreludeV3<'flight, 'listener, 'startup>,
    pub(super) opening: RootMaintenanceStorageOpeningOriginalV2,
    pub(super) peer: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) native: Option<Box<RootMaintenanceNativeOriginalV3>>,
    pub(super) unsigned: Option<Result<(), Cause>>,
    pub(super) final_result: Option<Result<(), Cause>>,
    pub(super) first: Option<MaintenanceFirstV3>,
    pub(super) negative: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) negative_disposition: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) closed: bool,
}

impl<'flight, 'listener, 'startup> RootMaintenanceStorageReceivingV3<'flight, 'listener, 'startup> {
    pub(crate) fn from_prelude_v3(prelude: RootMaintenanceStoragePreludeV3<'flight, 'listener, 'startup>) -> Self {
        Self { prelude, opening: Default::default(), peer: None, native: None, unsigned: None,
            final_result: None, first: None, negative: None, negative_disposition: None, closed: false }
    }

    /// Receives the current native subject and returns independently prepared31 DATA.
    ///
    /// # Errors
    /// Retains actual R payment, native currentness, canonical original, policy,
    /// lease, profile or unchanged-horizon refusals without disposing custody.
    pub fn receive_unsigned_once_v3(&mut self, policy: &RootCurrentPolicyInputDataV1<'_>) -> Result<(), Stop> {
        if self.peer.is_some() || self.closed {
            self.closed = true;
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        let root = &mut self.prelude.original;
        self.peer = Some(root.flight.admit_maintenance_storage_controller_peer_once_v2());
        if !matches!(self.peer, Some(Ok(()))) { self.finish_negative_inner(); return Err(Stop::Ready); }
        self.unsigned = Some((|| -> Result<(), Cause> {
            self.opening.admit_query_once_v2(&mut root.flight.maintenance_storage_stage_receiving_v2()?,
                std::mem::size_of::<RootMaintenanceNativeOriginalV3>())?;
            self.native = Some(Box::new(RootMaintenanceNativeOriginalV3::new()));
            super::maintenance_unsigned::receive_once_v3(&mut self.opening,
                self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?, root, policy)
        })());
        self.select_failure(false);
        let _owed = self.prelude.original.native.finish_opening_if_owed_v1();
        if !matches!(self.unsigned, Some(Ok(()))) || self.failure().is_some() {
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        Ok(())
    }

    /// Verifies actual31/fresh18 and final current cuts on the same Root stream.
    ///
    /// # Errors
    /// Retains changed proof, current assignment, signed policy, native cut,
    /// original deadline, EOF, post or final acknowledgement failures.
    pub fn receive_final_once_v3(&mut self, policy: &RootCurrentPolicyInputDataV1<'_>) -> Result<(), Stop> {
        if self.closed || !matches!(self.unsigned, Some(Ok(()))) || self.final_result.is_some()
            || self.failure().is_some() {
            self.closed = true;
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        let root = &mut self.prelude.original;
        let native = self.native.as_mut().ok_or(Stop::Ready)?;
        native.phase = MaintenancePhaseV3::Final;
        self.final_result = Some((|| -> Result<(), Cause> {
            let sample = native.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
            self.opening.require_current_clock_v1(sample)?;
            native.final_header_io.run_once(&mut root.original, &mut native.final_header,
                self.opening.current_cutoff_v1()?, DeadlineStreamDirectionV1::Read)?;
            let announced = ResourceCompletionProofDataV2::declared_bytes_v2(&native.final_header)?;
            let demand = RootMaintenanceFinalExchangeOriginalV3::receiving_demand_v3(root.flight, announced)?;
            root.flight.maintenance_storage_stage_receiving_v2()?.admit_maintenance_final_proof_once_v2(
                RootContinuationDemandV1::from_demand_v1(demand))?;
            let mut exchange = Box::new(RootMaintenanceFinalExchangeOriginalV3::new(&self.opening)?);
            let returned = exchange.run_once_v3(&self.opening, native, announced, root, policy);
            native.final_exchange = Some(exchange);
            returned?;
            Ok(())
        })());
        self.select_failure(true);
        if !matches!(self.final_result, Some(Ok(()))) || self.failure().is_some() {
            self.finish_negative_inner();
            return Err(Stop::Ready);
        }
        Ok(())
    }

    pub(crate) fn require_final_complete_v3(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.closed || self.failure().is_some() || !matches!(self.final_result, Some(Ok(())))
            || self.prelude.original.negative_disposition_entered_v1() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.native.as_ref().and_then(|native| native.final_exchange.as_ref())
            .ok_or(NormalRootStartupErrorV1::Service)?.require_complete_v3()
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    /// Runs all entered negative posts and the same original socket disposition.
    ///
    /// # Errors
    /// Retains original and later debt failures without positive native disposal.
    pub fn finish_negative_once_v3(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.finish_negative_inner();
        if matches!(self.negative_disposition, Some(Ok(()))) { Ok(()) }
        else { Err(NormalRootStartupErrorV1::Service) }
    }

    fn finish_negative_inner(&mut self) {
        if self.negative_disposition.is_some() { return; }
        let root = &mut self.prelude.original;
        let _owed = root.native.finish_opening_if_owed_v1();
        if let Some(native) = self.native.as_mut() { native.finish_posts_once_v3(root.flight); }
        let already = self.native.as_ref().and_then(|native| native.final_exchange.as_ref())
            .is_some_and(|exchange| exchange.peer_post_entered_v3());
        if !already { self.negative = Some(root.flight.finish_maintenance_storage_controller_peer_posts_once_v2()); }
        self.negative_disposition = Some(root.finish_negative_once_v1());
    }

    /// Transfers the entire completed graph to the existing native Root finisher.
    ///
    /// # Errors
    /// Retains the offered graph on any upper End, post or disposal refusal.
    ///
    /// # Panics
    /// This function does not unwind. An impossible premature consuming transfer
    /// follows the Root finisher's process-fatal invariant after negative posts.
    pub fn finish_positive_once_v3(self) -> Result<(), NormalRootStartupErrorV1> {
        let (work, flight) = match self.into_completed_dispatch_v3() {
            Ok(value) => value,
            Err(mut original) => { let _owed = original.finish_negative_once_v3(); std::process::abort(); }
        };
        flight.finish_maintenance_storage_dispatch_once_v3(work)
    }

    fn select_failure(&mut self, final_turn: bool) {
        if self.first.is_some() { return; }
        let failed = if final_turn { matches!(self.final_result, Some(Err(_))) }
            else { matches!(self.unsigned, Some(Err(_))) };
        if !failed { return; }
        self.first = Some(if self.opening.failure().is_some() { MaintenanceFirstV3::Opening }
            else if self.native.as_ref().is_some_and(|native| native.failure().is_some()) {
                MaintenanceFirstV3::Native(self.native.as_ref().map_or(MaintenancePhaseV3::Opening, |native| native.phase))
            } else if self.prelude.original.flight.failure().is_some() { MaintenanceFirstV3::Financial }
            else { MaintenanceFirstV3::Body(final_turn) });
    }

    /// Borrows the original selected failure without decoding or native reentry.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let selected = match self.first {
            Some(MaintenanceFirstV3::Opening) => self.opening.failure(),
            Some(MaintenanceFirstV3::Native(phase)) => self.native.as_ref()?.phase_failure_v3(phase)
                .or_else(|| self.native.as_ref()?.clock.as_ref()?.failure()),
            Some(MaintenanceFirstV3::Financial) => self.prelude.original.flight.failure(),
            Some(MaintenanceFirstV3::Body(false)) => self.unsigned.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
            Some(MaintenanceFirstV3::Body(true)) => self.final_result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
            None => None,
        };
        self.prelude.original.native.failure_before_v1()
            .or_else(|| self.peer.as_ref()?.as_ref().err().map(|cause| cause as _)).or(selected)
            .or_else(|| self.prelude.original.native.failure_after_v1())
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| self.negative.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.negative_disposition.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}
