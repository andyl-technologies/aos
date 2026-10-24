//! Borrows the genuine authorized Recover for passive Stop cleanup observation.
//!
//! The same financial and native engine funds the exact Host 1/3 cold Session.
//! Source dispatch provenance is required before lending. This original loan
//! permits observation only; completed Recover cannot authorize a later Stop.

use super::*;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::{ControllerInitialBrokerSessionReceivingV1, ControllerInitialBrokerSessionShapeV1};

/// Holds the actual kind-2 Recover, Source comparison and Controller borrower.
#[doc(hidden)]
pub struct OperatorStopCleanupObservationLoanV1<'owner, 'controller> {
    pub(super) inner: OperatorCreateRecoveryLoanV1<'owner, 'controller>,
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Lends the actual current Stop observation after exact Source binding.
    ///
    /// # Errors
    /// Refuses changed target, C/Source, authorization, horizon or native debt.
    #[doc(hidden)]
    pub fn borrow_stop_cleanup_observation_v1<'owner, 'controller>(
        &'owner mut self,
        controller: &'controller mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<OperatorStopCleanupObservationLoanV1<'owner, 'controller>, ResourceReservationErrorV1> {
        self.stop_dispatch_source_data_v1(controller, source)?;
        if !matches!(self.horizon, Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
        let inner = OperatorCreateRecoveryLoanV1 { owner: self, controller };
        inner.require_current_v1()?;
        Ok(OperatorStopCleanupObservationLoanV1 { inner })
    }
}

impl OperatorStopCleanupObservationLoanV1<'_, '_> {
    /// Rejoins the actual current Recover and its exact pending admission.
    ///
    /// # Errors
    /// Refuses changed native, authorization, target or admission custody.
    pub fn require_current_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        self.inner.require_current_v1()
    }

    /// Adds actual co-resident cold representation before its allocation.
    ///
    /// # Errors
    /// Retains arithmetic, capacity and currentness refusals on the same payer.
    pub fn reserve_additional_v1(&mut self, additional: ResourceVector)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.inner.reserve_additional_v1(additional)
    }

    /// Checks the original capability deadline before a cold frontier.
    ///
    /// # Errors
    /// Retains clock, boot, provenance, cutoff and wall-expiry refusals.
    pub fn check_frontier_v1(&mut self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.inner.check_frontier_v1()
    }

    /// Runs an independently owed clock post after an entered cold body.
    ///
    /// # Errors
    /// Retains the actual prepaid observation and clock refusal.
    pub fn observe_owed_clock_after_once_v1(&mut self)
        -> Result<RawPairedClockSample, ResourceReservationErrorV1>
    {
        self.inner.observe_owed_clock_after_once_v1()
    }

    /// Prepares the actual Host receiver with its finite cleanup funding mark.
    ///
    /// # Errors
    /// Retains reentry, representation and actual native preparation refusal.
    pub fn prepare_session_once_v1(&mut self, shape: ControllerInitialBrokerSessionShapeV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.require_current_v1()?;
        self.check_frontier_v1()?;
        let nonce = self.inner.owner.stop_cleanup_nonce.observe_once();
        self.inner.owner.latch_primary_failure_v1();
        nonce.map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.inner.prepare_recovery_session_once_v2(shape, true)
    }

    /// Moves the same genuinely prepared receiver into the SDK cold owner.
    ///
    /// # Errors
    /// Refuses unprepared, failed, expired or already moved custody.
    pub fn take_session_receiver_once_v1(&mut self)
        -> Result<ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1>
    {
        self.inner.take_storage_session_receiver_once_v1()
    }

    /// Retains a negative SDK marker without manufacturing a completion.
    pub fn retain_sdk_refusal_once_v1(&mut self) {
        self.inner.retain_storage_sdk_refusal_once_v1();
    }

    /// Borrows the actual selected original failure.
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.owner.failure_v1()
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Observes the current full Source and its exact A7 under this Recover.
    ///
    /// # Errors
    /// Retains wrong purpose, original authorization, Source, native or clock
    /// failure; no Session or Root connection is opened by this method.
    #[doc(hidden)]
    pub fn observe_stop_cleanup_source_once_v1(
        &mut self,
        controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.recovery_purpose_data_v1(controller)?
            != aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::StopCleanup
            || !matches!(self.horizon, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        OperatorCreateRecoveryLoanV1 { owner: self, controller }.observe_source_once_v1(source)
    }
}

impl<'owner, 'controller> OperatorStopCleanupObservationLoanV1<'owner, 'controller> {
    /// Joins the sole decoded Host3 body to this actual completed native query.
    ///
    /// This comparison exposes no journal, Source writer or effect permission.
    /// Its caller retains the genuine Session and every completed SDK original.
    ///
    /// # Errors
    /// Refuses changed authority/Source, another native query or decoded body,
    /// missing cleanup entropy or an aliased passive query/cleanup identifier.
    #[doc(hidden)]
    pub fn require_completed_inventory_data_v1(
        &mut self,
        source: &ProtectedSourceDomainJournalOwnerV1,
        journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        decoded: &aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        use sha2::{Digest as _, Sha256};

        self.require_current_v1()?;
        self.inner.owner.source.require_current_identity_v2(source)?;
        let method = aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
        let (request, _) = self.inner.owner.storage
            .require_stop_cleanup_inventory_data_v1(journal, outcome)?;
        let cleanup = self.inner.owner.stop_cleanup_nonce.value()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        if request == *cleanup || decoded.method_v2() != method
            || decoded.body_digest_v2() != <[u8; 32]>::from(Sha256::digest(exact_body))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.inner.owner.stop_cleanup_observation.selected.is_some() {
            self.inner.owner.stop_cleanup_observation.repeated.get_or_insert(ResourceReservationErrorV1::Conflict);
            self.inner.owner.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.inner.owner.stop_cleanup_observation.selected = Some((|| {
            use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryModelDataV2;
            let ControllerInventoryModelDataV2::Host(inventory) = decoded.model_v2() else {
                return Err(ResourceReservationErrorV1::Conflict);
            };
            let comparison = StopCleanupHostComparisonDataV1::select(inventory, request)?;
            Ok(StopCleanupObservationReceiptV1 {
                request,
                session: outcome.request().session_binding(),
                signed_request: Sha256::digest(outcome.request().canonical_packet()).into(),
                answer: Sha256::digest(outcome.canonical_packet()).into(),
                body: decoded.body_digest_v2(),
                comparison,
            })
        })());
        self.inner.owner.latch_primary_failure_v1();
        self.inner.owner.stop_cleanup_observation.selected().map(|_| ())
    }

    /// Borrows the sole paid passive Host3 query of this exact Stop Session.
    ///
    /// # Errors
    /// Refuses another completed cold original, expired authority, reentry,
    /// missing native preparation or incomplete same-payer receiving bounds.
    pub fn borrow_inventory_once_v1<'query>(
        &'query mut self,
        receiving: &ControllerInitialBrokerSessionReceivingV1,
        journal: &Journal,
        shape: crate::DeleteInventorySecurityShapeDataV1,
    ) -> Result<ControllerRecoveryInventoryLoanV2<'query, 'owner, 'controller, 'static, 'static>,
        ResourceReservationErrorV1>
    {
        self.require_current_v1()?;
        storage::inventory::RecoveryInventorySourceV2::StopCleanup(self)
            .begin_query_v2(receiving, journal, shape)
    }
}


/// Retains finite sole-decoder comparison DATA beside its actual native query.
pub(super) struct StopCleanupObservationOriginalV1 {
    selected: Option<Result<StopCleanupObservationReceiptV1, ResourceReservationErrorV1>>,
    repeated: Option<ResourceReservationErrorV1>,
}

impl Default for StopCleanupObservationOriginalV1 {
    fn default() -> Self { Self { selected: None, repeated: None } }
}

impl StopCleanupObservationOriginalV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.selected.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }

    pub(super) fn selected(&self) -> Result<&StopCleanupObservationReceiptV1, ResourceReservationErrorV1> {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.selected.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}

pub(super) enum StopCleanupHostComparisonDataV1 {
    Pending(aos_sandbox_protocol::host_stop_cleanup_candidate::HostStopCleanupCandidateDataV1),
    Dispatched(aos_sandbox_protocol::host_launch_cleanup_candidate::HostLaunchCleanupCandidateDataV1),
    Recovered(aos_sandbox_protocol::host_recovered_namespace::HostRecoveredNamespaceDataV7),
    Lineage(aos_sandbox_protocol::host_cleanup_lineage::HostCleanupLineageDataV1),
}

pub(super) struct StopCleanupObservationReceiptV1 {
    pub(super) request: [u8; 16],
    pub(super) session: [u8; 32],
    pub(super) signed_request: [u8; 32],
    pub(super) answer: [u8; 32],
    pub(super) body: [u8; 32],
    pub(super) comparison: StopCleanupHostComparisonDataV1,
}

impl StopCleanupHostComparisonDataV1 {
    fn select(
        inventory: &aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse,
        request: [u8; 16],
    ) -> Result<Self, ResourceReservationErrorV1> {
        use aos_sandbox_protocol::{
            host_stop_cleanup_candidate::HostStopCleanupCandidateDataV1 as Pending,
            host_launch_cleanup_candidate::HostLaunchCleanupCandidateDataV1 as Dispatched,
            host_recovered_namespace::HostRecoveredNamespaceDataV7 as Recovered,
            host_cleanup_lineage::HostCleanupLineageDataV1 as Lineage,
        };
        let rejected = || ResourceReservationErrorV1::Conflict;
        if !inventory.__buffa_unknown_fields.is_empty() { return Err(rejected()); }
        let selected = if !inventory.cleanup_lineages_v1.is_empty() {
            Self::Lineage(Lineage::from_inventory_v1(inventory).map_err(|_| rejected())?.ok_or_else(rejected)?)
        } else if !inventory.recovered_namespaces_v7.is_empty() {
            Self::Recovered(Recovered::from_inventory_v7(inventory).map_err(|_| rejected())?.ok_or_else(rejected)?)
        } else if inventory.present_stop_cleanup_candidates_v1.first()
            .is_some_and(|row| row.starts_with(b"AOSHLC10"))
        {
            Self::Dispatched(Dispatched::from_inventory_v1(inventory).map_err(|_| rejected())?.ok_or_else(rejected)?)
        } else {
            Self::Pending(Pending::from_inventory_v1(inventory).map_err(|_| rejected())?.ok_or_else(rejected)?)
        };
        let observed = match &selected {
            Self::Pending(row) => row.request_id_v1(),
            Self::Dispatched(row) => row.request_id_v1(),
            Self::Recovered(row) => row.observation_v7().request_id_v5(),
            Self::Lineage(row) => row.observation_v1().request_id_v5(),
        };
        if *observed != request { return Err(rejected()); }
        Ok(selected)
    }
}
