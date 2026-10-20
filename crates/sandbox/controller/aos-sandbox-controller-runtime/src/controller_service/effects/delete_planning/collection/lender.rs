//! Lends full initial-planning preimages from the same retained six originals.
//!
//! A completed historical collection cannot grant fresh preaccept. This short
//! loan additionally rechecks its genuine same Root/default-local Runtime owner
//! under the same still-held authorized Source/C17 and original Root horizon.

use super::*;
mod pending;
use aos_sandbox_protocol::domain_ledger::{delete_batch::DeleteBatchOwnerCutDataV2,
    delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2};

/// Borrows all original initial-planning preimages without an adoption factory.
///
/// Root must independently verify them, while a later preaccept phase must
/// collect fresh actual six owners under its new genuine pending challenge.
pub(in crate::controller_service) struct ControllerDeleteInitialSixPlanningLoanV2<'borrow, 'cache> {
    sessions: [DeleteSessionInventoryCutDataV2<'borrow>; 4],
    negotiated: [aos_sandbox_broker_session_security::controller_composition::DeleteInventoryNegotiatedPreimagesV2<'borrow>; 4],
    cache: &'borrow aos_sandbox_controller_domain::cache_residency::CacheDeleteInventoryOriginalV1<'cache>,
    transfer: ControllerDeleteTransferPlanningLoanV2<'borrow>,
    cuts: [DeleteBatchOwnerCutDataV2; 6],
    initial: [u8; 32],
    // Entered refusal stays beside every real planning original and the same
    // exclusive Session writer interval through the independent outer post.
    candidate: Option<Result<aos_sandbox_controller_domain::ControllerDeleteCandidateOriginalV2,
        ResourceReservationErrorV1>>,
}

impl<'borrow, 'cache> ControllerDeleteInitialSixPlanningLoanV2<'borrow, 'cache> {
    /// Borrows complete signed packets plus native/protected/model coordinates.
    pub(in crate::controller_service) fn sessions_v2(&self) -> &[DeleteSessionInventoryCutDataV2<'borrow>; 4] {
        &self.sessions
    }

    /// Borrows both actual Hello packets, checked history, context and fixed paths.
    pub(in crate::controller_service) fn negotiated_sessions_v2(&self) -> &[aos_sandbox_broker_session_security::controller_composition::DeleteInventoryNegotiatedPreimagesV2<'borrow>; 4] {
        &self.negotiated
    }

    /// Borrows the same Cache five-journal/physical/reducer original.
    pub(in crate::controller_service) fn cache_v2(&self)
        -> &aos_sandbox_controller_domain::cache_residency::CacheDeleteInventoryOriginalV1<'cache>
    {
        self.cache
    }

    /// Borrows actual original Root planning Open/Challenge and full native/trust reply.
    pub(in crate::controller_service) fn planning_root_v2(&self) -> (
        &aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningOpenDataV3,
        &aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningChallengeDataV3,
        &[u8; aos_sandbox_protocol::domain_ledger::delete_root::planning::DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2],
    ) {
        self.transfer.canonical_planning_preimages_v2()
    }

    /// Borrows the exact six canonical descriptor DATA in fixed lifecycle order.
    pub(in crate::controller_service) fn cuts_v2(&self) -> &[DeleteBatchOwnerCutDataV2; 6] { &self.cuts }

    /// Returns the same tagged full initial-Six commitment.
    pub(in crate::controller_service) fn initial_six_v2(&self) -> [u8; 32] { self.initial }
}

impl<'sessions, 'cache, 'profile> ControllerDeletePlanningCollectionV2<'sessions, 'cache, 'profile> {
    /// Lends only this actual completed collection with a fresh same-Root gate.
    ///
    /// An invalid/repeated/expired borrow terminates after the same prearmed
    /// Source/C17 after, with the entire refused frame and original cause held.
    pub(in crate::controller_service) fn borrow_initial_planning_once_v2<'borrow>(
        &'borrow mut self,
        fields: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> ControllerDeleteInitialSixPlanningLoanV2<'borrow, 'cache> {
        self.planning_lender = Some((|| {
            if !self.complete || self.outer_after.is_some() || self.planning_lender.is_some()
                || !std::ptr::eq(profile, fields.profile.as_ref()) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if !matches!(self.planning_lender, Some(Ok(()))) {
            self.finish_failed_outer_v2(authorized, bank, controller, profile);
        }
        let cuts = match self.owner_cuts_data_v2() {
            Ok(cuts) => cuts,
            Err(_) => {
                self.planning_lender = Some(Err(ResourceReservationErrorV1::Conflict));
                self.finish_failed_outer_v2(authorized, bank, controller, profile);
            }
        };
        let initial = match self.initial_six.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(initial) => initial,
            None => {
                self.planning_lender = Some(Err(ResourceReservationErrorV1::Conflict));
                self.finish_failed_outer_v2(authorized, bank, controller, profile);
            }
        };
        let sessions = (|| Ok::<_, ResourceReservationErrorV1>([
            session_preimage_from_originals_v2(&self.sessions, &self.broker_models, 0)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?,
            session_preimage_from_originals_v2(&self.sessions, &self.broker_models, 1)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?,
            session_preimage_from_originals_v2(&self.sessions, &self.broker_models, 2)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?,
            session_preimage_from_originals_v2(&self.sessions, &self.broker_models, 3)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?,
        ]))();
        let sessions = match sessions {
            Ok(sessions) => sessions,
            Err(cause) => {
                self.planning_lender = Some(Err(cause));
                self.outer_after = Some(bank.finish_delete_planning_source_failure_once_v1(authorized, controller, profile));
                std::process::abort();
            }
        };
        let negotiated = (|| Some([
            self.sessions[0].as_ref()?.negotiated_preimages_v2()?,
            self.sessions[1].as_ref()?.negotiated_preimages_v2()?,
            self.sessions[2].as_ref()?.negotiated_preimages_v2()?,
            self.sessions[3].as_ref()?.negotiated_preimages_v2()?,
        ]))();
        let negotiated = match negotiated {
            Some(negotiated) => negotiated,
            None => {
                self.planning_lender = Some(Err(ResourceReservationErrorV1::Conflict));
                self.outer_after = Some(bank.finish_delete_planning_source_failure_once_v1(authorized, controller, profile));
                std::process::abort();
            }
        };
        let cache = match self.cache.as_ref() {
            Some(cache) => cache,
            None => {
                self.planning_lender = Some(Err(ResourceReservationErrorV1::Conflict));
                self.outer_after = Some(bank.finish_delete_planning_source_failure_once_v1(authorized, controller, profile));
                std::process::abort();
            }
        };
        let transfer = match self.root.as_mut() {
            Some(root) => root.borrow_transfer_planning_v2(fields, authorized, bank, controller),
            None => Err(ResourceReservationErrorV1::Conflict),
        };
        let transfer = match transfer {
            Ok(transfer) => transfer,
            Err(cause) => {
                self.planning_lender = Some(Err(cause));
                self.outer_after = Some(bank.finish_delete_planning_source_failure_once_v1(authorized, controller, profile));
                std::process::abort();
            }
        };
        ControllerDeleteInitialSixPlanningLoanV2 {
            sessions, negotiated, cache, transfer, cuts, initial, candidate: None,
        }
    }
}
