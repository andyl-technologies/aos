//! Binds each sole decoded model to its actual completed native query.
//!
//! These fixed comparison receipts cannot stand in for the maintenance's
//! current Source/C scope, native afters or cold population conjunction. The
//! native inventory owner must already have physically disposed its positive
//! IO prefix on the same held Session Journal before any receipt is stored.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use sha2::{Digest as _, Sha256};

struct CompletedInventoryModelDataV2 {
    request_id: [u8; 16],
    request_packet_digest: [u8; 32],
    body_digest: [u8; 32],
    method: BrokerMethod,
}

pub(super) struct CatalogMaintenanceInventoryEvidenceV2 {
    queries: [Option<Result<CompletedInventoryModelDataV2, ResourceReservationErrorV1>>; 4],
    repeated: Option<ResourceReservationErrorV1>,
}

impl CatalogMaintenanceInventoryEvidenceV2 {
    pub(super) fn new() -> Self {
        Self {
            queries: std::array::from_fn(|_| None),
            repeated: None,
        }
    }

    pub(super) fn require_model_v2(
        &self,
        index: usize,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        decoded: &ControllerInventoryDecodedOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        let held = self
            .queries
            .get(index)
            .and_then(Option::as_ref)
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        if self.repeated.is_some()
            || held.request_id != outcome.request().request_id()
            || held.request_packet_digest
                != <[u8; 32]>::from(Sha256::digest(outcome.request().canonical_packet()))
            || held.body_digest != <[u8; 32]>::from(Sha256::digest(exact_body))
            || held.body_digest != decoded.body_digest_v2()
            || held.method != outcome.method()
            || held.method != decoded.method_v2()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn failure_v2(&self, index: usize) -> Option<&(dyn Error + 'static)> {
        self.repeated.as_ref().map(|cause| cause as _).or_else(|| {
            self.queries
                .get(index)?
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _)
        })
    }
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Retains the exact decoder/native comparison after positive IO disposal.
    ///
    /// The SDK calls this while its opaque completed borrower still owns the
    /// same receiver and mutable Session. The supplied immutable model has a
    /// private sole-decoder constructor; a caller-built empty model cannot be
    /// substituted for the actual authenticated body.
    ///
    /// # Errors
    /// Refuses another ordinal, repeated comparison, changed current scope,
    /// unpaid or incomplete native query, another Journal or substituted body.
    #[doc(hidden)]
    pub fn retain_inventory_model_once_v2(
        &mut self,
        index: usize,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        decoded: &ControllerInventoryDecodedOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        if index >= self.owner.inventory.len()
            || self.owner.inventory_evidence.queries[index].is_some()
        {
            self.owner
                .inventory_evidence
                .repeated
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            self.owner
                .first
                .get_or_insert(First::InventoryEvidence(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let returned = (|| {
            let (_, method) =
                super::super::operator_create_recovery::storage::inventory::maintenance_context_v2(
                    index,
                )?;
            self.owner.inventory[index]
                .require_completed_inventory_data_v2(journal, outcome, method, false)?;
            let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
            else {
                return Err(ResourceReservationErrorV1::Conflict);
            };
            let body_digest: [u8; 32] = Sha256::digest(exact_body).into();
            if decoded.method_v2() != method || decoded.body_digest_v2() != body_digest {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(CompletedInventoryModelDataV2 {
                request_id: outcome.request().request_id(),
                request_packet_digest: Sha256::digest(outcome.request().canonical_packet()).into(),
                body_digest,
                method,
            })
        })();
        self.owner.inventory_evidence.queries[index] = Some(returned);
        if !matches!(self.owner.inventory_evidence.queries[index], Some(Ok(_))) {
            self.owner
                .first
                .get_or_insert(First::InventoryEvidence(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        Ok(())
    }
}
