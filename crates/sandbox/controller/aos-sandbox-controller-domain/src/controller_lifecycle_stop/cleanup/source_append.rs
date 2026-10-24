//! Joins the actual Source22 payer, final Host3 query and held Root completion.
//!
//! This private constructor lends no journal or generic mutation authority.
//! Its returned original still borrows the actual SDK and Root owners; only
//! the separately closed A8 append may consume their completed evidence.

use super::*;
mod authorization;
mod append;
pub(crate) use authorization::StopCleanupSourceAppendAuthorizationV1;
pub use append::StopCleanupSourceAppendOriginalV1;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSourceAffinityV1;
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    outcome_capture::{ControllerInventoryDecodedOriginalV2, ControllerInventoryModelDataV2},
};
use aos_sandbox_protocol::domain_ledger::stop_completion::{
    LifecycleStopCompletionBindingDataV1, LifecycleStopCompletionDataV1,
    LifecycleStopCompletionEvidenceDataV1,
};
use crate::normal_root::{RootStopCleanupClientClosedV1, RootStopCleanupClientCompletedBorrowV1};
use sha2::{Digest as _, Sha256};

/// Preserves the actual provider refusal at the closed completion join.
#[derive(Debug, thiserror::Error)]
pub enum StopCleanupCompletionErrorV1 {
    /// Retains the genuine Source22 receiving or native inventory cause.
    #[error(transparent)]
    Receiving(#[from] ResourceReservationErrorV1),
    /// Retains the actual protected Source identity or historical model cause.
    #[error(transparent)]
    Source(#[from] crate::JournalError),
    /// Retains a malformed canonical Host or completion comparison.
    #[error(transparent)]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    /// Retains refusal by the actual held Root exchange original.
    #[error(transparent)]
    Root(#[from] RootStopCleanupClientClosedV1),
    /// Refuses another subject, native query, packet or Source association.
    #[error("Stop cleanup completion association refused")]
    Association,
}

type CompletionResult<T> = std::result::Result<T, StopCleanupCompletionErrorV1>;

/// Retains genuine final-query and Root evidence for one same-Source A8 append.
///
/// The financial affinity comes from the actual funded Source22 owner. Root
/// and SDK references keep their native completion owners alive. No public
/// constructor accepts completion DATA or a digest in place of those owners.
#[doc(hidden)]
#[must_use = "retain the actual SDK and Root owners through A8 readback"]
pub struct StopCleanupCompletionOriginalV1<'held> {
    root: RootStopCleanupClientCompletedBorrowV1<'held>,
    session: &'held Journal,
    outcome: &'held AuthenticatedBrokerMethodOutcomeV1,
    decoded: &'held ControllerInventoryDecodedOriginalV2,
    affinity: ControllerStopCleanupSourceAffinityV1,
    source: crate::journal::source_provisioning::SourceProvisioningIdentityV1,
    subject: Subject,
    data: LifecycleStopCompletionDataV1,
    historical: crate::lifecycle::LifecycleRecordDigestV1,
    fence: crate::lifecycle::LiveRuntimeFenceV1,
    expiry: i64,
    cutoff: u64,
}

impl<'owner, 'source> ControllerHostStopCleanupSourceLoanV1<'owner, 'source> {
    /// Borrows completion only from the actual second native Host3 and Root48.
    ///
    /// Both observed and executed cleanup require independently issued query
    /// index1. This rechecks its already registered native model and immutable
    /// five-tuple; it never repeats registration or adopts a decoded receipt.
    ///
    /// # Errors
    /// Retains provider, financial, Source identity or exact evidence refusal.
    #[doc(hidden)]
    pub fn borrow_stop_cleanup_completion_once_v1<'held>(
        &mut self,
        controller: &Journal,
        root: RootStopCleanupClientCompletedBorrowV1<'held>,
        session: &'held Journal,
        outcome: &'held AuthenticatedBrokerMethodOutcomeV1,
        decoded: &'held ControllerInventoryDecodedOriginalV2,
    ) -> CompletionResult<StopCleanupCompletionOriginalV1<'held>> {
        if self.original()?.completion_entered {
            held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.reentry.get_or_insert(CLOSED);
            return Err(CLOSED.into());
        }
        held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.completion_entered = true;
        // Pay the compiled carrier and its actual native affinity before
        // capturing either. Packet/model bodies remain in their paid SDK owner.
        let bytes = std::mem::size_of::<StopCleanupCompletionOriginalV1<'held>>()
            .checked_mul(3).and_then(|n| u64::try_from(n).ok()).ok_or(CLOSED)?;
        let demand = ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .checked_add(ControllerStopCleanupSourceAffinityV1::receiving_demand_v1()
                .map_err(ResourceReservationErrorV1::from)?)
            .map_err(ResourceReservationErrorV1::from)?;
        self.reserve_additional_v1(controller, demand)?;
        self.check_frontier_v1(controller)?;
        self.require_completed_cleanup_host_horizon_v1(controller)?;
        root.require_same_source22_v1(self, controller)?;
        let receipt = completed_query(self, controller, session, outcome, decoded)?;
        if root.final_host_outcome_digest_v1()? != receipt.3 {
            return Err(StopCleanupCompletionErrorV1::Association);
        }

        let subject = self.subject_data_v1(controller)?;
        let evidence = completed_evidence(decoded, subject, root.executed_cleanup_data_v1()?)?;
        let affinity = self.capture_inventory_financial_original_v1(controller)?;
        let source = self.source.journal_ref_v1().source_provisioning_identity_v1()?;
        let dispatch_record = self.original()?.dispatch_record;
        let parts = held_owner_mut(self.owner).host_turn.cleanup_native_parts_v1()?;
        let (operation, historical) = parts.read.operation_v1()?;
        let (projection, _) = parts.read.projection_ready_v1()?;
        let crate::lifecycle::LifecycleIntentV1::Stop { fence, .. } = operation.intent() else {
            return Err(StopCleanupCompletionErrorV1::Association);
        };
        let fence = *fence;
        let data = LifecycleStopCompletionDataV1::from_data_v1(
            LifecycleStopCompletionBindingDataV1 {
                operation: operation.operation_id(),
                operation_record: historical.digest(),
                dispatch_record,
                recovery: OperationId::from_bytes(*subject.recovery_operation_v1()),
                recovery_request: ObjectDigest::from_bytes(*subject.recovery_request_digest_v1()),
                source_root: projection.root(),
                cleanup_request: *subject.cleanup_request_v1(),
                query: (receipt.0, receipt.1, receipt.2),
                outcome: receipt.3,
                body: receipt.4,
                root_query: root.query_digest_v1()?,
                root_decision: root.decision_digest_v1()?,
                root_completion: *root.completion_bytes_v1()?,
            }, evidence,
        ).map_err(|_| StopCleanupCompletionErrorV1::Association)?;
        let expiry = root.verified_authority_expiry_data_v1()?;
        let cutoff = self.completed_cleanup_host_cutoff_data_v1(controller)?;
        let original = StopCleanupCompletionOriginalV1 {
            root, session, outcome, decoded, affinity, source, subject, data,
            historical, fence, expiry, cutoff,
        };
        original.require_same_source22_v1(self, controller)?;
        Ok(original)
    }
}

impl StopCleanupCompletionOriginalV1<'_> {
    pub(crate) fn require_same_source22_v1(
        &self,
        loan: &ControllerHostStopCleanupSourceLoanV1<'_, '_>,
        controller: &Journal,
    ) -> CompletionResult<()> {
        loan.require_same_inventory_financial_original_v1(&self.affinity, controller)?;
        self.root.require_same_source22_v1(loan, controller)?;
        self.require_current_v1(loan.source.journal_ref_v1(), &loan.subject_data_v1(controller)?)?;
        let receipt = completed_query(loan, controller, self.session, self.outcome, self.decoded)?;
        let binding = self.data.binding_v1();
        if receipt != (binding.query.0, binding.query.1, binding.query.2, binding.outcome, binding.body)
            || self.root.final_host_outcome_digest_v1()? != binding.outcome
            || self.root.query_digest_v1()? != binding.root_query
            || self.root.decision_digest_v1()? != binding.root_decision
            || self.root.completion_bytes_v1()? != &binding.root_completion
        {
            return Err(StopCleanupCompletionErrorV1::Association);
        }
        Ok(())
    }

    pub(crate) fn require_current_v1(&self, source: &Journal, subject: &Subject)
        -> std::result::Result<(crate::lifecycle::LifecycleRecordDigestV1, ObjectDigest), crate::JournalError>
    {
        source.require_current_source_provisioning_identity_v1(&self.source)?;
        if subject != &self.subject {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        Ok((self.historical, ObjectDigest::from_bytes(self.data.binding_v1().outcome)))
    }
}

fn completed_query(
    loan: &ControllerHostStopCleanupSourceLoanV1<'_, '_>,
    controller: &Journal,
    session: &Journal,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    decoded: &ControllerInventoryDecodedOriginalV2,
) -> CompletionResult<QueryReference> {
    loan.require_current_v1(controller)?;
    let method = aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
    let (request, binding) = loan.state_v1(1)
        .require_completed_inventory_model_v3(session, outcome, decoded, method, false)?;
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(StopCleanupCompletionErrorV1::Association);
    };
    let actual = (request, binding, Sha256::digest(outcome.request().canonical_packet()).into(),
        Sha256::digest(outcome.canonical_packet()).into(), Sha256::digest(exact_body).into());
    if actual != loan.completed_host_inventory_reference_data_v1(controller, 1)?
        || actual.4 != decoded.body_digest_v2()
        || actual.0 == loan.completed_host_inventory_reference_data_v1(controller, 0)?.0
    {
        return Err(StopCleanupCompletionErrorV1::Association);
    }
    Ok(actual)
}

fn completed_evidence(decoded: &ControllerInventoryDecodedOriginalV2, subject: Subject, executed: bool)
    -> CompletionResult<LifecycleStopCompletionEvidenceDataV1>
{
    use aos_sandbox_protocol::{host_cleanup_lineage::HostCleanupLineageDataV1,
        host_recovered_namespace::{HostRecoveredNamespaceDataV7, HostRecoveryStopPhaseDataV7}};
    let ControllerInventoryModelDataV2::Host(inventory) = decoded.model_v2() else {
        return Err(StopCleanupCompletionErrorV1::Association);
    };
    if !inventory.__buffa_unknown_fields.is_empty() {
        return Err(StopCleanupCompletionErrorV1::Association);
    }
    if let Some(lineage) = HostCleanupLineageDataV1::from_inventory_v1(inventory)? {
        if lineage.subject_v1().historical_scope_v1() != subject.historical_scope_v1()
            || (executed && lineage.subject_v1() != &subject) {
            return Err(StopCleanupCompletionErrorV1::Association);
        }
        return Ok(if executed { LifecycleStopCompletionEvidenceDataV1::ExecutedLineage(lineage) }
            else { LifecycleStopCompletionEvidenceDataV1::ObservedLineage(lineage) });
    }
    if !executed {
        if let Some(row) = HostRecoveredNamespaceDataV7::from_inventory_v7(inventory)? {
            if row.saved_phase_v7() == HostRecoveryStopPhaseDataV7::Complete
                && row.historical_scope_v7() == subject.historical_scope_v1() {
                return Ok(LifecycleStopCompletionEvidenceDataV1::ObservedComplete(row));
            }
        }
    }
    Err(StopCleanupCompletionErrorV1::Association)
}
