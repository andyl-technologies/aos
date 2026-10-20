//! Reads a protected original Environment association without renewing its lease.
//!
//! A genuine execution Source scope alone constructs this borrowed owner. It
//! replays the same canonical generation/activation engines and compares the
//! actual protected specification cut. A past deadline remains historical DATA;
//! no current evidence, execution source, effect, append or GC grant is issued.

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;
use aos_sandbox_protocol::domain_ledger::records::{
    current_record_candidates_from_rows, decode_reducer_payload_with_validator,
    replay_projection_records,
};
use crate::controller_execution_spec_attempt::ControllerExecutionSpecAttemptV1;
use crate::protected_domain_journal::ProtectedDomainJournalErrorV1;
use super::protected_journal::{EnvironmentProtectedJournalProjectionV1,
    EnvironmentProtectedJournalSchemaV1, EnvironmentProtectedRecordKindV1};
use super::{EnvironmentActivationTransactionV1, EnvironmentGenerationHistoryV1,
    EnvironmentLeaseConsumerV1, decode_environment_activation_v1,
    environment_activation_digest_v1};

#[derive(Clone, Copy)]
struct OriginalSpecificationV4 {
    execution: ExecutionId,
    create: OperationId,
    specification_digest: ObjectDigest,
    accepted_request_digest: ObjectDigest,
}

/// Keeps a read-only original Environment/spec/lease association on SAME Source.
///
/// This type cannot be constructed from rows, a descriptor, evidence or a wire
/// response. Its named comparisons authorize no runtime effect or lease renewal.
#[must_use]
pub struct HistoricalEnvironmentExecutionOwnerV4<'source> {
    view: HistoricalLedgerReadViewV1<'source>,
    history: Option<Result<EnvironmentGenerationHistoryV1, ProtectedDomainJournalErrorV1>>,
    projection: Option<Result<EnvironmentProtectedJournalProjectionV1, ProtectedDomainJournalErrorV1>>,
    activations: Vec<Result<EnvironmentActivationTransactionV1, ProtectedDomainJournalErrorV1>>,
    returned: Option<Result<(), ProtectedDomainJournalErrorV1>>,
    original: Option<OriginalSpecificationV4>,
    repeated: Option<ProtectedDomainJournalErrorV1>,
}

/// Retains the same historical replay models through enclosing native posts.
///
/// Consuming the actual borrowed owner creates this passive custody. It has no
/// Source view, writer, binding lender, dispatch or positive-disposal port.
pub struct HistoricalEnvironmentExecutionModelsV4 {
    history: Option<Result<EnvironmentGenerationHistoryV1, ProtectedDomainJournalErrorV1>>,
    projection: Option<Result<EnvironmentProtectedJournalProjectionV1, ProtectedDomainJournalErrorV1>>,
    activations: Vec<Result<EnvironmentActivationTransactionV1, ProtectedDomainJournalErrorV1>>,
    returned: Option<Result<(), ProtectedDomainJournalErrorV1>>,
    _original: Option<OriginalSpecificationV4>,
    repeated: Option<ProtectedDomainJournalErrorV1>,
}

impl HistoricalEnvironmentExecutionModelsV4 {
    /// Borrows the same retained replay or association refusal without IO.
    #[must_use]
    pub fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        historical_failure_v4(&self.history, &self.projection, &self.activations,
            &self.returned, &self.repeated)
    }
}

impl<'source> HistoricalEnvironmentExecutionOwnerV4<'source> {
    /// Moves owned replay results while ending only the borrowed Source view.
    ///
    /// The enclosing genuine native scope remains held and still owes all
    /// posts. This handoff grants no positive completion or resource credit.
    #[must_use]
    pub fn into_retained_models_v4(self) -> HistoricalEnvironmentExecutionModelsV4 {
        let Self { view: _, history, projection, activations, returned, original, repeated } = self;
        HistoricalEnvironmentExecutionModelsV4 {
            history, projection, activations, returned, _original: original, repeated,
        }
    }

    pub(crate) fn from_source_read_v4(
        source: aos_sandbox_broker::source_receiving::SourceExecutionReadViewV1<'source>,
    ) -> Self {
        Self { view: source.into_historical_view_v1(), history: None, projection: None,
            activations: Vec::new(), returned: None, original: None, repeated: None }
    }

    /// Replays and binds the actual protected original specification once.
    ///
    /// Lease and Root evidence expiry do not renew or invalidate historical
    /// facts. The exact recorded activation/manifest/generation and execution
    /// lease association must still exist on this same native Source prefix.
    ///
    /// # Errors
    /// Retains canonical replay/association refusal or rejects reentry. This
    /// grants no current Environment evidence, execution source or native IO.
    pub fn observe_original_specification_v4(&mut self,
        specification: &ControllerExecutionSpecAttemptV1,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        if self.returned.is_some() {
            self.repeated.get_or_insert_with(invalid);
            return Err(invalid());
        }
        self.returned = Some(self.observe_inner_v4(specification));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(invalid()) }
    }

    fn observe_inner_v4(&mut self, specification: &ControllerExecutionSpecAttemptV1)
        -> Result<(), ProtectedDomainJournalErrorV1>
    {
        self.history = Some(current_record_candidates_from_rows::<EnvironmentProtectedJournalSchemaV1>(
            self.view.all_records()).map_err(ProtectedDomainJournalErrorV1::from)
            .and_then(super::protected_owner::recover_environment_history_candidates_v2));
        let history = self.history.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(invalid)?;
        self.projection = Some(replay_projection_records::<EnvironmentProtectedJournalSchemaV1>(
            self.view.all_records(), history).map_err(ProtectedDomainJournalErrorV1::from));
        let projection = self.projection.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(invalid)?;
        super::protected_owner::validate_claimed_environment_history_v1(projection, history)?;
        self.activations.try_reserve_exact(projection.records().len()).map_err(|_| invalid())?;
        let heads = specification.source_heads();
        let mut matched = false;
        for record in projection.records().iter()
            .filter(|record| record.key().kind() == EnvironmentProtectedRecordKindV1::Current)
        {
            self.activations.push((|| {
                let payload = decode_reducer_payload_with_validator::<EnvironmentProtectedJournalSchemaV1>(
                    record.key(), record.payload(), history)?;
                decode_environment_activation_v1(payload.body(), history).map_err(|_| invalid())
            })());
            let activation = self.activations.last().and_then(|result| result.as_ref().ok()).ok_or_else(invalid)?;
            if environment_activation_digest_v1(activation).map_err(|_| invalid())? != heads.environment_activation {
                continue;
            }
            let selector = activation.current().filter(|selector| activation.observed() == Some(*selector))
                .ok_or_else(invalid)?;
            if matched || selector.generation().get() != heads.environment_generation
                || selector.manifest().digest() != heads.environment_manifest
                || !activation.leases().iter().any(|lease|
                    lease.generation() == selector.generation()
                        && lease.consumer() == EnvironmentLeaseConsumerV1::Execution(specification.execution()))
            { return Err(invalid()); }
            matched = true;
        }
        if !matched { return Err(invalid()); }
        self.original = Some(OriginalSpecificationV4 {
            execution: specification.execution(), create: specification.create_operation(),
            specification_digest: specification.specification_digest(),
            accepted_request_digest: specification.accepted_request_digest(),
        });
        Ok(())
    }

    /// Refuses incomplete, failed or reused historical binding without IO.
    ///
    /// # Errors
    /// Rejects before Query model/native growth unless the same one original
    /// specification comparison completed and no later entry was refused.
    pub fn require_historical_binding_v4(&self) -> Result<(), ProtectedDomainJournalErrorV1> {
        if !matches!(self.returned, Some(Ok(()))) || self.repeated.is_some() || self.original.is_none() {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares exact original Source512 identities for a read-only Query61.
    ///
    /// # Errors
    /// Rejects an unobserved/failed owner or another original execution/Create.
    pub fn require_capture_source_v4(&self,
        source: &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV1,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.require_historical_binding_v4()?;
        let original = self.original.ok_or_else(invalid)?;
        if source.settlement().execution() != original.execution
            || source.settlement().create_operation() != original.create
        { return Err(invalid()); }
        Ok(())
    }

    /// Compares full immutable Source944/spec/request association for Query61.
    ///
    /// # Errors
    /// Rejects changed identities, canonical spec or accepted request commitment.
    /// Its historical ongoing deadline is never checked as new effect authority.
    pub fn require_ongoing_capture_source_v4(&self,
        source: &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.require_capture_source_v4(source.original_source_v1())?;
        let original = self.original.ok_or_else(invalid)?;
        if source.lifetime_v2().specification_digest_v2() != original.specification_digest
            || source.lifetime_v2().accepted_request_digest_v2() != original.accepted_request_digest
        { return Err(invalid()); }
        Ok(())
    }

    /// Borrows the earliest retained canonical or association error.
    #[must_use]
    pub fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        historical_failure_v4(&self.history, &self.projection, &self.activations,
            &self.returned, &self.repeated)
    }
}

fn historical_failure_v4<'models>(
    history: &'models Option<Result<EnvironmentGenerationHistoryV1, ProtectedDomainJournalErrorV1>>,
    projection: &'models Option<Result<EnvironmentProtectedJournalProjectionV1, ProtectedDomainJournalErrorV1>>,
    activations: &'models [Result<EnvironmentActivationTransactionV1, ProtectedDomainJournalErrorV1>],
    returned: &'models Option<Result<(), ProtectedDomainJournalErrorV1>>,
    repeated: &'models Option<ProtectedDomainJournalErrorV1>,
) -> Option<&'models (dyn std::error::Error + 'static)> {
    history.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
        .or_else(|| projection.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
        .or_else(|| activations.iter().find_map(|result| result.as_ref().err()).map(|cause| cause as _))
        .or_else(|| returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
        .or_else(|| repeated.as_ref().map(|cause| cause as _))
}

fn invalid() -> ProtectedDomainJournalErrorV1 {
    ProtectedDomainJournalErrorV1::NonCanonicalRecord
}
