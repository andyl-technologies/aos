//! Publishes the minimal immutable generation and fresh execution lease.
//!
//! Every successor is built from the genuine held Root response and the actual
//! same Source scope. The sole canonical reducer/CAS planner and semantic native
//! append engine own all durable transitions. Root Prepared DATA is never
//! adopted as Source Observed; the actual Desired/Prepared/Committed/Observed
//! sequence and exact lease are independently committed and read back here.

use std::error::Error;
use aos_sandbox_model::{ExecutionId, ObjectDigest, ResourceId, Revision, RawPairedClockSample};
use aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1;
use aos_sandbox_broker::domain_transaction_custody::{DomainPlannedMembersDataV1, plan_members_v1};
use aos_sandbox_protocol::domain_ledger::records::{current_record_candidates_from_rows,
    replay_projection_records, decode_reducer_payload_with_validator};
use crate::journal::{JournalError, JournalTransaction, ControllerCoordinatorSelectionV1 as Selection};
use crate::normal_root::RootEnvironmentClientOriginalV1;
use super::transport::EnvironmentRootResponseDataV1;
use super::super::*;
use super::super::protected_journal::{EnvironmentProtectedJournalSchemaV1 as Schema,
    EnvironmentProtectedRecordKindV1 as Kind, EnvironmentReducerRecordV1 as Record,
    environment_protected_key_v1, environment_reducer_envelope_v1};

#[derive(Debug, thiserror::Error)]
pub(crate) enum EnvironmentPublicationErrorV1 {
    #[error("the actual held Root or same Source publication is incomplete")]
    Closed,
    #[error(transparent)]
    Model(#[from] EnvironmentModelError),
    #[error(transparent)]
    History(#[from] EnvironmentHistoryError),
    #[error(transparent)]
    Domain(#[from] crate::protected_domain_journal::ProtectedDomainJournalErrorV1),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Keeps one exact privately planned Environment successor on its Source cut.
pub(crate) struct PreparedEnvironmentPublicationV1 {
    members: DomainPlannedMembersDataV1<Schema>,
    sequence: u64,
    root: ObjectDigest,
    response: EnvironmentRootResponseDataV1,
    final_lease: bool,
}

impl PreparedEnvironmentPublicationV1 {
    pub(crate) fn transaction_v1(&self) -> &JournalTransaction { self.members.transaction() }

    pub(crate) fn require_same_source_v1(&self,
        source: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        let history = history_v1(source).map_err(|_| JournalError::ProtectedBoundary)?;
        let projection = replay_projection_records::<Schema>(source.all_records(), &history)
            .map_err(JournalError::EnvironmentProjection)?;
        if projection.root() != self.root { return Err(JournalError::StaleAuthoritySnapshot); }
        Ok(())
    }
}

/// Retains the exact current planner/error and its completed Source lease cut.
pub(crate) struct EnvironmentSourcePublicationOriginalV1 {
    planned: Option<Result<NextEnvironmentPublicationV1, EnvironmentPublicationErrorV1>>,
    completed: Option<EnvironmentRootResponseDataV1>,
    completed_sequence: Option<u64>,
    error: Option<EnvironmentPublicationErrorV1>,
}

impl EnvironmentSourcePublicationOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self { planned: None, completed: None, completed_sequence: None, error: None }
    }

    /// Plans only the next real phase from the actual held Root and Source cut.
    ///
    /// # Errors
    /// Retains malformed history, a changed artifact/Source cut or the original
    /// canonical planner refusal. A failed plan cannot be replaced or retried.
    pub(crate) fn prepare_next_v1(&mut self, client: &RootEnvironmentClientOriginalV1,
        source: crate::journal::QualifiedEnvironmentSourceViewV1<'_>, now: RawPairedClockSample,
    ) -> Result<Option<&PreparedEnvironmentPublicationV1>, EnvironmentPublicationErrorV1> {
        if self.error.is_some() || self.completed.is_some() || self.planned.is_some() {
            self.error.get_or_insert(EnvironmentPublicationErrorV1::Closed);
            return Err(EnvironmentPublicationErrorV1::Closed);
        }
        self.planned = Some(plan_next_v1(client, source.view_v1(), now));
        match self.planned.as_ref() {
            Some(Ok(NextEnvironmentPublicationV1::Append(prepared))) => Ok(Some(prepared)),
            Some(Ok(NextEnvironmentPublicationV1::Current { response, sequence })) => {
                self.completed = Some(*response);
                self.completed_sequence = Some(*sequence);
                Ok(None)
            }
            _ => Err(EnvironmentPublicationErrorV1::Closed),
        }
    }

    /// Records only the same native append's positively disposed readback.
    pub(crate) fn complete_step_v1(&mut self, actual: crate::journal::CompletedEnvironmentSourceAppendV1,
    ) -> Result<bool, EnvironmentPublicationErrorV1> {
        let plan = match self.planned.as_ref() {
            Some(Ok(NextEnvironmentPublicationV1::Append(plan))) => plan,
            _ => return Err(EnvironmentPublicationErrorV1::Closed),
        };
        let (committed, following, transaction) = actual.comparison_data_v1();
        let expected = plan.sequence.checked_add(u64::try_from(plan.members.transaction().records().len())
            .map_err(|_| EnvironmentPublicationErrorV1::Closed)?).and_then(|value| value.checked_add(1));
        if Some(committed.commit_sequence) != expected || committed.commit_sequence.checked_add(1) != Some(following)
            || transaction != *plan.members.transaction().id() {
            self.error.get_or_insert(EnvironmentPublicationErrorV1::Closed);
            return Err(EnvironmentPublicationErrorV1::Closed);
        }
        let terminal = plan.final_lease;
        if terminal { self.completed = Some(plan.response); self.completed_sequence = Some(following); }
        // All native/readback owners were positively disposed by the sole
        // Source scope before this pure planned transaction can be dropped.
        self.planned = None;
        Ok(terminal)
    }

    pub(crate) fn require_completed_for_root_v1(&self, response: EnvironmentRootResponseDataV1)
        -> Result<(), JournalError>
    {
        if self.error.is_some() || self.completed != Some(response) || self.completed_sequence.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.planned.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.error.as_ref().map(|cause| cause as _))
    }
}

fn history_v1(view: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>)
    -> Result<EnvironmentGenerationHistoryV1, EnvironmentPublicationErrorV1>
{
    let candidates = current_record_candidates_from_rows::<Schema>(view.all_records())
        .map_err(crate::protected_domain_journal::ProtectedDomainJournalErrorV1::from)?;
    super::super::protected_owner::recover_environment_history_candidates_v2(candidates)
        .map_err(Into::into)
}

fn plan_next_v1(client: &RootEnvironmentClientOriginalV1,
    read: CanonicalWriterReadViewV1<'_, Selection>, now: RawPairedClockSample,
) -> Result<NextEnvironmentPublicationV1, EnvironmentPublicationErrorV1> {
    let provisional = client.provisional_v1()?;
    let response = client.response_data_v1()?;
    let manifest = provisional.manifest_v1();
    let trusted = client.trusted_time_v1(now)?;
    let source = read.historical_view();
    let mut history = history_v1(source)?;
    let projection = replay_projection_records::<Schema>(source.all_records(), &history)
        .map_err(crate::protected_domain_journal::ProtectedDomainJournalErrorV1::from)?;
    let mut final_lease = false;
    let (key, record) = if let Some(existing) = history.latest(manifest.sandbox()) {
        if existing != manifest { return Err(EnvironmentPublicationErrorV1::Closed); }
        let mut previous = None;
        for envelope in projection.records().iter().filter(|record|
            matches!(record.key().kind(), Kind::LeaseEffect | Kind::Current))
        {
            let payload = decode_reducer_payload_with_validator::<Schema>(envelope.key(), envelope.payload(), &history)
                .map_err(crate::protected_domain_journal::ProtectedDomainJournalErrorV1::from)?;
            let activation = decode_environment_activation_v1(payload.body(), &history)?;
            if activation.project() == manifest.project() && activation.sandbox() == manifest.sandbox() {
                if previous.as_ref().is_none_or(|old: &EnvironmentActivationTransactionV1|
                    old.revision() < activation.revision()) { previous = Some(activation); }
                else if previous.as_ref().is_some_and(|old| old.revision() == activation.revision() && old != &activation) {
                    return Err(EnvironmentPublicationErrorV1::Closed);
                }
            }
        }
        let selector = EnvironmentSelectorV1::from_manifest(manifest)?;
        let (transaction, revision, predecessor, phase, current, observed, mut leases, roots) = match previous {
            None => (ResourceId::from_bytes(response.operation), Revision::new(1), None,
                EnvironmentActivationPhaseV1::Desired, None, None, Vec::new(), Vec::new()),
            Some(previous) => {
                if previous.desired() != &selector { return Err(EnvironmentPublicationErrorV1::Closed); }
                let execution = ExecutionId::from_bytes(response.execution);
                if matches!(previous.phase(), EnvironmentActivationPhaseV1::Observed | EnvironmentActivationPhaseV1::Released)
                    && previous.current() == Some(&selector) && previous.observed() == Some(&selector)
                    && previous.leases().iter().any(|lease|
                        lease_is_current_v1(lease, execution, manifest.generation(), trusted))
                {
                    // This projection came only from the actual qualified
                    // Source scope and was canonically replayed above. Root's
                    // fresh measured closure remains held. Outer Source/C
                    // native posts still gate the real operation's disposal.
                    return Ok(NextEnvironmentPublicationV1::Current { response, sequence: read.next_sequence() });
                }
                let phase = match previous.phase() {
                    EnvironmentActivationPhaseV1::Desired => EnvironmentActivationPhaseV1::Prepared,
                    EnvironmentActivationPhaseV1::Prepared => EnvironmentActivationPhaseV1::Committed,
                    EnvironmentActivationPhaseV1::Committed => EnvironmentActivationPhaseV1::Observed,
                    EnvironmentActivationPhaseV1::Observed | EnvironmentActivationPhaseV1::Released => EnvironmentActivationPhaseV1::Released,
                };
                let current = if matches!(phase, EnvironmentActivationPhaseV1::Committed | EnvironmentActivationPhaseV1::Observed | EnvironmentActivationPhaseV1::Released)
                    { Some(selector.clone()) } else { None };
                let observed = if matches!(phase, EnvironmentActivationPhaseV1::Observed | EnvironmentActivationPhaseV1::Released)
                    { Some(selector.clone()) } else { None };
                let mut leases = previous.leases().to_vec();
                if phase == EnvironmentActivationPhaseV1::Released {
                    // Exact real monotonic expiry permits release only at the
                    // existing Released frontier; live leases remain retained.
                    leases.retain(|lease| lease.boot() != trusted.boot() || lease.expires_at() > trusted.observed().get());
                }
                (previous.transaction(), previous.revision().checked_next().map_err(|_| EnvironmentModelError::InvalidModel)?,
                    Some(environment_activation_digest_v1(&previous)?), phase, current, observed, leases,
                    provisional.prepared_v1().gc_roots().to_vec())
            }
        };
        if matches!(phase, EnvironmentActivationPhaseV1::Observed | EnvironmentActivationPhaseV1::Released) {
            let execution = ExecutionId::from_bytes(response.execution);
            if leases.iter().any(|lease| lease.consumer() == EnvironmentLeaseConsumerV1::Execution(execution)) {
                return Err(EnvironmentPublicationErrorV1::Closed);
            }
            leases.push(EnvironmentGenerationLeaseV1::new(EnvironmentLeaseConsumerV1::Execution(execution),
                manifest.generation(), ResourceId::from_bytes(response.execution), client.lease_cutoff_v1()?, &trusted)?);
            leases.sort_unstable();
            final_lease = true;
        }
        let activation = EnvironmentActivationTransactionV1::new(transaction, manifest.project(), manifest.sandbox(),
            revision, predecessor, selector, current, observed, leases, roots, Vec::new(), phase, &trusted)?;
        let kind = if matches!(phase, EnvironmentActivationPhaseV1::Desired | EnvironmentActivationPhaseV1::Prepared)
            { Kind::LeaseEffect } else { Kind::Current };
        (environment_protected_key_v1(kind, manifest.project(), manifest.sandbox(), transaction)?,
            PublicationRecordV1::Activation(activation))
    } else {
        history = EnvironmentGenerationHistoryV1::from_protected_manifests(vec![manifest.clone()])?;
        (environment_protected_key_v1(Kind::Generation, manifest.project(), manifest.sandbox(),
            ResourceId::from_bytes(*manifest.sandbox().as_bytes()))?, PublicationRecordV1::Generation)
    };
    let old = projection.records().iter().find(|envelope| envelope.key() == &key);
    let revision = old.map(|envelope| envelope.revision().checked_add(1))
        .unwrap_or(Some(1)).ok_or(EnvironmentModelError::InvalidModel)?;
    let predecessor = old.map(|envelope| envelope.digest());
    let envelope = environment_reducer_envelope_v1(key, revision, predecessor, match &record {
        PublicationRecordV1::Generation => Record::Generation(manifest),
        PublicationRecordV1::Activation(activation) => Record::Activation(activation),
    }, &history)?;
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::new().chain_update(b"aos.environment.source.publication.v1\0")
        .chain_update(response.operation).chain_update(read.next_sequence().to_be_bytes())
        .chain_update(envelope.digest().as_bytes()).finalize();
    let mut transaction = [0; 16];transaction.copy_from_slice(&digest[..16]);
    let members = plan_members_v1::<Schema>(source, read.next_sequence(), projection.root(), transaction,
        vec![envelope], &history).map_err(crate::protected_domain_journal::ProtectedDomainJournalErrorV1::from)?;
    Ok(NextEnvironmentPublicationV1::Append(PreparedEnvironmentPublicationV1 { members, sequence: read.next_sequence(), root: projection.root(), response, final_lease }))
}

enum PublicationRecordV1 { Generation, Activation(EnvironmentActivationTransactionV1) }

enum NextEnvironmentPublicationV1 {
    Append(PreparedEnvironmentPublicationV1),
    Current { response: EnvironmentRootResponseDataV1, sequence: u64 },
}

// This is a comparison over canonically replayed DATA, never a lease issuer.
// The caller must still hold the qualified Source scope and fresh Root owner.
fn lease_is_current_v1(lease: &EnvironmentGenerationLeaseV1, execution: ExecutionId,
    generation: Revision, now: EnvironmentTrustedTimeV1,
) -> bool {
    lease.consumer() == EnvironmentLeaseConsumerV1::Execution(execution)
        && lease.generation() == generation
        && lease.status() == EnvironmentGenerationLeaseStatusV1::Active
        && lease.boot() == now.boot()
        && lease.observed_at() <= now.observed()
        && lease.expires_at() > now.observed().get()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(boot: u8, observed: u64) -> EnvironmentTrustedTimeV1 {
        EnvironmentTrustedTimeV1::from_verified_observation(ObjectDigest::from_bytes([boot; 32]),
            EnvironmentLeaseTimeV1::new(observed).unwrap()).unwrap()
    }

    #[test]
    fn same_execution_borrows_only_its_unexpired_same_boot_lease() {
        let execution = ExecutionId::from_bytes([1; 16]);
        let generation = Revision::new(1);
        let lease = EnvironmentGenerationLeaseV1::new(EnvironmentLeaseConsumerV1::Execution(execution),
            generation, ResourceId::from_bytes([2; 16]), 20, &time(3, 10)).unwrap();

        assert!(lease_is_current_v1(&lease, execution, generation, time(3, 11)));
        assert!(lease_is_current_v1(&lease, execution, generation, time(3, 19)));
        assert!(!lease_is_current_v1(&lease, execution, generation, time(3, 20)));
        assert!(!lease_is_current_v1(&lease, execution, generation, time(4, 11)));
        assert!(!lease_is_current_v1(&lease, execution, generation, time(3, 9)));
        assert!(!lease_is_current_v1(&lease, ExecutionId::from_bytes([4; 16]), generation, time(3, 11)));
        assert!(!lease_is_current_v1(&lease, execution, Revision::new(2), time(3, 11)));
        assert_eq!(lease.expires_at(), 20);
        assert_eq!(lease.observed_at().get(), 10);
    }
}
