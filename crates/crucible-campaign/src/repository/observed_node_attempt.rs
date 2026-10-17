//! Isolated CAS publication for independently identified node observations.
//!
//! All immutable children precede the ledger ref CAS. The ref is an operational
//! root under `observed-attempt-ledgers/`, separate from deterministic campaign
//! indexes. Retention owners must inventory this namespace before destructive
//! collection; every retained record exposes its complete CAS child table.

use crucible_cas::content_envelope::ContentEnvelope;

use super::*;
use crate::observed_node_attempt::{
    MAX_OBSERVED_RECORD_BYTES, ObservedAttemptAdmission, ObservedAttemptRequest,
    ObservedAttemptResult, ObservedAttemptState, ObservedDispatchReservation,
    ObservedEnvelopeRecord, ObservedExecutionPermit, ObservedLedger, ObservedReservation,
    execution_key,
};

impl CampaignRepository {
    /// Loads an observed result and authenticates its complete retained closure.
    ///
    /// Schema authentication refuses legacy deterministic observations even
    /// when their broad CAS kind and envelope version have the same shape.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, corrupt, unsupported or foreign record,
    /// inconsistent child table, or missing/corrupt retained evidence.
    pub fn load_observed_result(
        &self,
        id: crate::observed_node_attempt::ObservedAttemptId,
    ) -> Result<ObservedAttemptResult, CampaignRepositoryError> {
        let _guard = self.acquire_gc_exclusion_guard()?;
        let envelope = self.read_observed_envelope(id.content_id(), ObjectKind::Observation)?;
        let Some(ObservedEnvelopeRecord::Result(result)) =
            ObservedEnvelopeRecord::decode(id.content_id(), &envelope)?
        else {
            return Err(integrity("observed-result-record-schema-mismatch"));
        };
        self.authenticated_closure_ids([id.content_id()])?;
        Ok(result)
    }

    pub(in crate::repository) fn validate_observed_closure_record(
        &self,
        record: &ObservedEnvelopeRecord,
    ) -> Result<(), CampaignRepositoryError> {
        match record {
            ObservedEnvelopeRecord::Request(request) => {
                let roster = request.capabilities().roster();
                let scenario = self.load_scenario_artifact(roster.scenario())?;
                let configuration = self.load_configuration_artifact(roster.configuration())?;
                if configuration.scenario_artifact() != roster.scenario()
                    || configuration.scenario() != scenario.scenario()
                {
                    return Err(integrity("observed-closure-artifact-binding-mismatch"));
                }
            }
            ObservedEnvelopeRecord::Ledger(ledger) => {
                let mut after = None;
                let mut entries = 0_usize;
                loop {
                    let page = self.merkle.scan(ledger.executions, after, 256)?;
                    for (key, id) in page.entries().iter().copied() {
                        entries = entries
                            .checked_add(1)
                            .ok_or_else(|| integrity("observed-ledger-entry-limit"))?;
                        if entries > MAX_CAMPAIGN_CLOSURE_OBJECTS {
                            return Err(integrity("observed-ledger-entry-limit"));
                        }
                        let envelope = self.read_observed_envelope(id, ObjectKind::CampaignFact)?;
                        let Some(ObservedEnvelopeRecord::State(state)) =
                            ObservedEnvelopeRecord::decode(id, &envelope)?
                        else {
                            return Err(integrity("observed-ledger-index-not-state"));
                        };
                        if execution_key(state.request().execution()) != key
                            || state.request().capabilities().digest() != ledger.capabilities
                        {
                            return Err(integrity("observed-ledger-index-binding-mismatch"));
                        }
                    }
                    let Some(cursor) = page.next_after() else {
                        break;
                    };
                    after = Some(cursor);
                }
            }
            ObservedEnvelopeRecord::Result(_)
            | ObservedEnvelopeRecord::State(_)
            | ObservedEnvelopeRecord::Reservation(_) => {}
        }
        Ok(())
    }

    /// Reserves an independent node execution before any native dispatch.
    ///
    /// A repeated request returns its original state without a dispatch permit.
    /// Reusing an execution nonce for different inputs or realization refuses.
    /// The mandatory authenticator binds stored scenario/configuration payloads
    /// and the complete inputs to a host-sealed admitted graph.
    ///
    /// # Errors
    ///
    /// Returns an error for failed admission, absent/corrupt artifact closure,
    /// execution-nonce reuse, a foreign ledger realization, or publication failure.
    pub fn reserve_observed_attempt(
        &self,
        ledger_name: &str,
        request: &ObservedAttemptRequest,
        admission: &impl ObservedAttemptAdmission,
    ) -> Result<ObservedReservation, CampaignRepositoryError> {
        let name = observed_ref_name(ledger_name)?;
        let _guard = self.lock_mutation()?;
        self.authenticate_observed_request(request, admission)?;

        let current = self.refs.read_ref(&name)?;
        let ledger = match current {
            Some(id) => self.read_observed_ledger(id)?,
            None => ObservedLedger {
                capabilities: request.capabilities().digest(),
                executions: self.merkle.empty()?.content_id(),
            },
        };
        require_observed_realization(&ledger, request)?;

        let reservation = self.read_observed_dispatch_reservation(request.execution())?;
        if let Some(reservation) = &reservation {
            require_observed_dispatch_binding(reservation, ledger_name, request)?;
        }

        if let Some(state) = self.observed_state_in(&ledger, request.execution())? {
            if reservation.is_none() {
                return Err(integrity("observed-ledger-state-has-no-dispatch-custody"));
            }
            if state.request() != request {
                return Err(integrity("observed-execution-nonce-reused"));
            }
            return Ok(ObservedReservation::Existing(state));
        }

        self.put_observed_envelope(&request.envelope()?, ObjectKind::CampaignFact)?;
        if reservation.is_some() {
            // A crash or uncertain ref error between nonce custody and ledger
            // publication must never mint a recovered dispatch permit.
            let state = ObservedAttemptState::Quarantined {
                request: request.clone(),
                reason: "dispatch-reservation-publication-uncertain".to_owned(),
            };
            self.advance_observed_state(&name, current, ledger, &state)?;
            return Ok(ObservedReservation::Existing(state));
        }

        let reservation = ObservedDispatchReservation {
            ledger: ledger_name.to_owned(),
            request: request.clone(),
        };
        let reservation_id =
            self.put_observed_envelope(&reservation.envelope()?, ObjectKind::CampaignFact)?;
        match self.refs.compare_exchange(
            &observed_nonce_ref_name(request.execution())?,
            None,
            reservation_id,
        )? {
            RefCasOutcome::Advanced { .. } => {}
            RefCasOutcome::Conflict { current, .. } => {
                return Err(CampaignRepositoryError::RefConflict { current });
            }
        }
        self.advance_observed_state(
            &name,
            current,
            ledger,
            &ObservedAttemptState::Reserved(request.clone()),
        )?;

        Ok(ObservedReservation::Fresh(ObservedExecutionPermit {
            ledger: ledger_name.to_owned(),
            request: request.clone(),
        }))
    }

    /// Reads the authoritative state for one independently identified execution.
    ///
    /// A recovered `Reserved` state never authorizes another native dispatch.
    ///
    /// # Errors
    ///
    /// Returns an error if the ref, ledger, index, state or its retained children
    /// are corrupt, unsupported or absent. Returns `None` for an unknown nonce.
    pub fn observed_attempt_state(
        &self,
        ledger_name: &str,
        execution: crate::ExecutionId,
    ) -> Result<Option<ObservedAttemptState>, CampaignRepositoryError> {
        let name = observed_ref_name(ledger_name)?;
        let _guard = self.acquire_gc_exclusion_guard()?;
        match self.refs.read_ref(&name)? {
            Some(id) => {
                let state = self.observed_state_in(&self.read_observed_ledger(id)?, execution)?;
                if let Some(state) = &state {
                    self.require_observed_dispatch_custody(ledger_name, state.request())?;
                }
                Ok(state)
            }
            None => Ok(None),
        }
    }

    /// Reads original observed state through globally retained nonce custody.
    ///
    /// This lookup does not acquire dispatch authority or create a new physical
    /// sample. A partial reservation may have custody without a ledger state.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt custody, inconsistent original ownership or
    /// missing/corrupt evidence. Returns `None` if no lifecycle state is retained.
    pub fn observed_execution_state(
        &self,
        execution: crate::ExecutionId,
    ) -> Result<Option<ObservedAttemptState>, CampaignRepositoryError> {
        let _guard = self.acquire_gc_exclusion_guard()?;
        let Some(reservation) = self.read_observed_dispatch_reservation(execution)? else {
            return Ok(None);
        };
        let Some(head) = self
            .refs
            .read_ref(&observed_ref_name(&reservation.ledger)?)?
        else {
            return Ok(None);
        };
        let state = self.observed_state_in(&self.read_observed_ledger(head)?, execution)?;
        if let Some(state) = &state {
            require_observed_dispatch_binding(&reservation, &reservation.ledger, state.request())?;
        }
        Ok(state)
    }

    /// Publishes completed observed bytes under their original dispatch permit.
    ///
    /// Retrying publication returns the identical original result. A different
    /// result, execution nonce, realization or request cannot replace it. This
    /// method never updates the legacy deterministic observation indexes.
    ///
    /// # Errors
    ///
    /// Returns an error for foreign or quarantined ownership, missing/corrupt
    /// evidence closure, divergent retry bytes or CAS publication failure.
    pub fn publish_observed_result(
        &self,
        permit: &ObservedExecutionPermit,
        result: &ObservedAttemptResult,
    ) -> Result<ObservedAttemptResult, CampaignRepositoryError> {
        if result.request() != permit.request() {
            return Err(integrity("observed-result-request-mismatch"));
        }

        let name = observed_ref_name(permit.ledger())?;
        let _guard = self.lock_mutation()?;
        self.require_observed_dispatch_custody(permit.ledger(), permit.request())?;
        let current = self
            .refs
            .read_ref(&name)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let ledger = self.read_observed_ledger(current)?;
        require_observed_realization(&ledger, result.request())?;
        let prior = self
            .observed_state_in(&ledger, result.request().execution())?
            .ok_or(CampaignRepositoryError::NotFound)?;

        match prior {
            ObservedAttemptState::Completed(original) if original == *result => {
                return Ok(original);
            }
            ObservedAttemptState::Reserved(request) if request == *permit.request() => {}
            _ => return Err(integrity("observed-result-ownership-or-retry-mismatch")),
        }

        self.authenticated_closure_ids([result.incoming(), result.outgoing(), result.evidence()])?;
        self.put_observed_envelope(&result.envelope()?, ObjectKind::Observation)?;
        self.advance_observed_state(
            &name,
            Some(current),
            ledger,
            &ObservedAttemptState::Completed(result.clone()),
        )?;
        Ok(result.clone())
    }

    /// Quarantines a reserved execution after uncertain native ownership.
    ///
    /// Quarantine is monotonic: the nonce can never obtain another dispatch
    /// permit or be published through the normal completion path. A new physical
    /// observation requires an explicitly new execution nonce.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid reason, unknown ownership, divergent
    /// request, completed result, corrupt state or publication failure.
    pub fn quarantine_observed_attempt(
        &self,
        ledger_name: &str,
        request: &ObservedAttemptRequest,
        reason: &str,
    ) -> Result<ObservedAttemptState, CampaignRepositoryError> {
        if reason.len() > 256 {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "observed quarantine reason",
            }
            .into());
        }
        crate::policy::validate_identifier(reason, "observed quarantine reason is invalid")?;

        let name = observed_ref_name(ledger_name)?;
        let _guard = self.lock_mutation()?;
        self.require_observed_dispatch_custody(ledger_name, request)?;
        let current = self
            .refs
            .read_ref(&name)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let ledger = self.read_observed_ledger(current)?;
        require_observed_realization(&ledger, request)?;
        let prior = self
            .observed_state_in(&ledger, request.execution())?
            .ok_or(CampaignRepositoryError::NotFound)?;
        if prior.request() != request {
            return Err(integrity("observed-quarantine-request-mismatch"));
        }
        match prior {
            ObservedAttemptState::Quarantined { .. } => return Ok(prior),
            ObservedAttemptState::Reserved(_) => {}
            ObservedAttemptState::Completed(_) => {
                return Err(integrity("observed-completed-execution-cannot-quarantine"));
            }
        }
        let state = ObservedAttemptState::Quarantined {
            request: request.clone(),
            reason: reason.to_owned(),
        };
        self.advance_observed_state(&name, Some(current), ledger, &state)?;
        Ok(state)
    }

    fn authenticate_observed_request(
        &self,
        request: &ObservedAttemptRequest,
        admission: &impl ObservedAttemptAdmission,
    ) -> Result<(), CampaignRepositoryError> {
        let roster = request.capabilities().roster();
        let scenario = self.load_scenario_artifact(roster.scenario())?;
        let configuration = self.load_configuration_artifact(roster.configuration())?;
        if configuration.scenario_artifact() != roster.scenario()
            || configuration.scenario() != scenario.scenario()
        {
            return Err(integrity(
                "observed-artifact-scenario-configuration-mismatch",
            ));
        }
        self.authenticated_closure_ids([request.inputs()])?;
        admission.authenticate(request, &scenario, &configuration)?;
        Ok(())
    }

    fn require_observed_dispatch_custody(
        &self,
        ledger_name: &str,
        request: &ObservedAttemptRequest,
    ) -> Result<(), CampaignRepositoryError> {
        let reservation = self
            .read_observed_dispatch_reservation(request.execution())?
            .ok_or_else(|| integrity("observed-dispatch-custody-missing"))?;
        require_observed_dispatch_binding(&reservation, ledger_name, request)
    }

    fn read_observed_dispatch_reservation(
        &self,
        execution: crate::ExecutionId,
    ) -> Result<Option<ObservedDispatchReservation>, CampaignRepositoryError> {
        let Some(id) = self.refs.read_ref(&observed_nonce_ref_name(execution)?)? else {
            return Ok(None);
        };
        let envelope = self.read_observed_envelope(id, ObjectKind::CampaignFact)?;
        let Some(ObservedEnvelopeRecord::Reservation(reservation)) =
            ObservedEnvelopeRecord::decode(id, &envelope)?
        else {
            return Err(integrity("observed-dispatch-custody-shape"));
        };
        if reservation.request.execution() != execution {
            return Err(integrity("observed-dispatch-custody-nonce-mismatch"));
        }
        Ok(Some(reservation))
    }

    fn read_observed_ledger(
        &self,
        id: ContentId,
    ) -> Result<ObservedLedger, CampaignRepositoryError> {
        let actual = self.read_observed_envelope(id, ObjectKind::CampaignSnapshot)?;
        let record: ObservedLedger = crate::codec::decode_bounded(
            actual.body(),
            MAX_OBSERVED_RECORD_BYTES,
            "observed ledger bytes",
        )?;
        require_observed_envelope(&actual, &record.envelope()?)?;
        Ok(record)
    }

    fn observed_state_in(
        &self,
        ledger: &ObservedLedger,
        execution: crate::ExecutionId,
    ) -> Result<Option<ObservedAttemptState>, CampaignRepositoryError> {
        let Some(id) = self
            .merkle
            .get(ledger.executions, execution_key(execution))?
        else {
            return Ok(None);
        };
        let actual = self.read_observed_envelope(id, ObjectKind::CampaignFact)?;
        let state: ObservedAttemptState = crate::codec::decode_bounded(
            actual.body(),
            MAX_OBSERVED_RECORD_BYTES,
            "observed state bytes",
        )?;
        require_observed_envelope(&actual, &state.envelope()?)?;
        if state.request().execution() != execution
            || state.request().capabilities().digest() != ledger.capabilities
        {
            return Err(integrity("observed-index-execution-realization-mismatch"));
        }

        let request_envelope =
            self.read_observed_envelope(state.request().content_id()?, ObjectKind::CampaignFact)?;
        require_observed_envelope(&request_envelope, &state.request().envelope()?)?;
        if let ObservedAttemptState::Completed(result) = &state {
            let result_envelope =
                self.read_observed_envelope(result.id()?.content_id(), ObjectKind::Observation)?;
            require_observed_envelope(&result_envelope, &result.envelope()?)?;
            self.authenticated_closure_ids([
                result.incoming(),
                result.outgoing(),
                result.evidence(),
            ])?;
        }
        Ok(Some(state))
    }

    fn advance_observed_state(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        mut ledger: ObservedLedger,
        state: &ObservedAttemptState,
    ) -> Result<(), CampaignRepositoryError> {
        let state_id = self.put_observed_envelope(&state.envelope()?, ObjectKind::CampaignFact)?;
        ledger.executions = self
            .merkle
            .insert(
                ledger.executions,
                execution_key(state.request().execution()),
                state_id,
            )?
            .content_id();
        let next = self.put_observed_envelope(&ledger.envelope()?, ObjectKind::CampaignSnapshot)?;
        match self.refs.compare_exchange(name, expected, next)? {
            RefCasOutcome::Advanced { .. } => Ok(()),
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    fn put_observed_envelope(
        &self,
        envelope: &ContentEnvelope,
        kind: ObjectKind,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let bytes = envelope.canonical_bytes();
        if bytes.len() > MAX_OBSERVED_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "observed envelope bytes",
            }
            .into());
        }
        let id = envelope.content_id(kind);
        let receipt = self
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))?;
        if receipt.id != id {
            return Err(integrity("observed-put-receipt-mismatch"));
        }
        Ok(id)
    }

    fn read_observed_envelope(
        &self,
        id: ContentId,
        kind: ObjectKind,
    ) -> Result<ContentEnvelope, CampaignRepositoryError> {
        if id.kind() != kind {
            return Err(integrity("observed-object-kind-mismatch"));
        }
        let bytes = self
            .blobs
            .read(id, None)?
            .read_all(MAX_OBSERVED_RECORD_BYTES as u64)?;
        let envelope =
            ContentEnvelope::from_canonical_bytes(&bytes).map_err(CampaignCodecError::from)?;
        if envelope.content_id(kind) != id {
            return Err(integrity("observed-content-id-mismatch"));
        }
        Ok(envelope)
    }
}

fn observed_ref_name(name: &str) -> Result<RefName, CampaignRepositoryError> {
    if name.is_empty() || name.contains('/') {
        return Err(CampaignRepositoryError::InvalidRequest {
            reason: "observed ledger name must be one nonempty ref segment",
        });
    }
    Ok(RefName::new(format!("observed-attempt-ledgers/{name}"))?)
}

fn observed_nonce_ref_name(
    execution: crate::ExecutionId,
) -> Result<RefName, CampaignRepositoryError> {
    Ok(RefName::new(format!(
        "observed-execution-reservations/{}",
        execution_key(execution).to_hex()
    ))?)
}

fn require_observed_dispatch_binding(
    reservation: &ObservedDispatchReservation,
    ledger_name: &str,
    request: &ObservedAttemptRequest,
) -> Result<(), CampaignRepositoryError> {
    if reservation.ledger != ledger_name || reservation.request != *request {
        return Err(integrity(
            "observed-execution-nonce-reused-across-ledgers-or-requests",
        ));
    }
    Ok(())
}

fn require_observed_realization(
    ledger: &ObservedLedger,
    request: &ObservedAttemptRequest,
) -> Result<(), CampaignRepositoryError> {
    if ledger.capabilities != request.capabilities().digest() {
        return Err(integrity("observed-ledger-realization-mismatch"));
    }
    Ok(())
}

fn require_observed_envelope(
    actual: &ContentEnvelope,
    expected: &ContentEnvelope,
) -> Result<(), CampaignRepositoryError> {
    if actual.canonical_bytes() != expected.canonical_bytes() {
        return Err(integrity("observed-envelope-schema-or-children-mismatch"));
    }
    Ok(())
}
