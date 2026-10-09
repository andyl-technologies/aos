//! Original common grants, bounded native prefixes, and guest-write custody.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{Id, U64, canonical};
use crucible_node_provider::gem5::{Gem5ExactRange, Gem5Run};

use crate::{
    node_contract::*,
    node_scheduling::{InputPayload, NativePublication},
};

use super::{
    QualifiedGem5Node, ledger::PREFIX_STORAGE_CREDIT, node::native_refusal,
    positions::callback_positions, refusal,
};

impl QualifiedGem5Node {
    pub(super) fn begin(&mut self, admission: &OperationAdmission) -> Submission {
        let check = || -> Result<(), OperationFailure> {
            if self.quarantined
                || self.active.is_some()
                || !self.same_world(admission.activation())
                || admission.token().route() != &self.preparation.route
                || admission.inputs().is_some()
            {
                return Err(refusal(
                    "gem5 original exact grant has foreign, active or input-bearing custody",
                ));
            }
            let (start, limit) = match admission.request() {
                OperationRequest::ExactRun {
                    start,
                    limit,
                    boundary_policy: ExactBoundaryPolicy::HorizonPark,
                }
                | OperationRequest::BoundarySettle { start, limit } => (*start, *limit),
                _ => {
                    return Err(refusal(
                        "gem5 selected closed profile does not implement this operation",
                    ));
                }
            };
            if start != self.preparation.native.logical_position()
                || start >= limit
                || start.microstep >= self.authority.maximum_microsteps()
                || limit.microstep >= self.authority.maximum_microsteps()
            {
                return Err(refusal(
                    "gem5 exact grant differs from its genuine current full coordinate",
                ));
            }
            self.preparation
                .native
                .next_publication_bound(&self.authority)
                .map_err(native_refusal)?;
            self.ledger.can_run_prefix(PREFIX_STORAGE_CREDIT)
        };
        if let Err(error) = check() {
            return Submission::Refused(Refusal {
                reason: error.reason,
            });
        }
        if let Err(error) = self.ledger.reserve(admission) {
            return Submission::Refused(Refusal {
                reason: error.reason,
            });
        }
        self.activation_authority = Some(Rc::clone(&admission.activation.authority));
        self.active = Some(admission.token().operation().clone());
        self.observation = None;
        Submission::Accepted
    }

    pub(super) fn poll_original(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        let original = match self.ledger.original(token) {
            Ok(original) => original,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Some(error) = &original.failure {
            return Poll::Ready(Err(error.clone()));
        }
        if let Some(outcome) = &original.outcome {
            return Poll::Ready(Ok(outcome.clone()));
        }
        if self.quarantined || self.active.as_ref() != Some(token.operation()) {
            return Poll::Ready(Err(refusal(
                "gem5 original poll lacks retained active custody",
            )));
        }
        let limit = match original.original.request() {
            OperationRequest::ExactRun { limit, .. }
            | OperationRequest::BoundarySettle { limit, .. } => *limit,
            _ => {
                return Poll::Ready(Err(refusal(
                    "gem5 original operation is outside implemented exact scope",
                )));
            }
        };
        let prefix_index = original.prefixes.len();
        let activation_id = original.original.activation.record().activation_id.clone();
        if let Err(error) = self.ledger.prepare_prefix(token) {
            return Poll::Ready(Err(self.contain_failure(token, error.reason)));
        }
        let prefix_identity = match canonical::json_hash(
            "crucible.gem5.original-prefix.v1",
            &serde_json::json!({"operation":token.operation(),"owners":token.route().owners,"activation":activation_id,"prefix":prefix_index}),
        ) {
            Ok(identity) => identity,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.to_string()))),
        };
        let prefix_id = match Id::new(format!("gem5-prefix/{}", prefix_identity.digest)) {
            Ok(id) => id,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.to_string()))),
        };
        let request = Gem5Run {
            kind: "run".to_owned(),
            operation: prefix_id,
            exclusive_tick: limit.time_ps,
            maximum_events: self.resources.maximum_events_per_poll,
            exact_range: Some(Gem5ExactRange {
                start: self.preparation.native.logical_position(),
                limit,
                maximum_microsteps: self.authority.maximum_microsteps(),
            }),
        };
        let mut publications = Vec::new();
        let mut evidence = Vec::new();
        if publications.try_reserve(1).is_err() || evidence.try_reserve(1).is_err() {
            return Poll::Ready(Err(self.contain_failure(
                token,
                "gem5 native publication retention slot allocation refused".to_owned(),
            )));
        }
        let receipt = match self.preparation.native.run_exact(&self.authority, request) {
            Ok(receipt) => receipt,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.to_string()))),
        };
        if let Err(error) = self.preparation.native.validate_completion(&receipt) {
            return Poll::Ready(Err(self.contain_failure(token, error.to_string())));
        }
        if receipt.publications.len() > 1 {
            return Poll::Ready(Err(self.contain_failure(
                token,
                "gem5 installed fixed guest emitted more than its single native stdout write"
                    .to_owned(),
            )));
        }
        // The raw native receipt enters immutable host custody before any native
        // ACK. Budget progress remains a prefix of the original common grant.
        let proof_ref = match self.ledger.retain_prefix(token, receipt.clone()) {
            Ok(reference) => reference,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.reason))),
        };
        if !receipt.output.is_empty() && receipt.publications.is_empty() {
            return Poll::Ready(Err(self.contain_failure(
                token,
                "gem5 legacy file-polled output has no qualified native birth".to_owned(),
            )));
        }
        if receipt.reason == "event_budget" && receipt.publications.is_empty() {
            if let Err(error) = self.preparation.native.acknowledge(&receipt.operation) {
                return Poll::Ready(Err(self.contain_failure(token, error.to_string())));
            }
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut sequence = self.sequence;
        for birth in &receipt.publications {
            let expected = match sequence.checked_add(1) {
                Some(value) => value,
                None => {
                    return Poll::Ready(Err(self.contain_failure(
                        token,
                        "gem5 native output sequence exhausted".to_owned(),
                    )));
                }
            };
            let Some(endpoint) = &self.output else {
                return Poll::Ready(Err(self.contain_failure(
                    token,
                    "gem5 native output lacks an admitted public lane".to_owned(),
                )));
            };
            if birth.output_id.get() != expected
                || birth.guest_pid != U64::new(100)
                || birth.context_id != U64::new(0)
                || birth.guest_fd != 1
                || birth.causal_parent.get() != 0
                || birth.payload.len() as u64 > self.maximum_payload
            {
                return Poll::Ready(Err(self.contain_failure(token, "gem5 stdout birth differs from the installed single-thread closed guest profile".to_owned())));
            }
            let (evaluation, publication) = match callback_positions(
                birth.tick,
                birth.tick_ordinal,
                self.authority.maximum_microsteps(),
            ) {
                Ok(positions) => positions,
                Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.reason))),
            };
            let payload = match canonical::content_ref(&birth.payload, "application/octet-stream") {
                Ok(reference) => reference,
                Err(error) => {
                    return Poll::Ready(Err(self.contain_failure(token, error.to_string())));
                }
            };
            let publication_id = match Id::new(format!("gem5/output/{}", birth.output_id.get())) {
                Ok(identity) => identity,
                Err(error) => {
                    return Poll::Ready(Err(self.contain_failure(token, error.to_string())));
                }
            };
            evidence.push(InputPayload {
                reference: payload.clone(),
                bytes: birth.payload.clone(),
            });
            publications.push(NativePublication {
                publication_id,
                endpoint: endpoint.clone(),
                native_sequence: birth.output_id,
                publication,
                evaluation: Some(evaluation),
                causal_parents: Vec::new(),
                payload,
                payload_bytes: birth.payload.clone(),
            });
            sequence = expected;
        }
        if let Err(error) = self.ledger.retain_objects(token, evidence) {
            return Poll::Ready(Err(self.contain_failure(token, error.reason)));
        }
        let scheduling = match self.scheduling(proof_ref, publications) {
            Ok(observation) => observation,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.reason))),
        };
        let reached = receipt.after.logical_position;
        let stop = if reached == limit {
            StopReason::HorizonPark
        } else if !scheduling.publications.is_empty() {
            StopReason::Output
        } else if receipt.reason == "guest_exit" {
            StopReason::Lifecycle
        } else {
            return Poll::Ready(Err(self.contain_failure(
                token,
                "gem5 terminal native stop lacks qualified exact classification".to_owned(),
            )));
        };
        let outcome = OperationOutcome {
            operation: token.operation().clone(),
            node: token.route().node.clone(),
            owners: token.route().owners.clone(),
            progress: ProgressEvidence::Exact { reached, stop },
            retained_outputs: scheduling
                .publications
                .iter()
                .map(|publication| publication.publication_id.clone())
                .collect(),
            scheduling: Some(scheduling),
        };
        match self.ledger.original_mut(token) {
            Ok(original) => original.outcome = Some(outcome.clone()),
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.reason))),
        }
        self.sequence = sequence;
        Poll::Ready(Ok(outcome))
    }

    pub(super) fn authenticate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        let retained = self.ledger.original(original.token())?;
        if !self.same_world(original.activation())
            || retained.original.request() != original.request()
            || retained.outcome.as_ref() != Some(outcome)
            || retained.failure.is_some()
        {
            return Err(refusal(
                "gem5 outcome differs from its original live operation and native receipt custody",
            ));
        }
        for receipt in &retained.prefixes {
            self.preparation
                .native
                .validate_completion(receipt)
                .map_err(native_refusal)?;
        }
        Ok(())
    }

    pub(super) fn acknowledge_original(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        let original = self.ledger.original(token)?;
        let outcome = original
            .outcome
            .as_ref()
            .ok_or_else(|| refusal("gem5 publication ACK precedes original terminal outcome"))?;
        if outcome.retained_outputs != outputs {
            return Err(refusal(
                "gem5 publication ACK changed original output inventory",
            ));
        }
        if original.acknowledged {
            return Ok(());
        }
        let last = original
            .prefixes
            .last()
            .ok_or_else(|| refusal("gem5 original terminal outcome lost its native prefix"))?;
        if let Err(error) = self.preparation.native.acknowledge(&last.operation) {
            return Err(self.contain_failure(token, error.to_string()));
        }
        self.ledger.original_mut(token)?.acknowledged = true;
        self.active = None;
        Ok(())
    }

    fn contain_failure(&mut self, token: &OperationToken, reason: String) -> OperationFailure {
        let failure = OperationFailure {
            effects: EffectKnowledge::MayHaveProgressed,
            reason,
        };
        if let Ok(original) = self.ledger.original_mut(token) {
            original.failure = Some(failure.clone());
        }
        self.quarantine_resources();
        failure
    }
}
