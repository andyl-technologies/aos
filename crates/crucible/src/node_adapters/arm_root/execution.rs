//! Mediates original common permissions and model-aware Serial prefixes.
//!
//! Every subordinate Poll retains its original request scope and raw native
//! result. Budget ACKs release only mechanical prefix administration; they never
//! manufacture a common completion, public commit or acknowledged UART byte.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{Id, Phase, Position, U64, canonical};
use crucible_node_provider::gem5::{ArmRootRunOutcome, Gem5ExactRange, Gem5Run};

use crate::{node_contract::*, node_scheduling::NativePublication};

use super::{QualifiedArmRootNode, refusal};

impl QualifiedArmRootNode {
    pub(super) fn begin(&mut self, admission: &OperationAdmission) -> Submission {
        let validate = || -> Result<(), OperationFailure> {
            if self.quarantined
                || self.active.is_some()
                || !self.same_world(admission.activation())
                || admission.token().route() != &self.preparation.route
                || admission.inputs().is_some()
            {
                return Err(refusal(
                    "ARM original grant has foreign, active or input-bearing custody",
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
                        "ARM source-owned root profile does not implement this operation",
                    ));
                }
            };
            if start != self.preparation.native.logical_position()
                || start >= limit
                || start.microstep >= self.authority.maximum_microsteps()
                || limit.microstep >= self.authority.maximum_microsteps()
            {
                return Err(refusal(
                    "ARM common permission differs from its actual full starting coordinate",
                ));
            }
            self.preparation
                .native
                .next_publication_bound(&self.authority)
                .map_err(|error| refusal(&error.to_string()))?;
            Ok(())
        };
        if let Err(error) = validate().and_then(|()| self.ledger.reserve(admission)) {
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
        if let Some(failure) = &original.failure {
            return Poll::Ready(Err(failure.clone()));
        }
        if let Some(outcome) = &original.outcome {
            return Poll::Ready(Ok(outcome.clone()));
        }
        if self.quarantined || self.active.as_ref() != Some(token.operation()) {
            return Poll::Ready(Err(refusal(
                "ARM Poll lost its original active native custody",
            )));
        }
        let limit = match original.admission.request() {
            OperationRequest::ExactRun { limit, .. }
            | OperationRequest::BoundarySettle { limit, .. } => *limit,
            _ => return Poll::Ready(Err(refusal("ARM original grant changed operation class"))),
        };
        let index = original.prefixes.len();
        let activation = SavedRuntimeActivation::from(original.admission.activation.record());
        if let Err(error) = self.ledger.prepare_prefix(token) {
            return Poll::Ready(Err(self.contain_failure(token, error.reason)));
        }
        let digest = match canonical::json_hash(
            "crucible.gem5.arm-root-original-poll.v1",
            &serde_json::json!({
                "operation":token.operation(), "route":token.route(), "activation":activation, "poll":index,
            }),
        ) {
            Ok(digest) => digest,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.to_string()))),
        };
        let operation = match Id::new(format!("arm-root-poll/{}", digest.digest)) {
            Ok(operation) => operation,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.to_string()))),
        };
        let request = Gem5Run {
            kind: "run".to_owned(),
            operation,
            exclusive_tick: limit.time_ps,
            maximum_events: self.resources.maximum_events_per_poll,
            exact_range: Some(Gem5ExactRange {
                start: self.preparation.native.logical_position(),
                limit,
                maximum_microsteps: self.authority.maximum_microsteps(),
            }),
        };
        let mut publications = Vec::new();
        if publications.try_reserve_exact(1).is_err() {
            return Poll::Ready(Err(self.contain_failure(
                token,
                "ARM original Serial publication slot is unavailable".to_owned(),
            )));
        }
        let native = match self.preparation.native.run_exact(&self.authority, request) {
            Ok(native) => native,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.to_string()))),
        };
        let proof = match self.ledger.retain_prefix(token, native.clone()) {
            Ok(proof) => proof,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.reason))),
        };
        let prefix = match native {
            ArmRootRunOutcome::Completed { prefix, .. } => prefix,
            ArmRootRunOutcome::Refused {
                refusal: native_refusal,
                ..
            } => {
                // This authentic receipt proves no callbacks for this Poll,
                // never for the earlier successful prefixes of the same grant.
                if let Err(error) = self
                    .preparation
                    .native
                    .acknowledge_refusal(&native_refusal.original.operation)
                {
                    return Poll::Ready(Err(self.contain_failure(token, error.to_string())));
                }
                let progressed = self.ledger.original(token).is_ok_and(|original| {
                    original
                        .prefixes
                        .iter()
                        .filter_map(|prefix| prefix.outcome.completion())
                        .any(|prefix| prefix.processed_events.get() > 0)
                });
                let failure = OperationFailure {
                    effects: if progressed {
                        EffectKnowledge::MayHaveProgressed
                    } else {
                        EffectKnowledge::None
                    },
                    reason: "ARM original native Poll refused its pre-effect diagnostic credit"
                        .to_owned(),
                };
                if let Ok(original) = self.ledger.original_mut(token) {
                    original.failure = Some(failure.clone());
                }
                self.active = None;
                return Poll::Ready(Err(failure));
            }
        };
        if prefix.publications.len() > 1 || prefix.output.len() != prefix.publications.len() {
            return Poll::Ready(Err(self.contain_failure(
                token,
                "ARM stop-on-first-UART source contract differs".to_owned(),
            )));
        }
        if prefix.reason == "event_budget"
            && prefix.publications.is_empty()
            && prefix.after.logical_position < limit
        {
            if let Err(error) = self.preparation.native.acknowledge(&prefix.operation) {
                return Poll::Ready(Err(self.contain_failure(token, error.to_string())));
            }
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut sequence = self.sequence;
        for birth in &prefix.publications {
            let expected = match sequence.checked_add(1) {
                Some(expected) => expected,
                None => {
                    return Poll::Ready(Err(self.contain_failure(
                        token,
                        "ARM original Serial sequence exhausted".to_owned(),
                    )));
                }
            };
            if birth.output_id.get() != expected
                || birth.facet != "serial"
                || birth.terminal != "system.terminal"
                || birth.causal_parent.get() != 0
                || birth.payload.len() != 1
            {
                return Poll::Ready(Err(self.contain_failure(
                    token,
                    "ARM genuine Serial birth differs from its installed root model".to_owned(),
                )));
            }
            let (evaluation, publication) = match serial_positions(
                birth.tick,
                birth.tick_ordinal,
                self.authority.maximum_microsteps(),
            ) {
                Ok(positions) => positions,
                Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.reason))),
            };
            let payload = match canonical::content_ref(&birth.payload, "application/octet-stream") {
                Ok(payload) => payload,
                Err(error) => {
                    return Poll::Ready(Err(self.contain_failure(token, error.to_string())));
                }
            };
            let publication_id = match Id::new(format!("arm-root/serial/{}", birth.output_id.get()))
            {
                Ok(publication_id) => publication_id,
                Err(error) => {
                    return Poll::Ready(Err(self.contain_failure(token, error.to_string())));
                }
            };
            if let Err(error) = self.ledger.retain_payload(token, &payload, &birth.payload) {
                return Poll::Ready(Err(self.contain_failure(token, error.reason)));
            }
            publications.push(NativePublication {
                publication_id,
                endpoint: self.output.clone(),
                native_sequence: birth.output_id,
                publication,
                evaluation: Some(evaluation),
                causal_parents: Vec::new(),
                payload,
                payload_bytes: birth.payload.clone(),
            });
            sequence = expected;
        }
        let scheduling = match self.scheduling(proof, publications) {
            Ok(scheduling) => scheduling,
            Err(error) => return Poll::Ready(Err(self.contain_failure(token, error.reason))),
        };
        let reached = prefix.after.logical_position;
        let stop = if reached == limit {
            StopReason::HorizonPark
        } else if !scheduling.publications.is_empty() {
            StopReason::Output
        } else if prefix.reason == "guest_exit" {
            StopReason::Lifecycle
        } else {
            return Poll::Ready(Err(self.contain_failure(
                token,
                "ARM terminal prefix has no qualified common stop".to_owned(),
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
                .map(|birth| birth.publication_id.clone())
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
        admission: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        let original = self.ledger.original(admission.token())?;
        if !self.same_world(admission.activation())
            || original.admission.request() != admission.request()
            || original.outcome.as_ref() != Some(outcome)
            || original.failure.is_some()
        {
            return Err(refusal(
                "ARM terminal outcome differs from its retained original grant",
            ));
        }
        for (index, prefix) in original.prefixes.iter().enumerate() {
            let current_scope = prefix.route == *original.admission.token().route()
                && prefix.activation
                    == SavedRuntimeActivation::from(original.admission.activation.record());
            let historical_scope =
                self.restored
                    .as_ref()
                    .and_then(|source| {
                        source.wire.operations.iter().find(|saved| {
                            saved.original.operation == *admission.token().operation()
                        })
                    })
                    .and_then(|saved| saved.prefixes.get(index))
                    .is_some_and(|saved| {
                        saved.body == prefix.proof
                            && saved.route == prefix.route
                            && saved.activation == prefix.activation
                    });
            if (!current_scope && !historical_scope)
                || !original.evidence.iter().any(|body| {
                    body.reference == prefix.proof && body.bytes == prefix.outcome.bytes()
                })
            {
                return Err(refusal(
                    "ARM terminal outcome lost exact original native prefix provenance",
                ));
            }
        }
        self.preparation
            .native
            .next_publication_bound(&self.authority)
            .map_err(|error| refusal(&error.to_string()))?;
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
            .ok_or_else(|| refusal("ARM output ACK precedes its original terminal outcome"))?;
        if outcome.retained_outputs != outputs {
            return Err(refusal(
                "ARM output ACK changed original publication inventory",
            ));
        }
        if original.acknowledged {
            return Ok(());
        }
        let prefix = original
            .prefixes
            .last()
            .and_then(|prefix| prefix.outcome.completion())
            .ok_or_else(|| {
                refusal("ARM successful output ACK lost its original native terminal prefix")
            })?;
        if let Err(error) = self.preparation.native.acknowledge(&prefix.operation) {
            return Err(self.contain_failure(token, error.to_string()));
        }
        self.ledger.original_mut(token)?.acknowledged = true;
        self.active = None;
        Ok(())
    }

    fn contain_failure(&mut self, token: &OperationToken, reason: String) -> OperationFailure {
        let failure = OperationFailure {
            effects: EffectKnowledge::Unknown,
            reason,
        };
        if let Ok(original) = self.ledger.original_mut(token) {
            original.failure = Some(failure.clone());
        }
        self.quarantine_resources();
        failure
    }
}

pub(super) fn serial_positions(
    tick: U64,
    tie: U64,
    cap: U64,
) -> Result<(Position, Position), OperationFailure> {
    let microstep = tie
        .get()
        .checked_sub(1)
        .and_then(|value| value.checked_mul(2))
        .ok_or_else(|| refusal("ARM original Serial callback coordinate is invalid"))?;
    let reaction = Position::new(tick, microstep.into(), Phase::Reaction);
    let publication = reaction
        .reaction_publication(cap)
        .map_err(|error| refusal(&error.to_string()))?;
    Ok((reaction, publication))
}
