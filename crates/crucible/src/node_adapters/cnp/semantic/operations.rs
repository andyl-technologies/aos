//! Original exact Begin/Poll/Cancel and authenticated publication retirement.

use crucible_node_contract::{Extensions, Id, OperatingMode, U64, Validate};
use crucible_node_provider::{
    bodies::*,
    envelope::{Method, Nullable},
};

use crate::node_contract::{
    CancelStatus, ExactBoundaryPolicy, OperationAdmission, OperationFailure, OperationOutcome,
    OperationRequest, OperationToken,
};

use super::{
    CnpSemanticNode, after_effect,
    preparation::request_id,
    refused,
    state::{OriginalCancellation, OriginalOperation},
    unknown,
};

impl CnpSemanticNode {
    pub(super) fn check_token(
        &self,
        token: &OperationToken,
    ) -> Result<&OriginalOperation, OperationFailure> {
        let original = self
            .state()?
            .operations
            .get(token.operation())
            .ok_or_else(|| refused("generic original operation is absent"))?;
        if !original.admission.token().same_authority(token) {
            return Err(refused(
                "generic operation token has foreign original authority",
            ));
        }
        Ok(original)
    }

    pub(super) fn begin_original(
        &mut self,
        admission: &OperationAdmission,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let token = admission.token();
        if let Some(original) = self.state()?.operations.get(token.operation()) {
            if !original.admission.token().same_authority(token)
                || original.admission.request() != admission.request()
                || !original
                    .admission
                    .activation()
                    .same_authority(admission.activation())
            {
                return Err(refused("generic retry changed original admission"));
            }
            return original.validate_repeated_begin();
        }
        let (start, limit, _boundary) = match admission.request() {
            OperationRequest::ExactRun {
                start,
                limit,
                boundary_policy,
            } => (*start, *limit, *boundary_policy),
            OperationRequest::BoundarySettle { start, limit } if start.time_ps == limit.time_ps => {
                (*start, *limit, ExactBoundaryPolicy::HorizonPark)
            }
            _ => {
                return Err(refused(
                    "generic installed native source supports exact operations only",
                ));
            }
        };
        if token.route() != &self.route || start > limit {
            return Err(refused(
                "generic original grant changed native route or interval",
            ));
        }
        let source = self.source()?;
        let install = source.installation();
        if self.state()?.operations.len() >= install.maximum_operations
            || self
                .state()?
                .operations
                .values()
                .any(|original| !original.acknowledged)
        {
            return Err(refused(
                "generic original operation credit or owner reservation is unavailable",
            ));
        }
        if let Some(batch) = admission.inputs() {
            let staged = self
                .state()?
                .inputs
                .get(batch.stage_operation())
                .ok_or_else(|| refused("generic grant input cut has not been natively staged"))?;
            if staged.original.batch() != batch.batch()
                || staged.original.inventory() != batch.inventory()
                || !staged
                    .original
                    .activation()
                    .same_authority(admission.activation())
                || staged.acknowledgement.is_none()
            {
                return Err(refused(
                    "generic grant changed original native input association",
                ));
            }
        }
        source.preflight_operation(self.scope()?, admission)?;
        // Refuse an unsupported source translation before the original native
        // world activation or input authorization can perform any effect.
        let boundary_policy = source.boundary_policy(self.scope()?, admission)?;
        let reserved = install
            .maximum_authorization_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(install.maximum_result_bytes))
            .ok_or_else(|| refused("generic original callback credit overflows"))?;
        self.state_mut()?
            .credit
            .reserve_bytes(reserved, install.maximum_semantic_bytes)?;
        let watermark = self.state()?.watermark;
        let input = source.input_authorization(self.scope()?, admission, watermark)?;
        input.reference.verify(&input.bytes).map_err(unknown)?;
        super::budget::serialized_size(&input, install.maximum_authorization_bytes)?;
        self.state_mut()?
            .credit
            .reserve(admission.request(), install.maximum_semantic_bytes)?;
        let record = admission.activation().record();
        let arguments = ExactRunArguments {
            grant_id: token.operation().clone(),
            participant_ids: install.owner.owner.participant_ids.clone(),
            realization_id: install.realize.realization_id.clone(),
            activation_id: record.activation_id.clone(),
            world_generation: record.generation,
            owner_generation: install.binding.authority.owner_generation,
            input_epoch: install.binding.authority.input_epoch.clone(),
            mode: OperatingMode::Exact,
            ordering_profile: "superdense-v1".into(),
            start,
            limit,
            boundary_policy,
            input_authorization: input.reference.clone(),
            input_watermark: watermark,
        };
        self.state_mut()?
            .credit
            .reserve(&arguments, install.maximum_semantic_bytes)?;
        let serde_json::Value::Object(arguments) =
            serde_json::to_value(arguments).map_err(unknown)?
        else {
            return Err(refused(
                "generic exact argument serializer is not an object",
            ));
        };
        let begin = BeginRequest {
            kind: if matches!(admission.request(), OperationRequest::BoundarySettle { .. }) {
                BeginKind::BoundarySettle
            } else {
                BeginKind::ExactRun
            },
            binding_hash: install.owner.identity().map_err(unknown)?,
            owner_generation: install.binding.authority.owner_generation,
            activation_id: Nullable(Some(record.activation_id.clone())),
            world_generation: record.generation,
            arguments,
            extensions: Extensions::new(),
        };
        begin.validate().map_err(unknown)?;
        // Complete the exact request, ID and retained credit before activation.
        // Once this original row exists, every uncertain attempt keeps custody.
        let (id, original) = OriginalOperation::prepare(
            admission,
            begin,
            &mut self.state_mut()?.credit,
            install.maximum_semantic_bytes,
        )?;
        let begin = original.begin.clone();
        self.state_mut()?
            .operations
            .insert(token.operation().clone(), original);
        let result = (|| {
            self.activate_original(admission.activation())?;
            self.upload(&input.reference, &input.bytes)?;
            let response = self.call(
                id,
                Some(token.operation().clone()),
                Method::Begin,
                true,
                begin,
            )?;
            if !response.shape.is_accepted() {
                self.retain_terminal(token, &response)?;
            }
            self.state_mut()?
                .operations
                .get_mut(token.operation())
                .ok_or_else(|| unknown("generic original Begin custody disappeared"))?
                .begin_acknowledged = true;
            Ok(())
        })();
        if let Err(failure) = result {
            let original = self
                .state_mut()?
                .operations
                .get_mut(token.operation())
                .ok_or_else(|| unknown("generic original failed Begin custody disappeared"))?;
            original.retain_failure(&failure);
            return original.validate_repeated_begin();
        }
        Ok(())
    }

    pub(super) fn retain_terminal(
        &mut self,
        token: &OperationToken,
        response: &ResponseBody,
    ) -> Result<(), OperationFailure> {
        let result = self.authenticate_terminal(token, response);
        if let Err(error) = &result {
            // A failed source decode cannot make a new native attempt eligible.
            // Complete raw response/body journals remain in the actual capsule.
            self.state_mut()?
                .operations
                .get_mut(token.operation())
                .ok_or_else(|| unknown("generic original failure reservation disappeared"))?
                .retain_failure(error);
        }
        result
    }

    fn authenticate_terminal(
        &mut self,
        token: &OperationToken,
        response: &ResponseBody,
    ) -> Result<(), OperationFailure> {
        let admission = self.check_token(token)?.admission.clone();
        let outcome = self
            .source()?
            .outcome(self.scope()?, &admission, response)
            .map_err(after_effect)?;
        self.source()?
            .validate_outcome(self.scope()?, &admission, &outcome)
            .map_err(after_effect)?;
        if outcome.operation != *token.operation()
            || outcome.node != self.route.node
            || outcome.owners != self.route.owners
        {
            return Err(unknown(
                "generic installed oracle returned a foreign original result",
            ));
        }
        let maximum = self.source()?.installation().maximum_result_bytes;
        super::budget::serialized_size(&outcome, maximum).map_err(after_effect)?;
        self.state_mut()?
            .operations
            .get_mut(token.operation())
            .ok_or_else(|| unknown("generic original result reservation disappeared"))?
            .outcome = Some(outcome);
        Ok(())
    }

    pub(super) fn poll_original(
        &mut self,
        token: &OperationToken,
    ) -> Result<Option<OperationOutcome>, OperationFailure> {
        self.current()?;
        let original = self.check_token(token)?;
        if let Some(outcome) = &original.outcome {
            self.source()?
                .validate_outcome(self.scope()?, &original.admission, outcome)?;
            return Ok(Some(outcome.clone()));
        }
        if let Some(failure) = &original.failure {
            return Err(failure.clone());
        }
        self.source()?
            .preflight_transition(self.scope()?.native, super::CnpSemanticTransition::Query)?;
        let sequence = U64::new(
            original
                .polls
                .get()
                .checked_add(1)
                .ok_or_else(|| refused("generic original polling identity exhausted"))?,
        );
        let request =
            Id::new(format!("cnp-poll-{}-{sequence}", token.operation())).map_err(unknown)?;
        self.state_mut()?
            .operations
            .get_mut(token.operation())
            .ok_or_else(|| refused("generic original operation disappeared"))?
            .polls = sequence;
        let response = self.call(
            request,
            Some(token.operation().clone()),
            Method::Poll,
            true,
            PollRequest {
                after_observation_sequence: U64::new(0),
                extensions: Extensions::new(),
            },
        )?;
        let Some(MethodResult::Poll(result)) = response.result else {
            return Err(unknown("generic original poll did not complete"));
        };
        if result.operation_id != *token.operation() {
            return Err(unknown("generic poll changed original operation identity"));
        }
        let original = self.check_token(token)?;
        let Some(saved) = result.validated_outcome(&original.begin).map_err(unknown)? else {
            return Ok(None);
        };
        self.retain_terminal(token, &saved)?;
        Ok(self.check_token(token)?.outcome.clone())
    }

    pub(super) fn cancel_original(
        &mut self,
        token: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        self.current()?;
        let original = self.check_token(token)?;
        if let Some(status) = original.cancellation_status() {
            return status;
        }
        self.source()?
            .preflight_transition(self.scope()?.native, super::CnpSemanticTransition::Query)?;
        let request = request_id("cancel", token.operation())?;
        let body = CancelRequest {
            reason: Id::new("common-original-cancellation").map_err(unknown)?,
            extensions: Extensions::new(),
        };
        self.state_mut()?
            .operations
            .get_mut(token.operation())
            .ok_or_else(|| refused("generic original cancellation custody disappeared"))?
            .cancellation = OriginalCancellation::Pending;
        let result = (|| {
            let response = self.call(
                request,
                Some(token.operation().clone()),
                Method::Cancel,
                true,
                body,
            )?;
            let Some(MethodResult::Cancel(result)) = response.result else {
                return Err(unknown(
                    "generic original cancellation request remains unresolved",
                ));
            };
            Ok(result.cancel_requested)
        })();
        self.state_mut()?
            .operations
            .get_mut(token.operation())
            .ok_or_else(|| unknown("generic original cancellation custody disappeared"))?
            .complete_cancellation(result)
    }

    pub(super) fn acknowledge_original(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let original = self.check_token(token)?;
        let outcome = original.outcome.as_ref().ok_or_else(|| {
            refused("generic original publication has no authenticated terminal result")
        })?;
        if outcome.retained_outputs != outputs {
            return Err(refused(
                "generic publication ACK changed exact original output population",
            ));
        }
        if original.acknowledged {
            return Ok(());
        }
        let source = self.source()?;
        source.preflight_transition(
            self.scope()?.native,
            super::CnpSemanticTransition::Retirement,
        )?;
        if original.retirement.is_none() {
            let consumption =
                source.consumption(self.scope()?, &original.admission, outcome, outputs)?;
            consumption
                .reference
                .verify(&consumption.bytes)
                .map_err(unknown)?;
            super::budget::serialized_size(
                &consumption,
                source.installation().maximum_authorization_bytes,
            )?;
            self.state_mut()?
                .operations
                .get_mut(token.operation())
                .ok_or_else(|| refused("generic original retirement reservation disappeared"))?
                .retirement = Some(consumption);
        }
        let consumption = self
            .check_token(token)?
            .retirement
            .as_ref()
            .ok_or_else(|| unknown("generic original consumption body disappeared"))?
            .clone();
        let begin_id = request_id("begin", token.operation())?;
        let request = RetireRequest {
            request_ids: vec![begin_id.clone()],
            operation_ids: vec![token.operation().clone()],
            disposition: RetirementDisposition::Consumed,
            custody_receipt: Nullable(Some(consumption.reference.clone())),
            extensions: Extensions::new(),
        };
        let id = request_id("retire", token.operation())?;
        self.upload(&consumption.reference, &consumption.bytes)?;
        let response = self.call(id, None, Method::Retire, true, request)?;
        let Some(MethodResult::Retire(result)) = response.result else {
            return Err(unknown(
                "generic original native retirement remains unresolved",
            ));
        };
        if result.retired_request_ids != [begin_id]
            || result.retired_operation_ids != [token.operation().clone()]
        {
            return Err(unknown(
                "generic original native retirement changed ACK population",
            ));
        }
        let original = self.check_token(token)?;
        source
            .validate_retirement(self.scope()?, &original.admission, &consumption, &result)
            .map_err(after_effect)?;
        self.state_mut()?
            .operations
            .get_mut(token.operation())
            .ok_or_else(|| unknown("generic original ACK custody disappeared"))?
            .acknowledged = true;
        Ok(())
    }
}
